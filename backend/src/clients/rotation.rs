//! Two-key DPoP rotation with a durable prepare/confirm boundary.
use super::*;
const LIFETIME: i64 = 900;
const PERIOD: i64 = 30 * 86400;
#[derive(Clone, Deserialize, Serialize)]
pub(super) struct Pending {
    pub id: String,
    pub request_id: String,
    pub jwk: Value,
    pub thumbprint: String,
    pub generation: i64,
    pub created_at: i64,
    pub expires_at: i64,
}
pub(super) fn control(n: &Enrollment) -> Value {
    let rotated = n.rotated_at.or(n.enrolled_at).unwrap_or(n.created_at);
    json!({"generation":n.generation,"rotated_at":n.rotated_at,"next_rotation_at":rotated+PERIOD,"rotation_due":n.rotation_requested||now()-rotated>=PERIOD,"pending":n.rotation.as_ref().map(|p|json!({"id":p.id,"expires_at":p.expires_at,"key_fingerprint":p.thumbprint,"expired":p.expires_at<=now()}))})
}
pub(super) fn host_control(a: &App, id: &str) -> Result<Value> {
    let n = by_host(a, id)?
        .into_iter()
        .find(|n| ["active", "approved"].contains(&n.state.as_str()))
        .ok_or_else(unauthorized)?;
    Ok(control(&n))
}
fn candidate(n: &Enrollment, p: &Pending) -> Enrollment {
    let mut candidate = n.clone();
    candidate.jwk = p.jwk.clone();
    candidate.thumbprint = p.thumbprint.clone();
    candidate.generation = p.generation;
    candidate
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Prepare {
    request_id: String,
    new_proof: String,
}
pub(crate) async fn prepare(
    State(a): State<App>,
    h: HeaderMap,
    Path(id): Path<String>,
    Json(p): Json<Prepare>,
) -> Result<Json<Value>> {
    let _gate = a.gate.lock().await;
    let mut n = authenticate(&a, &h, &id, "rotation/prepare")?;
    rate(&a, &format!("rotation:{}", n.id), 6)?;
    if operations::recovery(&a)? {
        return Err(fail(
            StatusCode::SERVICE_UNAVAILABLE,
            "Complete recovery review before credential rotation",
        ));
    }
    if n.state != "active"
        || p.request_id.len() != 64
        || !p.request_id.bytes().all(|b| b.is_ascii_hexdigit())
        || p.new_proof.len() > 2048
    {
        return Err(bad(
            "An active enrollment, bounded request ID and new-key proof are required",
        ));
    }
    let access = h
        .get(header::AUTHORIZATION)
        .and_then(|s| s.to_str().ok())
        .and_then(|s| s.strip_prefix("DPoP "))
        .ok_or_else(unauthorized)?;
    let mut new_headers = HeaderMap::new();
    new_headers.insert("DPoP", p.new_proof.parse().map_err(|_| unauthorized())?);
    let (jwk, thumbprint) = proof(
        &a,
        &new_headers,
        "POST",
        &format!("{PREFIX}/hosts/{id}/rotation/prepare"),
        Some(access),
        None,
    )?;
    if thumbprint == n.thumbprint {
        return Err(bad("Rotation requires a fresh machine key"));
    }
    if let Some(pending) = &n.rotation {
        if pending.expires_at > now()
            && (pending.request_id != p.request_id || pending.thumbprint != thumbprint)
        {
            return Err(fail(
                StatusCode::CONFLICT,
                "Another rotation is pending; resume it or wait for expiration",
            ));
        }
        if pending.request_id == p.request_id {
            if pending.expires_at <= now() {
                return Err(fail(
                    StatusCode::GONE,
                    "Unconfirmed rotation expired; the original credential remains valid",
                ));
            }
            if pending.thumbprint != thumbprint {
                return Err(unauthorized());
            }
            return Ok(Json(prepared(&n, pending)));
        }
    }
    if rows(&a)?.iter().any(|other| {
        other.id != n.id
            && (other.thumbprint == thumbprint
                || other
                    .rotation
                    .as_ref()
                    .is_some_and(|p| p.thumbprint == thumbprint && p.expires_at > now()))
    }) {
        return Err(fail(
            StatusCode::CONFLICT,
            "This public key is already associated with another machine",
        ));
    }
    let pending = Pending {
        id: token()[..32].into(),
        request_id: p.request_id,
        jwk,
        thumbprint,
        generation: n
            .generation
            .checked_add(1)
            .ok_or(bad("Credential generation exhausted"))?,
        created_at: now(),
        expires_at: now() + LIFETIME,
    };
    n.rotation = Some(pending.clone());
    store(&a, &n)?;
    audit(&a, "machine", "client prepare credential rotation", &id)?;
    monitoring::record_event(
        &a,
        &id,
        "credential_rotation_prepared",
        json!({"generation":pending.generation,"key_fingerprint":pending.thumbprint}),
    )?;
    Ok(Json(prepared(&n, &pending)))
}
fn prepared(n: &Enrollment, p: &Pending) -> Value {
    json!({"api_version":1,"rotation_id":p.id,"generation":p.generation,"expires_at":p.expires_at,"key_fingerprint":p.thumbprint,"access_token":credential(&candidate(n,p)),"token_type":"DPoP"})
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Confirm {
    rotation_id: String,
}
pub(crate) async fn confirm(
    State(a): State<App>,
    h: HeaderMap,
    Path(id): Path<String>,
    Json(p): Json<Confirm>,
) -> Result<Json<Value>> {
    let _gate = a.gate.lock().await;
    rate(&a, "rotation-confirm", 1200)?;
    if operations::recovery(&a)? {
        return Err(fail(
            StatusCode::SERVICE_UNAVAILABLE,
            "Complete recovery review before credential rotation",
        ));
    }
    if p.rotation_id.len() != 32 || !p.rotation_id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(unauthorized());
    }
    let mut n = by_host(&a, &id)?
        .into_iter()
        .find(|n| {
            n.state == "active"
                && (n.rotation.as_ref().is_some_and(|v| v.id == p.rotation_id)
                    || n.last_rotation.as_deref() == Some(p.rotation_id.as_str()))
        })
        .ok_or_else(unauthorized)?;
    rate(&a, &format!("confirm:{}", n.id), 6)?;
    if let Some(pending) = n.rotation.clone().filter(|v| v.id == p.rotation_id) {
        let access = h
            .get(header::AUTHORIZATION)
            .and_then(|s| s.to_str().ok())
            .and_then(|s| s.strip_prefix("DPoP "))
            .filter(|s| s.len() == 43)
            .ok_or_else(unauthorized)?;
        let next = candidate(&n, &pending);
        if !equal(&credential(&next), access) {
            return Err(unauthorized());
        }
        proof(
            &a,
            &h,
            "POST",
            &format!("{PREFIX}/hosts/{id}/rotation/confirm"),
            Some(access),
            Some(&pending.thumbprint),
        )?;
        if pending.expires_at <= now() {
            return Err(fail(
                StatusCode::GONE,
                "Unconfirmed rotation expired; retain the original credential",
            ));
        }
        n.jwk = pending.jwk;
        n.thumbprint = pending.thumbprint;
        n.generation = pending.generation;
        n.rotated_at = Some(now());
        n.last_rotation = Some(pending.id);
        n.rotation = None;
        n.rotation_requested = false;
        // No token, old signing key, or unconfirmed key is accepted by ordinary machine routes afterwards.
        store(&a, &n)?;
        audit(&a, "machine", "client confirm credential rotation", &id)?;
        monitoring::record_event(
            &a,
            &id,
            "credential_rotation_completed",
            json!({"generation":n.generation,"key_fingerprint":n.thumbprint}),
        )?;
    } else {
        authenticate(&a, &h, &id, "rotation/confirm")?;
    }
    Ok(Json(
        json!({"api_version":1,"host_id":id,"rotation_id":n.last_rotation,"generation":n.generation,"confirmed":true,"rotated_at":n.rotated_at}),
    ))
}
pub(crate) async fn request(
    State(a): State<App>,
    h: HeaderMap,
    Path(id): Path<String>,
    Json(p): Json<Revoke>,
) -> Result<Json<Value>> {
    let who = admin(&a, &h, true).await?;
    let _gate = a.gate.lock().await;
    if !p.acknowledge {
        return Err(bad("Confirm requesting machine credential rotation"));
    }
    let mut n = rows(&a)?
        .into_iter()
        .find(|n| n.id == id && n.state == "active")
        .ok_or(fail(
            StatusCode::NOT_FOUND,
            "Active client identity not found",
        ))?;
    let host = n.host_id.as_deref().ok_or_else(unauthorized)?;
    if !monitoring::rotation_capable(&a, host, &n.id)? {
        return Err(fail(
            StatusCode::CONFLICT,
            "Update the client to a rotation-capable version and wait for its inventory report",
        ));
    }
    n.rotation_requested = true;
    store(&a, &n)?;
    audit(&a, &who, "client request credential rotation", host)?;
    Ok(Json(json!({"requested":true,"credentials":control(&n)})))
}
