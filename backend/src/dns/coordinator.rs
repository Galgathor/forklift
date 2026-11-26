//! Durable request identity for DNS writes handled by the manager.
use super::*;
use rusqlite::OptionalExtension;

pub(super) fn record_identity(
    who: &str,
    zone: &str,
    draft: &RecordDraft,
) -> Result<(String, Option<String>)> {
    let Some(key) = &draft.request_id else {
        return Ok((token()[..32].into(), None));
    };
    if key.len() != 32
        || !key
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(bad(
            "DNS request ID must be 32 lowercase hexadecimal characters",
        ));
    }
    let id = digest(&json!(["dns-record-request", who, key]).to_string());
    let fingerprint = digest(&json!([zone, draft]).to_string());
    Ok((id, Some(fingerprint)))
}

pub(super) async fn resume_record(
    a: &App,
    who: &str,
    id: &str,
    fingerprint: Option<&str>,
) -> Result<Option<Value>> {
    let Some(fingerprint) = fingerprint else {
        return Ok(None);
    };
    let stored =
        a.db.lock()
            .unwrap()
            .query_row(
                "SELECT data,status,error FROM dns_changes WHERE id=?",
                [id],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, Option<String>>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(anyhow::Error::from)?;
    let Some((data, status, error)) = stored else {
        return Ok(None);
    };
    let change: Change = serde_json::from_str(&data).map_err(anyhow::Error::from)?;
    if change.request_digest.as_deref() != Some(fingerprint) {
        return Err(Error(
            StatusCode::CONFLICT,
            "This DNS request ID belongs to a different edit. Use a new ID for the new edit."
                .into(),
        ));
    }
    if status == "completed" {
        if let Some(error) = error {
            return Err(Error(StatusCode::CONFLICT, error));
        }
        return Ok(Some(
            json!({"id":id,"status":"completed","warnings":change.warnings}),
        ));
    }
    Ok(Some(apply(a, who, &change).await?))
}
