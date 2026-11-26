//! Bounded, reviewed record-set import. Never execute zone-file directives or server settings.
use super::*;

fn one() -> u8 {
    1
}
#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct File {
    #[serde(default = "one")]
    format: u8,
    #[serde(alias = "name")]
    zone: String,
    rrsets: Vec<RecordSet>,
}
#[derive(Clone, Deserialize, Serialize)]
struct RecordSet {
    name: String,
    #[serde(rename = "type")]
    kind: String,
    ttl: u32,
    records: Vec<Record>,
}
#[derive(Clone, Deserialize, Serialize)]
struct Record {
    content: String,
    #[serde(default)]
    disabled: bool,
}
#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Mode {
    Merge,
    Replace,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Preview {
    data: File,
    mode: Mode,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Commit {
    data: File,
    mode: Mode,
    expected_revision: String,
    plan_hash: String,
    acknowledge: bool,
    confirm_name: String,
}
struct Plan {
    steps: Vec<Step>,
    changes: Vec<Value>,
    warnings: Vec<String>,
    hash: String,
}
async fn plan(z: &Value, file: &File, mode: Mode) -> Result<Plan> {
    let zone = z["name"].as_str().ok_or(bad("Invalid DNS zone"))?;
    if file.format != 1 || name(&file.zone, false)? != zone {
        return Err(bad(
            "Import format must be 1 and its zone/name must match the selected zone",
        ));
    }
    if file.rrsets.is_empty()
        || file.rrsets.len() > 512
        || file.rrsets.iter().map(|r| r.records.len()).sum::<usize>() > 5000
    {
        return Err(bad(
            "Import 1–512 record sets with at most 5000 values per file",
        ));
    }
    let children = zones().await?;
    let mut seen = HashSet::new();
    let mut next = BTreeMap::new();
    let mut warnings=vec!["Unlisted records are retained. Forward and reverse imports are independent; changed sets release automatic PTR/host ownership.".into()];
    for set in &file.rrsets {
        let owner = owner(&set.name, zone)?;
        let kind = set.kind.to_ascii_uppercase();
        ttl(set.ttl)?;
        if !seen.insert((owner.clone(), kind.clone())) {
            return Err(bad("Duplicate record sets in the import are not allowed"));
        }
        if set.records.is_empty() || set.records.len() > 100 {
            return Err(bad("Each imported record set needs 1–100 values"));
        }
        if kind == "SOA" {
            warnings.push("Imported SOA is retained for reference only; the existing SOA and native serial policy are preserved. Edit timers/contact in zone settings.".into());
            continue;
        }
        if children.iter().any(|z| {
            z["name"]
                .as_str()
                .is_some_and(|child| child.len() > zone.len() && within(&owner, child))
        }) {
            return Err(bad(
                "An imported owner belongs to a more specific configured zone",
            ));
        }
        let mut records = Vec::new();
        let mut unique = HashSet::new();
        for record in &set.records {
            let value = content(&kind, &record.content)?;
            if !unique.insert(value.clone()) {
                return Err(bad("Duplicate imported values are not allowed"));
            }
            records.push(json!({"content":value,"disabled":record.disabled}));
        }
        let current = find(z, &owner, &kind);
        let mut after = json!({"name":owner,"type":kind,"ttl":set.ttl,"records":records,"comments":current.as_ref().map(|r|r["comments"].clone()).unwrap_or(json!([]))});
        if matches!(mode, Mode::Merge)
            && let Some(current) = &current
        {
            let old = values(current);
            let mut combined = current["records"]
                .as_array()
                .cloned()
                .ok_or(bad("Invalid native DNS record set"))?;
            for record in records {
                if !old.iter().any(|v| record["content"] == *v) {
                    combined.push(record);
                }
            }
            if combined.len() > 100 {
                return Err(bad("Merged record set would exceed 100 values"));
            }
            after["records"] = json!(combined);
            after["ttl"] = current["ttl"].clone();
        }
        if kind == "CNAME"
            && (owner == zone || after["records"].as_array().is_some_and(|r| r.len() != 1))
        {
            return Err(bad(
                "A CNAME needs exactly one value and cannot occupy the zone apex",
            ));
        }
        if kind == "NS"
            && owner == zone
            && !after["records"]
                .as_array()
                .is_some_and(|r| r.iter().any(|v| v["disabled"] == false))
        {
            return Err(bad("The zone must retain an active apex nameserver"));
        }
        next.insert((owner, kind), after);
    }
    let mut final_sets = sets(z)
        .into_iter()
        .map(|r| {
            (
                (
                    r["name"].as_str().unwrap_or("").to_owned(),
                    r["type"].as_str().unwrap_or("").to_owned(),
                ),
                r,
            )
        })
        .collect::<BTreeMap<_, _>>();
    final_sets.extend(next.clone());
    for (owner, kind) in final_sets.keys() {
        if kind == "CNAME"
            && final_sets
                .keys()
                .any(|(other, t)| other == owner && t != "CNAME")
        {
            return Err(bad(
                "A CNAME conflicts with another record type. Resolve that owner through DNS before importing.",
            ));
        }
    }
    let mut steps = Vec::new();
    let mut changes = Vec::new();
    for ((owner, kind), mut after) in next {
        let before = find(z, &owner, &kind);
        if before
            .as_ref()
            .is_some_and(|v| canonical(v) == canonical(&after))
        {
            continue;
        }
        host_records::strip_markers(&mut after);
        changes.push(json!({"name":owner,"type":kind,"before":before.as_ref().map(canonical),"after":canonical(&after)}));
        steps.push(Step {
            zone: zone.into(),
            name: owner,
            rr_type: kind,
            before: before.as_ref().map(host_records::record_revision),
            after: Some(after),
            protect_comments: true,
        });
    }
    let hash = digest(&json!({"zone":zone_revision(z),"mode":mode,"steps":steps}).to_string());
    Ok(Plan {
        steps,
        changes,
        warnings,
        hash,
    })
}
pub(crate) async fn export(
    State(a): State<App>,
    h: HeaderMap,
    Path(z): Path<String>,
) -> Result<Response> {
    peer::editor(&a, &h, false).await?;
    let z = name(&z, false)?;
    let data = zone(&z).await?;
    managed(&data)?;
    let file =
        json!({"format":1,"zone":z,"rrsets":sets(&data).iter().map(canonical).collect::<Vec<_>>()});
    let bytes = serde_json::to_vec_pretty(&file).map_err(anyhow::Error::from)?;
    Ok((
        [
            (header::CONTENT_TYPE, "application/json".to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{z}records.json\""),
            ),
        ],
        bytes,
    )
        .into_response())
}
pub(crate) async fn preview(
    State(a): State<App>,
    h: HeaderMap,
    Path(z): Path<String>,
    Json(p): Json<Preview>,
) -> Result<Json<Value>> {
    peer::editor(&a, &h, true).await?;
    let _guard = a.gate.lock().await;
    no_pending(&a)?;
    let z = name(&z, false)?;
    let current = zone(&z).await?;
    managed(&current)?;
    let plan = plan(&current, &p.data, p.mode).await?;
    Ok(Json(
        json!({"zone":z,"expected_revision":zone_revision(&current),"plan_hash":plan.hash,"changes":plan.changes,"warnings":plan.warnings}),
    ))
}
pub(crate) async fn commit(
    State(a): State<App>,
    h: HeaderMap,
    Path(z): Path<String>,
    Json(p): Json<Commit>,
) -> Result<Json<Value>> {
    let who = peer::editor(&a, &h, true).await?;
    let _guard = a.gate.lock().await;
    no_pending(&a)?;
    let z = name(&z, false)?;
    if !p.acknowledge || p.confirm_name != z {
        return Err(bad(
            "Review the import and confirm the exact zone name including its final dot",
        ));
    }
    let current = zone(&z).await?;
    managed(&current)?;
    if zone_revision(&current) != p.expected_revision {
        return Err(Error(
            StatusCode::CONFLICT,
            "Zone changed after preview. Generate a new import preview before applying.".into(),
        ));
    }
    let plan = plan(&current, &p.data, p.mode).await?;
    if plan.hash != p.plan_hash {
        return Err(Error(
            StatusCode::CONFLICT,
            "Import content or ownership changed after preview; review a new preview".into(),
        ));
    }
    let change = Change {
        id: token()[..32].into(),
        request_digest: None,
        key: format!("import:{z}"),
        steps: plan.steps,
        links: vec![],
        warnings: plan.warnings,
        clear_ptr: None,
        host: None,
    };
    save(&a, &change, "pending", None)?;
    audit(
        &a,
        &who,
        "DNS attempt reviewed import",
        &change_target(&change),
    )?;
    Ok(Json(apply(&a, &who, &change).await?))
}
