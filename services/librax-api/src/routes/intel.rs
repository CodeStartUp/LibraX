

use axum::Json;
use axum::extract::{Path, Query, State};
use librax_enrichment::{IocKind, IocRecord, IocVerdict};
use librax_types::CanonicalEvent;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::error::ApiError;
use crate::state::SharedState;


const HOST_SAMPLE: usize = 12;

#[derive(Serialize)]
pub struct FeedResponse {
    pub feed: String,
    pub total: usize,
    pub synthetic: bool,
    pub note: String,
    pub indicators: Vec<IocRecord>,
}


pub async fn feed(State(state): State<SharedState>) -> Json<FeedResponse> {
    let intel = state.intel();

    let mut indicators: Vec<IocRecord> = intel.all().cloned().collect();
    indicators.sort_by(|a, b| {

        let rank = |v: IocVerdict| match v {
            IocVerdict::Malicious => 0,
            IocVerdict::Suspicious => 1,
            IocVerdict::Unknown => 2,
            IocVerdict::Clean => 3,
        };
        rank(a.verdict)
            .cmp(&rank(b.verdict))
            .then(a.kind_label.cmp(&b.kind_label))
            .then(a.value.cmp(&b.value))
    });

    Json(FeedResponse {
        feed: intel.feed_name().to_string(),
        total: indicators.len(),
        synthetic: true,
        note: "Local synthetic feed. LibraX does not call VirusTotal or any external \
               intelligence service in this build, and an indicator that is absent returns \
               UNKNOWN rather than CLEAN."
            .to_string(),
        indicators,
    })
}

#[derive(Deserialize)]
pub struct LookupQuery {
    pub value: String,
}


#[derive(Serialize)]
pub struct Sighting {
    pub event_id: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub source_id: String,
    pub source_type: String,
    pub host: Option<String>,
    pub user: Option<String>,
    pub activity: String,

    pub matched_field: String,
    pub message: String,
}

#[derive(Serialize)]
pub struct LookupResponse {
    pub query: String,
    pub kind: Option<IocKind>,
    pub kind_label: String,
    pub record: IocRecord,

    pub observed_here: bool,
    pub sighting_count: usize,
    pub sightings: Vec<Sighting>,
    pub incident_ids: Vec<String>,
    pub assessment: String,
}

pub async fn lookup(
    State(state): State<SharedState>,
    Query(query): Query<LookupQuery>,
) -> Result<Json<LookupResponse>, ApiError> {
    lookup_value(state, query.value).await
}


pub async fn lookup_path(
    State(state): State<SharedState>,
    Path(value): Path<String>,
) -> Result<Json<LookupResponse>, ApiError> {
    lookup_value(state, value).await
}

async fn lookup_value(state: SharedState, value: String) -> Result<Json<LookupResponse>, ApiError> {
    let needle = value.trim().to_string();
    if needle.is_empty() {
        return Err(ApiError::BadRequest(
            "provide a hash, address or domain to look up".to_string(),
        ));
    }

    let kind = IocKind::of(&needle);
    let record = state.intel().lookup(&needle);

    let (sightings, incident_ids) = state.read(|soc| {
        let mut sightings: Vec<Sighting> = Vec::new();

        for event in &soc.events {
            if let Some(field) = matched_field(event, &needle) {
                sightings.push(Sighting {
                    event_id: event.event_id.clone(),
                    timestamp: event.timestamp,
                    source_id: event.source_id.clone(),
                    source_type: format!("{:?}", event.source_type),
                    host: event.host_name().map(str::to_string),
                    user: event.user().map(str::to_string),
                    activity: event.activity.clone(),
                    matched_field: field,
                    message: event.message.clone(),
                });
            }
        }

        sightings.sort_by_key(|s| s.timestamp);

        let seen: Vec<&str> = sightings.iter().map(|s| s.event_id.as_str()).collect();
        let mut incidents: Vec<String> = soc
            .incidents
            .iter()
            .filter(|built| {


                built.incident.signals.iter().any(|signal_id| {
                    soc.signals.iter().any(|s| {
                        &s.signal_id == signal_id
                            && s.evidence_event_ids
                                .iter()
                                .any(|id| seen.contains(&id.as_str()))
                    })
                })
            })
            .map(|built| built.incident.incident_id.clone())
            .collect();
        incidents.sort();
        incidents.dedup();

        (sightings, incidents)
    });

    let observed_here = !sightings.is_empty();
    let assessment = assess(&record, observed_here, sightings.len(), &incident_ids);

    Ok(Json(LookupResponse {
        query: needle,
        kind,
        kind_label: kind
            .map(|k| k.label().to_string())
            .unwrap_or_else(|| "Unrecognised".to_string()),
        record,
        observed_here,
        sighting_count: sightings.len(),

        sightings: sightings.into_iter().rev().take(50).collect(),
        incident_ids,
        assessment,
    }))
}


fn assess(
    record: &IocRecord,
    observed_here: bool,
    sightings: usize,
    incidents: &[String],
) -> String {
    let verdict = match record.verdict {
        IocVerdict::Malicious => "The feed reports this indicator as malicious",
        IocVerdict::Suspicious => "The feed reports this indicator as suspicious",
        IocVerdict::Clean => "The feed assesses this indicator as benign",
        IocVerdict::Unknown => {
            "No configured feed has an opinion on this indicator, which is not a clearance"
        }
    };

    if !observed_here {
        return format!("{verdict}. It has not been seen in this estate's retained telemetry.");
    }

    let where_seen = if incidents.is_empty() {
        format!(
            "It appears in {sightings} retained event(s), none of which correlated into an incident."
        )
    } else {
        format!(
            "It appears in {sightings} retained event(s), contributing to {}.",
            incidents.join(", ")
        )
    };

    let action = match record.verdict {
        IocVerdict::Malicious | IocVerdict::Suspicious => {
            " Treat the hosts in the sightings below as in scope."
        }
        IocVerdict::Clean => {
            " A benign verdict does not clear the activity: legitimate tools get abused, so judge \
             the usage rather than the file."
        }
        IocVerdict::Unknown => {
            " Unknown plus locally observed is the case worth submitting for analysis."
        }
    };

    format!("{verdict}. {where_seen}{action}")
}


fn matched_field(event: &CanonicalEvent, needle: &str) -> Option<String> {
    let eq = |value: Option<&str>| value.is_some_and(|v| v.eq_ignore_ascii_case(needle));

    if let Some(process) = &event.process {
        if eq(process.hash_sha256.as_deref()) {
            return Some(format!("process SHA256 ({})", process.name));
        }
        if eq(process.hash_md5.as_deref()) {
            return Some(format!("process MD5 ({})", process.name));
        }
    }

    if eq(event.dst_ip()) {
        return Some("destination address".to_string());
    }
    if eq(event.src_ip()) {
        return Some("source address".to_string());
    }
    if let Some(dst) = &event.destination {
        if eq(dst.domain.as_deref()) {
            return Some("destination domain".to_string());
        }
    }


    for (key, value) in &event.attributes {
        if value
            .as_str()
            .is_some_and(|v| v.eq_ignore_ascii_case(needle))
        {
            return Some(format!("attribute `{key}`"));
        }
    }

    None
}

#[derive(Deserialize)]
pub struct FileQuery {

    pub name: Option<String>,

    pub verdict: Option<String>,
    pub host: Option<String>,

    pub bad_only: Option<bool>,
    pub limit: Option<usize>,
}


struct Artifact {
    name: String,
    sha256: Option<String>,
    md5: Option<String>,
    signed: Option<bool>,
    signer: Option<String>,
    command_line: Option<String>,
}


fn artifact_of(event: &CanonicalEvent) -> Option<Artifact> {
    if let Some(process) = &event.process {
        return Some(Artifact {
            name: process.name.clone(),
            sha256: process.hash_sha256.clone(),
            md5: process.hash_md5.clone(),
            signed: process.signed,
            signer: process.signer.clone(),
            command_line: process.command_line.clone(),
        });
    }


    if let Some(name) = event.attribute_str("attachment_name") {
        return Some(Artifact {
            name: name.to_string(),
            sha256: event.attribute_str("attachment_sha256").map(str::to_string),
            md5: event.attribute_str("attachment_md5").map(str::to_string),
            signed: None,
            signer: None,
            command_line: None,
        });
    }

    if let Some(name) = event.attribute_str("file_name") {
        return Some(Artifact {
            name: name.to_string(),
            sha256: event
                .attribute_str("file_sha256")
                .or_else(|| event.attribute_str("sha256"))
                .map(str::to_string),
            md5: event
                .attribute_str("file_md5")
                .or_else(|| event.attribute_str("md5"))
                .map(str::to_string),
            signed: None,
            signer: None,
            command_line: None,
        });
    }

    None
}


#[derive(Serialize)]
pub struct FileView {
    pub name: String,
    pub sha256: Option<String>,
    pub md5: Option<String>,
    pub verdict: IocVerdict,
    pub verdict_label: String,
    pub threat_name: Option<String>,
    pub malware_family: Option<String>,
    pub detection_ratio: Option<String>,
    pub signed: Option<bool>,
    pub signer: Option<String>,

    pub host_count: usize,
    pub hosts: Vec<String>,
    pub user_count: usize,
    pub users: Vec<String>,
    pub execution_count: usize,
    pub first_seen: chrono::DateTime<chrono::Utc>,
    pub last_seen: chrono::DateTime<chrono::Utc>,
    pub command_lines: Vec<String>,
    pub event_ids: Vec<String>,

    pub notes: Vec<String>,
}

#[derive(Serialize)]
pub struct FilesResponse {
    pub total: usize,
    pub returned: usize,
    pub malicious: usize,
    pub unknown: usize,
    pub files: Vec<FileView>,
}


pub async fn files(
    State(state): State<SharedState>,
    Query(query): Query<FileQuery>,
) -> Json<FilesResponse> {
    let intel = state.intel();

    let mut by_key: BTreeMap<String, FileView> = BTreeMap::new();

    state.read(|soc| {
        for event in &soc.events {


            let Some(artifact) = artifact_of(event) else {
                continue;
            };
            let Artifact {
                name,
                sha256,
                md5,
                signed,
                signer,
                command_line,
            } = artifact;


            let key = sha256
                .clone()
                .or_else(|| md5.clone())
                .unwrap_or_else(|| name.to_lowercase());

            let record = sha256
                .as_deref()
                .or(md5.as_deref())
                .map(|h| intel.lookup(h));

            let entry = by_key.entry(key).or_insert_with(|| FileView {
                name: name.clone(),
                sha256: sha256.clone(),
                md5: md5.clone(),
                verdict: record.as_ref().map(|r| r.verdict).unwrap_or_default(),
                verdict_label: record
                    .as_ref()
                    .map(|r| r.verdict.label().to_string())
                    .unwrap_or_else(|| IocVerdict::Unknown.label().to_string()),
                threat_name: record.as_ref().and_then(|r| r.threat_name.clone()),
                malware_family: record.as_ref().and_then(|r| r.malware_family.clone()),
                detection_ratio: record.as_ref().and_then(|r| r.detection_ratio.clone()),
                signed: signed.or_else(|| record.as_ref().and_then(|r| r.signed)),
                signer: signer
                    .clone()
                    .or_else(|| record.as_ref().and_then(|r| r.signer.clone())),
                host_count: 0,
                hosts: Vec::new(),
                user_count: 0,
                users: Vec::new(),
                execution_count: 0,
                first_seen: event.timestamp,
                last_seen: event.timestamp,
                command_lines: Vec::new(),
                event_ids: Vec::new(),
                notes: record.as_ref().map(|r| r.notes.clone()).unwrap_or_else(|| {
                    vec![
                        "No hash reported by the source, so the feed could not be consulted."
                            .to_string(),
                    ]
                }),
            });

            entry.execution_count += 1;
            entry.first_seen = entry.first_seen.min(event.timestamp);
            entry.last_seen = entry.last_seen.max(event.timestamp);


            if let Some(host) = event.host_name() {
                if !entry.hosts.iter().any(|h| h == host) {
                    entry.host_count += 1;
                    if entry.hosts.len() < HOST_SAMPLE {
                        entry.hosts.push(host.to_string());
                    }
                }
            }
            if let Some(user) = event.user() {
                if !entry.users.iter().any(|u| u == user) {
                    entry.user_count += 1;
                    if entry.users.len() < HOST_SAMPLE {
                        entry.users.push(user.to_string());
                    }
                }
            }
            if let Some(cmd) = &command_line {
                if !entry.command_lines.contains(cmd) && entry.command_lines.len() < 5 {
                    entry.command_lines.push(cmd.clone());
                }
            }
            if entry.event_ids.len() < 25 {
                entry.event_ids.push(event.event_id.clone());
            }
        }
    });

    let mut files: Vec<FileView> = by_key.into_values().collect();

    let total = files.len();
    let malicious = files
        .iter()
        .filter(|f| f.verdict == IocVerdict::Malicious)
        .count();
    let unknown = files
        .iter()
        .filter(|f| f.verdict == IocVerdict::Unknown)
        .count();

    if let Some(name) = query.name.as_deref().map(str::to_lowercase) {
        files.retain(|f| f.name.to_lowercase().contains(&name));
    }
    if let Some(host) = query.host.as_deref().map(str::to_lowercase) {
        files.retain(|f| f.hosts.iter().any(|h| h.to_lowercase().contains(&host)));
    }
    if let Some(verdict) = query.verdict.as_deref() {
        files.retain(|f| f.verdict_label.eq_ignore_ascii_case(verdict));
    }
    if query.bad_only.unwrap_or(false) {
        files.retain(|f| f.verdict.is_bad());
    }


    files.sort_by(|a, b| {
        let rank = |v: IocVerdict| match v {
            IocVerdict::Malicious => 0,
            IocVerdict::Suspicious => 1,
            IocVerdict::Unknown => 2,
            IocVerdict::Clean => 3,
        };
        rank(a.verdict)
            .cmp(&rank(b.verdict))
            .then(b.execution_count.cmp(&a.execution_count))
    });

    files.truncate(query.limit.unwrap_or(200).min(1_000));

    Json(FilesResponse {
        total,
        returned: files.len(),
        malicious,
        unknown,
        files,
    })
}
