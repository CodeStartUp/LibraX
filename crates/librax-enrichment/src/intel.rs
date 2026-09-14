

use std::collections::HashMap;

use chrono::{DateTime, Duration, TimeZone, Utc};
use serde::{Deserialize, Serialize};

use crate::inventory::demo;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IocKind {
    Md5,
    Sha1,
    Sha256,
    Ipv4,
    Domain,
    Url,
}

impl IocKind {
    pub fn label(self) -> &'static str {
        match self {
            IocKind::Md5 => "MD5",
            IocKind::Sha1 => "SHA1",
            IocKind::Sha256 => "SHA256",
            IocKind::Ipv4 => "IPv4",
            IocKind::Domain => "Domain",
            IocKind::Url => "URL",
        }
    }


    pub fn of(value: &str) -> Option<Self> {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return None;
        }

        let hex = trimmed.chars().all(|c| c.is_ascii_hexdigit());
        match (hex, trimmed.len()) {
            (true, 32) => return Some(IocKind::Md5),
            (true, 40) => return Some(IocKind::Sha1),
            (true, 64) => return Some(IocKind::Sha256),
            _ => {}
        }

        if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
            return Some(IocKind::Url);
        }

        let octets: Vec<&str> = trimmed.split('.').collect();
        if octets.len() == 4 && octets.iter().all(|o| o.parse::<u8>().is_ok()) {
            return Some(IocKind::Ipv4);
        }

        if trimmed.contains('.') && !trimmed.contains(' ') {
            return Some(IocKind::Domain);
        }

        None
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IocVerdict {
    Malicious,
    Suspicious,

    Clean,

    #[default]
    Unknown,
}

impl IocVerdict {
    pub fn label(self) -> &'static str {
        match self {
            IocVerdict::Malicious => "MALICIOUS",
            IocVerdict::Suspicious => "SUSPICIOUS",
            IocVerdict::Clean => "CLEAN",
            IocVerdict::Unknown => "UNKNOWN",
        }
    }

    pub fn is_bad(self) -> bool {
        matches!(self, IocVerdict::Malicious | IocVerdict::Suspicious)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocRecord {
    pub kind: IocKind,
    pub kind_label: String,
    pub value: String,
    pub verdict: IocVerdict,
    pub verdict_label: String,

    pub confidence: f32,

    pub threat_name: Option<String>,
    pub malware_family: Option<String>,
    pub categories: Vec<String>,

    pub detection_ratio: Option<String>,

    pub first_reported: Option<DateTime<Utc>>,
    pub last_reported: Option<DateTime<Utc>>,
    pub feeds: Vec<String>,
    pub notes: Vec<String>,


    pub asn: Option<String>,
    pub country: Option<String>,
    pub hosting: Option<String>,


    pub file_names: Vec<String>,
    pub file_type: Option<String>,
    pub signer: Option<String>,
    pub signed: Option<bool>,
}

impl IocRecord {
    fn new(kind: IocKind, value: &str, verdict: IocVerdict, confidence: f32) -> Self {
        Self {
            kind,
            kind_label: kind.label().to_string(),
            value: value.to_string(),
            verdict,
            verdict_label: verdict.label().to_string(),
            confidence,
            threat_name: None,
            malware_family: None,
            categories: Vec::new(),
            detection_ratio: None,
            first_reported: None,
            last_reported: None,
            feeds: Vec::new(),
            notes: Vec::new(),
            asn: None,
            country: None,
            hosting: None,
            file_names: Vec::new(),
            file_type: None,
            signer: None,
            signed: None,
        }
    }


    pub fn unknown(value: &str) -> Self {
        let kind = IocKind::of(value).unwrap_or(IocKind::Domain);
        let mut record = Self::new(kind, value, IocVerdict::Unknown, 0.0);
        record.notes.push(
            "Not present in any configured feed. This is not a clearance: it means no feed has \
             an opinion, which is the expected result for freshly built tooling and for files \
             created on the host."
                .to_string(),
        );
        record
    }
}


pub struct ThreatIntel {
    records: HashMap<String, IocRecord>,
    feed_name: String,
}

impl Default for ThreatIntel {
    fn default() -> Self {
        Self::demo()
    }
}

impl ThreatIntel {
    pub fn feed_name(&self) -> &str {
        &self.feed_name
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }


    pub fn all(&self) -> impl Iterator<Item = &IocRecord> {
        self.records.values()
    }


    pub fn lookup(&self, value: &str) -> IocRecord {
        let key = value.trim().to_lowercase();

        self.records
            .get(&key)
            .cloned()
            .unwrap_or_else(|| IocRecord::unknown(value.trim()))
    }

    pub fn verdict(&self, value: &str) -> IocVerdict {
        self.records
            .get(&value.trim().to_lowercase())
            .map(|r| r.verdict)
            .unwrap_or_default()
    }

    fn insert(&mut self, record: IocRecord) {
        self.records.insert(record.value.to_lowercase(), record);
    }


    pub fn demo() -> Self {
        let mut intel = Self {
            records: HashMap::new(),
            feed_name: "librax-local-feed".to_string(),
        };

        let day = |d: i64| Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap() + Duration::days(d);
        let now = Utc::now();


        let mut lure = IocRecord::new(
            IocKind::Sha256,
            hashes::LURE_SHA256,
            IocVerdict::Malicious,
            0.97,
        );
        lure.threat_name = Some("Trojan.Downloader.MacroDoc".into());
        lure.malware_family = Some("Emotet-like macro dropper".into());
        lure.categories = vec![
            "dropper".into(),
            "macro".into(),
            "phishing-attachment".into(),
        ];
        lure.detection_ratio = Some("58/72".into());
        lure.first_reported = Some(day(212));
        lure.last_reported = Some(now - Duration::hours(6));
        lure.feeds = vec!["librax-local-feed".into(), "community-submissions".into()];
        lure.file_names = vec!["Benefits_Enrolment.docm".into(), "HR_Form_Q3.docm".into()];
        lure.file_type = Some("Office Open XML with macros".into());
        lure.signed = Some(false);
        lure.notes = vec![
            "Contains an auto-executing macro that fetches a second stage over HTTPS.".into(),
            "Distributed in HR-themed lures aimed at healthcare and education.".into(),
        ];
        intel.insert(lure);

        let mut lure_md5 =
            IocRecord::new(IocKind::Md5, hashes::LURE_MD5, IocVerdict::Malicious, 0.97);
        lure_md5.threat_name = Some("Trojan.Downloader.MacroDoc".into());
        lure_md5.malware_family = Some("Emotet-like macro dropper".into());
        lure_md5.categories = vec!["dropper".into(), "macro".into()];
        lure_md5.detection_ratio = Some("58/72".into());
        lure_md5.first_reported = Some(day(212));
        lure_md5.feeds = vec!["librax-local-feed".into()];
        lure_md5.file_names = vec!["Benefits_Enrolment.docm".into()];
        lure_md5.signed = Some(false);
        lure_md5.notes = vec![format!(
            "MD5 of the same sample as SHA256 {}.",
            hashes::LURE_SHA256
        )];
        intel.insert(lure_md5);

        let mut beacon = IocRecord::new(
            IocKind::Sha256,
            hashes::BEACON_SHA256,
            IocVerdict::Malicious,
            0.94,
        );
        beacon.threat_name = Some("Backdoor.CobaltStrike.Beacon".into());
        beacon.malware_family = Some("Cobalt Strike".into());
        beacon.categories = vec!["backdoor".into(), "c2-implant".into()];
        beacon.detection_ratio = Some("49/71".into());
        beacon.first_reported = Some(day(41));
        beacon.last_reported = Some(now - Duration::days(2));
        beacon.feeds = vec!["librax-local-feed".into()];
        beacon.file_names = vec!["msupdate.dll".into(), "sync_helper.dll".into()];
        beacon.file_type = Some("PE32+ DLL".into());
        beacon.signed = Some(false);
        beacon.notes = vec![
            "In-memory implant; beacons on a fixed interval with jitter.".into(),
            "Configuration points at infrastructure also seen in this incident.".into(),
        ];
        intel.insert(beacon);

        let mut ransom = IocRecord::new(
            IocKind::Sha256,
            hashes::RANSOM_SHA256,
            IocVerdict::Malicious,
            0.99,
        );
        ransom.threat_name = Some("Ransom.Win32.Locker".into());
        ransom.malware_family = Some("LockBit-like locker".into());
        ransom.categories = vec!["ransomware".into(), "encryptor".into()];
        ransom.detection_ratio = Some("67/72".into());
        ransom.first_reported = Some(day(305));
        ransom.last_reported = Some(now - Duration::hours(2));
        ransom.feeds = vec!["librax-local-feed".into(), "community-submissions".into()];
        ransom.file_names = vec!["svchost_helper.exe".into(), "locker.exe".into()];
        ransom.file_type = Some("PE32+ executable".into());
        ransom.signed = Some(false);
        ransom.notes = vec![
            "Deletes shadow copies, then encrypts and appends a new extension.".into(),
            "Healthcare victims reported; targets database and imaging shares first.".into(),
        ];
        intel.insert(ransom);


        for (sha, md5, name, signer, note) in [
            (
                hashes::POWERSHELL_SHA256,
                hashes::POWERSHELL_MD5,
                "powershell.exe",
                "Microsoft Windows",
                "Legitimate signed component. Abused here to run an encoded command; the binary \
                 itself is not the indicator, the command line is.",
            ),
            (
                hashes::SEVENZIP_SHA256,
                hashes::SEVENZIP_MD5,
                "7z.exe",
                "Igor Pavlov",
                "Legitimate archiver, widely deployed. Its presence is normal; compressing a \
                 database export into a temp directory at 03:00 is not.",
            ),
            (
                hashes::VSSADMIN_SHA256,
                hashes::VSSADMIN_MD5,
                "vssadmin.exe",
                "Microsoft Windows",
                "Legitimate administrative tool. Deleting every shadow copy with it is a \
                 recognised precursor to encryption.",
            ),
        ] {
            for (kind, value) in [(IocKind::Sha256, sha), (IocKind::Md5, md5)] {
                let mut record = IocRecord::new(kind, value, IocVerdict::Clean, 0.99);
                record.categories = vec!["signed-binary".into(), "living-off-the-land".into()];
                record.detection_ratio = Some("0/72".into());
                record.feeds = vec!["librax-local-feed".into()];
                record.file_names = vec![name.to_string()];
                record.file_type = Some("PE32+ executable".into());
                record.signer = Some(signer.to_string());
                record.signed = Some(true);
                record.notes = vec![note.to_string()];
                intel.insert(record);
            }
        }


        for (name, sha, md5, signer) in FLEET_SOFTWARE {
            for (kind, value) in [(IocKind::Sha256, *sha), (IocKind::Md5, *md5)] {
                let mut record = IocRecord::new(kind, value, IocVerdict::Clean, 0.98);
                record.categories = vec!["signed-binary".into(), "routine-software".into()];
                record.detection_ratio = Some("0/72".into());
                record.feeds = vec!["librax-local-feed".into()];
                record.file_names = vec![name.to_string()];
                record.file_type = Some("PE32+ executable".into());
                record.signer = Some(signer.to_string());
                record.signed = Some(true);
                record.notes = vec![
                    "Standard fleet software, assessed benign. Deployed widely enough that its \
                     absence would be the anomaly."
                        .to_string(),
                ];
                intel.insert(record);
            }
        }


        let mut attacker = IocRecord::new(
            IocKind::Ipv4,
            demo::ATTACKER_IP,
            IocVerdict::Malicious,
            0.96,
        );
        attacker.threat_name = Some("APT staging host".into());
        attacker.categories = vec!["command-and-control".into(), "bulletproof-hosting".into()];
        attacker.first_reported = Some(day(88));
        attacker.last_reported = Some(now - Duration::minutes(30));
        attacker.feeds = vec!["librax-local-feed".into()];
        attacker.asn = Some("AS49505 Selectel".into());
        attacker.country = Some("RO".into());
        attacker.hosting = Some("Bulletproof VPS provider".into());
        attacker.notes = vec![
            "Hosts the second stage and receives beacon traffic.".into(),
            "Reported by multiple healthcare victims in the last quarter.".into(),
        ];
        intel.insert(attacker);

        let mut vpn_src =
            IocRecord::new(IocKind::Ipv4, "203.0.113.77", IocVerdict::Suspicious, 0.71);
        vpn_src.categories = vec!["anonymising-vpn".into(), "residential-proxy".into()];
        vpn_src.first_reported = Some(day(150));
        vpn_src.last_reported = Some(now - Duration::hours(1));
        vpn_src.feeds = vec!["librax-local-feed".into()];
        vpn_src.asn = Some("AS20473 Choopa".into());
        vpn_src.country = Some("RO".into());
        vpn_src.hosting = Some("Commercial VPN exit".into());
        vpn_src.notes = vec![
            "Commercial VPN exit node. Not malicious by itself, and staff do travel; it is \
             suspicious because this account has never authenticated from this country."
                .into(),
        ];
        intel.insert(vpn_src);

        for (ip, asn, country) in [
            ("91.219.236.18", "AS200651 Flokinet", "IS"),
            ("45.133.1.90", "AS204957 Serverion", "NL"),
        ] {
            let mut record = IocRecord::new(IocKind::Ipv4, ip, IocVerdict::Malicious, 0.88);
            record.categories = vec!["command-and-control".into()];
            record.first_reported = Some(day(120));
            record.feeds = vec!["librax-local-feed".into()];
            record.asn = Some(asn.into());
            record.country = Some(country.into());
            record.notes = vec!["Known C2 infrastructure.".into()];
            intel.insert(record);
        }


        let mut c2 = IocRecord::new(
            IocKind::Domain,
            demo::C2_DOMAIN,
            IocVerdict::Malicious,
            0.95,
        );
        c2.threat_name = Some("APT C2 domain".into());
        c2.categories = vec!["command-and-control".into(), "newly-registered".into()];
        c2.first_reported = Some(day(86));
        c2.last_reported = Some(now - Duration::minutes(30));
        c2.feeds = vec!["librax-local-feed".into()];
        c2.notes = vec![
            "Registered 14 days before first use and named to imitate a CDN.".into(),
            format!("Resolves to {}.", demo::ATTACKER_IP),
        ];
        intel.insert(c2);

        let mut phish = IocRecord::new(
            IocKind::Domain,
            demo::PHISHING_DOMAIN,
            IocVerdict::Malicious,
            0.93,
        );
        phish.threat_name = Some("Credential phishing / malware delivery".into());
        phish.categories = vec!["phishing".into(), "lookalike-domain".into()];
        phish.first_reported = Some(day(205));
        phish.feeds = vec!["librax-local-feed".into()];
        phish.notes = vec![
            "Lookalike domain used as the sender and payload host for the HR lure.".into(),
            "Sender authentication (SPF, DKIM, DMARC) fails for this domain.".into(),
        ];
        intel.insert(phish);

        for domain in ["update.microsoft.com", "login.microsoftonline.com"] {
            let mut record = IocRecord::new(IocKind::Domain, domain, IocVerdict::Clean, 0.99);
            record.categories = vec!["vendor-service".into()];
            record.detection_ratio = Some("0/72".into());
            record.feeds = vec!["librax-local-feed".into()];
            record.notes =
                vec!["Expected vendor traffic; present so benign lookups return a verdict.".into()];
            intel.insert(record);
        }

        intel
    }
}


pub const FLEET_SOFTWARE: &[(&str, &str, &str, &str)] = &[
    (
        "chrome.exe",
        "1a4b7c09e25d83f6a0c1e94b37d0526fa8b1c40e97d3f562a8e0b19c34d7f608",
        "0c9a1e47d35b8206f4a9c1e73b05d248",
        "Google LLC",
    ),
    (
        "OUTLOOK.EXE",
        "5e0d92a17c48b3f6019ad2e85c73f04b6a19e8c07d24b53fa9c18e06b47d3520",
        "7b3e0a91c46d5f28039a1c8e07b54d26",
        "Microsoft Corporation",
    ),
    (
        "EpicClient.exe",
        "3c8a15e79d02b46f5a1c09e83b7d5240fa6b19c07e48d3521a9c80e16b57d3f04",
        "e40b1a97c25d3f68049a1c7e03b85d24",
        "Epic Systems Corporation",
    ),
    (
        "svchost.exe",
        "9d21c8a05e47b3f61a0c9e83d75b024fa1b68c907e35d24fa8c01e97b46d35f28",
        "2f8b0a51c94d7e36018a1c5e04b93d27",
        "Microsoft Windows",
    ),
    (
        "MsMpEng.exe",
        "4b70e1a92c85d3f6019c8a0e47b52d38fa0b91c67e04d25fa3c18e90b76d5f142",
        "8a1c0e94b25d7f36049a1c8e03b47d25",
        "Microsoft Windows",
    ),
    (
        "explorer.exe",
        "7a30c8e15b94d2f6018a9c0e37b45d290fa1b68c50e93d247a8c10e96b35d7f04",
        "5d1a0c98e34b7f26019a1c5e08b42d37",
        "Microsoft Windows",
    ),
];


pub mod hashes {
    pub const LURE_SHA256: &str =
        "9f2c1b7ad4e58c0a3b6d9e11f47c2a8de5b0f39c7a1d4e62b8f05c93a7e1d208";
    pub const LURE_MD5: &str = "3d8f1a52c7b04e69a1d3f8025b6c9e74";

    pub const BEACON_SHA256: &str =
        "c41d8ba0f6e37592ad8b1c04e97f26db3a5c80e19f4b7d6a2c93e058fb17d4a6";
    pub const BEACON_MD5: &str = "b7e94c2f61a05d38e4c7a91b0f256d83";

    pub const RANSOM_SHA256: &str =
        "e78b3c19d05af64721c8e93b0d6f47a5c21e98b34f07d5a6e1b92c48037fa5d1";
    pub const RANSOM_MD5: &str = "f2a61d84c05b7e39a8d1c6f04b25e97a";

    pub const POWERSHELL_SHA256: &str =
        "6b1f80c3a94e27d5b0c8f61a3e07d924b5c8a01f7e63d24a9b05c8f31e7a06d2";
    pub const POWERSHELL_MD5: &str = "04029e121a0cfa5991749937dd22a1d9";

    pub const SEVENZIP_SHA256: &str =
        "2a7d90e18c34b06f5a9e2d71c08b43f6e5a19c07d82b64f3a0e97c15b28d6403";
    pub const SEVENZIP_MD5: &str = "a5b1c9e07d28f36405a9c1e83b07d264";

    pub const VSSADMIN_SHA256: &str =
        "8c05a1e39d47b26f0a8c53e19b07d245f6a08c31e94b7d520a6c8f03b91e7d48";
    pub const VSSADMIN_MD5: &str = "d9e07a41c58b36204f9a1c73e08b52d6";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn indicator_types_are_inferred_from_shape() {
        assert_eq!(IocKind::of(hashes::LURE_MD5), Some(IocKind::Md5));
        assert_eq!(IocKind::of(hashes::LURE_SHA256), Some(IocKind::Sha256));
        assert_eq!(IocKind::of("185.220.101.47"), Some(IocKind::Ipv4));
        assert_eq!(IocKind::of("cdn-sync-update.net"), Some(IocKind::Domain));
        assert_eq!(IocKind::of("https://evil.test/x"), Some(IocKind::Url));
        assert_eq!(IocKind::of("   "), None);
    }

    #[test]
    fn an_ip_is_not_mistaken_for_a_domain() {

        assert_eq!(IocKind::of("10.10.2.15"), Some(IocKind::Ipv4));
        assert_eq!(IocKind::of("999.1.1.1"), Some(IocKind::Domain));
    }

    #[test]
    fn the_lure_is_malicious_by_either_hash() {
        let intel = ThreatIntel::demo();

        for value in [hashes::LURE_SHA256, hashes::LURE_MD5] {
            let record = intel.lookup(value);
            assert_eq!(record.verdict, IocVerdict::Malicious, "{value}");
            assert!(record.malware_family.is_some());
            assert!(record.detection_ratio.is_some());
        }
    }

    #[test]
    fn lookups_are_case_insensitive() {
        let intel = ThreatIntel::demo();
        assert_eq!(
            intel.verdict(&hashes::LURE_SHA256.to_uppercase()),
            IocVerdict::Malicious
        );
    }

    #[test]
    fn an_unreported_indicator_is_unknown_rather_than_clean() {
        let intel = ThreatIntel::demo();
        let record = intel.lookup("00000000000000000000000000000000");

        assert_eq!(record.verdict, IocVerdict::Unknown);
        assert!(
            record.notes[0].contains("not a clearance"),
            "the difference has to be stated: {:?}",
            record.notes
        );
    }

    #[test]
    fn abused_system_binaries_stay_clean_with_the_nuance_recorded() {
        let intel = ThreatIntel::demo();

        for value in [hashes::POWERSHELL_SHA256, hashes::SEVENZIP_MD5] {
            let record = intel.lookup(value);
            assert_eq!(
                record.verdict,
                IocVerdict::Clean,
                "a signed system tool must not be called malware: {value}"
            );
            assert_eq!(record.signed, Some(true));
            assert!(!record.notes.is_empty());
        }


        let ps = intel.lookup(hashes::POWERSHELL_SHA256);
        assert!(ps.notes[0].contains("command line"), "{:?}", ps.notes);
    }

    #[test]
    fn the_travelling_user_address_is_suspicious_not_malicious() {
        let intel = ThreatIntel::demo();
        let record = intel.lookup("203.0.113.77");

        assert_eq!(record.verdict, IocVerdict::Suspicious);
        assert!(record.country.is_some() && record.asn.is_some());
        assert!(
            record.notes[0].contains("staff do travel"),
            "{:?}",
            record.notes
        );
    }

    #[test]
    fn attacker_infrastructure_is_flagged_with_context() {
        let intel = ThreatIntel::demo();

        let ip = intel.lookup(demo::ATTACKER_IP);
        assert_eq!(ip.verdict, IocVerdict::Malicious);
        assert!(ip.asn.is_some() && ip.country.is_some());

        for domain in [demo::C2_DOMAIN, demo::PHISHING_DOMAIN] {
            assert_eq!(intel.verdict(domain), IocVerdict::Malicious, "{domain}");
        }
    }

    #[test]
    fn every_record_names_the_feed_it_came_from() {
        let intel = ThreatIntel::demo();
        for record in intel.all() {
            assert!(
                !record.feeds.is_empty(),
                "{} has no feed attribution",
                record.value
            );
        }
    }
}
