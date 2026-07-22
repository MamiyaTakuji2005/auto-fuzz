//! Payload tables — known high-probability probes for each vuln class.
//!
//! These are the "sweep the table first" seeds. The engine mutates from them,
//! exploring the neighborhood of each proven payload rather than starting blind.
//!
//! Most tables are ported from a curated corpus (`payload_data/*.json`) carrying
//! per-payload metadata — `context` (where the payload belongs: html_body, json,
//! xml, attribute…), `severity`, `targets`, `encoding`, and a `description`. The
//! metadata is carried through to results (e.g. JSONL output) and is the basis
//! for future context-aware injection-point selection. NoSQLi has no curated
//! source and keeps its hand-written table.

use serde::Deserialize;

/// Categories for payload classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadCategory {
    Sqlinjection,
    Xss,
    Ssti,
    CommandInjection,
    PathTraversal,
    Xxe,
    NoSqli,
    Ssrf,
    PrototypePollution,
    Custom,
}

/// Risk level for gating execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PayloadRisk {
    Safe,
    Invasive,
    Destructive,
}

/// A single payload with identity and metadata.
#[derive(Debug, Clone)]
pub struct PayloadCase {
    pub id: String,
    pub payload: String,
    pub category: PayloadCategory,
    pub risk: PayloadRisk,
    /// Human-readable description of what the payload does.
    pub description: String,
    /// Where the payload is meant to land: `html_body`, `json`, `xml`,
    /// `attribute`, `url`, `string`, `numeric`, `js_string`, … Empty when
    /// unknown (hand tables). Basis for context-aware injection selection.
    pub context: String,
    /// Impact hint from the curated corpus: `critical` / `high` / `medium` / `low`.
    pub severity: String,
    /// Wrapping/encoding applied to the payload (`raw`, `url`, `double_url`, …).
    pub encoding: String,
    /// Technology targets this payload is tuned for (`php`, `java`, `windows`, …).
    pub targets: Vec<String>,
    pub tags: Vec<String>,
}

/// A named collection of payload cases.
#[derive(Debug, Clone)]
pub struct PayloadTable {
    pub name: String,
    pub cases: Vec<PayloadCase>,
}

/// Raw shape of one entry in a curated `payload_data/*.json` file — also the
/// `payloads` array in an external module file (see `crate::module`).
#[derive(Debug, Clone, Deserialize)]
pub struct RawPayload {
    pub value: String,
    #[serde(default)]
    pub encoding: String,
    #[serde(default)]
    pub context: String,
    #[serde(default)]
    pub targets: Vec<String>,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub severity_hint: String,
}

impl PayloadTable {
    /// Build from a legacy `&[&str]` table, assigning category, risk, and
    /// sequential IDs. Metadata fields are left empty (hand tables carry none).
    pub fn from_legacy(
        name: &str,
        category: PayloadCategory,
        risk: PayloadRisk,
        payloads: &[&str],
    ) -> Self {
        Self {
            name: name.into(),
            cases: payloads.iter().enumerate().map(|(i, p)| PayloadCase {
                id: format!("{name}[{i}]"),
                payload: p.to_string(),
                category,
                risk: classify_risk(risk, p),
                description: String::new(),
                context: String::new(),
                severity: String::new(),
                encoding: String::new(),
                targets: vec![],
                tags: vec![],
            }).collect(),
        }
    }

    /// Build from a curated JSON corpus (`payload_data/*.json`), preserving
    /// per-payload metadata. `default_risk` is the table's floor; individual
    /// payloads are upgraded to `Destructive` when their content warrants it
    /// (see [`classify_risk`]), so a read-only table can still flag the odd
    /// state-changing entry.
    fn from_curated(
        name: &str,
        category: PayloadCategory,
        default_risk: PayloadRisk,
        json: &str,
    ) -> Self {
        let raw: Vec<RawPayload> = serde_json::from_str(json)
            .unwrap_or_else(|e| panic!("payload_data/{name}.json is malformed: {e}"));
        Self::from_raw(name, category, default_risk, raw)
    }

    /// Build from already-parsed [`RawPayload`] entries, preserving per-payload
    /// metadata and applying the same risk-upgrade rule as [`from_curated`].
    /// Used both by the built-in `include_str!` tables and by external module
    /// files (`crate::module`), which deserialize their own `payloads` array.
    pub fn from_raw(
        name: &str,
        category: PayloadCategory,
        default_risk: PayloadRisk,
        raw: Vec<RawPayload>,
    ) -> Self {
        Self {
            name: name.into(),
            cases: raw.into_iter().enumerate().map(|(i, r)| PayloadCase {
                id: format!("{name}[{i}]"),
                risk: classify_risk(default_risk, &r.value),
                payload: r.value,
                category,
                description: r.description,
                context: r.context,
                severity: r.severity_hint,
                encoding: r.encoding,
                targets: r.targets,
                tags: vec![],
            }).collect(),
        }
    }

    pub fn payloads(&self) -> Vec<String> {
        self.cases.iter().map(|c| c.payload.clone()).collect()
    }

    pub fn len(&self) -> usize { self.cases.len() }

    pub fn is_empty(&self) -> bool { self.cases.is_empty() }
}

/// Upgrade a table's default risk to `Destructive` when a payload's content is
/// state-changing or executes code — so a destructive probe can't hide inside
/// an `Invasive`/`Safe` table and slip past the risk gate. Conservative: it
/// prefers a false `Destructive` (over-cautious gating) to a false `Safe`.
fn classify_risk(default: PayloadRisk, payload: &str) -> PayloadRisk {
    let p = payload.to_ascii_lowercase();
    const DESTRUCTIVE: &[&str] = &[
        // SQL / NoSQL state changes
        "drop table", "drop database", "delete from", "truncate", "insert into",
        "update ", "alter table", "into outfile", "into dumpfile", "xp_cmdshell",
        // command / RCE
        "expect://", "rm -rf", "rm -r ", "mkfs", "shutdown", "reboot", "> /dev/sd",
        "dd if=", ":(){", "/etc/shadow",
        // unbounded DoS ($where infinite loops) — bounded sleeps stay Invasive
        "while(true)",
    ];
    if DESTRUCTIVE.iter().any(|needle| p.contains(needle)) {
        PayloadRisk::Destructive
    } else {
        default
    }
}

// ── Built-in tables ───────────────────────────────────────────────────────
//
// Curated tables embed their JSON at compile time (self-contained binary).
// NoSQLi has no curated source and stays on its hand-written array.

pub fn sqli_table()      -> PayloadTable { PayloadTable::from_curated("sqli",      PayloadCategory::Sqlinjection,     PayloadRisk::Invasive,   include_str!("payload_data/sqli.json")) }
pub fn xss_table()       -> PayloadTable { PayloadTable::from_curated("xss",       PayloadCategory::Xss,              PayloadRisk::Safe,       include_str!("payload_data/xss.json")) }
pub fn ssti_table()      -> PayloadTable { PayloadTable::from_curated("ssti",      PayloadCategory::Ssti,             PayloadRisk::Invasive,   include_str!("payload_data/ssti.json")) }
pub fn cmd_table()       -> PayloadTable { PayloadTable::from_curated("command",   PayloadCategory::CommandInjection, PayloadRisk::Destructive, include_str!("payload_data/command.json")) }
pub fn traversal_table() -> PayloadTable { PayloadTable::from_curated("traversal", PayloadCategory::PathTraversal,    PayloadRisk::Safe,       include_str!("payload_data/traversal.json")) }
pub fn xxe_table()       -> PayloadTable { PayloadTable::from_curated("xxe",       PayloadCategory::Xxe,              PayloadRisk::Invasive,   include_str!("payload_data/xxe.json")) }
pub fn ssrf_table()      -> PayloadTable { PayloadTable::from_curated("ssrf",      PayloadCategory::Ssrf,             PayloadRisk::Safe,       include_str!("payload_data/ssrf.json")) }
pub fn proto_pollution_table() -> PayloadTable { PayloadTable::from_curated("prototype_pollution", PayloadCategory::PrototypePollution, PayloadRisk::Invasive, include_str!("payload_data/prototype_pollution.json")) }
pub fn nosqli_table()    -> PayloadTable { PayloadTable::from_curated("nosqli",    PayloadCategory::NoSqli,           PayloadRisk::Invasive,   include_str!("payload_data/nosqli.json")) }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_curated_table_parses_and_is_nonempty() {
        let tables = [
            sqli_table(), xss_table(), ssti_table(), cmd_table(),
            traversal_table(), xxe_table(), ssrf_table(), proto_pollution_table(),
            nosqli_table(),
        ];
        for t in &tables {
            assert!(!t.is_empty(), "{} parsed empty", t.name);
            for c in &t.cases {
                assert!(!c.payload.is_empty(), "{} has an empty payload", t.name);
            }
        }
    }

    #[test]
    fn destructive_payloads_are_flagged() {
        // xxe is an Invasive table, but its expect:// RCE entry must be Destructive.
        let xxe = xxe_table();
        let expect = xxe.cases.iter().find(|c| c.payload.contains("expect://"));
        if let Some(c) = expect {
            assert_eq!(c.risk, PayloadRisk::Destructive, "expect:// XXE must gate as Destructive");
        }
        // A DROP TABLE sqli entry (Invasive table) must be Destructive.
        assert_eq!(classify_risk(PayloadRisk::Invasive, "'; DROP TABLE users--"), PayloadRisk::Destructive);
        // A plain reflection probe stays at the table default.
        assert_eq!(classify_risk(PayloadRisk::Safe, "<script>alert(1)</script>"), PayloadRisk::Safe);
    }

    #[test]
    fn metadata_is_preserved() {
        let xss = xss_table();
        // Curated entries carry context + severity.
        assert!(xss.cases.iter().any(|c| c.context == "html_body"));
        assert!(xss.cases.iter().any(|c| !c.severity.is_empty()));
    }
}
