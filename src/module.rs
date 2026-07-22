//! External module files — one campaign in one JSON file.
//!
//! A module file is a **diff over a built-in vuln class**: it names a `class`
//! (which supplies the detectors + feedback, and the default grammar/seeds),
//! then overrides any of the *data* half — atoms, chain weights, placement,
//! length, gen_ratio, shells, and the seed corpus. Every section is optional
//! except `class`; omit `grammar` to keep the class's hardcoded atoms, omit
//! `payloads` to keep its table. `--preset <path>` loads one of these; the same
//! flag with a known class name is just the zero-override case.
//!
//! Grammar and payloads live in separate named sections inside the one file so
//! that "use this file's payloads but the hardcoded atoms" stays expressible
//! (drop the `grammar` section) without a second file format.
//!
//! The parsed form is turned into a `Preset` by `agent::Preset::from_module_file`
//! — the diff-apply lives there because it touches private preset internals.

use std::collections::HashMap;

use serde::Deserialize;

use crate::evolutionary::atoms::{LengthPolicy, PlacementPolicy};
use crate::payloads::RawPayload;

/// One external module file: a data-only override over the base `class`.
#[derive(Debug, Clone, Deserialize)]
pub struct ModuleFile {
    /// Base vuln class (`sqli`, `xss`, `ssti`, `cmdi`, `path`, `nosql`, `ssrf`,
    /// `xxe`, `proto`). Supplies detectors + feedback and the defaults the rest
    /// of the file overrides. Required.
    pub class: String,

    /// File-level metadata, carried through to findings. Optional.
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub severity: String,

    /// Generation/mutation blend for this campaign (0.0 = pure havoc, 1.0 =
    /// pure generation). Inherits the class default when absent.
    #[serde(default)]
    pub gen_ratio: Option<f32>,

    /// Bypass shells for the havoc `WrapDelimiter` op: `[[prefix, suffix], …]`.
    #[serde(default)]
    pub shells: Vec<(String, String)>,

    /// Atom grammar override. Absent → keep the class's hardcoded grammar.
    #[serde(default)]
    pub grammar: Option<GrammarSpec>,

    /// Seed corpus override. Absent → keep the class's built-in table.
    #[serde(default)]
    pub payloads: Option<Vec<RawPayload>>,

    /// Detector names, resolved through `crate::signals::registry`
    /// (`["status", "error:dbms", "body-signature:cloud"]`). A non-empty list
    /// makes the module self-contained — it replaces the base class's detectors.
    /// Absent/empty → inherit the class's set. See `KNOWN_SIGNALS` for the names.
    #[serde(default)]
    pub signals: Vec<String>,
}

/// The `grammar` section — mirrors the four generation primitives. Every field
/// is optional; an absent field falls back to the base class's value.
#[derive(Debug, Clone, Deserialize)]
pub struct GrammarSpec {
    /// The atom vocabulary. Empty → keep the class's atoms.
    #[serde(default)]
    pub atoms: Vec<String>,
    /// Nested `from → (to → weight)` transition map. Empty → keep the class's chain.
    #[serde(default)]
    pub chain: HashMap<String, HashMap<String, f32>>,
    /// Placement weights `{append, prepend, wrap}`. Absent → keep the class's.
    #[serde(default)]
    pub placement: Option<PlacementSpec>,
    /// Length policy `{min_atoms, max_atoms, stop_prob}`. Absent → keep the class's.
    #[serde(default)]
    pub length: Option<LengthSpec>,
}

/// Serde mirror of [`PlacementPolicy`]'s three weights.
#[derive(Debug, Clone, Deserialize)]
pub struct PlacementSpec {
    pub append: f32,
    pub prepend: f32,
    pub wrap: f32,
}

impl PlacementSpec {
    pub fn into_policy(self) -> PlacementPolicy {
        PlacementPolicy::new(self.append, self.prepend, self.wrap)
    }
}

/// Serde mirror of [`LengthPolicy`]'s geometric parameters.
#[derive(Debug, Clone, Deserialize)]
pub struct LengthSpec {
    pub min_atoms: usize,
    pub max_atoms: usize,
    pub stop_prob: f32,
}

impl LengthSpec {
    pub fn into_policy(self) -> LengthPolicy {
        LengthPolicy::new(self.min_atoms, self.max_atoms, self.stop_prob)
    }
}

impl ModuleFile {
    /// Parse a module file from disk. Errors carry the path for a legible
    /// message when `--preset <path>` is neither a known class nor loadable.
    pub fn from_path(path: &str) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read module file '{path}': {e}"))?;
        Self::from_str(&text).map_err(|e| format!("module file '{path}' is malformed: {e}"))
    }

    /// Parse from a JSON string (path-independent; used by tests).
    pub fn from_str(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_module_is_just_a_class() {
        let m = ModuleFile::from_str(r#"{"class": "ssrf"}"#).unwrap();
        assert_eq!(m.class, "ssrf");
        assert!(m.grammar.is_none());
        assert!(m.payloads.is_none());
        assert!(m.gen_ratio.is_none());
        assert!(m.shells.is_empty());
    }

    #[test]
    fn full_module_round_trips_every_section() {
        let json = r#"{
            "class": "ssrf",
            "name": "cloud-metadata",
            "description": "SSRF cloud sweep",
            "severity": "critical",
            "gen_ratio": 0.2,
            "shells": [["<!--", "-->"], ["/*", "*/"]],
            "grammar": {
                "atoms": ["http://", "169.254.169.254", "/latest/meta-data/"],
                "chain": { "http://": { "169.254.169.254": 20.0 } },
                "placement": { "append": 1.5, "prepend": 1.0, "wrap": 0.5 },
                "length": { "min_atoms": 1, "max_atoms": 6, "stop_prob": 0.75 }
            },
            "payloads": [
                { "value": "http://169.254.169.254/latest/meta-data/", "severity_hint": "critical" }
            ],
            "signals": ["status", "timedelay"]
        }"#;
        let m = ModuleFile::from_str(json).unwrap();
        assert_eq!(m.class, "ssrf");
        assert_eq!(m.gen_ratio, Some(0.2));
        assert_eq!(m.shells.len(), 2);
        assert_eq!(m.shells[0], ("<!--".into(), "-->".into()));

        let g = m.grammar.unwrap();
        assert_eq!(g.atoms.len(), 3);
        assert_eq!(g.chain["http://"]["169.254.169.254"], 20.0);
        let placement = g.placement.unwrap().into_policy();
        assert_eq!(placement.append, 1.5);
        let length = g.length.unwrap().into_policy();
        assert_eq!(length.min_atoms, 1);
        assert_eq!(length.max_atoms, 6);

        let payloads = m.payloads.unwrap();
        assert_eq!(payloads.len(), 1);
        assert_eq!(payloads[0].value, "http://169.254.169.254/latest/meta-data/");
        assert_eq!(payloads[0].severity_hint, "critical");

        // signals parsed but not yet acted on
        assert_eq!(m.signals, vec!["status", "timedelay"]);
    }

    #[test]
    fn payloads_only_module_omits_grammar() {
        let json = r#"{
            "class": "sqli",
            "payloads": [ { "value": "' OR 1=1--" } ]
        }"#;
        let m = ModuleFile::from_str(json).unwrap();
        assert!(m.grammar.is_none(), "grammar stays absent → hardcoded atoms inherited");
        assert_eq!(m.payloads.unwrap().len(), 1);
    }
}
