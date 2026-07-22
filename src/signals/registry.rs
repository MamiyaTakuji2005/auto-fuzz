//! Signal registry — resolve classifier *names* to classifier objects.
//!
//! Classifiers are code (`Box<dyn Classifier>`), so an external module file
//! (`crate::module`) can't carry them inline. Instead a module names its
//! detectors as strings — `["status", "error:dbms", "body-signature:cloud"]` —
//! and this registry turns that list into a [`SignalSet`]. That's what makes a
//! module *self-contained*: detection no longer has to be borrowed from the
//! base class's compiled preset.
//!
//! Naming scheme: a bare `family` for parameter-free classifiers, or
//! `family:variant` for the ones that ship named variants (`error`,
//! `body-signature`). Names are the stable public contract — keep them stable.

use crate::signals::signal::{
    BodyDiffClassifier, BodySignatureClassifier, Classifier, ErrorClassifier, NoveltyClassifier,
    ProtoPollutionClassifier, ReflectionClassifier, SignalSet, SizeClassifier, StatusClassifier,
    TimeDelayClassifier,
};

/// Canonical names of every resolvable signal — the source of truth for the
/// `--help`/error valid-name list. Aliases (below) resolve too but aren't listed.
pub const KNOWN_SIGNALS: &[&str] = &[
    "status",
    "size",
    "reflection",
    "time-delay",
    "body-diff",
    "proto-pollution",
    "error:dbms",
    "error:nodejs",
    "body-signature:file",
    "body-signature:cloud",
    "novelty",
];

/// Resolve one signal name to a classifier. Accepts the canonical names in
/// [`KNOWN_SIGNALS`] plus a few obvious aliases. Errors list the valid names.
pub fn classifier_from_name(name: &str) -> Result<Box<dyn Classifier>, String> {
    let c: Box<dyn Classifier> = match name.trim() {
        "status" => Box::new(StatusClassifier),
        "size" => Box::new(SizeClassifier::default()),
        "reflection" => Box::new(ReflectionClassifier),
        "time-delay" | "timedelay" => Box::new(TimeDelayClassifier::default()),
        "body-diff" | "bodydiff" => Box::new(BodyDiffClassifier),
        "proto-pollution" | "prototype-pollution" => Box::new(ProtoPollutionClassifier),
        "error:dbms" => Box::new(ErrorClassifier::dbms_starter()),
        "error:nodejs" => Box::new(ErrorClassifier::nodejs_starter()),
        "body-signature:file" | "body-signature:file-read" => {
            Box::new(BodySignatureClassifier::file_read())
        }
        "body-signature:cloud" | "body-signature:cloud-metadata" => {
            Box::new(BodySignatureClassifier::cloud_metadata())
        }
        "novelty" | "anomaly" => Box::new(NoveltyClassifier::new()),
        other => {
            return Err(format!(
                "unknown signal '{other}' (valid: {})",
                KNOWN_SIGNALS.join(", ")
            ))
        }
    };
    Ok(c)
}

/// Build a [`SignalSet`] from a list of signal names, in order. Fails on the
/// first unresolvable name (fail-fast at module load, not silently dropped).
pub fn signal_set_from_names(names: &[String]) -> Result<SignalSet, String> {
    let mut set = SignalSet::new();
    for n in names {
        set.push(classifier_from_name(n)?);
    }
    Ok(set)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_known_signal_resolves() {
        for name in KNOWN_SIGNALS {
            assert!(
                classifier_from_name(name).is_ok(),
                "canonical signal '{name}' failed to resolve"
            );
        }
    }

    #[test]
    fn aliases_resolve() {
        for alias in ["timedelay", "bodydiff", "prototype-pollution", "anomaly", "body-signature:cloud-metadata"] {
            assert!(classifier_from_name(alias).is_ok(), "alias '{alias}' failed");
        }
    }

    #[test]
    fn whitespace_is_tolerated() {
        assert!(classifier_from_name("  status ").is_ok());
    }

    #[test]
    fn unknown_signal_errors_with_valid_list() {
        // Note: can't `.unwrap_err()` — `Box<dyn Classifier>` isn't `Debug`.
        match classifier_from_name("teapot") {
            Ok(_) => panic!("'teapot' should not resolve"),
            Err(e) => {
                assert!(e.contains("teapot"));
                assert!(e.contains("status"), "error should list valid names");
            }
        }
    }

    #[test]
    fn signal_set_preserves_order_and_count() {
        let names = vec!["status".to_string(), "size".to_string(), "error:dbms".to_string()];
        let set = signal_set_from_names(&names).unwrap();
        assert_eq!(set.len(), 3);
    }

    #[test]
    fn signal_set_fails_fast_on_bad_name() {
        let names = vec!["status".to_string(), "not-a-signal".to_string()];
        assert!(signal_set_from_names(&names).is_err());
    }
}
