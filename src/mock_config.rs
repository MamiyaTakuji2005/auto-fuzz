use std::path::Path;

use async_trait::async_trait;
use serde::Deserialize;

use crate::signals::signal::ProbeResponse;
use crate::signals::{Probe, Request};

/// A mock target defined by a TOML config file.
#[derive(Debug, Clone, Deserialize)]
pub struct MockTarget {
    pub name: String,
    pub trigger_payload: String,
    pub baseline_url: String,
    #[serde(default = "default_method")]
    pub baseline_method: String,
    pub response: ResponseConfig,
}

fn default_method() -> String {
    "GET".to_string()
}

#[derive(Debug, Clone, Deserialize)]
pub struct ResponseConfig {
    /// Substrings in the injected payload that trigger a "vulnerable" response.
    pub triggers: Vec<String>,
    pub trigger_status: u16,
    /// `{{payload}}` is replaced with the actual injected string.
    pub trigger_body: String,
    #[serde(default = "default_clean_status")]
    pub clean_status: u16,
    #[serde(default = "default_clean_body")]
    pub clean_body: String,
    #[serde(default = "default_trigger_delay")]
    pub trigger_delay_ms: u64,
    #[serde(default = "default_clean_delay")]
    pub clean_delay_ms: u64,
    /// Literal substrings that only appear in a genuinely-leaked response
    /// (e.g. `root:x:0:0`, `AccessKeyId`). When set, calibration wires a
    /// `BodySignatureClassifier` so classes detectable only by leaked content
    /// (path-traversal, SSRF) can actually confirm a hit.
    #[serde(default)]
    pub confirm_signatures: Vec<String>,
}

fn default_clean_status() -> u16 { 200 }
fn default_clean_body() -> String { "ok".to_string() }
fn default_trigger_delay() -> u64 { 5 }
fn default_clean_delay() -> u64 { 5 }

// ── TOML file structure ──────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct ConfigFile {
    pub targets: Vec<MockTarget>,
    /// Optional override for the atom vocabulary.
    /// If present, replaces the built-in ATOMS table.
    #[serde(default)]
    pub atoms: Option<Vec<String>>,
}

/// Load a full config (targets + optional atoms) from a TOML file.
pub fn load_config(path: impl AsRef<Path>) -> Result<ConfigFile, String> {
    let content = std::fs::read_to_string(path.as_ref())
        .map_err(|e| format!("failed to read {}: {}", path.as_ref().display(), e))?;
    let config: ConfigFile =
        toml::from_str(&content).map_err(|e| format!("failed to parse TOML: {}", e))?;
    Ok(config)
}

/// Load mock targets from a TOML file (convenience wrapper).
pub fn load_targets(path: impl AsRef<Path>) -> Result<Vec<MockTarget>, String> {
    Ok(load_config(path)?.targets)
}

/// A probe that simulates responses based on a TOML config.
pub struct ConfigProbe {
    pub target: MockTarget,
}

impl ConfigProbe {
    pub fn new(target: MockTarget) -> Self {
        Self { target }
    }
}

#[async_trait]
impl Probe for ConfigProbe {
    async fn send(&self, req: &Request) -> Result<ProbeResponse, String> {
        // Extract the injected payload from the URL query string.
        // Split only on the FIRST `=` — the payload itself may contain `=`
        // (e.g. `<img src=x onerror=alert(1)>`). Using `split('=').nth(1)`
        // here truncates at the second `=` and breaks reflection matching.
        let payload = req
            .url
            .split('?')
            .nth(1)
            .unwrap_or("")
            .splitn(2, '=')
            .nth(1)
            .unwrap_or("")
            .to_string();

        let triggered = self
            .target
            .response
            .triggers
            .iter()
            .any(|t| payload.contains(t.as_str()));

        if triggered {
            let body = self
                .target
                .response
                .trigger_body
                .replace("{{payload}}", &payload);
            Ok(ProbeResponse {
                status: self.target.response.trigger_status,
                body: body.into_bytes(),
                duration: std::time::Duration::from_millis(self.target.response.trigger_delay_ms),
            })
        } else {
            Ok(ProbeResponse {
                status: self.target.response.clean_status,
                body: self.target.response.clean_body.clone().into_bytes(),
                duration: std::time::Duration::from_millis(self.target.response.clean_delay_ms),
            })
        }
    }
}
