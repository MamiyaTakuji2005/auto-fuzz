//! Real HTTP transport for the fuzzer, behind the `http` feature.
//!
//! A thin [`Probe`] over `reqwest`. Kept out of the default build so the core
//! engine stays dependency-light; the `fuzz` CLI and the `fuzz-gui` workbench
//! both enable `http`.

use std::time::{Duration, Instant};

use async_trait::async_trait;

use crate::signals::signal::ProbeResponse;
use crate::signals::{Probe, Request};

/// Sends live HTTP requests via `reqwest`.
pub struct HttpProbe {
    client: reqwest::Client,
}

impl HttpProbe {
    /// Build a probe with the given per-request timeout.
    pub fn new(timeout: Duration) -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(timeout)
                .build()
                .expect("failed to build HTTP client"),
        }
    }
}

#[async_trait]
impl Probe for HttpProbe {
    async fn send(&self, req: &Request) -> Result<ProbeResponse, String> {
        let start = Instant::now();
        let method = match req.method.to_uppercase().as_str() {
            "GET" => reqwest::Method::GET,
            "POST" => reqwest::Method::POST,
            "PUT" => reqwest::Method::PUT,
            "PATCH" => reqwest::Method::PATCH,
            "DELETE" => reqwest::Method::DELETE,
            "HEAD" => reqwest::Method::HEAD,
            "OPTIONS" => reqwest::Method::OPTIONS,
            other => return Err(format!("unsupported method: {other}")),
        };
        let mut builder = self.client.request(method, &req.url);
        for (k, v) in &req.headers {
            builder = builder.header(k.as_str(), v.as_str());
        }
        if !req.body.is_empty() {
            builder = builder.body(req.body.clone());
        }
        let resp = builder.send().await.map_err(|e| e.to_string())?;
        let status = resp.status().as_u16();
        let body = resp.bytes().await.map_err(|e| e.to_string())?;
        Ok(ProbeResponse {
            status,
            body: body.to_vec(),
            duration: start.elapsed(),
        })
    }
}
