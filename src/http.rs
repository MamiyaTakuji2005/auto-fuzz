//! Real HTTP transport for the fuzzer, behind the `http` feature.
//!
//! A thin [`Probe`] over `reqwest`. Kept out of the default build so the core
//! engine stays dependency-light; the `fuzz` CLI and the `fuzz-gui` workbench
//! both enable `http`.

use std::time::{Duration, Instant};

use async_trait::async_trait;

use crate::signals::signal::ProbeResponse;
use crate::signals::{Probe, Request};

/// Per-request CSRF-token handling for stateful forms (e.g. DVWA's `login.php`).
///
/// Before each probe: GET `url`, extract a token via `regex` (capture group 1),
/// and append `field=<token>` to the request body. The shared cookie jar keeps
/// the GET and the POST in the same session so the token validates.
#[derive(Debug, Clone)]
pub struct CsrfConfig {
    pub url: String,
    pub field: String,
    pub regex: regex::Regex,
}

/// Sends live HTTP requests via `reqwest`. Optionally refreshes a CSRF token
/// before each request (see [`CsrfConfig`]).
pub struct HttpProbe {
    client: reqwest::Client,
    csrf: Option<CsrfConfig>,
}

impl HttpProbe {
    /// Build a probe with the given per-request timeout.
    pub fn new(timeout: Duration) -> Self {
        Self { client: Self::client(timeout), csrf: None }
    }

    /// Build a probe that refreshes a CSRF token before every request.
    pub fn with_csrf(timeout: Duration, csrf: CsrfConfig) -> Self {
        Self { client: Self::client(timeout), csrf: Some(csrf) }
    }

    fn client(timeout: Duration) -> reqwest::Client {
        // `mut` is only needed when the keepalive-disable block below is compiled
        // in (default); with the `keepalive` feature on, that block is cfg'd out.
        #[cfg_attr(feature = "keepalive", allow(unused_mut))]
        let mut builder = reqwest::Client::builder()
            .timeout(timeout)
            .cookie_store(true); // persist the session across token-GET and probe

        // By default, disable HTTP keepalive. Fuzzing typically opens a fresh
        // connection per probe so the target cannot throttle us by serializing
        // many in-flight requests down one persistent pipe. Enable the
        // `keepalive` feature to restore connection reuse (e.g. for stateful
        // targets or login sessions that break on churn).
        #[cfg(not(feature = "keepalive"))]
        {
            builder = builder.pool_max_idle_per_host(0);
        }

        builder.build().expect("failed to build HTTP client")
    }

    /// GET the CSRF page in-session and pull the token out of the response body.
    async fn fetch_token(&self, cfg: &CsrfConfig) -> Result<String, String> {
        let body = self.client.get(&cfg.url).send().await
            .map_err(|e| format!("csrf GET failed: {e}"))?
            .text().await.map_err(|e| format!("csrf body read failed: {e}"))?;
        cfg.regex.captures(&body)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string())
            .ok_or_else(|| format!("csrf token not found at {} (regex mismatch)", cfg.url))
    }
}

#[async_trait]
impl Probe for HttpProbe {
    async fn send(&self, req: &Request) -> Result<ProbeResponse, String> {
        let start = Instant::now();

        // CSRF: refresh a fresh token in-session and append it to the body.
        let refreshed_body;
        let send_body = match &self.csrf {
            Some(cfg) => {
                let token = self.fetch_token(cfg).await?;
                let sep = if req.body.is_empty() { "" } else { "&" };
                refreshed_body = format!("{}{}{}={}", req.body, sep, cfg.field, token);
                &refreshed_body
            }
            None => &req.body,
        };

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
        if !send_body.is_empty() {
            builder = builder.body(send_body.clone());
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
