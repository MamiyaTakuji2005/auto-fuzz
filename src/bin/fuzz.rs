//! `fuzz` — headless CLI runner for the auto-fuzz engine against a real URL.
//!
//! Run: `cargo run --bin fuzz --features http -- --preset sqli \
//!         --url 'https://target/post.php' --inject-query id --budget 150`
//!
//! The report is deliberately mechanics-first: baseline profile, probes sent,
//! and every signal observed (confirmed or merely interesting) so you can see
//! the request/response + baseline-diff pipeline working end to end, regardless
//! of whether anything is actually confirmed.

use std::sync::Arc;
use std::time::Duration;

use auto_fuzz::agent::{FuzzMode, FuzzResult, Fuzzer, Hit, PayloadSource};
use auto_fuzz::http::{CsrfConfig, HttpProbe};
use auto_fuzz::module::ModuleFile;

struct Args {
    preset: String,
    url: String,
    method: String,
    inject_query: Option<String>,
    /// Form-encoded POST body template with `{{payload}}`, e.g. `pass={{payload}}`.
    inject_body: Option<String>,
    /// Path to a file containing the body template (preserves trailing newlines).
    inject_body_file: Option<String>,
    /// Raw JSON body: the payload becomes the whole body with `application/json`
    /// (for prototype pollution / NoSQLi JSON injection).
    inject_json: bool,
    /// Content-Type for --inject-body (default: application/x-www-form-urlencoded).
    content_type: Option<String>,
    budget: usize,
    timeout_secs: u64,
    mode: FuzzMode,
    hunt: bool,
    /// Static headers merged into every request (`Name: Value`), plus `--cookie`.
    headers: Vec<(String, String)>,
    /// CSRF token refresh: GET this URL before each probe to pull a fresh token.
    csrf_url: Option<String>,
    csrf_field: String,
    csrf_regex: Option<String>,
    /// Emit one JSON object per hit to stdout (implies silent — no banner/report).
    jsonl: bool,
    /// Maximum concurrent in-flight probes (default: 1 = sequential).
    concurrency: usize,
    /// Rate limit in requests per second (0 = unlimited).
    rate_limit: f32,
    /// Out-of-band collaborator (URL or bare host) for `{{oob}}` substitution.
    oob: Option<String>,
    /// Optional RNG seed for deterministic runs.
    seed: Option<u64>,
}

fn parse_args() -> Result<Args, String> {
    let mut preset = None;
    let mut url = None;
    let mut method = "GET".to_string();
    let mut inject_query = None;
    let mut inject_body = None;
    let mut inject_body_file = None;
    let mut inject_json = false;
    let mut budget = 100usize;
    let mut timeout_secs = 15u64;
    let mut mode = FuzzMode::Evolutionary;
    let mut hunt = false;
    let mut headers: Vec<(String, String)> = Vec::new();
    let mut csrf_url = None;
    let mut csrf_field = "user_token".to_string();
    let mut csrf_regex = None;
    let mut jsonl = false;
    let mut concurrency = 1usize;
    let mut rate_limit = 0.0f32;
    let mut oob = None;
    let mut seed = None;
    let mut content_type = None;

    let argv: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < argv.len() {
        let key = argv[i].clone();
        // Fetch the value that follows a flag, advancing the cursor onto it.
        let take_val = |i: &mut usize| -> Result<String, String> {
            *i += 1;
            argv.get(*i).cloned().ok_or_else(|| format!("missing value for {key}"))
        };
        match key.as_str() {
            "--preset" => preset = Some(take_val(&mut i)?),
            "--url" => url = Some(take_val(&mut i)?),
            "--method" => method = take_val(&mut i)?.to_uppercase(),
            "--inject-query" => inject_query = Some(take_val(&mut i)?),
            "--inject-body" => inject_body = Some(take_val(&mut i)?),
            "--inject-body-file" => inject_body_file = Some(take_val(&mut i)?),
            "--inject-json" => inject_json = true,
            "--budget" => budget = take_val(&mut i)?.parse().map_err(|_| "budget must be a number".to_string())?,
            "--timeout" => timeout_secs = take_val(&mut i)?.parse().map_err(|_| "timeout must be a number".to_string())?,
            "--mode" => {
                mode = match take_val(&mut i)?.as_str() {
                    "evolutionary" => FuzzMode::Evolutionary,
                    "table" => FuzzMode::Table,
                    "table-then-evo" => FuzzMode::TableThenEvolutionary,
                    "inputs-only" => FuzzMode::InputsOnly,
                    other => return Err(format!("unknown mode: {other}")),
                };
            }
            "--header" => {
                let h = take_val(&mut i)?;
                let (name, value) = h.split_once(':')
                    .ok_or_else(|| format!("--header must be 'Name: Value', got: {h}"))?;
                headers.push((name.trim().to_string(), value.trim().to_string()));
            }
            "--cookie" => headers.push(("Cookie".to_string(), take_val(&mut i)?)),
            "--csrf-url" => csrf_url = Some(take_val(&mut i)?),
            "--csrf-field" => csrf_field = take_val(&mut i)?,
            "--csrf-regex" => csrf_regex = Some(take_val(&mut i)?),
            "--jsonl" | "--json" => jsonl = true,
            "--hunt" => hunt = true,
            "--concurrency" | "--conc" => {
                concurrency = take_val(&mut i)?.parse()
                    .map_err(|_| "concurrency must be a number".to_string())?;
                if concurrency < 1 { concurrency = 1; }
            }
            "--rate-limit" | "--rate" => {
                rate_limit = take_val(&mut i)?.parse()
                    .map_err(|_| "rate-limit must be a number".to_string())?;
            }
            "--oob-url" | "--oob" | "--interactsh-url" => oob = Some(take_val(&mut i)?),
            "--seed" => seed = Some(take_val(&mut i)?.parse().map_err(|_| "seed must be a number".to_string())?),
            "--content-type" => content_type = Some(take_val(&mut i)?),
            "-h" | "--help" => return Err("help".to_string()),
            other => return Err(format!("unknown flag: {other}")),
        }
        i += 1;
    }

    Ok(Args {
        preset: preset.ok_or("--preset is required")?,
        url: url.ok_or("--url is required")?,
        method,
        inject_query,
        inject_body,
        inject_body_file,
        inject_json,
        budget,
        timeout_secs,
        mode,
        hunt,
        headers,
        csrf_url,
        csrf_field,
        csrf_regex,
        jsonl,
        concurrency,
        rate_limit,
        oob,
        seed,
        content_type,
    })
}

// `--preset <arg>` is dual-purpose: a known class name selects the compiled-in
// module; anything else is treated as a path to an external module file (grammar
// + payloads, applied as a diff over the file's declared `class`). A class name
// shadows a same-named file — use `./name` to force the file.
fn apply_preset(f: Fuzzer<HttpProbe>, preset: &str) -> Result<Fuzzer<HttpProbe>, String> {
    Ok(match preset {
        "sqli" => f.sql_injection(),
        "xss" => f.xss(),
        "ssti" => f.ssti(),
        "cmdi" => f.command_injection(),
        "path" | "path-traversal" => f.path_traversal(),
        "nosql" => f.nosql_injection(),
        "ssrf" => f.ssrf(),
        "xxe" => f.xxe(),
        "proto" | "prototype-pollution" => f.prototype_pollution(),
        path => {
            let module = ModuleFile::from_path(path).map_err(|e| {
                format!("--preset '{path}' is neither a known class nor a loadable module file: {e}")
            })?;
            f.module_file(module)?
        }
    })
}

fn print_hits(label: &str, hits: &[Hit]) {
    if hits.is_empty() {
        println!("  ({label}: none)");
        return;
    }
    println!("  {label} ({}):", hits.len());
    for h in hits.iter().take(15) {
        let sigs = if h.signals.is_empty() { "-".to_string() } else { h.signals.join(", ") };
        println!(
            "    score {:>4.1}  [{}]  {:?}",
            h.adjusted_score, sigs, truncate(&h.payload, 60)
        );
    }
    if hits.len() > 15 {
        println!("    … and {} more", hits.len() - 15);
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n { s.to_string() } else {
        format!("{}…", s.chars().take(n).collect::<String>())
    }
}

// recall-first (see ANOMALY.md): triage belongs HERE, in the report — not in
// the detector. When the anomaly detector lands, this is where the noise it
// accepts by design gets made cheap to scan: rank by deviation magnitude, group
// identical fingerprints (500 identical 403s = one line), dedup payloads.
fn report(r: &FuzzResult) {
    println!("\n─── result ───────────────────────────────────────────");
    println!("probes sent:   {}", r.probes_sent);
    println!("corpus size:   {}", r.corpus_size);
    println!("baseline:      {}", r.baseline);
    println!();
    print_hits("confirmed", &r.confirmed);
    print_hits("interesting", &r.interesting);
    println!("──────────────────────────────────────────────────────");
    if r.confirmed.is_empty() {
        println!("No confirmed hits — but the point of this run was the pipeline:");
        println!("baseline captured, probes sent, responses diffed & classified. ✔");
    }
}

/// Emit one JSON object per hit to stdout (ProjectDiscovery-style JSONL), so the
/// stream pipes cleanly into jq / the crawler loop. A one-line summary goes to
/// stderr, keeping stdout pure JSONL.
fn emit_jsonl(r: &FuzzResult, url: &str, method: &str, inject: &str, preset: &str) {
    let source_str = |s: &PayloadSource| match s {
        PayloadSource::Table { preset, index } => format!("table:{preset}:{index}"),
        PayloadSource::UserInput { index } => format!("input:{index}"),
        PayloadSource::Evolutionary => "evolutionary".to_string(),
    };
    let line = |h: &Hit, confirmed: bool| {
        let obj = serde_json::json!({
            "url": url,
            "method": method,
            "inject": inject,
            "preset": preset,
            "payload": h.payload,
            "confirmed": confirmed,
            "score": h.adjusted_score,
            "raw_score": h.raw_score,
            "confidence": h.confidence,
            "signals": h.signals,
            "source": source_str(&h.source),
            // Curated metadata — present for table-sourced hits, null otherwise.
            "severity": h.severity,
            "description": h.description,
            "context": h.context,
        });
        println!("{obj}");
    };
    for h in &r.confirmed { line(h, true); }
    for h in &r.interesting { if !h.confirmed { line(h, false); } }
    eprintln!(
        "[fuzz] {} confirmed, {} interesting, {} probes",
        r.confirmed.len(), r.interesting.len(), r.probes_sent
    );
}

#[tokio::main]
async fn main() {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            if e != "help" { eprintln!("error: {e}\n"); }
            eprintln!("usage: fuzz --preset <class|path> --url <URL> \\");
            eprintln!("            # class = sqli|xss|ssti|cmdi|path|nosql|ssrf|xxe|proto (compiled-in),");
            eprintln!("            # or a path to an external module .json (grammar + payloads over a base class)");
            eprintln!("            [--inject-query <param> | --inject-body '<tmpl>' | --inject-body-file <path> [--content-type <ct>] | --inject-json] \\");
            eprintln!("            [--method GET] [--budget 100] [--timeout 15] [--mode evolutionary] [--hunt]");
            eprintln!("            [--concurrency 1] [--rate-limit 0]  # concurrent probes + rate limiting");
            eprintln!("            [--seed <u64>]  # deterministic RNG (omit for entropy)");
            eprintln!("            [--oob-url <collaborator>]  # substituted into {{{{oob}}}} (OOB payloads skipped if unset)");
            eprintln!("            [--header 'Name: Value']... [--cookie 'a=b; c=d']");
            eprintln!("            [--csrf-url <URL> [--csrf-field user_token] [--csrf-regex <pat with group 1>]]");
            eprintln!("            [--jsonl]   # one JSON object per hit to stdout, silent otherwise");
            std::process::exit(if e == "help" { 0 } else { 2 });
        }
    };

    // If --inject-body-file was given, read the file verbatim (preserves trailing
    // newlines that bash command substitution would strip).
    let inject_body = if let Some(path) = &args.inject_body_file {
        if args.inject_body.is_some() {
            eprintln!("error: --inject-body and --inject-body-file are mutually exclusive");
            std::process::exit(2);
        }
        match std::fs::read_to_string(path) {
            Ok(s) => Some(s),
            Err(e) => { eprintln!("error: failed to read --inject-body-file {path}: {e}"); std::process::exit(2); }
        }
    } else {
        args.inject_body.clone()
    };

    // When injecting into a query param, drop only that param's existing value
    // (the injection re-adds it) but KEEP the other params — e.g. DVWA's SQLi
    // needs `Submit=Submit` alongside the injected `id`. Falls back to a plain
    // `?`-split if the URL doesn't parse.
    let base_url = match &args.inject_query {
        Some(param) => match url::Url::parse(&args.url) {
            Ok(mut u) => {
                let kept: Vec<(String, String)> = u.query_pairs()
                    .filter(|(k, _)| k != param)
                    .map(|(k, v)| (k.into_owned(), v.into_owned()))
                    .collect();
                u.query_pairs_mut().clear();
                for (k, v) in &kept { u.query_pairs_mut().append_pair(k, v); }
                if kept.is_empty() { u.set_query(None); }
                u.to_string()
            }
            Err(_) => args.url.split('?').next().unwrap_or(&args.url).to_string(),
        },
        None => args.url.clone(),
    };

    // --jsonl implies silent: stdout carries only JSON lines, so the plan and
    // human report are suppressed (a summary still goes to stderr).
    let verbose = !args.jsonl;
    if verbose {
        println!("target:    {} {}", args.method, base_url);
        println!("preset:    {}   mode: {:?}", args.preset, args.mode);
        if let Some(q) = &args.inject_query {
            println!("inject:    query param `{q}`");
        }
        if let Some(t) = &inject_body {
            let ct = args.content_type.as_deref().unwrap_or("application/x-www-form-urlencoded");
            println!("inject:    body `{ct}` `{t}`");
        }
        if args.inject_json {
            println!("inject:    raw JSON body (payload is the body; application/json)");
        }
        for (name, value) in &args.headers {
            // Avoid dumping full auth/cookie values to the terminal.
            println!("header:    {name}: {}", truncate(value, 16));
        }
        println!("budget:    {} probes   timeout: {}s", args.budget, args.timeout_secs);
    }

    let timeout = Duration::from_secs(args.timeout_secs);
    let probe = match &args.csrf_url {
        Some(url) => {
            // Default regex pulls the token out of `name='FIELD' ... value='TOKEN'`.
            let pat = args.csrf_regex.clone().unwrap_or_else(|| {
                format!(r#"{}['"][^>]*?value=['"]([^'"]+)"#, regex::escape(&args.csrf_field))
            });
            let regex = match regex::Regex::new(&pat) {
                Ok(r) => r,
                Err(e) => { eprintln!("error: bad --csrf-regex: {e}"); std::process::exit(2); }
            };
            if verbose { println!("csrf:      GET {url}  field `{}`", args.csrf_field); }
            Arc::new(HttpProbe::with_csrf(timeout, CsrfConfig {
                url: url.clone(), field: args.csrf_field.clone(), regex,
            }))
        }
        None => Arc::new(HttpProbe::new(timeout)),
    };
    let mut f = Fuzzer::new(probe).target(&base_url, &args.method);
    f = match apply_preset(f, &args.preset) {
        Ok(f) => f,
        Err(e) => { eprintln!("error: {e}"); std::process::exit(2); }
    };
    f = f.mode(args.mode);
    for (name, value) in &args.headers {
        f = f.header(name, value);
    }
    // Injection point (mutually exclusive; JSON body wins, then body template/form, then query).
    if args.inject_json {
        f = f.body_json("{{payload}}"); // payload IS the JSON body
    } else if let Some(t) = &inject_body {
        if let Some(ct) = &args.content_type {
            f = f.body_template(ct, t);
        } else {
            f = f.body_form(t);
        }
    } else if let Some(q) = &args.inject_query {
        f = f.inject_query(q);
    }
    f = f.budget(args.budget);
    if args.concurrency > 1 {
        f = f.concurrency(args.concurrency);
        if verbose { println!("concurrency: {} in-flight probes", args.concurrency); }
    }
    if args.rate_limit > 0.0 {
        f = f.rate_limit(args.rate_limit);
        if verbose { println!("rate-limit: {:.1} req/s", args.rate_limit); }
    }
    if args.hunt {
        f = f.hunt();
        if verbose { println!("mode:      HUNT (recall-first — flags any response unlike baseline)"); }
    }
    if let Some(oob) = &args.oob {
        f = f.oob(oob);
        if verbose { println!("oob:       {} (substituted into {{{{oob}}}})", oob); }
    }
    if let Some(seed) = args.seed {
        f = f.replay_seed(seed);
        if verbose { println!("seed:      {}", seed); }
    }

    // Injection descriptor for the JSONL context field.
    let inject = if args.inject_json {
        "json-body".to_string()
    } else {
        match (&inject_body, &args.inject_query) {
            (Some(t), _) => {
                let ct = args.content_type.as_deref().unwrap_or("form");
                format!("body:{ct}:{t}")
            }
            (_, Some(q)) => format!("query:{q}"),
            _ => if args.method == "POST" { "body".into() } else { "query:q".into() },
        }
    };

    match f.run().await {
        Ok(r) => {
            if r.oob_skipped > 0 {
                eprintln!(
                    "[fuzz] skipped {} OOB payload(s) — pass --oob-url <collaborator> to enable them",
                    r.oob_skipped
                );
            }
            if args.jsonl {
                emit_jsonl(&r, &base_url, &args.method, &inject, &args.preset);
            } else {
                report(&r);
            }
        }
        Err(e) => { eprintln!("\nrun failed: {e}"); std::process::exit(1); }
    }
}
