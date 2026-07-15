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

use auto_fuzz::agent::{FuzzMode, FuzzResult, Fuzzer, Hit};
use auto_fuzz::http::HttpProbe;

struct Args {
    preset: String,
    url: String,
    method: String,
    inject_query: Option<String>,
    /// Form-encoded POST body template with `{{payload}}`, e.g. `pass={{payload}}`.
    inject_body: Option<String>,
    budget: usize,
    timeout_secs: u64,
    mode: FuzzMode,
    hunt: bool,
    /// Static headers merged into every request (`Name: Value`), plus `--cookie`.
    headers: Vec<(String, String)>,
}

fn parse_args() -> Result<Args, String> {
    let mut preset = None;
    let mut url = None;
    let mut method = "GET".to_string();
    let mut inject_query = None;
    let mut inject_body = None;
    let mut budget = 100usize;
    let mut timeout_secs = 15u64;
    let mut mode = FuzzMode::Evolutionary;
    let mut hunt = false;
    let mut headers: Vec<(String, String)> = Vec::new();

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
            "--hunt" => hunt = true,
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
        budget,
        timeout_secs,
        mode,
        hunt,
        headers,
    })
}

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
        other => return Err(format!("unknown preset: {other}")),
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

#[tokio::main]
async fn main() {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            if e != "help" { eprintln!("error: {e}\n"); }
            eprintln!("usage: fuzz --preset <sqli|xss|ssti|cmdi|path|nosql|ssrf|xxe> --url <URL> \\");
            eprintln!("            [--inject-query <param> | --inject-body '<tmpl with {{{{payload}}}}>'] \\");
            eprintln!("            [--method GET] [--budget 100] [--timeout 15] [--mode evolutionary] [--hunt]");
            eprintln!("            [--header 'Name: Value']... [--cookie 'a=b; c=d']");
            std::process::exit(if e == "help" { 0 } else { 2 });
        }
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

    println!("target:    {} {}", args.method, base_url);
    println!("preset:    {}   mode: {:?}", args.preset, args.mode);
    if let Some(q) = &args.inject_query {
        println!("inject:    query param `{q}`");
    }
    if let Some(t) = &args.inject_body {
        println!("inject:    form body `{t}`");
    }
    for (name, value) in &args.headers {
        // Avoid dumping full auth/cookie values to the terminal.
        println!("header:    {name}: {}", truncate(value, 16));
    }
    println!("budget:    {} probes   timeout: {}s", args.budget, args.timeout_secs);

    let probe = Arc::new(HttpProbe::new(Duration::from_secs(args.timeout_secs)));
    let mut f = Fuzzer::new(probe).target(&base_url, &args.method);
    f = match apply_preset(f, &args.preset) {
        Ok(f) => f,
        Err(e) => { eprintln!("error: {e}"); std::process::exit(2); }
    };
    f = f.mode(args.mode);
    for (name, value) in &args.headers {
        f = f.header(name, value);
    }
    // Injection point: query param or form body (mutually exclusive; body wins).
    if let Some(t) = &args.inject_body {
        f = f.body_form(t);
    } else if let Some(q) = &args.inject_query {
        f = f.inject_query(q);
    }
    f = f.budget(args.budget);
    if args.hunt {
        f = f.hunt();
        println!("mode:      HUNT (recall-first — flags any response unlike baseline)");
    }

    match f.run().await {
        Ok(r) => report(&r),
        Err(e) => { eprintln!("\nrun failed: {e}"); std::process::exit(1); }
    }
}
