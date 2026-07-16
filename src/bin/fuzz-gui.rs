//! `fuzz-gui` — workbench for the auto-fuzz evolutionary engine.
//!
//! Run: `cargo run --bin fuzz-gui --features gui --release`

use auto_fuzz::agent::{Fuzzer, FuzzMode, FuzzResult};
use auto_fuzz::http::HttpProbe;
use eframe::egui;
use std::sync::mpsc;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const ALL_METHODS: &[&str] = &["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];

// ── Preset / Mode / Injection enums for UI ──────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UiPreset {
    Custom,
    Sqli,
    Xss,
    Ssti,
    Cmdi,
    PathTraversal,
    Nosql,
    Ssrf,
    Xxe,
    ProtoPollution,
}

impl UiPreset {
    const ALL: &'static [UiPreset] = &[
        UiPreset::Custom,
        UiPreset::Sqli,
        UiPreset::Xss,
        UiPreset::Ssti,
        UiPreset::Cmdi,
        UiPreset::PathTraversal,
        UiPreset::Nosql,
        UiPreset::Ssrf,
        UiPreset::Xxe,
        UiPreset::ProtoPollution,
    ];
    fn label(self) -> &'static str {
        match self {
            UiPreset::Custom => "Custom",
            UiPreset::Sqli => "SQL Injection",
            UiPreset::Xss => "XSS",
            UiPreset::Ssti => "SSTI",
            UiPreset::Cmdi => "Command Injection",
            UiPreset::PathTraversal => "Path Traversal",
            UiPreset::Nosql => "NoSQL Injection",
            UiPreset::Ssrf => "SSRF",
            UiPreset::Xxe => "XXE",
            UiPreset::ProtoPollution => "Prototype Pollution",
        }
    }
    fn default_gen_ratio(self) -> f32 {
        match self {
            UiPreset::Sqli | UiPreset::Xss | UiPreset::Ssti => 0.8,
            UiPreset::Cmdi | UiPreset::PathTraversal | UiPreset::Nosql => 0.7,
            UiPreset::Ssrf | UiPreset::Xxe => 0.0,
            UiPreset::ProtoPollution => 0.4,
            UiPreset::Custom => 0.7,
        }
    }
    fn default_seeds(self) -> &'static str {
        match self {
            UiPreset::Sqli => "'\n\"\n' OR '1'='1\nUNION SELECT\n--",
            UiPreset::Xss => "<\n<script>\n<img onerror=>\n\"'><",
            UiPreset::Ssti => "{{\n{{7*7}}\n${7*7}\n<%=7*7%>",
            UiPreset::Cmdi => ";\n| id\n& whoami\n$(`id`)",
            UiPreset::PathTraversal => "../\n..%2f\n../../etc/passwd\n%2e%2e/",
            UiPreset::Nosql => "' || '1'=='1\n{ \"$ne\": null }\n$gt\n$regex",
            UiPreset::Ssrf => "http://localhost\nhttp://169.254.169.254\nhttp://127.0.0.1\nfile://",
            UiPreset::Xxe => "<!ENTITY xxe SYSTEM \"file:///etc/passwd\">\n%xxe;",
            UiPreset::ProtoPollution => "{\"__proto__\":{\"json spaces\":10}}\n{\"__proto__\":{\"isAdmin\":true}}\n{\"constructor\":{\"prototype\":{\"polluted\":true}}}",
            UiPreset::Custom => "'\n\"\n<\n{{",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UiMode {
    Evolutionary,
    Table,
    TableThenEvo,
    InputsOnly,
}

impl UiMode {
    const ALL: &'static [UiMode] = &[
        UiMode::Evolutionary,
        UiMode::Table,
        UiMode::TableThenEvo,
        UiMode::InputsOnly,
    ];
    fn label(self) -> &'static str {
        match self {
            UiMode::Evolutionary => "Evolutionary",
            UiMode::Table => "Table Sweep",
            UiMode::TableThenEvo => "Table → Evolutionary",
            UiMode::InputsOnly => "Inputs Only",
        }
    }
    fn to_fuzz_mode(self) -> FuzzMode {
        match self {
            UiMode::Evolutionary => FuzzMode::Evolutionary,
            UiMode::Table => FuzzMode::Table,
            UiMode::TableThenEvo => FuzzMode::TableThenEvolutionary,
            UiMode::InputsOnly => FuzzMode::InputsOnly,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UiInjection {
    QueryParam,
    BodyRaw,
    BodyForm,
    BodyJson,
    Header,
    PathSegment,
}

impl UiInjection {
    const ALL: &'static [UiInjection] = &[
        UiInjection::QueryParam,
        UiInjection::BodyRaw,
        UiInjection::BodyForm,
        UiInjection::BodyJson,
        UiInjection::Header,
        UiInjection::PathSegment,
    ];
    fn label(self) -> &'static str {
        match self {
            UiInjection::QueryParam => "Query Parameter",
            UiInjection::BodyRaw => "Body (Raw)",
            UiInjection::BodyForm => "Body (Form)",
            UiInjection::BodyJson => "Body (JSON)",
            UiInjection::Header => "Header",
            UiInjection::PathSegment => "Path Segment",
        }
    }
}

// ── Run record ───────────────────────────────────────────────────────────

#[derive(Clone)]
struct RunRecord {
    id: usize,
    duration: Duration,
    target_url: String,
    preset: String,
    mode: String,
    seeds: Vec<String>,
    gen_ratio: f32,
    max_probes: usize,
    rng_seed: Option<u64>,
    hits: usize,
    confirmed: usize,
    probes_sent: usize,
    corpus_size: usize,
    baseline: String,
    oob_skipped: usize,
    signal_counts: Vec<(String, usize)>,
    hits_detail: Vec<HitDetail>,
    error: Option<String>,
}

#[derive(Clone)]
struct HitDetail {
    payload: String,
    score: u8,
    confidence: f32,
    confirmed: bool,
    signals: Vec<String>,
    suppressed: Vec<String>,
    source: String,
}

// ── Runner ───────────────────────────────────────────────────────────────

struct Runner {
    cancel: tokio::sync::watch::Sender<bool>,
    progress_rx: mpsc::Receiver<Progress>,
    result_rx: mpsc::Receiver<Option<RunRecord>>,
    running: Arc<Mutex<bool>>,
}

#[derive(Debug, Clone)]
struct Progress {
    probes: usize,
    total: usize,
}

/// Configuration snapshot passed to the worker thread.
#[derive(Clone)]
struct RunConfig {
    id: usize,
    target_url: String,
    method: String,
    preset: UiPreset,
    mode: UiMode,
    injection: UiInjection,
    inject_param: String,
    inject_template: String,
    seeds: Vec<String>,
    gen_ratio: f32,
    max_probes: usize,
    rng_seed: Option<u64>,
    timeout_secs: u64,
    stop_on_first_hit: bool,
    /// Out-of-band collaborator (URL or bare host) for `{{oob}}` substitution.
    oob: String,
}

fn launch(cfg: RunConfig) -> Runner {
    let (progress_tx, progress_rx) = mpsc::channel();
    let (result_tx, result_rx) = mpsc::channel();
    let (cancel_tx, mut cancel_rx) = tokio::sync::watch::channel(false);
    let running = Arc::new(Mutex::new(true));
    let running_clone = running.clone();
    let running_clone2 = running.clone();
    let start = Instant::now();

    let result_tx_err = result_tx.clone();
    let cfg_err = cfg.clone();

    std::thread::Builder::new()
        .name(format!("fuzz-{}", cfg.id))
        .spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("tokio runtime");

                rt.block_on(async move {
                    let probe = Arc::new(HttpProbe::new(Duration::from_secs(cfg.timeout_secs)));

                    let progress_tx = Arc::new(Mutex::new(progress_tx));
                    let progress_cb = progress_tx.clone();
                    let max_probes = cfg.max_probes;

                    // Build the Fuzzer with the selected preset and configuration.
                    let mut fuzzer = Fuzzer::new(probe)
                        .target(&cfg.target_url, &cfg.method)
                        .budget(cfg.max_probes)
                        .gen_ratio(cfg.gen_ratio)
                        .mode(cfg.mode.to_fuzz_mode())
                        .on_progress(Arc::new(move |probes, total| {
                            let _ = progress_cb.lock().unwrap().send(Progress { probes, total });
                        }));

                    // Apply preset
                    fuzzer = match cfg.preset {
                        UiPreset::Sqli => fuzzer.sql_injection(),
                        UiPreset::Xss => fuzzer.xss(),
                        UiPreset::Ssti => fuzzer.ssti(),
                        UiPreset::Cmdi => fuzzer.command_injection(),
                        UiPreset::PathTraversal => fuzzer.path_traversal(),
                        UiPreset::Nosql => fuzzer.nosql_injection(),
                        UiPreset::Ssrf => fuzzer.ssrf(),
                        UiPreset::Xxe => fuzzer.xxe(),
                        UiPreset::ProtoPollution => fuzzer.prototype_pollution(),
                        UiPreset::Custom => fuzzer,
                    };

                    // Apply injection point
                    fuzzer = match cfg.injection {
                        UiInjection::QueryParam => fuzzer.inject_query(&cfg.inject_param),
                        UiInjection::BodyRaw => fuzzer.inject_body_raw(),
                        UiInjection::BodyForm => fuzzer.body_form(&cfg.inject_template),
                        UiInjection::BodyJson => fuzzer.body_json(&cfg.inject_template),
                        UiInjection::Header => fuzzer.inject_header(&cfg.inject_param),
                        UiInjection::PathSegment => fuzzer.inject_path(),
                    };

                    // Apply optional seeds
                    if !cfg.seeds.is_empty() {
                        fuzzer = fuzzer.seeds(cfg.seeds.iter().cloned());
                    }

                    // Apply replay seed
                    if let Some(s) = cfg.rng_seed {
                        fuzzer = fuzzer.replay_seed(s);
                    }

                    // Apply timeout
                    fuzzer = fuzzer.request_timeout(Duration::from_secs(cfg.timeout_secs));

                    // Apply stop-on-first-hit
                    if cfg.stop_on_first_hit {
                        fuzzer = fuzzer.stop_on_first_hit();
                    }

                    // Apply OOB collaborator for {{oob}} substitution (else those
                    // payloads are skipped).
                    if !cfg.oob.trim().is_empty() {
                        fuzzer = fuzzer.oob(cfg.oob.trim());
                    }

                    let _max_probes = max_probes; // suppress unused warning
                    let preset_name = cfg.preset.label().to_string();
                    let mode_name = cfg.mode.label().to_string();
                    let cfg_seeds = cfg.seeds.clone();
                    let cfg_gen = cfg.gen_ratio;
                    let cfg_budget = cfg.max_probes;
                    let cfg_seed = cfg.rng_seed;
                    let cfg_url = cfg.target_url.clone();
                    let cfg_id = cfg.id;

                    let fut = fuzzer.run();
                    tokio::pin!(fut);

                    let outcome = tokio::select! {
                        _ = cancel_rx.changed() => {
                            return;
                        }
                        result = &mut fut => match result {
                            Ok(res) => res,
                            Err(e) => {
                                let _ = result_tx.send(Some(run_record_error(
                                    cfg_id, start.elapsed(), cfg_url, preset_name, mode_name,
                                    cfg_seeds, cfg_gen, cfg_budget, cfg_seed, e,
                                )));
                                return;
                            }
                        },
                    };

                    let record = build_record(
                        cfg_id, start.elapsed(), cfg_url, preset_name, mode_name,
                        cfg_seeds, cfg_gen, cfg_budget, cfg_seed, &outcome,
                    );
                    let _ = result_tx.send(Some(record));
                    *running_clone.lock().unwrap() = false;
                });
            }));

            *running_clone2.lock().unwrap() = false;
            if let Err(panic) = result {
                let msg = if let Some(s) = panic.downcast_ref::<String>() { s.clone() }
                    else if let Some(s) = panic.downcast_ref::<&str>() { s.to_string() }
                    else { "unknown panic".into() };
                let _ = result_tx_err.send(Some(run_record_error(
                    cfg_err.id, start.elapsed(), cfg_err.target_url,
                    cfg_err.preset.label().to_string(), cfg_err.mode.label().to_string(),
                    cfg_err.seeds, cfg_err.gen_ratio, cfg_err.max_probes, cfg_err.rng_seed,
                    format!("panic: {msg}"),
                )));
            }
        })
        .expect("failed to spawn fuzz thread");

    Runner { cancel: cancel_tx, progress_rx, result_rx, running }
}

fn build_record(
    id: usize,
    duration: Duration,
    target_url: String,
    preset: String,
    mode: String,
    seeds: Vec<String>,
    gen_ratio: f32,
    max_probes: usize,
    rng_seed: Option<u64>,
    outcome: &FuzzResult,
) -> RunRecord {
    let hits_detail: Vec<HitDetail> = outcome.interesting.iter().map(|h| {
        let source = match &h.source {
            auto_fuzz::agent::PayloadSource::Table { preset, index } => format!("table:{preset}[{index}]"),
            auto_fuzz::agent::PayloadSource::UserInput { index } => format!("input[{index}]"),
            auto_fuzz::agent::PayloadSource::Evolutionary => "evolved".into(),
        };
        HitDetail {
            payload: h.payload.clone(),
            score: h.raw_score,
            confidence: h.confidence,
            confirmed: h.confirmed,
            signals: h.signals.clone(),
            suppressed: h.suppressed.clone(),
            source,
        }
    }).collect();

    let mut signal_map: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for h in &outcome.interesting {
        for sig in &h.signals {
            *signal_map.entry(sig.clone()).or_default() += 1;
        }
    }
    let mut signal_counts: Vec<(String, usize)> = signal_map.into_iter().collect();
    signal_counts.sort_by_key(|(_, c)| std::cmp::Reverse(*c));

    RunRecord {
        id, duration, target_url, preset, mode, seeds, gen_ratio, max_probes, rng_seed,
        hits: outcome.interesting.len(),
        confirmed: outcome.confirmed.len(),
        probes_sent: outcome.probes_sent,
        corpus_size: outcome.corpus_size,
        baseline: outcome.baseline.clone(),
        oob_skipped: outcome.oob_skipped,
        signal_counts,
        hits_detail,
        error: None,
    }
}

#[allow(clippy::too_many_arguments)]
fn run_record_error(
    id: usize,
    duration: Duration,
    target_url: String,
    preset: String,
    mode: String,
    seeds: Vec<String>,
    gen_ratio: f32,
    max_probes: usize,
    rng_seed: Option<u64>,
    error: String,
) -> RunRecord {
    RunRecord {
        id, duration, target_url, preset, mode, seeds, gen_ratio, max_probes, rng_seed,
        hits: 0, confirmed: 0, probes_sent: 0, corpus_size: 0,
        baseline: String::new(), oob_skipped: 0, signal_counts: vec![], hits_detail: vec![],
        error: Some(error),
    }
}

// ── egui App ─────────────────────────────────────────────────────────────

struct App {
    target_url: String,
    method: String,
    preset: UiPreset,
    mode: UiMode,
    injection: UiInjection,
    inject_param: String,
    inject_template: String,
    seeds_text: String,
    gen_ratio: f32,
    max_probes: usize,
    rng_seed: u64,
    timeout_secs: u64,
    stop_on_first_hit: bool,
    oob: String,
    runner: Option<Runner>,
    progress: Progress,
    status: String,
    next_id: usize,
    history: Vec<RunRecord>,
    selected_history: Option<usize>,
    error_message: Option<String>,
}

impl Default for App {
    fn default() -> Self {
        Self {
            target_url: "http://testphp.vulnweb.com/listproducts.php?cat=".into(),
            method: "GET".into(),
            preset: UiPreset::Custom,
            mode: UiMode::Evolutionary,
            injection: UiInjection::QueryParam,
            inject_param: "q".into(),
            inject_template: String::new(),
            seeds_text: "'\n\"\n<\n{{".into(),
            gen_ratio: 0.7,
            max_probes: 50,
            rng_seed: 0,
            timeout_secs: 30,
            stop_on_first_hit: false,
            oob: String::new(),
            runner: None,
            progress: Progress { probes: 0, total: 0 },
            status: "Ready".into(),
            next_id: 1,
            history: Vec::new(),
            selected_history: None,
            error_message: None,
        }
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let mut finished = false;

        // Drain events from runner
        if let Some(ref runner) = self.runner {
            while let Ok(p) = runner.progress_rx.try_recv() {
                self.progress = p;
            }
            while let Ok(r) = runner.result_rx.try_recv() {
                if let Some(record) = r {
                    if let Some(ref err) = record.error {
                        self.error_message = Some(err.clone());
                    } else {
                        self.history.push(record);
                        self.selected_history = Some(self.history.len() - 1);
                    }
                }
                finished = true;
            }
            let alive = *runner.running.lock().unwrap();
            if alive {
                self.status = format!("Running — probes: {} / {}", self.progress.probes, self.progress.total);
            } else if !finished {
                self.status = "Finishing...".into();
            }
        }
        if finished {
            self.runner = None;
            self.status = "Ready".into();
        }

        let running = self.runner.is_some();

        // ── Top bar ─────────────────────────────────────────────────────
        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.heading("auto-fuzz workbench");
            ui.label(egui::RichText::new(
                "Atom-chain generation + havoc mutation · corpus-driven · deterministic replay",
            ).weak());
        });

        // ── Left panel — configuration ──────────────────────────────────
        egui::SidePanel::left("left")
            .resizable(true)
            .default_width(340.0)
            .show(ctx, |ui| {
                egui::ScrollArea::vertical().show(ui, |ui| {
                    // ── Target ──
                    ui.heading("Target");
                    ui.horizontal(|ui| {
                        egui::ComboBox::from_id_salt("method")
                            .selected_text(&self.method)
                            .show_ui(ui, |ui| {
                                for m in ALL_METHODS {
                                    ui.selectable_value(&mut self.method, m.to_string(), *m);
                                }
                            });
                        ui.add(egui::TextEdit::singleline(&mut self.target_url)
                            .hint_text("https://target.com/endpoint"));
                    });

                    ui.separator();

                    // ── Preset ──
                    ui.heading("Preset");
                    egui::ComboBox::from_id_salt("preset")
                        .selected_text(self.preset.label())
                        .show_ui(ui, |ui| {
                            for &p in UiPreset::ALL {
                                if ui.selectable_label(self.preset == p, p.label()).clicked() {
                                    self.preset = p;
                                    // Apply preset defaults
                                    self.seeds_text = p.default_seeds().into();
                                    self.gen_ratio = p.default_gen_ratio();
                                }
                            }
                        });

                    ui.add_space(4.0);

                    // ── Mode ──
                    ui.heading("Mode");
                    egui::ComboBox::from_id_salt("mode")
                        .selected_text(self.mode.label())
                        .show_ui(ui, |ui| {
                            for &m in UiMode::ALL {
                                if ui.selectable_label(self.mode == m, m.label()).clicked() {
                                    self.mode = m;
                                }
                            }
                        });

                    ui.add_space(4.0);

                    // ── Injection ──
                    ui.heading("Injection Point");
                    egui::ComboBox::from_id_salt("injection")
                        .selected_text(self.injection.label())
                        .show_ui(ui, |ui| {
                            for &inj in UiInjection::ALL {
                                if ui.selectable_label(self.injection == inj, inj.label()).clicked() {
                                    self.injection = inj;
                                }
                            }
                        });
                    match self.injection {
                        UiInjection::QueryParam => {
                            ui.horizontal(|ui| {
                                ui.label("Param:");
                                ui.add(egui::TextEdit::singleline(&mut self.inject_param)
                                    .desired_width(120.0));
                            });
                        }
                        UiInjection::Header => {
                            ui.horizontal(|ui| {
                                ui.label("Header:");
                                ui.add(egui::TextEdit::singleline(&mut self.inject_param)
                                    .desired_width(120.0));
                            });
                        }
                        UiInjection::BodyForm | UiInjection::BodyJson => {
                            ui.label("Template:");
                            ui.add(egui::TextEdit::multiline(&mut self.inject_template)
                                .desired_rows(2)
                                .hint_text(r#"key={{payload}}"#));
                        }
                        UiInjection::BodyRaw | UiInjection::PathSegment => {}
                    }

                    ui.separator();

                    // ── Seeds ──
                    ui.heading("Seeds");
                    ui.add(egui::TextEdit::multiline(&mut self.seeds_text)
                        .desired_rows(3).hint_text("one per line"));

                    ui.separator();

                    // ── OOB collaborator ──
                    ui.heading("OOB");
                    ui.horizontal(|ui| {
                        ui.label("Collaborator:");
                        ui.add(egui::TextEdit::singleline(&mut self.oob)
                            .hint_text("host or url for {{oob}} — blank skips OOB payloads"));
                    });

                    ui.separator();

                    // ── Engine ──
                    ui.heading("Engine");
                    ui.add(egui::Slider::new(&mut self.gen_ratio, 0.0..=1.0).text("gen_ratio"));
                    ui.label(format!("{}% gen / {}% havoc",
                        (self.gen_ratio * 100.0) as u32, ((1.0 - self.gen_ratio) * 100.0) as u32));
                    ui.add(egui::Slider::new(&mut self.max_probes, 5..=500).text("max_probes"));
                    ui.add(egui::Slider::new(&mut self.timeout_secs, 1..=60).text("timeout (s)"));
                    ui.horizontal(|ui| {
                        ui.label("Seed:");
                        ui.add(egui::DragValue::new(&mut self.rng_seed));
                        if ui.button("🎲").clicked() { self.rng_seed = rand::random(); }
                    });
                    ui.checkbox(&mut self.stop_on_first_hit, "Stop on first hit");

                    ui.separator();

                    // ── Run / Stop ──
                    ui.horizontal(|ui| {
                        if ui.add_enabled(!running, egui::Button::new("▶ Run")).clicked() {
                            self.error_message = None;
                            let seeds: Vec<String> = self.seeds_text.lines()
                                .map(|l| l.trim().to_string())
                                .filter(|l| !l.is_empty())
                                .collect();
                            let rng = if self.rng_seed == 0 { None } else { Some(self.rng_seed) };
                            self.progress = Progress { probes: 0, total: self.max_probes };
                            let cfg = RunConfig {
                                id: self.next_id,
                                target_url: self.target_url.clone(),
                                method: self.method.clone(),
                                preset: self.preset,
                                mode: self.mode,
                                injection: self.injection,
                                inject_param: self.inject_param.clone(),
                                inject_template: self.inject_template.clone(),
                                seeds,
                                gen_ratio: self.gen_ratio,
                                max_probes: self.max_probes,
                                rng_seed: rng,
                                timeout_secs: self.timeout_secs,
                                stop_on_first_hit: self.stop_on_first_hit,
                                oob: self.oob.clone(),
                            };
                            self.runner = Some(launch(cfg));
                            self.next_id += 1;
                            self.status = "Launching...".into();
                        }
                        if ui.add_enabled(running, egui::Button::new("⏹ Stop")).clicked() {
                            if let Some(ref r) = self.runner { let _ = r.cancel.send(true); }
                        }
                    });

                    if running {
                        ui.add(egui::ProgressBar::new(
                            self.progress.probes as f32 / self.progress.total.max(1) as f32,
                        ).text(&self.status));
                    } else {
                        ui.label(&self.status);
                    }

                    if let Some(ref err) = self.error_message {
                        ui.separator();
                        ui.colored_label(egui::Color32::from_rgb(255, 80, 80),
                            format!("Error: {err}"));
                    }

                    ui.separator();

                    // ── History ──
                    ui.heading(format!("History ({})", self.history.len()));
                    if ui.button("Clear history").clicked() {
                        self.history.clear();
                        self.selected_history = None;
                    }

                    for rec in self.history.iter().rev() {
                        let idx = self.history.iter().position(|r| r.id == rec.id).unwrap_or(0);
                        let is_selected = self.selected_history == Some(idx);
                        let err_mark = if rec.error.is_some() { " ⚠" } else { "" };
                        let label = format!(
                            "#{}{} {} {} — {} hits ({}✓) {:.1}s",
                            rec.id, err_mark, rec.preset, rec.mode,
                            rec.hits, rec.confirmed, rec.duration.as_secs_f32(),
                        );
                        if ui.selectable_label(is_selected, label).clicked() {
                            self.selected_history = Some(idx);
                        }
                    }
                });
            });

        // ── Central panel — results ─────────────────────────────────────
        egui::CentralPanel::default().show(ctx, |ui| {
            let Some(idx) = self.selected_history else {
                ui.centered_and_justified(|ui| {
                    ui.label(egui::RichText::new("Select a run from history to see results").weak());
                });
                return;
            };
            let rec = &self.history[idx];

            if let Some(ref err) = rec.error {
                ui.colored_label(egui::Color32::from_rgb(255, 80, 80), format!("⚠ Error: {err}"));
                return;
            }

            // Stats cards
            ui.horizontal(|ui| {
                card(ui, "Duration", &format!("{:.1}s", rec.duration.as_secs_f32()));
                card(ui, "Probes", &format!("{}", rec.probes_sent));
                card(ui, "Hits", &format!("{}", rec.hits));
                card(ui, "Confirmed", &format!("{}", rec.confirmed));
                if rec.corpus_size > 0 {
                    card(ui, "Corpus", &format!("{}", rec.corpus_size));
                }
                if rec.oob_skipped > 0 {
                    card(ui, "OOB skipped", &format!("{}", rec.oob_skipped));
                }
                card(ui, "Preset", &rec.preset);
                card(ui, "Mode", &rec.mode);
                card(ui, "Budget", &format!("{}", rec.max_probes));
                card(ui, "gen_ratio", &format!("{:.2}", rec.gen_ratio));
                card(ui, "RNG seed", &format!("{:?}", rec.rng_seed));
            });

            // Target URL + seed count
            ui.add_space(2.0);
            ui.label(egui::RichText::new(format!(
                "🎯 {} · {} seed{}",
                rec.target_url.split('?').next().unwrap_or(&rec.target_url),
                rec.seeds.len(),
                if rec.seeds.len() == 1 { "" } else { "s" },
            )).weak().size(11.0));

            // Baseline health
            ui.add_space(2.0);
            ui.label(egui::RichText::new(format!("📋 Baseline: {}", rec.baseline))
                .weak().size(11.0));

            ui.separator();

            // Signal distribution
            if !rec.signal_counts.is_empty() {
                ui.heading("Signal distribution");
                let total: usize = rec.signal_counts.iter().map(|(_, c)| c).sum();
                ui.horizontal(|ui| {
                    for (sig, count) in &rec.signal_counts {
                        let pct = if total > 0 { *count as f32 / total as f32 } else { 0.0 };
                        ui.vertical(|ui| {
                            ui.label(sig);
                            ui.add(egui::ProgressBar::new(pct).desired_width(60.0).text(format!("{count}")));
                        });
                    }
                });
                ui.separator();
            }

            // Hits table
            let confirmed_count = rec.hits_detail.iter().filter(|h| h.confirmed).count();
            ui.heading(format!("Hits — {} total, {} confirmed", rec.hits_detail.len(), confirmed_count));

            egui::ScrollArea::vertical().show(ui, |ui| {
                egui::Grid::new("hits").striped(true).show(ui, |ui| {
                    ui.strong("#");
                    ui.strong("Payload");
                    ui.strong("Score");
                    ui.strong("Conf.");
                    ui.strong("Source");
                    ui.strong("Signals");
                    ui.strong("Suppressed");
                    ui.end_row();

                    for (i, h) in rec.hits_detail.iter().enumerate() {
                        let color = if h.confirmed {
                            egui::Color32::from_rgb(80, 220, 80)
                        } else {
                            egui::Color32::from_rgb(220, 200, 60)
                        };
                        ui.colored_label(color, format!("{}", i + 1));
                        ui.label(&h.payload);
                        ui.label(format!("{}", h.score));
                        let conf_color = if h.confidence > 0.7 {
                            egui::Color32::from_rgb(80, 220, 80)
                        } else if h.confidence > 0.3 {
                            egui::Color32::from_rgb(220, 200, 60)
                        } else {
                            egui::Color32::from_rgb(200, 100, 100)
                        };
                        ui.colored_label(conf_color, format!("{:.0}%", h.confidence * 100.0));
                        ui.label(&h.source);
                        ui.label(h.signals.join(", "));
                        ui.label(egui::RichText::new(h.suppressed.join(", ")).weak());
                        ui.end_row();
                    }
                });
            });
        });

        if running {
            ctx.request_repaint();
        }
    }
}

fn card(ui: &mut egui::Ui, label: &str, value: &str) {
    egui::Frame::group(ui.style())
        .corner_radius(6.0)
        .inner_margin(egui::Margin {
            left: 8, right: 8, top: 4, bottom: 4,
        })
        .show(ui, |ui| {
            ui.vertical(|ui| {
                ui.label(egui::RichText::new(label).weak().size(10.0));
                ui.label(egui::RichText::new(value).strong().size(14.0));
            });
        });
}

fn main() -> eframe::Result {
    eframe::run_native(
        "auto-fuzz workbench",
        eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default()
                .with_inner_size([1200.0, 750.0])
                .with_title("auto-fuzz workbench"),
            ..Default::default()
        },
        Box::new(|_cc| Ok(Box::new(App::default()))),
    )
}
