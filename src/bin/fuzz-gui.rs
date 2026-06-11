//! `fuzz-gui` — benchmark workbench for the auto-fuzz evolutionary engine.
//!
//! Run: `cargo run --bin fuzz-gui --features gui --release`

use auto_fuzz::evolutionary::*;
use auto_fuzz::signals::*;
use auto_fuzz::signals::signal::*;
use async_trait::async_trait;
use eframe::egui;
use rand::SeedableRng;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use url::Url;

// ── HTTP Probe (TLS verification ON by default) ──────────────────────────

struct HttpProbe {
    client: reqwest::Client,
}

impl HttpProbe {
    fn new() -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("failed to build HTTP client"),
        }
    }
}

const ALL_METHODS: &[&str] = &["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];

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
        Ok(ProbeResponse { status, body: body.to_vec(), duration: start.elapsed() })
    }
}

// ── Run record ───────────────────────────────────────────────────────────

#[derive(Clone)]
struct RunRecord {
    id: usize,
    started: Instant,
    duration: Duration,
    target_url: String,
    method: String,
    seeds: Vec<String>,
    gen_ratio: f32,
    max_probes: usize,
    rng_seed: Option<u64>,
    hits: usize,
    confirmed: usize,
    probes_sent: usize,
    corpus_size: usize,
    signal_counts: Vec<(String, usize)>,
    hits_detail: Vec<HitDetail>,
    error: Option<String>,
}

#[derive(Clone)]
struct HitDetail {
    payload: String,
    score: u8,
    confirmed: bool,
    signals: Vec<String>,
}

// ── Fuzzer runner with real cancellation and progress ────────────────────

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

fn launch(
    id: usize,
    target_url: String,
    method: String,
    seeds: Vec<String>,
    gen_ratio: f32,
    max_probes: usize,
    rng_seed: Option<u64>,
) -> Runner {
    let (progress_tx, progress_rx) = mpsc::channel();
    let (result_tx, result_rx) = mpsc::channel();
    let (cancel_tx, mut cancel_rx) = tokio::sync::watch::channel(false);
    let running = Arc::new(Mutex::new(true));
    let running_clone = running.clone();
    let running_clone2 = running.clone();
    let start = Instant::now();

    // Clone everything the error handler needs before moving into the async block
    let target_url_err = target_url.clone();
    let method_err = method.clone();
    let seeds_err = seeds.clone();
    let result_tx_err = result_tx.clone();

    std::thread::Builder::new()
        .name(format!("fuzz-{}", id))
        .spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("tokio runtime");

                rt.block_on(async move {
                    let probe = HttpProbe::new();
                    let sampler = WeightedSampler::default_weights();
                    let havoc = HavocMutator::new(WeightedSampler::default_weights(), max_probes * 4);
                    let corpus = SeedCorpus::from_seeds(&seeds);
                    let feedback: Box<dyn Feedback> = Box::new(HttpFeedback::default());
                    let mut lp = EvolutionaryLoop::new(probe, corpus, sampler, havoc, feedback)
                        .with_gen_ratio(gen_ratio)
                        .with_max_probes(max_probes);

                    if let Some(s) = rng_seed { lp = lp.with_seed(s); }

                    let meth = method.clone();
                    let tgt = target_url.clone();

                    let probe_count = Arc::new(AtomicUsize::new(0));
                    let probe_count_clone = probe_count.clone();
                    let progress_tx = std::sync::Mutex::new(progress_tx);

                    let inject = move |payload: &str| -> Request {
                        let n = probe_count_clone.fetch_add(1, Ordering::Relaxed) + 1;
                        let _ = progress_tx.lock().unwrap().send(Progress { probes: n, total: max_probes });

                        if meth == "POST" || meth == "PUT" || meth == "PATCH" {
                            Request {
                                url: tgt.clone(), method: meth.clone(),
                                headers: std::collections::HashMap::new(),
                                body: payload.to_string(),
                            }
                        } else {
                            let mut url = Url::parse(&tgt).unwrap_or_else(|_| {
                                Url::parse(&format!("http://{}/", tgt)).unwrap()
                            });
                            url.query_pairs_mut().append_pair("q", payload);
                            Request {
                                url: url.to_string(), method: meth.clone(),
                                headers: std::collections::HashMap::new(),
                                body: String::new(),
                            }
                        }
                    };

                    let baseline = Request {
                        url: target_url.clone(), method: method.clone(),
                        headers: std::collections::HashMap::new(), body: String::new(),
                    };

                    let fut = lp.run(&baseline, inject);
                    tokio::pin!(fut);

                    let outcome = tokio::select! {
                        _ = cancel_rx.changed() => {
                            return;
                        }
                        result = &mut fut => match result {
                            Ok(outcome) => outcome,
                            Err(e) => {
                                let _ = result_tx.send(Some(RunRecord {
                                    id, started: start, duration: start.elapsed(),
                                    target_url, method, seeds, gen_ratio, max_probes, rng_seed,
                                    hits: 0, confirmed: 0, probes_sent: 0, corpus_size: 0,
                                    signal_counts: vec![], hits_detail: vec![],
                                    error: Some(e),
                                }));
                                return;
                            }
                        },
                    };

                    let hits_detail: Vec<HitDetail> = outcome.interesting.iter()
                        .map(|h| HitDetail {
                            payload: h.payload.clone(), score: h.score,
                            confirmed: h.confirmed,
                            signals: h.signals.iter().map(|s| s.kind().to_string()).collect(),
                        }).collect();

                    let mut signal_map: std::collections::HashMap<String, usize> =
                        std::collections::HashMap::new();
                    for h in &outcome.interesting {
                        for sig in &h.signals {
                            *signal_map.entry(sig.kind().to_string()).or_default() += 1;
                        }
                    }
                    let mut signal_counts: Vec<(String, usize)> = signal_map.into_iter().collect();
                    signal_counts.sort_by_key(|(_, c)| std::cmp::Reverse(*c));

                    let _ = result_tx.send(Some(RunRecord {
                        id, started: start, duration: start.elapsed(),
                        target_url, method, seeds, gen_ratio, max_probes, rng_seed,
                        hits: outcome.interesting.len(), confirmed: outcome.hits.len(),
                        probes_sent: outcome.probes_sent, corpus_size: outcome.final_corpus_size,
                        signal_counts, hits_detail, error: None,
                    }));
                    *running_clone.lock().unwrap() = false;
                });
            }));

            *running_clone2.lock().unwrap() = false;
            if let Err(panic) = result {
                let msg = if let Some(s) = panic.downcast_ref::<String>() { s.clone() }
                    else if let Some(s) = panic.downcast_ref::<&str>() { s.to_string() }
                    else { "unknown panic".into() };
                let _ = result_tx_err.send(Some(RunRecord {
                    id, started: start, duration: start.elapsed(),
                    target_url: target_url_err, method: method_err, seeds: seeds_err,
                    gen_ratio, max_probes, rng_seed,
                    hits: 0, confirmed: 0, probes_sent: 0, corpus_size: 0,
                    signal_counts: vec![], hits_detail: vec![],
                    error: Some(format!("panic: {msg}")),
                }));
            }
        })
        .expect("failed to spawn fuzz thread");

    Runner { cancel: cancel_tx, progress_rx, result_rx, running }
}

// ── egui App ─────────────────────────────────────────────────────────────

struct App {
    target_url: String,
    method: String,
    seeds_text: String,
    gen_ratio: f32,
    max_probes: usize,
    rng_seed: u64,
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
            seeds_text: "'\n\"\n<\n{{".into(),
            gen_ratio: 0.3,
            max_probes: 50,
            rng_seed: 0,
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
        let mut needs_repaint = false;

        // Drain events without borrowing conflicts
        let mut finished = false;
        if let Some(ref runner) = self.runner {
            while let Ok(p) = runner.progress_rx.try_recv() {
                self.progress = p;
                needs_repaint = true;
            }
            while let Ok(r) = runner.result_rx.try_recv() {
                if let Some(record) = r {
                    if let Some(ref err) = record.error {
                        self.error_message = Some(err.clone());
                    } else {
                        self.history.push(record);
                        let idx = self.history.len() - 1;
                        self.selected_history = Some(idx);
                    }
                }
                finished = true;
                needs_repaint = true;
            }
            let alive = *runner.running.lock().unwrap();
            if alive {
                self.status = format!("Running — probes: {} / {}", self.progress.probes, self.progress.total);
                needs_repaint = true;
            } else {
                self.status = "Finishing...".into();
                needs_repaint = true;
            }
        }
        if finished {
            self.runner = None;
        }

        // ── Top bar ─────────────────────────────────────────────────────
        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.heading("auto-fuzz workbench");
            ui.label(egui::RichText::new(
                "Atom-chain generation + havoc mutation · corpus-driven · deterministic replay",
            ).weak());
        });

        // ── Left panel ──────────────────────────────────────────────────
        egui::SidePanel::left("left").resizable(true).default_width(320.0).show(ctx, |ui| {
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
            ui.heading("Seeds");
            ui.add(egui::TextEdit::multiline(&mut self.seeds_text)
                .desired_rows(3).hint_text("one per line"));

            ui.separator();
            ui.heading("Engine");
            ui.add(egui::Slider::new(&mut self.gen_ratio, 0.0..=1.0).text("gen_ratio"));
            ui.label(format!("{}% gen / {}% havoc",
                (self.gen_ratio * 100.0) as u32, ((1.0 - self.gen_ratio) * 100.0) as u32));
            ui.add(egui::Slider::new(&mut self.max_probes, 5..=500).text("max_probes"));
            ui.horizontal(|ui| {
                ui.label("Seed:");
                ui.add(egui::DragValue::new(&mut self.rng_seed));
                if ui.button("🎲").clicked() { self.rng_seed = rand::random(); }
            });

            ui.separator();
            let running = self.runner.is_some();
            ui.horizontal(|ui| {
                if ui.add_enabled(!running, egui::Button::new("▶ Run")).clicked() {
                    self.error_message = None;
                    let seeds: Vec<String> = self.seeds_text.lines()
                        .map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect();
                    let rng = if self.rng_seed == 0 { None } else { Some(self.rng_seed) };
                    self.progress = Progress { probes: 0, total: self.max_probes };
                    self.runner = Some(launch(self.next_id, self.target_url.clone(),
                        self.method.clone(), seeds, self.gen_ratio, self.max_probes, rng));
                    self.next_id += 1;
                    self.status = "Launching...".into();
                }
                if ui.add_enabled(running, egui::Button::new("⏹ Stop")).clicked() {
                    if let Some(ref r) = self.runner { let _ = r.cancel.send(true); }
                }
            });

            if self.runner.is_some() {
                ui.add(egui::ProgressBar::new(
                    self.progress.probes as f32 / self.progress.total.max(1) as f32,
                ).text(&self.status));
            } else {
                ui.label(&self.status);
            }

            // Error display
            if let Some(ref err) = self.error_message {
                ui.separator();
                ui.colored_label(egui::Color32::from_rgb(255, 80, 80),
                    format!("Error: {err}"));
            }

            ui.separator();
            ui.heading(format!("History ({})", self.history.len()));
            if ui.button("Clear history").clicked() {
                self.history.clear();
                self.selected_history = None;
            }

            egui::ScrollArea::vertical().max_height(300.0).show(ui, |ui| {
                for rec in self.history.iter().rev() {
                    let is_selected = self.selected_history
                        == Some(self.history.iter().position(|r| r.id == rec.id).unwrap_or(0));
                    let err_mark = if rec.error.is_some() { " ⚠" } else { "" };
                    let label = format!("Run #{}{}  {} hits ({}✓)  {:.1}s  {}→{}",
                        rec.id, err_mark, rec.hits, rec.confirmed,
                        rec.duration.as_secs_f32(),
                        rec.seeds.join(","),
                        rec.target_url.split('?').next().unwrap_or(&rec.target_url));
                    if ui.selectable_label(is_selected, label).clicked() {
                        let pos = self.history.iter().position(|r| r.id == rec.id).unwrap_or(0);
                        self.selected_history = Some(pos);
                    }
                }
            });
        });

        // ── Central panel ───────────────────────────────────────────────
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

            ui.horizontal(|ui| {
                card(ui, "Duration", &format!("{:.1}s", rec.duration.as_secs_f32()));
                card(ui, "Probes", &format!("{}", rec.probes_sent));
                card(ui, "Hits", &format!("{}", rec.hits));
                card(ui, "Confirmed", &format!("{}", rec.confirmed));
                card(ui, "Corpus", &format!("{}", rec.corpus_size));
                card(ui, "gen_ratio", &format!("{:.2}", rec.gen_ratio));
                card(ui, "RNG seed", &format!("{:?}", rec.rng_seed));
            });

            ui.separator();
            ui.heading("Signal distribution");
            let total: usize = rec.signal_counts.iter().map(|(_, c)| c).sum();
            ui.horizontal(|ui| {
                for (sig, count) in &rec.signal_counts {
                    let pct = if total > 0 { *count as f32 / total as f32 } else { 0.0 };
                    ui.vertical(|ui| {
                        ui.label(sig);
                        ui.add(egui::ProgressBar::new(pct).desired_width(60.0).text(format!("{}", count)));
                    });
                }
            });

            ui.separator();
            let confirmed_count = rec.hits_detail.iter().filter(|h| h.confirmed).count();
            ui.heading(format!("Hits — {} total, {} confirmed", rec.hits_detail.len(), confirmed_count));

            egui::ScrollArea::vertical().show(ui, |ui| {
                egui::Grid::new("hits").striped(true).show(ui, |ui| {
                    ui.strong("#"); ui.strong("Payload"); ui.strong("Score"); ui.strong("Signals");
                    ui.end_row();
                    for (i, h) in rec.hits_detail.iter().enumerate() {
                        let color = if h.confirmed { egui::Color32::from_rgb(80, 220, 80) }
                            else { egui::Color32::from_rgb(220, 200, 60) };
                        ui.colored_label(color, format!("{}", i + 1));
                        ui.label(&h.payload);
                        ui.label(format!("{}", h.score));
                        ui.label(h.signals.join(", "));
                        ui.end_row();
                    }
                });
            });
        });

        if needs_repaint {
            ctx.request_repaint();
        }
    }
}

fn card(ui: &mut egui::Ui, label: &str, value: &str) {
    egui::Frame::none().corner_radius(6.0).fill(ui.style().visuals.extreme_bg_color)
        .show(ui, |ui| {
            ui.vertical(|ui| {
                ui.label(egui::RichText::new(label).weak().size(10.0));
                ui.label(egui::RichText::new(value).strong().size(16.0));
            });
        });
}

fn main() -> eframe::Result {
    eframe::run_native("auto-fuzz workbench",
        eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default()
                .with_inner_size([1100.0, 700.0])
                .with_title("auto-fuzz workbench"),
            ..Default::default()
        },
        Box::new(|_cc| Ok(Box::new(App::default()))),
    )
}
