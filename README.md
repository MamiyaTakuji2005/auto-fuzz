# auto-fuzz

Evolutionary web fuzzer. Atom-chain generation + havoc mutation, driven by response signal feedback.

Extracted from [re:Vise](https://github.com/MamiyaTakuji2005/re-Vise).

## How it works

Each iteration: build a payload from atoms (generation), mutate an existing one (havoc), send it to the target, classify the response. Interesting responses get more energy. Boring ones get less. No fixed payload lists — the engine discovers them.

## Usage

```rust
let result = Fuzzer::new(my_probe)
    .sql_injection()
    .target("https://example.com/search?q=", "GET")
    .budget(100)
    .run()
    .await
    .unwrap();
```

Presets exist for SQLi, XSS, SSTI, CMDi, SSRF, path traversal, NoSQLi, XXE, URL redirect. Each wires up the right classifiers and chain weights.

Three modes: evolutionary (generate + mutate from scratch), table (sweep a fixed list), table-then-evolutionary (sweep first, evolve from hits).

## Running

```bash
cargo run --example report --release   # benchmarks
cargo run --bin calibrate --release    # parameter sweep from targets.toml
```

### Calibration

Edit `targets.toml` to define mock targets — each entry specifies trigger conditions and simulated responses:

```toml
[[targets]]
name = "sqli"
trigger_payload = "42'; DROP TABLE users--"
baseline_url = "http://mock/?q=1"

[targets.response]
triggers = ["42", "' OR"]
trigger_status = 500
trigger_body = "SQL error near '{{payload}}'"
```

Add a new target by copying a block. No Rust changes needed.

Run: `cargo run --bin calibrate --release -- targets.toml`

Full calibration notes at `stuff/README.md`.

## License

MIT
