//! Benchmark: incremental cycle detection vs post-assembly detection.
//!
//! Builds an N-node linear chain with a cycle spliced at start/middle/end,
//! feeds it two ways:
//!   1. Old path: full doc assembled, batch Kahn's check at the end.
//!   2. New path: PARTIAL_STEP chunks streamed one at a time, incremental
//!      DFS check fires the moment the bad edge lands.
//!
//! Reports: time-to-detection for each, and the overhead the incremental
//! check adds on a clean (acyclic) stream of the same size.
//!
//! Run: cargo run --release --example incremental_cycle_bench

use spif_rust::incremental_dag::IncrementalDagChecker;
use spif_rust::reader::SPIFReader;
use spif_rust::types::*;
use spif_rust::writer::SPIFWriter;
use std::time::Instant;

/// Builds a linear chain s0 -> s1 -> ... -> s(n-1). If `cycle_at` is set,
/// node `cycle_at` forward-references node `cycle_at + WINDOW` (wrapped to
/// stay in range), so the cycle closes WINDOW steps later — not always at
/// the tail. This is what lets the benchmark show detection latency scaling
/// with how far the closing edge is from the splice point, not just with N.
const WINDOW: usize = 20;

fn linear_steps(n: usize, cycle_at: Option<usize>) -> Vec<TraceStep> {
    let closer = cycle_at.map(|c| (c + WINDOW).min(n - 1));
    let mut steps = Vec::with_capacity(n);
    steps.push(TraceStep {
        id: "s0".into(),
        step_type: "evidence".into(),
        content: Value::Text("root".into()),
        confidence: Distribution::certain("logical"),
        deps: vec![],
        alternatives: vec![],
    });
    for i in 1..n {
        let mut deps = vec![format!("s{}", i - 1)];
        if Some(i) == cycle_at {
            // forward-reference the node that will close the loop
            deps.push(format!("s{}", closer.unwrap()));
        }
        steps.push(TraceStep {
            id: format!("s{i}"),
            step_type: "inference".into(),
            content: Value::Text("x".into()),
            confidence: Distribution::certain("logical"),
            deps,
            alternatives: vec![],
        });
    }
    steps
}

fn bench_batch(n: usize, cycle_at: usize) -> (bool, std::time::Duration) {
    let steps = linear_steps(n, Some(cycle_at));
    let doc = SPIFDocument {
        payload: vec![Node {
            id: "n1".into(),
            node_type: "fact".into(),
            value: Value::Text("v".into()),
            confidence: Distribution::certain("logical"),
            refs: vec![],
        }],
        provenance: None,
        semantic: None,
        trace: steps,
        trace_method: "reasoning".into(),
        alternatives: vec![],
        delta: None,
        signature: None,
        signatures: vec![],
        task_info: None,
    };
    let bytes = SPIFWriter::new().encode(&doc).unwrap();
    let start = Instant::now();
    let result = SPIFReader::default().read(&bytes);
    let elapsed = start.elapsed();
    (result.is_err(), elapsed)
}

fn bench_incremental(n: usize, cycle_at: usize) -> (bool, std::time::Duration, usize) {
    let steps = linear_steps(n, Some(cycle_at));
    let mut checker = IncrementalDagChecker::new();
    let start = Instant::now();
    let mut detected = false;
    let mut steps_seen = 0;
    for s in &steps {
        steps_seen += 1;
        if checker.add_step(&s.id, &s.deps).is_err() {
            detected = true;
            break;
        }
    }
    let elapsed = start.elapsed();
    (detected, elapsed, steps_seen)
}

fn bench_clean_overhead(n: usize) -> (std::time::Duration, std::time::Duration) {
    let steps = linear_steps(n, None);

    // batch
    let doc = SPIFDocument {
        payload: vec![Node {
            id: "n1".into(),
            node_type: "fact".into(),
            value: Value::Text("v".into()),
            confidence: Distribution::certain("logical"),
            refs: vec![],
        }],
        provenance: None,
        semantic: None,
        trace: steps.clone(),
        trace_method: "reasoning".into(),
        alternatives: vec![],
        delta: None,
        signature: None,
        signatures: vec![],
        task_info: None,
    };
    let bytes = SPIFWriter::new().encode(&doc).unwrap();
    let start = Instant::now();
    SPIFReader::default().read(&bytes).unwrap();
    let batch = start.elapsed();

    // incremental
    let mut checker = IncrementalDagChecker::new();
    let start = Instant::now();
    for s in &steps {
        checker.add_step(&s.id, &s.deps).unwrap();
    }
    let incr = start.elapsed();

    (batch, incr)
}

fn main() {
    println!("=== Incremental vs batch cycle detection ===\n");

    for &n in &[1_000usize, 10_000, 50_000] {
        for &pos_name in &["start", "middle", "end"] {
            let cycle_at = match pos_name {
                "start" => 10.min(n - 1),
                "middle" => n / 2,
                _ => n.saturating_sub(WINDOW + 1).max(1),
            };

            let (batch_ok, batch_t) = bench_batch(n, cycle_at);
            let (incr_ok, incr_t, steps_seen) = bench_incremental(n, cycle_at);

            println!(
                "N={n:>6} cycle@{pos_name:<6} batch(decode+validate): detected={batch_ok} time={batch_t:>10.2?} (reads all {n} steps first)  |  incremental(dag-only): detected={incr_ok} time={incr_t:>10.2?} (aborted after {steps_seen}/{n} steps)"
            );
        }
    }

    println!("\n=== Overhead of incremental checking on a clean (acyclic) stream ===");
    for &n in &[1_000usize, 10_000, 50_000] {
        let (batch, incr) = bench_clean_overhead(n);
        let ratio = incr.as_secs_f64() / batch.as_secs_f64();
        println!("N={n:>6}  batch(full decode+validate)={batch:>10.2?}  incremental(dag-only)={incr:>10.2?}  ratio={ratio:.2}x");
    }

    println!("\n=== Adversarial: dense DAG, node i depends on ALL previous nodes ===");
    for &n in &[500usize, 1_000, 1_500, 2_000] {
        let mut c = IncrementalDagChecker::new();
        c.add_step("s0", &[]).unwrap();
        let start = Instant::now();
        for i in 1..n {
            let deps: Vec<String> = (0..i).map(|j| format!("s{j}")).collect();
            c.add_step(&format!("s{i}"), &deps).unwrap();
        }
        let elapsed = start.elapsed();
        println!("N={n:>6}  time={elapsed:>10.2?}");
    }

    println!("\n=== Adversarial: star fan-out, 50k leaves all depending on one hub ===");
    {
        let mut c = IncrementalDagChecker::new();
        c.add_step("hub", &[]).unwrap();
        let start = Instant::now();
        for i in 0..50_000 {
            c.add_step(&format!("leaf{i}"), &["hub".to_string()])
                .unwrap();
        }
        let elapsed = start.elapsed();
        println!("50k leaves: time={elapsed:>10.2?}");
    }
}
