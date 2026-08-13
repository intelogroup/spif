//! Incremental cycle detection for streaming trace DAGs.
//!
//! `validate_trace_dag` (reader.rs) runs Kahn's algorithm once, after the
//! whole document is assembled — a bad edge at step 1 is only reported after
//! step N arrives. This checker detects the cycle the moment the offending
//! edge shows up, so a long-running agent loop can abort early instead of
//! paying for the rest of the stream.
//!
//! Method: on each new step, add it as a node, wire up any deps that have
//! already arrived (and resolve deps that arrived out of order via a
//! pending-forward-edge table), then DFS forward from the new node. If the
//! DFS revisits the new node, a cycle closed right here.
//!
//! ponytail: DFS-from-new-node is O(V+E) worst case per insert (adversarial
//! wide fan-in), same asymptotic class as the batch algorithm — the win is
//! wall-clock-to-detection, not big-O. A Pearce-Kelly incremental topo-order
//! would give O(1) amortized; add it only if the naive version is measured
//! to be a real bottleneck on realistic traces.

use anyhow::{anyhow, Result};
use std::collections::{HashMap, HashSet};

#[derive(Default)]
pub struct IncrementalDagChecker {
    /// dep_id -> ids of steps that declared a dependency on dep_id
    dependents: HashMap<String, Vec<String>>,
    /// all step ids seen so far
    known: HashSet<String>,
    /// deps declared by each step (kept for dangling-ref checks at input time)
    deps_of: HashMap<String, Vec<String>>,
}

impl IncrementalDagChecker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a step. Returns Err immediately if this step closes a cycle.
    /// Deps that haven't arrived yet are allowed (forward references) and
    /// wired up lazily; a truly dangling dep is only knowable at the end of
    /// stream, so that check stays in the batch validator.
    pub fn add_step(&mut self, id: &str, deps: &[String]) -> Result<()> {
        if !self.known.insert(id.to_string()) {
            return Err(anyhow!("Duplicate TraceStep id: '{id}'"));
        }
        self.deps_of.insert(id.to_string(), deps.to_vec());
        for dep in deps {
            self.dependents
                .entry(dep.clone())
                .or_default()
                .push(id.to_string());
        }

        // DFS forward from `id` through the dependents graph. If we reach
        // `id` again, the edges we just added closed a cycle.
        let mut stack: Vec<String> = self
            .dependents
            .get(id)
            .cloned()
            .unwrap_or_default();
        let mut visited: HashSet<String> = HashSet::new();
        while let Some(node) = stack.pop() {
            if node == id {
                return Err(anyhow!(
                    "Cycle detected in trace DAG: step '{id}' reaches itself via '{node}'"
                ));
            }
            if !visited.insert(node.clone()) {
                continue;
            }
            if let Some(children) = self.dependents.get(&node) {
                stack.extend(children.iter().cloned());
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_immediate_two_cycle() {
        let mut c = IncrementalDagChecker::new();
        c.add_step("a", &["b".to_string()]).unwrap(); // forward ref, allowed
        let err = c.add_step("b", &["a".to_string()]).unwrap_err();
        assert!(err.to_string().contains("Cycle detected"));
    }

    #[test]
    fn allows_linear_chain() {
        let mut c = IncrementalDagChecker::new();
        c.add_step("s0", &[]).unwrap();
        for i in 1..1000 {
            c.add_step(&format!("s{i}"), &[format!("s{}", i - 1)])
                .unwrap();
        }
    }

    #[test]
    fn rejects_duplicate_id() {
        let mut c = IncrementalDagChecker::new();
        c.add_step("a", &[]).unwrap();
        let err = c.add_step("a", &[]).unwrap_err();
        assert!(err.to_string().contains("Duplicate"));
    }

    #[test]
    fn detects_long_range_cycle_at_close_point() {
        let mut c = IncrementalDagChecker::new();
        // s0 forward-references the node that will close the loop 5000 steps later.
        c.add_step("s0", &["s4999".to_string()]).unwrap();
        for i in 1..4999 {
            c.add_step(&format!("s{i}"), &[format!("s{}", i - 1)])
                .unwrap();
        }
        // s4999 depends on s4998, which transitively depends back on s0,
        // which itself depends on s4999 — cycle closes right here, not at
        // stream end.
        let err = c.add_step("s4999", &["s4998".to_string()]).unwrap_err();
        assert!(err.to_string().contains("Cycle detected"));
    }

    // ---------------------------------------------------------------
    // Edge cases
    // ---------------------------------------------------------------

    #[test]
    fn rejects_self_loop() {
        let mut c = IncrementalDagChecker::new();
        let err = c.add_step("a", &["a".to_string()]).unwrap_err();
        assert!(err.to_string().contains("Cycle detected"), "{err}");
    }

    #[test]
    fn allows_diamond_no_false_positive() {
        // a -> b, a -> c, b -> d, c -> d  (not a cycle)
        let mut c = IncrementalDagChecker::new();
        c.add_step("a", &[]).unwrap();
        c.add_step("b", &["a".to_string()]).unwrap();
        c.add_step("c", &["a".to_string()]).unwrap();
        c.add_step("d", &["b".to_string(), "c".to_string()])
            .unwrap();
    }

    #[test]
    fn allows_disconnected_components() {
        let mut c = IncrementalDagChecker::new();
        c.add_step("a1", &[]).unwrap();
        c.add_step("a2", &["a1".to_string()]).unwrap();
        c.add_step("b1", &[]).unwrap();
        c.add_step("b2", &["b1".to_string()]).unwrap();
        // cross-link that doesn't close anything
        c.add_step("a3", &["a2".to_string(), "b1".to_string()])
            .unwrap();
    }

    #[test]
    fn empty_stream_is_fine() {
        let c = IncrementalDagChecker::new();
        drop(c); // no steps added, nothing to check
    }

    #[test]
    fn single_step_no_deps() {
        let mut c = IncrementalDagChecker::new();
        c.add_step("only", &[]).unwrap();
    }

    #[test]
    fn detects_three_cycle() {
        let mut c = IncrementalDagChecker::new();
        c.add_step("a", &["c".to_string()]).unwrap(); // forward ref
        c.add_step("b", &["a".to_string()]).unwrap();
        let err = c.add_step("c", &["b".to_string()]).unwrap_err();
        assert!(err.to_string().contains("Cycle detected"));
    }

    #[test]
    fn duplicate_dep_in_same_step_does_not_false_positive() {
        // a step listing the same dep twice shouldn't be treated as a cycle
        let mut c = IncrementalDagChecker::new();
        c.add_step("a", &[]).unwrap();
        c.add_step("b", &["a".to_string(), "a".to_string()])
            .unwrap();
    }

    #[test]
    fn unicode_ids() {
        let mut c = IncrementalDagChecker::new();
        c.add_step("步骤-1", &[]).unwrap();
        c.add_step("étape_2", &["步骤-1".to_string()]).unwrap();
        // re-adding the same unicode id is a duplicate, not a cycle
        let err = c.add_step("步骤-1", &[]).unwrap_err();
        assert!(err.to_string().contains("Duplicate"));
    }

    #[test]
    fn cycle_error_names_involved_step() {
        let mut c = IncrementalDagChecker::new();
        c.add_step("x", &["y".to_string()]).unwrap();
        let err = c.add_step("y", &["x".to_string()]).unwrap_err();
        assert!(err.to_string().contains('y'), "{err}");
    }

    // ---------------------------------------------------------------
    // Stress / adversarial
    // ---------------------------------------------------------------

    /// Star graph: every node depends directly on the hub. Adversarial for
    /// a naive "DFS from new node" approach if it re-walked the whole
    /// dependents list on every insert — here it's cheap because only the
    /// hub has any dependents, and each new leaf's own dependents list is
    /// empty, so DFS from a fresh leaf is O(1) per insert.
    #[test]
    fn star_fan_out_from_hub_stays_fast() {
        let mut c = IncrementalDagChecker::new();
        c.add_step("hub", &[]).unwrap();
        let start = std::time::Instant::now();
        for i in 0..20_000 {
            c.add_step(&format!("leaf{i}"), &["hub".to_string()])
                .unwrap();
        }
        let elapsed = start.elapsed();
        assert!(
            elapsed.as_millis() < 2_000,
            "star fan-out took too long: {elapsed:?}"
        );
    }

    /// Adversarial dense DAG: node i depends on ALL previous nodes. This is
    /// the true worst case for DFS-from-new-node since dependents fan-in
    /// grows every insert — confirms it degrades gracefully (bounded
    /// polynomial, no infinite loop / no exponential blowup) rather than
    /// checking a specific complexity class.
    #[test]
    fn dense_all_previous_deps_terminates_reasonably() {
        let mut c = IncrementalDagChecker::new();
        let n = 1_500;
        c.add_step("s0", &[]).unwrap();
        let start = std::time::Instant::now();
        for i in 1..n {
            let deps: Vec<String> = (0..i).map(|j| format!("s{j}")).collect();
            c.add_step(&format!("s{i}"), &deps).unwrap();
        }
        let elapsed = start.elapsed();
        assert!(
            elapsed.as_secs() < 10,
            "dense DAG insert blew up: {elapsed:?}"
        );
    }

    /// Wide adversarial cycle: hub has 10k forward-ref dependents, and the
    /// LAST one closes a cycle back to the hub. Confirms the DFS actually
    /// walks the full wide frontier before concluding "no cycle" on every
    /// prior insert (no shortcutting that would miss a late-arriving edge),
    /// and still catches the true cycle when it lands.
    #[test]
    fn wide_frontier_cycle_still_caught() {
        let mut c = IncrementalDagChecker::new();
        c.add_step("hub", &["closer".to_string()]).unwrap(); // forward ref
        for i in 0..10_000 {
            c.add_step(&format!("leaf{i}"), &["hub".to_string()])
                .unwrap();
        }
        let err = c.add_step("closer", &["hub".to_string()]).unwrap_err();
        assert!(err.to_string().contains("Cycle detected"));
    }

    /// No stack overflow on a very deep linear chain — the DFS is
    /// iterative (explicit Vec stack), not recursive, so depth shouldn't
    /// blow the call stack the way a naive recursive DFS would.
    #[test]
    fn deep_chain_no_stack_overflow() {
        let mut c = IncrementalDagChecker::new();
        c.add_step("s0", &[]).unwrap();
        for i in 1..200_000 {
            c.add_step(&format!("s{i}"), &[format!("s{}", i - 1)])
                .unwrap();
        }
    }
}
