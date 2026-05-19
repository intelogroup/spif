use crate::types::*;
use chrono::{DateTime, TimeZone, Utc};

pub struct SPIFRenderer;

impl SPIFRenderer {
    pub fn new() -> Self {
        Self
    }

    fn conf_bar(&self, d: &Distribution, width: usize) -> String {
        // Clamp mean to [0, 1] so out-of-range values don't cause underflow panics.
        let clamped = d.mean.clamp(0.0, 1.0);
        let filled = (clamped * (width as f64)).round() as usize;
        let filled = filled.min(width);
        let bar = format!("{}{}", "█".repeat(filled), "░".repeat(width - filled));
        let pct = format!("{:.0}%", d.mean * 100.0);
        format!("[{}] {}  [{}]", bar, pct, d.semantics)
    }

    fn render_value(&self, v: &ciborium::value::Value) -> String {
        match v {
            ciborium::value::Value::Text(t) => t.clone(),
            ciborium::value::Value::Bytes(b) => format!("<binary {} bytes>", b.len()),
            ciborium::value::Value::Tag(tag, val) => {
                if *tag == TAG_NODEREF {
                    if let ciborium::value::Value::Text(id) = val.as_ref() {
                        return format!("→ {}", id);
                    }
                }
                format!("Tag({}: {:?})", tag, val)
            }
            _ => format!("{:?}", v),
        }
    }

    fn render_node(&self, n: &Node, indent: usize) -> String {
        let pad = "  ".repeat(indent);
        let mut lines = vec![
            format!("{}[{}] id={}", pad, n.node_type.to_uppercase(), n.id),
            format!("{}  value:      {}", pad, self.render_value(&n.value)),
            format!("{}  confidence: {}", pad, self.conf_bar(&n.confidence, 12)),
        ];
        if !n.refs.is_empty() {
            lines.push(format!("{}  refs:       {}", pad, n.refs.join(", ")));
        }
        lines.join("\n")
    }

    fn render_step(&self, s: &TraceStep, indent: usize) -> String {
        let pad = "  ".repeat(indent);
        let mut lines = vec![
            format!("{}[{}] id={}", pad, s.step_type.to_uppercase(), s.id),
            format!("{}  content:    {}", pad, self.render_value(&s.content)),
            format!("{}  confidence: {}", pad, self.conf_bar(&s.confidence, 12)),
        ];
        if !s.deps.is_empty() {
            lines.push(format!("{}  depends on: {}", pad, s.deps.join(", ")));
        }
        lines.join("\n")
    }

    pub fn render(&self, doc: &SPIFDocument) -> String {
        let mut sections = Vec::new();

        sections.push("═".repeat(60));
        sections.push("  SPIF DOCUMENT (Rust Viewer)  v0.2".to_string());
        sections.push("═".repeat(60));

        if let Some(ref sig) = doc.signature {
            sections.push(format!(
                "\nSIGNATURE\n  algorithm: {}\n  signer:    {}\n  status:    present",
                sig.algorithm, sig.signer
            ));
        } else {
            sections.push("\nSIGNATURE  unsigned".to_string());
        }

        if let Some(ref p) = doc.provenance {
            // Cast to i64 safely; fall back to epoch on overflow/out-of-range.
            let ts_ms = i64::try_from(p.timestamp_ms).unwrap_or(i64::MAX);
            let dt: DateTime<Utc> = Utc
                .timestamp_millis_opt(ts_ms)
                .single()
                .unwrap_or_else(|| DateTime::from_timestamp(0, 0).unwrap());
            sections.push(format!(
                "\nPROVENANCE\n  model:       {} {}\n  created:     {}\n  temperature: {}",
                p.source_model,
                p.model_version,
                dt.format("%Y-%m-%d %H:%M:%S UTC"),
                p.temperature
            ));
        }

        sections.push(format!("\nPAYLOAD  ({} nodes)", doc.payload.len()));
        sections.push("─".repeat(60));
        for n in &doc.payload {
            sections.push(self.render_node(n, 0));
        }

        if !doc.trace.is_empty() {
            sections.push(format!(
                "\nREASONING TRACE  ({} steps)\n  method: {}",
                doc.trace.len(),
                doc.trace_method
            ));
            sections.push("─".repeat(60));
            // Simple depth-based rendering (not building full DAG indent yet for speed)
            for s in &doc.trace {
                sections.push(self.render_step(s, 0));
            }
        }

        sections.push("\n".to_string() + &"═".repeat(60));
        sections.join("\n")
    }
}
