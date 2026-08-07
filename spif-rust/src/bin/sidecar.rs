use std::collections::HashSet;
use std::env;
use std::fs;
use std::io::Read;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::Serialize;
use serde_json::Value as JsonValue;

use spif_rust::reader::SPIFReader;
use spif_rust::writer::SPIFWriter;
use spif_rust::types::{Distribution, Node, Provenance, SPIFDocument};

// ---------------------------------------------------------------------------
// Structures & Enums
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct CRLClient {
    url: Option<String>,
    cache_ttl: Duration,
    state: Arc<RwLock<CRLState>>,
}

struct CRLState {
    revoked_keys: HashSet<String>,
    last_fetch: Option<Instant>,
}

struct PolicyEvaluator {
    policy: Option<JsonValue>,
    keystore_dir: Option<PathBuf>,
    crl_client: Option<CRLClient>,
}

#[derive(Serialize)]
struct ValidationResult {
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    failure_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    failure_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    document_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    provenance: Option<Provenance>,
}

// ---------------------------------------------------------------------------
// Key Slugify Helper
// ---------------------------------------------------------------------------

fn key_slug(key_id: &str) -> String {
    let mut slug = String::new();
    for c in key_id.chars() {
        if c.is_alphanumeric() || c == '-' || c == '_' || c == '~' || c == '.' {
            slug.push(c);
        } else {
            slug.push_str(&format!("%{:02X}", c as u8));
        }
    }
    slug
}

// ---------------------------------------------------------------------------
// CRL Client Implementation
// ---------------------------------------------------------------------------

impl CRLClient {
    fn new(url: Option<String>, cache_ttl_secs: u64) -> Self {
        Self {
            url,
            cache_ttl: Duration::from_secs(cache_ttl_secs),
            state: Arc::new(RwLock::new(CRLState {
                revoked_keys: HashSet::new(),
                last_fetch: None,
            })),
        }
    }

    fn get_revoked_keys(&self) -> HashSet<String> {
        let url = match &self.url {
            Some(u) => u,
            None => return HashSet::new(),
        };

        let now = Instant::now();
        let should_fetch = {
            let r = self.state.read().unwrap();
            match r.last_fetch {
                Some(lf) => now.duration_since(lf) > self.cache_ttl,
                None => true,
            }
        };

        if should_fetch {
            match self.fetch_crl(url) {
                Ok(keys) => {
                    let mut w = self.state.write().unwrap();
                    w.revoked_keys = keys;
                    w.last_fetch = Some(now);
                }
                Err(e) => {
                    eprintln!("[WARN] Failed to fetch CRL: {e}. Using cached list.");
                }
            }
        }

        self.state.read().unwrap().revoked_keys.clone()
    }

    fn fetch_crl(&self, url: &str) -> Result<HashSet<String>> {
        println!("[INFO] Fetching CRL from {}", url);
        let resp = ureq::get(url)
            .set("User-Agent", "SPIF-Sidecar/1.1-Rust")
            .timeout(Duration::from_secs(10))
            .call()?;
        
        let content = resp.into_string()?;
        self.parse_crl(&content)
    }

    fn parse_crl(&self, content: &str) -> Result<HashSet<String>> {
        let mut keys = HashSet::new();
        if let Ok(json_val) = serde_json::from_str::<JsonValue>(content) {
            if let Some(obj) = json_val.as_object() {
                if let Some(revoked) = obj.get("revoked").and_then(|v| v.as_object()) {
                    for k in revoked.keys() {
                        keys.insert(k.clone());
                    }
                } else {
                    for k in obj.keys() {
                        keys.insert(k.clone());
                    }
                }
            } else if let Some(arr) = json_val.as_array() {
                for v in arr {
                    if let Some(s) = v.as_str() {
                        keys.insert(s.to_string());
                    }
                }
            }
        } else {
            for line in content.lines() {
                let trimmed = line.trim();
                if !trimmed.is_empty() && !trimmed.starts_with('#') {
                    keys.insert(trimmed.to_string());
                }
            }
        }
        println!("[INFO] Parsed {} revoked keys", keys.len());
        Ok(keys)
    }
}

// ---------------------------------------------------------------------------
// JSON to CBOR Value Converter
// ---------------------------------------------------------------------------

fn json_to_ciborium(v: &serde_json::Value) -> ciborium::value::Value {
    use ciborium::value::Value as CborValue;
    match v {
        serde_json::Value::Null => CborValue::Null,
        serde_json::Value::Bool(b) => CborValue::Bool(*b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                CborValue::Integer(i.into())
            } else if let Some(u) = n.as_u64() {
                CborValue::Integer(u.into())
            } else {
                CborValue::Float(n.as_f64().unwrap_or(0.0))
            }
        }
        serde_json::Value::String(s) => CborValue::Text(s.clone()),
        serde_json::Value::Array(arr) => {
            CborValue::Array(arr.iter().map(json_to_ciborium).collect())
        }
        serde_json::Value::Object(obj) => {
            CborValue::Map(obj.iter().map(|(k, v)| {
                (CborValue::Text(k.clone()), json_to_ciborium(v))
            }).collect())
        }
    }
}

// ---------------------------------------------------------------------------
// Canonical content_id Calculation
// ---------------------------------------------------------------------------

fn compute_content_id(doc: &SPIFDocument) -> String {
    use ciborium::value::Value;
    use sha2::{Digest, Sha256};

    let mut prov_val = Value::Null;
    if let Some(p) = &doc.provenance {
        let mut map = Vec::new();
        map.push((Value::Text("source_model".to_string()), Value::Text(p.source_model.clone())));
        map.push((Value::Text("model_version".to_string()), Value::Text(p.model_version.clone())));
        map.push((Value::Text("temperature".to_string()), Value::Float(p.temperature)));
        map.push((Value::Text("input_hash".to_string()), Value::Text(p.input_hash.clone())));
        map.push((Value::Text("context_ref".to_string()), Value::Text(p.context_ref.clone())));
        map.push((Value::Text("timestamp_ms".to_string()), Value::Integer(p.timestamp_ms.into())));
        map.push((Value::Text("attempt".to_string()), Value::Integer(p.attempt.into())));
        map.push((Value::Text("task_id".to_string()), Value::Text(p.task_id.clone())));
        map.push((Value::Text("risk_tier".to_string()), Value::Text(p.risk_tier.clone())));
        map.push((Value::Text("model_card".to_string()), Value::Text(p.model_card.clone())));
        prov_val = Value::Map(map);
    }

    let encode_dist = |d: &Distribution| -> Value {
        let mut map = Vec::new();
        map.push((Value::Text("mean".to_string()), Value::Float(d.mean)));
        map.push((Value::Text("var".to_string()), Value::Float(d.var)));
        map.push((Value::Text("shape".to_string()), Value::Text(d.shape.clone())));
        map.push((Value::Text("semantics".to_string()), Value::Text(d.semantics.clone())));
        if let Some(p5) = d.p5 {
            map.push((Value::Text("p5".to_string()), Value::Float(p5)));
        }
        if let Some(p95) = d.p95 {
            map.push((Value::Text("p95".to_string()), Value::Float(p95)));
        }
        Value::Tag(1000, Box::new(Value::Map(map)))
    };

    let mut payload_list = Vec::new();
    for node in &doc.payload {
        let mut map = Vec::new();
        map.push((Value::Text("id".to_string()), Value::Text(node.id.clone())));
        map.push((Value::Text("type".to_string()), Value::Text(node.node_type.clone())));
        map.push((Value::Text("value".to_string()), node.value.clone()));
        map.push((Value::Text("confidence".to_string()), encode_dist(&node.confidence)));
        
        let refs_list: Vec<Value> = node.refs.iter()
            .map(|r| Value::Tag(1001, Box::new(Value::Text(r.clone()))))
            .collect();
        map.push((Value::Text("refs".to_string()), Value::Array(refs_list)));
        payload_list.push(Value::Map(map));
    }

    let mut trace_list = Vec::new();
    for step in &doc.trace {
        let mut map = Vec::new();
        map.push((Value::Text("id".to_string()), Value::Text(step.id.clone())));
        map.push((Value::Text("type".to_string()), Value::Text(step.step_type.clone())));
        map.push((Value::Text("content".to_string()), step.content.clone()));
        map.push((Value::Text("confidence".to_string()), encode_dist(&step.confidence)));
        
        let deps_list: Vec<Value> = step.deps.iter()
            .map(|d| Value::Text(d.clone()))
            .collect();
        map.push((Value::Text("deps".to_string()), Value::Array(deps_list)));

        let alts_list: Vec<Value> = step.alternatives.iter()
            .map(|a| a.clone())
            .collect();
        map.push((Value::Text("alternatives".to_string()), Value::Array(alts_list)));
        trace_list.push(Value::Map(map));
    }

    let mut final_map = Vec::new();
    final_map.push((Value::Text("payload".to_string()), Value::Array(payload_list)));
    final_map.push((Value::Text("trace".to_string()), Value::Array(trace_list)));
    final_map.push((Value::Text("provenance".to_string()), prov_val));

    let final_val = Value::Map(final_map);
    let mut encoded = Vec::new();
    ciborium::ser::into_writer(&final_val, &mut encoded).unwrap();

    let mut hasher = Sha256::new();
    hasher.update(&encoded);
    hex::encode(hasher.finalize())
}

// ---------------------------------------------------------------------------
// Policy Evaluator Implementation
// ---------------------------------------------------------------------------

impl PolicyEvaluator {
    fn new(
        policy_path: Option<&Path>,
        keystore_dir: Option<PathBuf>,
        crl_client: Option<CRLClient>,
    ) -> Self {
        let policy = policy_path.and_then(|p| {
            if p.exists() {
                let s = fs::read_to_string(p).ok()?;
                serde_json::from_str::<JsonValue>(&s).ok()
            } else {
                None
            }
        });

        Self {
            policy,
            keystore_dir,
            crl_client,
        }
    }

    fn validate_document(&self, raw_bytes: &[u8]) -> ValidationResult {
        let reader = SPIFReader::new();
        let doc = match reader.read(raw_bytes) {
            Ok(d) => d,
            Err(e) => {
                let err_str = e.to_string();
                let code = if err_str.contains("Checksum") {
                    "SPIF_ERROR_TAMPERED"
                } else {
                    "SPIF_ERROR_FORMAT"
                };
                return ValidationResult {
                    status: "invalid".to_string(),
                    failure_code: Some(code.to_string()),
                    failure_reason: Some(format!("SPIF decoding error: {}", err_str)),
                    document_id: None,
                    provenance: None,
                };
            }
        };

        let provenance = doc.provenance.clone();
        let model_id = doc.provenance.as_ref().map(|p| p.source_model.clone()).unwrap_or_default();

        let mut signatures = doc.signatures.clone();
        if let Some(sig) = &doc.signature {
            signatures.push(sig.clone());
        }

        let signer_id = signatures.first().map(|s| s.signer.clone()).unwrap_or_default();

        let require_sig = self.policy.as_ref()
            .and_then(|p| p.get("enforcement").and_then(|e| e.as_str()))
            .map(|e| e == "deny_and_alert")
            .unwrap_or(false) || self.keystore_dir.is_some();

        if require_sig && signatures.is_empty() {
            return ValidationResult {
                status: "invalid".to_string(),
                failure_code: Some("SPIF_ERROR_UNSIGNED".to_string()),
                failure_reason: Some("Signature required by policy, but none present".to_string()),
                document_id: None,
                provenance,
            };
        }

        if !signatures.is_empty() {
            if let Some(ks_dir) = &self.keystore_dir {
                for sig in &signatures {
                    let slug = key_slug(&sig.signer);
                    let pub_file = ks_dir.join(format!("{}.pub", slug));
                    if !pub_file.exists() {
                        return ValidationResult {
                            status: "invalid".to_string(),
                            failure_code: Some("SPIF_ERROR_UNTRUSTED".to_string()),
                            failure_reason: Some(format!("No public key for signer '{}' in keystore", sig.signer)),
                            document_id: None,
                            provenance,
                        };
                    }

                    if let Ok(keystore_bytes) = fs::read(pub_file) {
                        if let Ok(signer_bytes) = STANDARD.decode(&sig.signer) {
                            if signer_bytes != keystore_bytes {
                                return ValidationResult {
                                    status: "invalid".to_string(),
                                    failure_code: Some("SPIF_ERROR_SIGNATURE_INVALID".to_string()),
                                    failure_reason: Some("Keystore public key mismatch".to_string()),
                                    document_id: None,
                                    provenance,
                                };
                            }
                        }
                    }
                }
            }
        }

        let crl_enabled = self.policy.as_ref()
            .and_then(|p| p.get("crl_check").and_then(|c| c.get("enabled")).and_then(|e| e.as_bool()))
            .unwrap_or(false);

        if crl_enabled {
            if let Some(client) = &self.crl_client {
                let revoked = client.get_revoked_keys();
                for sig in &signatures {
                    if revoked.contains(&sig.signer) {
                        return ValidationResult {
                            status: "invalid".to_string(),
                            failure_code: Some("SPIF_ERROR_KEY_REVOKED".to_string()),
                            failure_reason: Some(format!(
                                "Signing key '{}...' is revoked in the active CRL",
                                if sig.signer.len() > 16 { &sig.signer[..16] } else { &sig.signer }
                            )),
                            document_id: None,
                            provenance,
                        };
                    }
                }
            }
        }

        if let Some(policy) = &self.policy {
            if let Some(allowed) = policy.get("allowed_models").and_then(|a| a.as_array()) {
                let allowed_set: HashSet<&str> = allowed.iter().filter_map(|v| v.as_str()).collect();
                if !allowed_set.contains(model_id.as_str()) {
                    return ValidationResult {
                        status: "invalid".to_string(),
                        failure_code: Some("SPIF_ERROR_POLICY_VIOLATION".to_string()),
                        failure_reason: Some(format!(
                            "Model '{}' is not authorized in enforcement policy",
                            model_id
                        )),
                        document_id: None,
                        provenance,
                    };
                }
            }

            if let Some(trusted) = policy.get("trusted_signers").and_then(|t| t.as_array()) {
                let trusted_set: HashSet<&str> = trusted.iter().filter_map(|v| v.as_str()).collect();
                let has_trusted = signatures.iter().any(|sig| trusted_set.contains(sig.signer.as_str()));
                if !has_trusted && !signatures.is_empty() {
                    return ValidationResult {
                        status: "invalid".to_string(),
                        failure_code: Some("SPIF_ERROR_POLICY_VIOLATION".to_string()),
                        failure_reason: Some(format!(
                            "Signer '{}...' is not in trusted_signers policy",
                            if signer_id.len() > 16 { &signer_id[..16] } else { &signer_id }
                        )),
                        document_id: None,
                        provenance,
                    };
                }
            }

            if let Some(min_conf) = policy.get("minimum_confidence_mean").and_then(|c| c.as_f64()) {
                let means: Vec<f64> = doc.payload.iter().map(|n| n.confidence.mean).collect();
                let avg_conf = if means.is_empty() {
                    1.0
                } else {
                    means.iter().sum::<f64>() / (means.len() as f64)
                };

                if avg_conf < min_conf {
                    return ValidationResult {
                        status: "invalid".to_string(),
                        failure_code: Some("SPIF_ERROR_POLICY_VIOLATION".to_string()),
                        failure_reason: Some(format!(
                            "Average confidence {:.2} is below policy minimum {:.2}",
                            avg_conf, min_conf
                        )),
                        document_id: None,
                        provenance,
                    };
                }
            }
        }

        let document_id = Some(compute_content_id(&doc));

        ValidationResult {
            status: "valid".to_string(),
            failure_code: None,
            failure_reason: None,
            document_id,
            provenance,
        }
    }
}

// ---------------------------------------------------------------------------
// FPR Generator
// ---------------------------------------------------------------------------

fn generate_fpr_bytes(
    failure_code: &str,
    failure_reason: &str,
    policy_id: Option<&str>,
    original_provenance: Option<&Provenance>,
) -> Vec<u8> {
    let payload_val = serde_json::json!({
        "status": "invalid",
        "failure_code": failure_code,
        "failure_reason": failure_reason,
        "rule_triggered": policy_id.unwrap_or("default_policy"),
        "action": "BLOCKED",
    });

    let payload_node = Node {
        id: "fpr_status".to_string(),
        node_type: "verification_failure".to_string(),
        value: json_to_ciborium(&payload_val),
        confidence: Distribution::certain("epistemic"),
        refs: Vec::new(),
    };

    let prov = match original_provenance {
        Some(op) => Provenance {
            source_model: op.source_model.clone(),
            model_version: op.model_version.clone(),
            temperature: op.temperature,
            input_hash: op.input_hash.clone(),
            context_ref: op.context_ref.clone(),
            timestamp_ms: system_time_ms(),
            attempt: op.attempt,
            task_id: op.task_id.clone(),
            risk_tier: op.risk_tier.clone(),
            model_card: op.model_card.clone(),
        },
        None => Provenance {
            source_model: "spif-sidecar-validator-rust".to_string(),
            timestamp_ms: system_time_ms(),
            temperature: 0.0,
            input_hash: String::new(),
            context_ref: String::new(),
            model_version: String::new(),
            attempt: 0,
            task_id: String::new(),
            risk_tier: String::new(),
            model_card: String::new(),
        },
    };

    let fpr_doc = SPIFDocument {
        payload: vec![payload_node],
        provenance: Some(prov),
        semantic: None,
        trace: Vec::new(),
        trace_method: "post-hoc".to_string(),
        alternatives: Vec::new(),
        delta: None,
        signature: None,
        signatures: Vec::new(),
        task_info: None,
    };

    SPIFWriter::new().encode(&fpr_doc).unwrap_or_default()
}

fn system_time_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// ---------------------------------------------------------------------------
// HTTP Request Interception & Reverse Proxy Forwarding
// ---------------------------------------------------------------------------

fn handle_proxy_request(
    upstream_url: &str,
    evaluator: &PolicyEvaluator,
    mut req: tiny_http::Request,
) -> Result<()> {
    let mut url = upstream_url.trim_end_matches('/').to_string();
    url.push_str(req.url());

    let method = req.method().as_str().to_string();
    let mut ureq_req = ureq::request(&method, &url);

    for h in req.headers() {
        let name = h.field.as_str().as_str();
        if name.to_lowercase() != "host" {
            ureq_req = ureq_req.set(name, h.value.as_str());
        }
    }

    let mut req_body = Vec::new();
    req.as_reader().read_to_end(&mut req_body)?;

    let upstream_res = if method == "POST" {
        ureq_req.send_bytes(&req_body)
    } else {
        ureq_req.call()
    };

    match upstream_res {
        Ok(resp) => {
            let status = resp.status();
            let headers: Vec<String> = resp.headers_names();
            
            let mut response_headers = Vec::new();
            let mut x_spif = None;
            for name in &headers {
                if let Some(val) = resp.header(name) {
                    if name.to_lowercase() == "x-spif" {
                        x_spif = Some(val.to_string());
                    }
                    response_headers.push((name.clone(), val.to_string()));
                }
            }

            let mut body_bytes = Vec::new();
            let mut reader = resp.into_reader();
            reader.read_to_end(&mut body_bytes)?;

            if let Some(b64_spif) = x_spif {
                if let Ok(raw_spif) = STANDARD.decode(b64_spif) {
                    let val_res = evaluator.validate_document(&raw_spif);
                    if val_res.status != "valid" {
                        return return_fpr_block(req, &val_res, evaluator);
                    }
                }
            }

            let mut client_resp = tiny_http::Response::from_data(body_bytes)
                .with_status_code(status);
            for (name, val) in response_headers {
                if let Ok(h) = tiny_http::Header::from_bytes(name.as_bytes(), val.as_bytes()) {
                    client_resp = client_resp.with_header(h);
                }
            }
            req.respond(client_resp)?;
        }
        Err(ureq::Error::Status(status, resp)) => {
            let mut body_bytes = Vec::new();
            let mut reader = resp.into_reader();
            reader.read_to_end(&mut body_bytes)?;

            let client_resp = tiny_http::Response::from_data(body_bytes)
                .with_status_code(status);
            req.respond(client_resp)?;
        }
        Err(e) => {
            let err_body = format!("Bad Gateway: {}", e);
            let client_resp = tiny_http::Response::from_data(err_body.as_bytes())
                .with_status_code(502);
            req.respond(client_resp)?;
        }
    }

    Ok(())
}

fn return_fpr_block(
    req: tiny_http::Request,
    val_res: &ValidationResult,
    evaluator: &PolicyEvaluator,
) -> Result<()> {
    let policy_id = evaluator.policy.as_ref()
        .and_then(|p| p.get("policy_id").and_then(|id| id.as_str()));

    let fpr_bytes = generate_fpr_bytes(
        val_res.failure_code.as_deref().unwrap_or("SPIF_ERROR_POLICY_VIOLATION"),
        val_res.failure_reason.as_deref().unwrap_or("Verification failed"),
        policy_id,
        val_res.provenance.as_ref(),
    );

    let fpr_b64 = STANDARD.encode(&fpr_bytes);

    let response = tiny_http::Response::from_data(fpr_bytes)
        .with_status_code(403)
        .with_header(tiny_http::Header::from_bytes("Content-Type", "application/x-spif").unwrap())
        .with_header(tiny_http::Header::from_bytes("X-Spif-FPR", fpr_b64.as_bytes()).unwrap());

    req.respond(response)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Main Binary Entry Point
// ---------------------------------------------------------------------------

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let mut port = 8000;
    let mut upstream = None;
    let mut policy_path = None;
    let mut keystore = None;
    let mut crl_url = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-p" | "--port" => {
                port = args[i + 1].parse()?;
                i += 2;
            }
            "-u" | "--upstream" => {
                upstream = Some(args[i + 1].clone());
                i += 2;
            }
            "--policy" => {
                policy_path = Some(args[i + 1].clone());
                i += 2;
            }
            "--keystore" => {
                keystore = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--crl-url" => {
                crl_url = Some(args[i + 1].clone());
                i += 2;
            }
            _ => {
                i += 1;
            }
        }
    }

    let mut active_crl_url = crl_url;
    if active_crl_url.is_none() {
        if let Some(path) = &policy_path {
            if let Ok(s) = fs::read_to_string(path) {
                if let Ok(json_val) = serde_json::from_str::<JsonValue>(&s) {
                    if let Some(endpoint) = json_val.get("crl_check")
                        .and_then(|c| c.get("endpoint"))
                        .and_then(|e| e.as_str())
                    {
                        active_crl_url = Some(endpoint.to_string());
                    }
                }
            }
        }
    }

    let crl_client = active_crl_url.map(|url| CRLClient::new(Some(url), 300));
    let evaluator = Arc::new(PolicyEvaluator::new(
        policy_path.as_ref().map(Path::new),
        keystore,
        crl_client,
    ));

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let server = Arc::new(tiny_http::Server::http(addr).map_err(|e| anyhow!("Server failed to bind: {}", e))?);
    println!("[INFO] Rust SPIF Sidecar running on http://127.0.0.1:{}", port);
    if let Some(ref up) = upstream {
        println!("[INFO] Upstream configured to forward requests to: {}", up);
    }

    let thread_count = 8;
    let mut threads = Vec::new();
    for _ in 0..thread_count {
        let server = Arc::clone(&server);
        let evaluator = Arc::clone(&evaluator);
        let upstream = upstream.clone();
        threads.push(std::thread::spawn(move || {
            loop {
                let mut req = match server.recv() {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("[ERROR] Error receiving request: {}", e);
                        break;
                    }
                };

                let path = req.url().to_string();
                let method = req.method().to_string();

                if (path == "/validate" || path == "/verify") && method == "POST" {
                    let mut body = Vec::new();
                    if req.as_reader().read_to_end(&mut body).is_ok() {
                        let mut raw_spif = body;
                        if let Ok(json_val) = serde_json::from_slice::<JsonValue>(&raw_spif) {
                            if let Some(spif_str) = json_val.get("spif").and_then(|v| v.as_str()) {
                                if let Ok(decoded) = STANDARD.decode(spif_str) {
                                    raw_spif = decoded;
                                }
                            } else if let Some(payload_str) = json_val.get("payload").and_then(|v| v.as_str()) {
                                if let Ok(decoded) = STANDARD.decode(payload_str) {
                                    raw_spif = decoded;
                                }
                            }
                        }

                        let res = evaluator.validate_document(&raw_spif);
                        let res_json = serde_json::to_vec(&res).unwrap();
                        let status_code = if res.status == "valid" { 200 } else { 403 };

                        let response = tiny_http::Response::from_data(res_json)
                            .with_status_code(status_code)
                            .with_header(tiny_http::Header::from_bytes("Content-Type", "application/json").unwrap());
                        let _ = req.respond(response);
                    }
                } else if let Some(ref up) = upstream {
                    if let Err(e) = handle_proxy_request(up, &evaluator, req) {
                        eprintln!("[ERROR] Proxy error: {}", e);
                    }
                } else {
                    let response = tiny_http::Response::from_string("Not Found")
                        .with_status_code(404);
                    let _ = req.respond(response);
                }
            }
        }));
    }

    for t in threads {
        let _ = t.join();
    }

    Ok(())
}
