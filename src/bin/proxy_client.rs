//! VPSProxy-like local client (multi-hop / chain) with HTTPS (MITM) support.
//!
//! Listens as an HTTP/HTTPS proxy on 127.0.0.1:2222.
//!   * Plain `GET http://host/path` forward-proxy requests → onion chain.
//!   * `CONNECT host:443` (browser HTTPS) → terminated locally with a cert minted
//!     by our own CA, the inner request is then sent through the chain (the exit
//!     gate's cURL fetches the real https:// target).
//!
//! Chain modes (config): sequential (default) or random (per-request shuffle,
//! optional fixed exit), mirroring the original VPSProxy chain options.
//!
//! Run:  cargo run --bin proxy_client -- vpsproxy.toml

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

// ==================== config ====================

#[derive(Debug, Deserialize)]
struct Config {
    #[serde(default = "default_listen")]
    listen: String,
    #[serde(default = "default_ca_dir")]
    ca_dir: String,
    /// "sequential" (default) or "random"
    #[serde(default)]
    mode: Mode,
    /// gates per random chain (default: all)
    #[serde(default)]
    hops: Option<usize>,
    /// keep the last [[gate]] as a constant exit in random mode
    #[serde(default)]
    fixed_exit: bool,
    gate: Vec<Gate>,
}

#[derive(Debug, Deserialize, Default, Clone, Copy, PartialEq)]
#[serde(rename_all = "lowercase")]
enum Mode {
    #[default]
    Sequential,
    Random,
}

#[derive(Debug, Deserialize, Clone)]
struct Gate {
    url: String,
    key: String, // 64 hex chars
    password: String,
}

fn default_listen() -> String {
    "127.0.0.1:2222".to_string()
}
fn default_ca_dir() -> String {
    "vpsproxy-ca".to_string()
}

impl Gate {
    fn key_bytes(&self) -> Result<[u8; 32], String> {
        let raw = hex_decode(&self.key).ok_or("key is not valid hex")?;
        if raw.len() != 32 {
            return Err(format!("key must be 64 hex chars (32 bytes), got {}", raw.len()));
        }
        let mut k = [0u8; 32];
        k.copy_from_slice(&raw);
        Ok(k)
    }
}

// ==================== crypto (AES-256-GCM, wire = b64(nonce||ct||tag)) ====================

fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> String {
    let cipher = Aes256Gcm::new(key.into());
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plaintext)
        .expect("encryption failure");
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    B64.encode(out)
}

fn decrypt(key: &[u8; 32], b64: &str) -> Result<Vec<u8>, String> {
    let raw = B64.decode(b64.trim()).map_err(|e| format!("base64: {e}"))?;
    if raw.len() < 12 + 16 {
        return Err("ciphertext envelope too short".into());
    }
    let (nonce_bytes, ct) = raw.split_at(12);
    Aes256Gcm::new(key.into())
        .decrypt(Nonce::from_slice(nonce_bytes), ct)
        .map_err(|_| "decrypt/auth failed (wrong exit key?)".into())
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

// ==================== chain selection ====================

fn select_chain(cfg: &Config) -> Vec<Gate> {
    if cfg.mode == Mode::Sequential || cfg.gate.len() == 1 {
        return cfg.gate.clone();
    }
    let n = cfg.gate.len();
    let want = cfg.hops.unwrap_or(n).clamp(1, n);

    if cfg.fixed_exit {
        let exit = cfg.gate[n - 1].clone();
        let mut pool: Vec<usize> = (0..n - 1).collect();
        shuffle(&mut pool);
        let take = want.saturating_sub(1).min(pool.len());
        let mut chain: Vec<Gate> = pool[..take].iter().map(|&i| cfg.gate[i].clone()).collect();
        chain.push(exit);
        chain
    } else {
        let mut idx: Vec<usize> = (0..n).collect();
        shuffle(&mut idx);
        idx[..want].iter().map(|&i| cfg.gate[i].clone()).collect()
    }
}

fn shuffle<T>(v: &mut [T]) {
    for i in (1..v.len()).rev() {
        let j = (OsRng.next_u32() as usize) % (i + 1);
        v.swap(i, j);
    }
}

/// Build the ciphertext for the FIRST gate of `chain` (onion, exit layer last).
fn build_onion(chain: &[Gate], target: &Value) -> Result<String, String> {
    let n = chain.len();
    let exit = &chain[n - 1];
    let mut inner = target.clone();
    inner["type"] = json!("target");
    inner["pw"] = json!(exit.password);
    let mut current = encrypt(&exit.key_bytes()?, inner.to_string().as_bytes());

    for i in (0..n - 1).rev() {
        let layer = json!({
            "type": "forward",
            "pw": chain[i].password,
            "next": chain[i + 1].url,
            "payload": current,
        });
        current = encrypt(&chain[i].key_bytes()?, layer.to_string().as_bytes());
    }
    Ok(current)
}

// ==================== local CA (MITM for HTTPS) ====================

struct Ca {
    signer: Mutex<(rcgen::Certificate, KeyPair)>,
    cache: Mutex<HashMap<String, Arc<ServerConfig>>>,
}

impl Ca {
    fn load_or_create(dir: &Path) -> Result<Arc<Ca>, String> {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        let cert_path = dir.join("ca_cert.pem");
        let key_path = dir.join("ca_key.pem");

        let (cert, key) = if cert_path.exists() && key_path.exists() {
            let cert_pem = std::fs::read_to_string(&cert_path).map_err(|e| e.to_string())?;
            let key_pem = std::fs::read_to_string(&key_path).map_err(|e| e.to_string())?;
            let key = KeyPair::from_pem(&key_pem).map_err(|e| e.to_string())?;
            let params = CertificateParams::from_ca_cert_pem(&cert_pem).map_err(|e| e.to_string())?;
            let cert = params.self_signed(&key).map_err(|e| e.to_string())?;
            (cert, key)
        } else {
            let key = KeyPair::generate().map_err(|e| e.to_string())?;
            let mut p = CertificateParams::new(Vec::<String>::new()).map_err(|e| e.to_string())?;
            p.distinguished_name.push(DnType::CommonName, "VPSProxy Local CA");
            p.distinguished_name.push(DnType::OrganizationName, "VPSProxy");
            p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
            let cert = p.self_signed(&key).map_err(|e| e.to_string())?;
            std::fs::write(&cert_path, cert.pem()).map_err(|e| e.to_string())?;
            std::fs::write(&key_path, key.serialize_pem()).map_err(|e| e.to_string())?;
            println!("Generated local CA. IMPORT THIS INTO YOUR BROWSER/OS TRUST:");
            println!("  {}", cert_path.display());
            (cert, key)
        };

        Ok(Arc::new(Ca {
            signer: Mutex::new((cert, key)),
            cache: Mutex::new(HashMap::new()),
        }))
    }

    fn server_config_for(&self, host: &str) -> Result<Arc<ServerConfig>, String> {
        if let Some(c) = self.cache.lock().unwrap().get(host) {
            return Ok(c.clone());
        }
        let (leaf_der, key_der) = {
            let guard = self.signer.lock().unwrap();
            let (ca_cert, ca_key) = &*guard;
            let leaf_key = KeyPair::generate().map_err(|e| e.to_string())?;
            let mut p = CertificateParams::new(vec![host.to_string()]).map_err(|e| e.to_string())?;
            p.distinguished_name.push(DnType::CommonName, host);
            p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
            let leaf = p.signed_by(&leaf_key, ca_cert, ca_key).map_err(|e| e.to_string())?;
            (leaf.der().to_vec(), leaf_key.serialize_der())
        };

        let certs = vec![CertificateDer::from(leaf_der)];
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der));
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| e.to_string())?;
        let config = Arc::new(config);
        self.cache.lock().unwrap().insert(host.to_string(), config.clone());
        Ok(config)
    }
}

// ==================== HTTP parsing ====================

struct ProxyRequest {
    method: String,
    target: String, // absolute URL (plain proxy) or origin-form "/path" (tunnel)
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

enum Incoming {
    Connect(String), // host:port
    Request(ProxyRequest),
    Eof,
}

async fn read_incoming<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Incoming, String> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];

    let header_end = loop {
        if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
            break pos;
        }
        let n = stream.read(&mut tmp).await.map_err(|e| e.to_string())?;
        if n == 0 {
            return if buf.is_empty() {
                Ok(Incoming::Eof)
            } else {
                Err("connection closed mid-headers".into())
            };
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.len() > 1 << 20 {
            return Err("request headers too large".into());
        }
    };

    let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let mut lines = head.split("\r\n");
    let request_line = lines.next().ok_or("empty request")?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().ok_or("no method")?.to_string();
    let target = parts.next().ok_or("no target")?.to_string();

    if method.eq_ignore_ascii_case("CONNECT") {
        return Ok(Incoming::Connect(target));
    }

    let mut headers = Vec::new();
    let mut content_length = 0usize;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            let k = k.trim().to_string();
            let v = v.trim().to_string();
            let kl = k.to_ascii_lowercase();
            if kl == "content-length" {
                content_length = v.parse().unwrap_or(0);
            }
            if matches!(kl.as_str(), "proxy-connection" | "connection") {
                continue;
            }
            headers.push((k, v));
        }
    }

    let body_start = header_end + 4;
    let mut body = buf[body_start..].to_vec();
    while body.len() < content_length {
        let n = stream.read(&mut tmp).await.map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
    }

    Ok(Incoming::Request(ProxyRequest { method, target, headers, body }))
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

// ==================== request processing ====================

#[derive(Clone)]
enum Ctx {
    Plain,
    Https(String), // CONNECT authority (default host)
}

fn build_url(ctx: &Ctx, req: &ProxyRequest) -> Option<String> {
    let t = &req.target;
    if t.starts_with("http://") || t.starts_with("https://") {
        return Some(t.clone());
    }
    let host = req
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("host"))
        .map(|(_, v)| v.clone())
        .or_else(|| match ctx {
            Ctx::Https(h) => Some(h.clone()),
            Ctx::Plain => None,
        })?;
    let scheme = match ctx {
        Ctx::Https(_) => "https",
        Ctx::Plain => "http",
    };
    Some(format!("{scheme}://{host}{t}"))
}

async fn process<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    req: ProxyRequest,
    ctx: &Ctx,
    cfg: &Config,
    http: &reqwest::Client,
) -> Result<(), String> {
    let url = match build_url(ctx, &req) {
        Some(u) => u,
        None => return write_simple(stream, 400, "cannot determine target URL").await,
    };

    let headers_json: Vec<Value> = req.headers.iter().map(|(k, v)| json!([k, v])).collect();
    let target = json!({
        "method": req.method,
        "url": url,
        "headers": headers_json,
        "body": B64.encode(&req.body),
    });

    let chain = select_chain(cfg);
    let onion = match build_onion(&chain, &target) {
        Ok(o) => o,
        Err(e) => return write_simple(stream, 500, &format!("onion build failed: {e}")).await,
    };

    let resp = http
        .post(&chain[0].url)
        .header("Content-Type", "application/octet-stream")
        .body(onion)
        .send()
        .await;
    let resp = match resp {
        Ok(r) => r,
        Err(e) => return write_simple(stream, 502, &format!("gate[0] unreachable: {e}")).await,
    };
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return write_simple(stream, 502, &format!("chain error: {}", text.trim())).await;
    }

    let exit_key = chain.last().unwrap().key_bytes()?;
    let plain = match decrypt(&exit_key, &text) {
        Ok(p) => p,
        Err(e) => return write_simple(stream, 502, &format!("response decrypt: {e}")).await,
    };
    let parsed: Value = match serde_json::from_slice(&plain) {
        Ok(v) => v,
        Err(e) => return write_simple(stream, 502, &format!("response json: {e}")).await,
    };
    write_target_response(stream, &parsed).await
}

async fn write_target_response<S: AsyncWrite + Unpin>(
    stream: &mut S,
    resp: &Value,
) -> Result<(), String> {
    let status = resp["status"].as_u64().unwrap_or(502) as u16;
    let body = B64
        .decode(resp["body"].as_str().unwrap_or(""))
        .map_err(|e| e.to_string())?;

    let mut head = format!("HTTP/1.1 {} {}\r\n", status, reason(status));
    if let Some(hs) = resp["headers"].as_array() {
        for h in hs {
            let (Some(name), Some(val)) = (h[0].as_str(), h[1].as_str()) else { continue };
            let nl = name.to_ascii_lowercase();
            if matches!(nl.as_str(), "content-length" | "transfer-encoding" | "connection") {
                continue;
            }
            head.push_str(&format!("{name}: {val}\r\n"));
        }
    }
    head.push_str(&format!("Content-Length: {}\r\n", body.len()));
    head.push_str("Connection: keep-alive\r\n\r\n");

    stream.write_all(head.as_bytes()).await.map_err(|e| e.to_string())?;
    stream.write_all(&body).await.map_err(|e| e.to_string())?;
    stream.flush().await.map_err(|e| e.to_string())?;
    Ok(())
}

async fn write_simple<S: AsyncWrite + Unpin>(
    stream: &mut S,
    status: u16,
    msg: &str,
) -> Result<(), String> {
    let body = msg.as_bytes();
    let head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
        status, reason(status), body.len()
    );
    stream.write_all(head.as_bytes()).await.map_err(|e| e.to_string())?;
    stream.write_all(body).await.map_err(|e| e.to_string())?;
    stream.flush().await.map_err(|e| e.to_string())?;
    Ok(())
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        _ => "Status",
    }
}

// ==================== connection handling ====================

const IDLE: Duration = Duration::from_secs(30);

/// Serve consecutive keep-alive requests on an already-established stream.
async fn serve_loop<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    ctx: Ctx,
    cfg: Arc<Config>,
    http: reqwest::Client,
) {
    loop {
        let inc = match tokio::time::timeout(IDLE, read_incoming(&mut stream)).await {
            Ok(Ok(i)) => i,
            _ => break, // idle timeout or read error → close
        };
        match inc {
            Incoming::Request(req) => {
                if process(&mut stream, req, &ctx, &cfg, &http).await.is_err() {
                    break;
                }
            }
            Incoming::Eof | Incoming::Connect(_) => break,
        }
    }
}

async fn handle(mut stream: TcpStream, cfg: Arc<Config>, http: reqwest::Client, ca: Arc<Ca>) {
    let first = match read_incoming(&mut stream).await {
        Ok(i) => i,
        Err(_) => return,
    };

    match first {
        Incoming::Connect(authority) => {
            let host = authority.split(':').next().unwrap_or(&authority).to_string();
            if stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .is_err()
            {
                return;
            }
            let config = match ca.server_config_for(&host) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("cert for {host}: {e}");
                    return;
                }
            };
            let acceptor = TlsAcceptor::from(config);
            match acceptor.accept(stream).await {
                Ok(tls) => serve_loop(tls, Ctx::Https(host), cfg, http).await,
                Err(e) => eprintln!("TLS handshake with browser failed for {host}: {e}"),
            }
        }
        Incoming::Request(req) => {
            let ctx = Ctx::Plain;
            if process(&mut stream, req, &ctx, &cfg, &http).await.is_ok() {
                serve_loop(stream, ctx, cfg, http).await;
            }
        }
        Incoming::Eof => {}
    }
}

// ==================== main ====================

#[tokio::main]
async fn main() {
    rustls::crypto::ring::default_provider().install_default().ok();

    let path = std::env::args().nth(1).unwrap_or_else(|| "vpsproxy.toml".to_string());
    let raw = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("cannot read config '{path}': {e}");
            std::process::exit(1);
        }
    };
    let cfg: Config = match toml::from_str(&raw) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("config parse error: {e}");
            std::process::exit(1);
        }
    };
    if cfg.gate.is_empty() {
        eprintln!("config has no [[gate]] entries");
        std::process::exit(1);
    }
    for (i, g) in cfg.gate.iter().enumerate() {
        if let Err(e) = g.key_bytes() {
            eprintln!("gate[{i}] ({}): {e}", g.url);
            std::process::exit(1);
        }
    }

    let ca = match Ca::load_or_create(&PathBuf::from(&cfg.ca_dir)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("CA init failed: {e}");
            std::process::exit(1);
        }
    };

    let listen = cfg.listen.clone();
    let mode = cfg.mode;
    let cfg = Arc::new(cfg);
    let http = reqwest::Client::builder().build().expect("http client");

    let listener = TcpListener::bind(&listen).await.unwrap_or_else(|e| {
        eprintln!("cannot bind {listen}: {e}");
        std::process::exit(1);
    });
    println!(
        "VPSProxy client on http://{listen}  | {} gate(s) | mode: {:?}",
        cfg.gate.len(),
        mode
    );
    println!("Browser proxy → {listen} (set HTTP *and* HTTPS/SSL proxy to this).");
    println!("For HTTPS sites, import {}/ca_cert.pem into your trust store.", cfg.ca_dir);

    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let (cfg, http, ca) = (cfg.clone(), http.clone(), ca.clone());
                tokio::spawn(handle(stream, cfg, http, ca));
            }
            Err(e) => eprintln!("accept error: {e}"),
        }
    }
}
