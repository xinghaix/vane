//! 本地 ACME CA：校验真实 JWS/EAB/nonce，解析客户端 CSR 并用测试 CA 签发。
use super::*;
use axum::{
    extract::{Request, State},
    routing::any,
    Router,
};
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

#[derive(Default)]
pub struct MockDns {
    pub values: Mutex<BTreeMap<String, String>>,
    pub deleted: AtomicUsize,
    pub cleanup_fail: AtomicBool,
    pub propagation_fail: AtomicBool,
    pub created: tokio::sync::Notify,
}
#[async_trait::async_trait]
impl ChallengeDns for MockDns {
    async fn prepare(&self, name: &str, value: &str) -> Result<Lease, String> {
        Ok(Lease {
            zone_name: "example.com".into(),
            zone_id: "zone".into(),
            name: name.into(),
            value: value.into(),
        })
    }
    async fn create(&self, lease: &Lease) -> Result<(), String> {
        self.values
            .lock()
            .unwrap()
            .insert(lease.name.clone(), lease.value.clone());
        self.created.notify_one();
        Ok(())
    }
    async fn cleanup(&self, lease: &Lease) -> Result<(), String> {
        if self.cleanup_fail.load(Ordering::Relaxed) {
            return Err("模拟清理失败".into());
        }
        self.values.lock().unwrap().remove(&lease.name);
        self.deleted.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
    async fn propagated(&self, name: &str, value: &str) -> Result<bool, String> {
        assert_eq!(name, "_acme-challenge.home.example.com");
        Ok(!self.propagation_fail.load(Ordering::Relaxed)
            && self.values.lock().unwrap().values().any(|v| v == value))
    }
}

pub struct MockCa {
    base: String,
    nonces: Mutex<BTreeSet<String>>,
    sequence: AtomicUsize,
    jwk: Mutex<Option<Value>>,
    pub accounts: AtomicUsize,
    pub orders: AtomicUsize,
    pub signatures: AtomicUsize,
    pub reject_order: AtomicBool,
    challenge_ready: AtomicBool,
    finalized: AtomicBool,
    certificate: Mutex<String>,
    dns: Arc<MockDns>,
    bad_nonce_once: AtomicBool,
}
impl MockCa {
    fn response(
        &self,
        status: http::StatusCode,
        body: String,
        location: Option<&str>,
    ) -> http::Response<axum::body::Body> {
        let nonce = format!("nonce-{}", self.sequence.fetch_add(1, Ordering::Relaxed));
        self.nonces.lock().unwrap().insert(nonce.clone());
        let mut response = http::Response::builder()
            .status(status)
            .header("replay-nonce", nonce)
            .header("content-type", "application/json");
        if let Some(location) = location {
            response = response.header("location", format!("{}{location}", self.base));
        }
        response.body(axum::body::Body::from(body)).unwrap()
    }
    fn order(&self) -> Value {
        let invalid = self.reject_order.load(Ordering::Relaxed);
        let mut value = json!({"status":if invalid{"invalid"}else if self.finalized.load(Ordering::Relaxed){"valid"}else if self.challenge_ready.load(Ordering::Relaxed){"ready"}else{"pending"},
            "identifiers":[{"type":"dns","value":"home.example.com"}],"authorizations":[format!("{}/authz/0",self.base)],"finalize":format!("{}/finalize/0",self.base)});
        if self.finalized.load(Ordering::Relaxed) {
            value["certificate"] = json!(format!("{}/cert/0", self.base));
        }
        if invalid {
            value["error"] =
                json!({"type":"urn:ietf:params:acme:error:unauthorized","detail":"test failure"});
        }
        value
    }
    fn verify_jws(&self, path: &str, body: &[u8]) -> Value {
        let envelope: Value = serde_json::from_slice(body).unwrap();
        let protected = envelope["protected"].as_str().unwrap();
        let payload = envelope["payload"].as_str().unwrap();
        let header: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(protected).unwrap()).unwrap();
        assert_eq!(header["url"], format!("{}{path}", self.base));
        assert_eq!(header["alg"], "ES256");
        assert!(self
            .nonces
            .lock()
            .unwrap()
            .remove(header["nonce"].as_str().unwrap()));
        let jwk = if let Some(jwk) = header.get("jwk") {
            *self.jwk.lock().unwrap() = Some(jwk.clone());
            jwk.clone()
        } else {
            assert_eq!(header["kid"], format!("{}/account/1", self.base));
            self.jwk.lock().unwrap().clone().unwrap()
        };
        let mut public_key = vec![4];
        public_key.extend(URL_SAFE_NO_PAD.decode(jwk["x"].as_str().unwrap()).unwrap());
        public_key.extend(URL_SAFE_NO_PAD.decode(jwk["y"].as_str().unwrap()).unwrap());
        ring::signature::UnparsedPublicKey::new(
            &ring::signature::ECDSA_P256_SHA256_FIXED,
            &public_key,
        )
        .verify(
            format!("{protected}.{payload}").as_bytes(),
            &URL_SAFE_NO_PAD
                .decode(envelope["signature"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap();
        self.signatures.fetch_add(1, Ordering::Relaxed);
        if payload.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap()
        }
    }
}
async fn handler(
    State(ca): State<Arc<MockCa>>,
    request: Request,
) -> http::Response<axum::body::Body> {
    let path = request.uri().path().to_string();
    if path == "/directory" {
        return ca.response(http::StatusCode::OK,json!({"newNonce":format!("{}/nonce",ca.base),"newAccount":format!("{}/new-account",ca.base),"newOrder":format!("{}/new-order",ca.base)}).to_string(),None);
    }
    if path == "/nonce" {
        return ca.response(http::StatusCode::OK, String::new(), None);
    }
    let bytes = axum::body::to_bytes(request.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let payload = ca.verify_jws(&path, &bytes);
    let (status, value, location) = match path.as_str() {
        "/new-account" => {
            ca.accounts.fetch_add(1, Ordering::Relaxed);
            let eab = &payload["externalAccountBinding"];
            let protected = eab["protected"].as_str().unwrap();
            let body = eab["payload"].as_str().unwrap();
            let header: Value =
                serde_json::from_slice(&URL_SAFE_NO_PAD.decode(protected).unwrap()).unwrap();
            assert_eq!(header["kid"], "test-eab");
            assert_eq!(header["alg"], "HS256");
            ring::hmac::verify(
                &ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &[1; 32]),
                format!("{protected}.{body}").as_bytes(),
                &URL_SAFE_NO_PAD
                    .decode(eab["signature"].as_str().unwrap())
                    .unwrap(),
            )
            .unwrap();
            (
                http::StatusCode::CREATED,
                json!({"status":"valid","orders":format!("{}/orders",ca.base)}),
                Some("/account/1"),
            )
        }
        "/new-order" => {
            ca.orders.fetch_add(1, Ordering::Relaxed);
            if ca.bad_nonce_once.swap(false, Ordering::Relaxed) {
                return ca.response(http::StatusCode::BAD_REQUEST,json!({"type":"urn:ietf:params:acme:error:badNonce","detail":"retry with fresh nonce"}).to_string(),None);
            }
            (http::StatusCode::CREATED, ca.order(), Some("/order/0"))
        }
        "/authz/0" => (
            http::StatusCode::OK,
            json!({"status":"pending","identifier":{"type":"dns","value":"home.example.com"},"challenges":[{"type":"dns-01","url":format!("{}/challenge/0",ca.base),"token":"challenge-token","status":"pending"}]}),
            None,
        ),
        "/challenge/0" => {
            let jwk = ca.jwk.lock().unwrap().clone().unwrap();
            let canonical = json!({"crv":jwk["crv"],"kty":jwk["kty"],"x":jwk["x"],"y":jwk["y"]});
            let thumbprint = URL_SAFE_NO_PAD.encode(
                ring::digest::digest(&ring::digest::SHA256, canonical.to_string().as_bytes())
                    .as_ref(),
            );
            let expected = URL_SAFE_NO_PAD.encode(
                ring::digest::digest(
                    &ring::digest::SHA256,
                    format!("challenge-token.{thumbprint}").as_bytes(),
                )
                .as_ref(),
            );
            assert!(ca
                .dns
                .values
                .lock()
                .unwrap()
                .values()
                .any(|value| value == &expected));
            ca.challenge_ready.store(true, Ordering::Relaxed);
            (
                http::StatusCode::OK,
                json!({"type":"dns-01","url":format!("{}/challenge/0",ca.base),"token":"challenge-token","status":"valid"}),
                None,
            )
        }
        "/order/0" => (http::StatusCode::OK, ca.order(), None),
        "/finalize/0" => {
            let der = URL_SAFE_NO_PAD
                .decode(payload["csr"].as_str().unwrap())
                .unwrap();
            let mut csr = rcgen::CertificateSigningRequestParams::from_der(
                &rustls::pki_types::CertificateSigningRequestDer::from(der),
            )
            .unwrap();
            csr.params.not_before = rcgen::date_time_ymd(2026, 1, 1);
            csr.params.not_after = rcgen::date_time_ymd(2030, 1, 1);
            let mut ca_params = rcgen::CertificateParams::default();
            ca_params
                .distinguished_name
                .push(rcgen::DnType::CommonName, "Vane Test CA");
            ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            let ca_key = rcgen::KeyPair::generate().unwrap();
            let issuer = rcgen::Issuer::from_params(&ca_params, &ca_key);
            let leaf = csr.signed_by(&issuer).unwrap();
            let root = ca_params.self_signed(&ca_key).unwrap();
            *ca.certificate.lock().unwrap() = format!("{}{}", leaf.pem(), root.pem());
            ca.finalized.store(true, Ordering::Relaxed);
            (http::StatusCode::OK, ca.order(), None)
        }
        "/cert/0" => {
            return ca.response(
                http::StatusCode::OK,
                ca.certificate.lock().unwrap().clone(),
                None,
            )
        }
        _ => panic!("未知 ACME 测试路径: {path}"),
    };
    ca.response(status, value.to_string(), location)
}

pub async fn start(dns: Arc<MockDns>) -> (String, Arc<MockCa>, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let ca = Arc::new(MockCa {
        base: base.clone(),
        nonces: Mutex::new(BTreeSet::new()),
        sequence: AtomicUsize::new(0),
        jwk: Mutex::new(None),
        accounts: AtomicUsize::new(0),
        orders: AtomicUsize::new(0),
        signatures: AtomicUsize::new(0),
        reject_order: AtomicBool::new(false),
        challenge_ready: AtomicBool::new(false),
        finalized: AtomicBool::new(false),
        certificate: Mutex::new(String::new()),
        dns,
        bad_nonce_once: AtomicBool::new(true),
    });
    let app = Router::new().fallback(any(handler)).with_state(ca.clone());
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("{base}/directory"), ca, task)
}
