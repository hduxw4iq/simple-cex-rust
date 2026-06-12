use base64::engine::general_purpose::{STANDARD as BASE64_STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use chrono::Utc;
use ed25519_dalek::Signer as _;
use p256::ecdsa::{Signature as P256Signature, SigningKey as P256SigningKey};
use p256::pkcs8::DecodePrivateKey;
use p256::SecretKey;
use rand::RngCore;
use reqwest;
use reqwest::Method;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::error::Error;
use url::Url;

const HOST: &str = "api.coinbase.com";

/// Minimal Coinbase Advanced Trade (CDP) client.
///
/// Authenticates each request with a short-lived Bearer JWT minted from a CDP API
/// key name (`organizations/{org}/apiKeys/{key}`) and its private key. Both CDP
/// key types are supported: an Ed25519 key (base64-encoded, signed with EdDSA) or
/// a legacy EC P-256 key (PEM, signed with ES256).
/// See https://docs.cdp.coinbase.com/coinbase-app/authentication-authorization/api-key-authentication
pub struct SimpleCoinbaseClient {
    api_key_name: String,
    api_secret_pem: String,
    proxy: Option<String>, // Format: "host:port"
}

impl SimpleCoinbaseClient {
    pub fn new(api_key_name: &str, api_secret_pem: &str, proxy: Option<String>) -> Self {
        Self {
            api_key_name: api_key_name.to_string(),
            // Keys pasted/stored with escaped newlines still parse as PEM.
            api_secret_pem: api_secret_pem.replace("\\n", "\n"),
            proxy,
        }
    }

    /// `path` is the request path including the leading slash, e.g.
    /// `/api/v3/brokerage/accounts`. `params` become the query string.
    pub async fn send_request(
        &self,
        method: Method,
        path: &str,
        params: &HashMap<String, String>,
    ) -> Result<Value, Box<dyn Error + Send + Sync>> {
        assert!(path.starts_with('/'));

        let query_string = params
            .iter()
            .map(|(key, value)| format!("{}={}", key, value))
            .collect::<Vec<String>>()
            .join("&");

        let full_url = if query_string.is_empty() {
            format!("https://{}{}", HOST, path)
        } else {
            format!("https://{}{}?{}", HOST, path, query_string)
        }
        .parse::<Url>()?;

        // The JWT `uri` claim binds the token to a single method+path (no query).
        let jwt = self.mint_jwt(method.as_str(), path)?;

        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("Accept", "application/json".parse().unwrap());
        headers.insert("Content-Type", "application/json".parse().unwrap());
        headers.insert(
            "Authorization",
            format!("Bearer {}", jwt).parse().unwrap(),
        );

        let mut client_builder = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(5))
            .timeout(std::time::Duration::from_secs(30));
        if let Some(proxy_addr) = &self.proxy {
            let proxy_url = format!("http://{}", proxy_addr);
            let proxy = reqwest::Proxy::https(&proxy_url).map_err(|e| {
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Failed to create proxy: {}", e),
                ))
            })?;
            client_builder = client_builder.proxy(proxy);
        }
        let client = client_builder.build()?;

        let response = match method {
            Method::GET => client.get(full_url).headers(headers).send().await?,
            Method::POST => client.post(full_url).headers(headers).send().await?,
            Method::DELETE => client.delete(full_url).headers(headers).send().await?,
            _ => {
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Unsupported method: {:?}", method),
                )));
            }
        };

        let status = response.status();
        let response_text = response.text().await?;
        if status.is_success() {
            let response_json: Value = serde_json::from_str(&response_text)?;
            Ok(response_json)
        } else {
            Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Response: status = [{}], body = {}", status, response_text),
            )))
        }
    }

    /// Build a CDP ES256 JWT for `{method} {HOST}{path}`, valid for 120 seconds.
    fn mint_jwt(
        &self,
        method: &str,
        path: &str,
    ) -> Result<String, Box<dyn Error + Send + Sync>> {
        let signer = self.load_signer()?;

        let mut nonce_bytes = [0u8; 16];
        rand::rng().fill_bytes(&mut nonce_bytes);
        let nonce = hex::encode(nonce_bytes);

        let header = json!({
            "typ": "JWT",
            "alg": signer.alg(),
            "kid": self.api_key_name,
            "nonce": nonce,
        });

        let now = Utc::now().timestamp();
        let claims = json!({
            "sub": self.api_key_name,
            "iss": "cdp",
            "nbf": now,
            "exp": now + 120,
            "uri": format!("{} {}{}", method, HOST, path),
        });

        let signing_input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims)?),
        );

        let sig_b64 = URL_SAFE_NO_PAD.encode(signer.sign(signing_input.as_bytes()));

        Ok(format!("{}.{}", signing_input, sig_b64))
    }

    /// Parse the CDP private key into a JWT signer. An EC PEM key (`BEGIN ...`)
    /// signs with ES256; otherwise the secret is treated as a base64 Ed25519 key
    /// (64-byte seed||public, or 32-byte seed) signing with EdDSA.
    fn load_signer(&self) -> Result<CbSigner, Box<dyn Error + Send + Sync>> {
        if self.api_secret_pem.contains("-----BEGIN") {
            let secret_key = SecretKey::from_sec1_pem(&self.api_secret_pem)
                .or_else(|_| SecretKey::from_pkcs8_pem(&self.api_secret_pem))
                .map_err(|e| {
                    Box::<dyn Error + Send + Sync>::from(format!(
                        "failed to parse Coinbase EC private key: {}",
                        e
                    ))
                })?;
            return Ok(CbSigner::Es256(Box::new(P256SigningKey::from(secret_key))));
        }

        let raw = BASE64_STANDARD
            .decode(self.api_secret_pem.trim())
            .map_err(|e| {
                Box::<dyn Error + Send + Sync>::from(format!(
                    "failed to base64-decode Coinbase Ed25519 key: {}",
                    e
                ))
            })?;
        let signing_key = match raw.len() {
            // libsodium/CDP format: 32-byte seed followed by 32-byte public key.
            64 => ed25519_dalek::SigningKey::from_keypair_bytes(
                &raw.as_slice().try_into().unwrap(),
            )
            .map_err(|e| {
                Box::<dyn Error + Send + Sync>::from(format!(
                    "invalid Coinbase Ed25519 keypair: {}",
                    e
                ))
            })?,
            32 => ed25519_dalek::SigningKey::from_bytes(&raw.as_slice().try_into().unwrap()),
            other => {
                return Err(Box::<dyn Error + Send + Sync>::from(format!(
                    "unexpected Coinbase Ed25519 key length: {} bytes",
                    other
                )));
            }
        };
        Ok(CbSigner::EdDsa(Box::new(signing_key)))
    }
}

/// JWT signer for whichever CDP key type was provided.
enum CbSigner {
    /// EC P-256 → ES256 (deterministic RFC 6979 ECDSA, 64-byte r||s).
    Es256(Box<P256SigningKey>),
    /// Ed25519 → EdDSA (64-byte signature).
    EdDsa(Box<ed25519_dalek::SigningKey>),
}

impl CbSigner {
    fn alg(&self) -> &'static str {
        match self {
            CbSigner::Es256(_) => "ES256",
            CbSigner::EdDsa(_) => "EdDSA",
        }
    }

    fn sign(&self, msg: &[u8]) -> Vec<u8> {
        match self {
            CbSigner::Es256(key) => {
                let sig: P256Signature = key.sign(msg);
                sig.to_bytes().to_vec()
            }
            CbSigner::EdDsa(key) => key.sign(msg).to_bytes().to_vec(),
        }
    }
}
