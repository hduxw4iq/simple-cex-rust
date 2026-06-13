use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use chrono::Utc;
use hmac::{Hmac, Mac};
use reqwest;
use reqwest::Method;
use serde_json;
use serde_json::Value;
use sha2::Sha256;
use std::collections::HashMap;
use std::error::Error;
use std::time::Duration;

/// Minimal OKX v5 REST client. Private endpoints are authenticated per the OKX
/// spec:
///   OK-ACCESS-SIGN = base64(HMAC-SHA256(secret,
///                          timestamp + METHOD + requestPath + body))
/// where `timestamp` is an ISO-8601 millisecond UTC string (also sent as the
/// `OK-ACCESS-TIMESTAMP` header), and for GET the query string is part of
/// `requestPath` and the body is empty. The passphrase set when the key was
/// created is sent as `OK-ACCESS-PASSPHRASE`.
pub struct SimpleOkxClient {
    api_key: String,
    api_secret: String,
    passphrase: String,
    proxy: Option<String>, // Format: "host:port"
}

impl SimpleOkxClient {
    pub fn new(api_key: &str, api_secret: &str, passphrase: &str, proxy: Option<String>) -> Self {
        Self {
            api_key: api_key.to_string(),
            api_secret: api_secret.to_string(),
            passphrase: passphrase.to_string(),
            proxy,
        }
    }

    /// `path` is the part after `/api/v5/`, e.g. `account/balance`. For GET the
    /// `params` become the query string; for POST, the JSON body. Returns the
    /// `data` field on success (`code == "0"`).
    pub async fn send_request(
        &self,
        method: Method,
        path: &str,
        params: &HashMap<String, String>,
    ) -> Result<Value, Box<dyn Error>> {
        let is_get = method == Method::GET;

        // The query string must be byte-identical between the request URL and the
        // signed requestPath, so build it once.
        let query_string = if is_get {
            params
                .iter()
                .map(|(key, value)| format!("{}={}", key, value))
                .collect::<Vec<String>>()
                .join("&")
        } else {
            String::new()
        };

        let body = if method == Method::POST {
            serde_json::to_string(params)?
        } else {
            String::new()
        };

        // requestPath includes the query string for GET (this is what is signed).
        let mut request_path = format!("/api/v5/{}", path);
        if is_get && !query_string.is_empty() {
            request_path.push('?');
            request_path.push_str(&query_string);
        }

        // ISO-8601 UTC with millisecond precision, e.g. 2020-12-08T09:08:57.715Z.
        let timestamp = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

        let prehash = format!("{}{}{}{}", timestamp, method.as_str(), request_path, body);
        let signature = {
            let mut mac = Hmac::<Sha256>::new_from_slice(self.api_secret.as_bytes())
                .expect("HMAC can take key of any size");
            mac.update(prehash.as_bytes());
            BASE64.encode(mac.finalize().into_bytes())
        };

        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("OK-ACCESS-KEY", self.api_key.parse().unwrap());
        headers.insert("OK-ACCESS-SIGN", signature.parse().unwrap());
        headers.insert("OK-ACCESS-TIMESTAMP", timestamp.parse().unwrap());
        headers.insert("OK-ACCESS-PASSPHRASE", self.passphrase.parse().unwrap());
        headers.insert("Content-Type", "application/json".parse().unwrap());

        // Build client with optional proxy (egress from a whitelisted IP when off
        // datacenter, mirroring the other exchange clients).
        let mut client_builder = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(30));
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

        let url = format!("https://www.okx.com{}", request_path);
        let response = match method {
            Method::GET => client.get(&url).headers(headers).send().await?,
            Method::POST => client.post(&url).headers(headers).body(body).send().await?,
            _ => {
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Unsupported method: {:?}", method),
                )));
            }
        };

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Response: status = [{}], body = {}", status, text),
            )));
        }

        let response_text = response.text().await?;
        let response_json: Value = serde_json::from_str(&response_text)?;
        if response_json["code"].as_str() == Some("0") {
            Ok(response_json["data"].clone())
        } else {
            Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!(
                    "OKX API error: code = {}, msg = {}",
                    response_json["code"], response_json["msg"]
                ),
            )))
        }
    }
}
