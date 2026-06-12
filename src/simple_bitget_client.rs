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

/// Minimal Bitget v2 REST client. Private endpoints are authenticated per the
/// Bitget spec: the request is signed with
///   sign = base64(HMAC-SHA256(api_secret, timestamp + METHOD + requestPath
///                             [+ "?" + queryString] + body))
/// and the signature, api key, timestamp and the passphrase set when the key was
/// created are sent as `ACCESS-*` headers. Leave api_key/api_secret/passphrase
/// empty for public endpoints (no signing).
pub struct SimpleBitgetClient {
    api_key: String,
    api_secret: String,
    passphrase: String,
    proxy: Option<String>, // Format: "host:port"
}

impl SimpleBitgetClient {
    pub fn new(api_key: &str, api_secret: &str, passphrase: &str, proxy: Option<String>) -> Self {
        Self {
            api_key: api_key.to_string(),
            api_secret: api_secret.to_string(),
            passphrase: passphrase.to_string(),
            proxy,
        }
    }

    /// `module` is the path under `/api/v2/`, e.g. `spot/account/assets`. For GET,
    /// `params` become the query string; for POST, the JSON body. Returns the
    /// `data` field on success (`code == "00000"`).
    pub async fn send_request(
        &self,
        method: Method,
        module: &str,
        params: &HashMap<String, String>,
    ) -> Result<Value, Box<dyn Error>> {
        let request_path = format!("/api/v2/{}", module);
        let url_base = "https://api.bitget.com";

        let is_get = method == Method::GET;

        // The query string must be byte-identical between the URL and the signed
        // prehash, so build it once. (HashMap order is arbitrary but consistent
        // within a single call since we reuse this exact string.)
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

        let timestamp = Utc::now().timestamp_millis().to_string();

        // Build the prehash string: timestamp + METHOD + requestPath [+ ?query] + body.
        let mut prehash = format!("{}{}{}", timestamp, method.as_str(), request_path);
        if is_get && !query_string.is_empty() {
            prehash.push('?');
            prehash.push_str(&query_string);
        }
        prehash.push_str(&body);

        let signature = if !self.api_secret.is_empty() {
            let mut mac = Hmac::<Sha256>::new_from_slice(self.api_secret.as_bytes())
                .expect("HMAC can take key of any size");
            mac.update(prehash.as_bytes());
            BASE64.encode(mac.finalize().into_bytes())
        } else {
            String::new()
        };

        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("Content-Type", "application/json".parse().unwrap());
        headers.insert("locale", "en-US".parse().unwrap());
        if !self.api_key.is_empty() {
            headers.insert("ACCESS-KEY", self.api_key.parse().unwrap());
            headers.insert("ACCESS-SIGN", signature.parse().unwrap());
            headers.insert("ACCESS-TIMESTAMP", timestamp.parse().unwrap());
            headers.insert("ACCESS-PASSPHRASE", self.passphrase.parse().unwrap());
        }

        // Build client with optional proxy (e.g. to egress from a whitelisted IP
        // when running off-datacenter; Bitget keys are IP-restricted).
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
            Method::GET => {
                let url = if query_string.is_empty() {
                    format!("{}{}", url_base, request_path)
                } else {
                    format!("{}{}?{}", url_base, request_path, query_string)
                };
                client.get(&url).headers(headers).send().await?
            }
            Method::POST => {
                client
                    .post(&format!("{}{}", url_base, request_path))
                    .headers(headers)
                    .body(body)
                    .send()
                    .await?
            }
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
        if response_json["code"].as_str() == Some("00000") {
            Ok(response_json["data"].clone())
        } else {
            Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!(
                    "Response: code = {}, msg = {}",
                    response_json["code"], response_json["msg"]
                ),
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_request_without_signature() {
        let client = SimpleBitgetClient::new("", "", "", None);
        let result = client
            .send_request(Method::GET, "public/time", &HashMap::new())
            .await;

        let now_ms = Utc::now().timestamp_millis();
        assert!(
            (result
                .unwrap()
                .get("serverTime")
                .unwrap()
                .as_str()
                .unwrap()
                .parse::<i64>()
                .unwrap()
                - now_ms)
                .abs()
                < 2000
        );
    }
}
