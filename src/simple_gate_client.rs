use chrono::Utc;
use hex;
use hmac::digest::Digest;
use hmac::{Hmac, Mac};
use reqwest;
use reqwest::Method;
use serde_json;
use serde_json::Value;
use sha2::Sha512;
use std::collections::HashMap;
use url::Url;

pub struct SimpleGateClient {
    api_key: String,
    api_secret: String,
    proxy: Option<String>, // Format: "host:port"
}

impl SimpleGateClient {
    pub fn new(api_key: &str, api_secret: &str, proxy: &Option<String>) -> Self {
        Self {
            api_key: api_key.to_string(),
            api_secret: api_secret.to_string(),
            proxy: proxy.clone(),
        }
    }

    // module: spot/time
    pub async fn send_request(
        &self,
        method: Method,
        module: &str,
        params: &HashMap<String, String>,
    ) -> Result<Value, Box<dyn std::error::Error>> {
        let query_string = params
            .iter()
            .map(|(key, value)| format!("{}={}", key, value))
            .collect::<Vec<String>>()
            .join("&");
        let path = format!("/api/v4/{}", module);
        let full_url = format!("https://api.gateio.ws{}?{}", path, query_string).parse::<Url>()?;

        let url_string = full_url.to_string();
        let user_agent = format!("simple-cex-client/1.0.0");

        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("User-Agent", user_agent.parse().unwrap());
        headers.insert("Accept", "application/json".parse().unwrap());
        headers.insert("Content-Type", "application/json".parse().unwrap());

        if !self.api_key.is_empty() {
            let timestamp = Utc::now().timestamp_millis() / 1000;

            headers.insert("KEY", self.api_key.parse().unwrap());
            headers.insert("Timestamp", timestamp.to_string().parse().unwrap());

            let signature = self.sign_hmac(
                &method,
                &path,
                &query_string,
                "",
                &timestamp.to_string(),
                self.api_secret.as_str(),
            )?;

            headers.insert("SIGN", signature.parse().unwrap());
        }

        // Build client with optional proxy
        let mut client_builder = reqwest::Client::builder();
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
        let client = client_builder.build().map_err(|e| {
            Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Failed to build client: {}", e),
            ))
        })?;

        // Send request
        let response = match method {
            Method::GET => client.get(full_url).headers(headers).send().await?,
            Method::POST => client.post(&url_string).headers(headers).send().await?,
            _ => {
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Unsupported method: {:?}", method),
                )));
            }
        };

        if response.status().is_success() {
            let response_text = response.text().await?;
            let response_json: Value = serde_json::from_str(&response_text)?;

            return Ok(response_json.clone());
        } else {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Response: status = [{}]", response.status()),
            )));
        }
    }

    fn sign_hmac(
        &self,
        method: &Method,
        path: &str,
        query_string: &str,
        payload: &str,
        timestamp: &str,
        key: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let hashed_payload = hex::encode(Sha512::digest(payload.as_bytes()).to_vec());

        let s = format!(
            "{}\n{}\n{}\n{}\n{}",
            method, path, query_string, hashed_payload, timestamp
        );

        let mut mac = Hmac::<Sha512>::new_from_slice(key.to_string().as_bytes())?;
        mac.update(s.as_bytes());
        let signature_byptes = mac.finalize().into_bytes();

        Ok(hex::encode(signature_byptes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_request_without_signature() {
        let client = SimpleGateClient::new("", "", &None);
        let result = client
            .send_request(Method::GET, "spot/time", &HashMap::new())
            .await;

        let now_ms = Utc::now().timestamp_millis();
        let server_time_ms = result
            .unwrap()
            .get("server_time")
            .unwrap()
            .as_i64()
            .unwrap();
        assert!((server_time_ms - now_ms).abs() < 2000);
    }

    #[tokio::test]
    async fn test_request_without_signature_with_proxy() {
        let client = SimpleGateClient::new("", "", &Some("oas.w4iq.com:3128".to_string()));
        let result = client
            .send_request(Method::GET, "spot/time", &HashMap::new())
            .await;

        let now_ms = Utc::now().timestamp_millis();
        let server_time_ms = result
            .unwrap()
            .get("server_time")
            .unwrap()
            .as_i64()
            .unwrap();
        assert!((server_time_ms - now_ms).abs() < 2000);
    }
}
