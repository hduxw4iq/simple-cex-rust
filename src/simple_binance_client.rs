use std::collections::HashMap;
use std::error::Error;
use reqwest;
use serde_json;
use chrono::Utc;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use serde_json::Value;
use reqwest::Method;

pub struct SimpleBinanceClient {
    api_key: String,
    api_secret: String,
}

impl SimpleBinanceClient {
    pub fn new(api_key: &str, api_secret: &str) -> Self {
        Self { api_key: api_key.to_string(), api_secret: api_secret.to_string() }
    }

    pub async fn send_request(&self, method: Method, url: &str, params: &HashMap<String, String>) -> Result<Value, Box<dyn Error + Send + Sync>> {
        assert!(url.starts_with("https://"));

        let timestamp = Utc::now().timestamp_millis().to_string();

        let mut query_str = params.iter()
            .map(|(key, value)| format!("{}={}", key, value))
            .collect::<Vec<String>>()
            .join("&");
        if !query_str.is_empty() {
            query_str.push_str("&");
        }

        // Generate signature
        let signature = if !self.api_key.is_empty() && !self.api_secret.is_empty() {
            let mut mac = Hmac::<Sha256>::new_from_slice(self.api_secret.as_bytes()).expect("HMAC can take key of any size");
            mac.update(query_str.as_bytes());
            let result = mac.finalize();
            let code_bytes = result.into_bytes();
            let signature: String = url::form_urlencoded::byte_serialize(format!("{:x}", code_bytes).as_bytes()).collect();
            signature
        } else {
            "".to_string()
        };
        if !signature.is_empty() {
            query_str.push_str(format!("timestamp={}", timestamp).as_str());
            query_str.push_str(format!("&recvWindow=5000").as_str());
            query_str.push_str(format!("&signature={}", signature).as_str());
        }

        // Build headers
        let mut headers = reqwest::header::HeaderMap::new();
        if !self.api_key.is_empty() {
            headers.insert("X-MBX-APIKEY", self.api_key.parse().unwrap());
        }

        // Send request
        let full_url = format!("{}?{}", url, query_str);
        println!("full_url: {}", full_url);

        let client = reqwest::Client::new();
        let response = match method {
            Method::GET => client.get(full_url).headers(headers).send().await?,
            Method::POST => client.post(full_url).headers(headers).send().await?,
            Method::DELETE => client.delete(full_url).headers(headers).send().await?,
            _ => return Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, format!("Unsupported method: {:?}", method)))),
        };

        if response.status().is_success() {
            let response_text = response.text().await?;
            let response_json: Value = serde_json::from_str(&response_text)?;
            return Ok(response_json);
        } else {
            return Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, format!("Response: status = [{}]", response.status()))));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_request_without_signature() {
        let client = SimpleBinanceClient {
            api_key: "".to_string(),
            api_secret: "".to_string(),
        };
        let result = client.send_request(Method::GET, "https://api.binance.com/api/v3/time", &HashMap::new()).await;

        let now_ms = Utc::now().timestamp_millis();
        assert!((result.unwrap().get("serverTime").unwrap().as_i64().unwrap() - now_ms).abs() < 2000);
    }
}
