use std::collections::HashMap;
use std::error::Error;
use hex;
use reqwest;
use serde_json;
use chrono::Utc;
use hmac::{Hmac, Mac};
use sha2::Sha512;
use serde_json::Value;
use reqwest::Method;

pub struct SimpleGateClient {
    api_key: String,
    api_secret: String,
}

impl SimpleGateClient {
    pub fn new(api_key: &str, api_secret: &str) -> Self {
        Self { api_key: api_key.to_string(), api_secret: api_secret.to_string() }
    }

    // module: spot/time
    pub async fn send_request(&self, method: Method, module: &str, params: &HashMap<String, String>) -> Result<Value, Box<dyn Error>> {
        let url = format!("https://api.gateio.ws/api/v4/{}", module);

        let params_str = match method {
            Method::GET => {
                params.iter()
                    .map(|(key, value)| format!("{}={}", key, value))
                    .collect::<Vec<String>>()
                    .join("&")
            }
            Method::POST => {
                serde_json::to_string(&params)?
            }
            _ => {
                return Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, format!("Unsupported method: {:?}", method))));
            }
        };


        // Prepare headers
        let mut headers = reqwest::header::HeaderMap::new();
        // headers.insert("Content-Type", "application/json".parse().unwrap());
        // headers.insert("KEY", self.api_key.parse().unwrap());
        // headers.insert("Timestamp", timestamp.parse().unwrap());
        // headers.insert("SIGN", signature.parse().unwrap());

        // Send request
        let client = reqwest::Client::new();
        let response = match method {
            Method::GET => {
                client.get(&format!("{}?{}", url, params_str))
                    .headers(headers)
                    .send()
                    .await?
            },
            Method::POST => {
                client.post(&url)
                    .body(params_str)
                    .headers(headers)
                    .send()
                    .await?
            },
            _ => {
                return Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, format!("Unsupported method: {:?}", method))));
            }
        };

        if response.status().is_success() {
            let response_text = response.text().await?;
            let response_json: Value = serde_json::from_str(&response_text)?;

            return Ok(response_json.clone());
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
        let client = SimpleGateClient {
            api_key: "".to_string(),
            api_secret: "".to_string(),
        };
        let result = client.send_request(Method::GET, "spot/time", &HashMap::new()).await;

        let now_ms = Utc::now().timestamp_millis();
        let server_time_ms = result.unwrap().get("server_time").unwrap().as_i64().unwrap();
        assert!((server_time_ms - now_ms).abs() < 2000);
    }
}
