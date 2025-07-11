use std::collections::HashMap;
use std::error::Error;
use hex;
use reqwest;
use serde_json;
use chrono::Utc;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use serde_json::Value;
use reqwest::Method;


pub struct SimpleBitgetClient {
    api_key: String,
    api_secret: String,
}

impl SimpleBitgetClient {
    pub fn new(api_key: &str, api_secret: &str) -> Self {
        Self { api_key: api_key.to_string(), api_secret: api_secret.to_string() }
    }

    /// Sends a request to Bitget API
    ///
    /// # Arguments
    /// * `product` - API product type: market, order, position, account, asset, spot-level-token, spot-margin-trade
    /// * `module` - Sub-module name under the product
    /// * `category` - Trading category: spot, linear, inverse, option
    /// * `params` - Request parameters as key-value pairs
    pub async fn send_request(&self, method: Method, module: &str, params: &HashMap<String, String>) -> Result<Value, Box<dyn Error>> {
        let url = format!("https://api.bitget.com/api/v2/{}", module);

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

        let timestamp = Utc::now().timestamp_millis().to_string();
        let recv_window = "5000";

        // Generate signature
        let signature = if !self.api_key.is_empty() && !self.api_secret.is_empty() {
            let mut mac = Hmac::<Sha256>::new_from_slice(self.api_secret.as_bytes()).expect("HMAC can take key of any size");
            mac.update(timestamp.as_bytes());
            mac.update(self.api_key.as_bytes());
            mac.update(recv_window.as_bytes());
            mac.update(params_str.as_bytes());
            let result = mac.finalize();
            let code_bytes = result.into_bytes();
            hex::encode(code_bytes)
        } else {
            "".to_string()
        };


        // Build headers
        let mut headers = reqwest::header::HeaderMap::new();
        if !self.api_key.is_empty() {
            headers.insert("X-BAPI-API-KEY", self.api_key.parse().unwrap());
            headers.insert("X-BAPI-SIGN", signature.parse().unwrap());
            headers.insert("X-BAPI-SIGN-TYPE", "2".parse().unwrap());
            headers.insert("X-BAPI-TIMESTAMP", timestamp.parse().unwrap());
            headers.insert("X-BAPI-RECV-WINDOW", recv_window.parse().unwrap());
            headers.insert("Content-Type", "application/json".parse().unwrap());
        }

        // Send request
        let client = reqwest::Client::new();
        let response = match method {
            Method::GET => {
                client.get(&format!("{}?{}", url, params_str))
                    // .headers(headers)
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
            if response_json["code"].as_str().unwrap().parse::<i64>().unwrap() == 0 {
                return Ok(response_json["data"].clone());
            } else {
                return Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, format!("Response: ret_code = {}, ret_msg = {}", response_json["retCode"], response_json["retMsg"]))));
            }
        } else {
            return Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, format!("Response: status = [{}]", response.status()))));
        }
    }
}