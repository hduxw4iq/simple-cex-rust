use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use chrono::Utc;
use hmac::{Hmac, Mac};
use reqwest;
use serde_json;
use serde_json::Value;
use sha2::{Digest, Sha256, Sha512};
use std::collections::HashMap;
use std::error::Error;
use std::time::Duration;

/// Minimal Kraken Spot REST client. Private endpoints are authenticated per the
/// Kraken spec:
///   API-Sign = base64(HMAC-SHA512(base64_decode(api_secret),
///                                 uri_path + SHA256(nonce + url-encoded POST data)))
/// sent together with the `API-Key` header. The api_secret is the base64 private
/// key string as shown in the Kraken API key management UI.
pub struct SimpleKrakenClient {
    api_key: String,
    api_secret: String,
    proxy: Option<String>, // Format: "host:port"
}

impl SimpleKrakenClient {
    pub fn new(api_key: &str, api_secret: &str, proxy: Option<String>) -> Self {
        Self {
            api_key: api_key.to_string(),
            api_secret: api_secret.to_string(),
            proxy,
        }
    }

    /// Compute the `API-Sign` value for a request. Pure (no I/O) so it can be
    /// validated against Kraken's documented test vector.
    fn sign(
        api_secret: &str,
        uri_path: &str,
        nonce: &str,
        postdata: &str,
    ) -> Result<String, Box<dyn Error>> {
        // SHA256(nonce + postdata).
        let mut sha256 = Sha256::new();
        sha256.update(nonce.as_bytes());
        sha256.update(postdata.as_bytes());
        let sha256_digest = sha256.finalize();

        // message = uri_path || SHA256(nonce + postdata).
        let mut message = uri_path.as_bytes().to_vec();
        message.extend_from_slice(&sha256_digest);

        // HMAC-SHA512 keyed by the base64-decoded secret, base64-encoded.
        let secret_bytes = BASE64.decode(api_secret.trim())?;
        let mut mac = Hmac::<Sha512>::new_from_slice(&secret_bytes)
            .map_err(|e| Box::new(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())))?;
        mac.update(&message);
        Ok(BASE64.encode(mac.finalize().into_bytes()))
    }

    /// Call a private method (e.g. `Balance` -> `/0/private/Balance`). Returns the
    /// `result` field on success; errors if Kraken's `error` array is non-empty.
    pub async fn send_request(
        &self,
        method: &str,
        params: &HashMap<String, String>,
    ) -> Result<Value, Box<dyn Error>> {
        let uri_path = format!("/0/private/{}", method);
        let url = format!("https://api.kraken.com{}", uri_path);

        // Nonce: always-increasing; ms timestamp is fine for our call cadence.
        let nonce = Utc::now().timestamp_millis().to_string();

        // Build the url-encoded POST body once and reuse the exact bytes for the
        // signature (Kraken signs the literal POST data, nonce included). Scoped so
        // the (non-Send) serializer is dropped before any `.await` below.
        let postdata = {
            let mut serializer = url::form_urlencoded::Serializer::new(String::new());
            serializer.append_pair("nonce", &nonce);
            for (key, value) in params {
                serializer.append_pair(key, value);
            }
            serializer.finish()
        };

        let signature = Self::sign(&self.api_secret, &uri_path, &nonce, &postdata)?;

        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("API-Key", self.api_key.parse().unwrap());
        headers.insert("API-Sign", signature.parse().unwrap());
        headers.insert(
            "Content-Type",
            "application/x-www-form-urlencoded".parse().unwrap(),
        );

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

        let response = client
            .post(&url)
            .headers(headers)
            .body(postdata)
            .send()
            .await?;

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
        if let Some(errors) = response_json["error"].as_array() {
            if !errors.is_empty() {
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Kraken API error: {:?}", errors),
                )));
            }
        }
        Ok(response_json["result"].clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Kraken's documented signature example.
    // https://docs.kraken.com/api/docs/guides/spot-rest-auth
    #[test]
    fn test_sign_matches_kraken_doc_vector() {
        let api_secret =
            "kQH5HW/8p1uGOVjbgWA7FunAmGO8lsSUXNsu3eow76sz84Q18fWxnyRzBHCd3pd5nE9qa99HAZtuZuj6F1huXg==";
        let uri_path = "/0/private/AddOrder";
        let nonce = "1616492376594";
        let postdata =
            "nonce=1616492376594&ordertype=limit&pair=XBTUSD&price=37500&type=buy&volume=1.25";

        let signature = SimpleKrakenClient::sign(api_secret, uri_path, nonce, postdata).unwrap();
        assert_eq!(
            signature,
            "4/dpxb3iT4tp/ZCVEwSnEsLxx0bqyhLpdfOpc6fn7OR8+UClSV5n9E6aSS8MPtnRfp32bAb0nmbRn6H8ndwLUQ=="
        );
    }
}
