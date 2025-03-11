use anyhow::{Result, Context};
use reqwest::{
    Client as ReqwestClient,
    Response,
    header::{HeaderMap, HeaderName, HeaderValue, COOKIE, USER_AGENT},
    redirect::Policy,
};
use std::time::Duration;
use std::collections::HashMap;
use tracing::{debug, warn};
use url::Url;

const DEFAULT_USER_AGENT: &str = "Web-Cache-Scanner/1.0 (Nsisong Labs)";

#[derive(Debug)]
pub struct Client {
    inner: ReqwestClient,
    headers: HeaderMap,
    cookies: HashMap<String, String>,
}

impl Client {
    pub fn builder() -> ClientBuilder {
        ClientBuilder::new()
    }

    pub async fn get(&self, url: &str) -> Result<Response> {
        let mut req = self.inner.get(url);
        
        // Add custom headers
        req = req.headers(self.headers.clone());
        
        // Add cookies
        if !self.cookies.is_empty() {
            let cookie_str = self.cookies.iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect::<Vec<_>>()
                .join("; ");
            req = req.header(COOKIE, cookie_str);
        }

        let resp = req.send().await.context("Failed to send request")?;
        debug!("GET {} -> {}", url, resp.status());
        
        Ok(resp)
    }

    pub async fn get_with_headers(&self, url: &str, headers: HeaderMap) -> Result<Response> {
        let mut combined_headers = self.headers.clone();
        for (key, value) in headers.iter() {
            combined_headers.insert(key, value.clone());
        }

        let resp = self.inner
            .get(url)
            .headers(combined_headers)
            .send()
            .await
            .context("Failed to send request with custom headers")?;
            
        debug!("GET {} with custom headers -> {}", url, resp.status());
        
        Ok(resp)
    }

    pub async fn detect_cache_behavior(&self, url: &str) -> Result<CacheBehavior> {
        // First request to potentially cache the response
        let resp1 = self.get(url).await?;
        let headers1 = resp1.headers().clone();
        let body1 = resp1.text().await?;

        // Small delay to ensure proper caching
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Second request to check if response is cached
        let resp2 = self.get(url).await?;
        let headers2 = resp2.headers().clone();
        let body2 = resp2.text().await?;

        // Check for common cache headers
        let has_cache_headers = headers1.contains_key("x-cache") 
            || headers1.contains_key("cf-cache-status")
            || headers1.contains_key("age")
            || headers1.contains_key("cache-control");

        // Compare responses
        if body1 == body2 {
            if has_cache_headers {
                let cache_status = self.analyze_cache_headers(&headers1);
                Ok(cache_status)
            } else {
                Ok(CacheBehavior::PotentiallyCached)
            }
        } else {
            Ok(CacheBehavior::Dynamic)
        }
    }

    fn analyze_cache_headers(&self, headers: &HeaderMap) -> CacheBehavior {
        if let Some(cc) = headers.get("cache-control") {
            let cc_str = cc.to_str().unwrap_or("");
            if cc_str.contains("no-store") || cc_str.contains("no-cache") {
                return CacheBehavior::NotCached;
            }
        }

        if headers.contains_key("x-cache") || headers.contains_key("cf-cache-status") {
            return CacheBehavior::Cached;
        }

        if headers.contains_key("age") {
            return CacheBehavior::Cached;
        }

        CacheBehavior::PotentiallyCached
    }

    pub async fn test_cache_headers(&self, url: &str) -> Result<CacheHeaderInfo> {
        let response = self.get(url).await?;
        let headers = response.headers();

        let mut info = CacheHeaderInfo {
            cache_control: headers.get("cache-control")
                .and_then(|v| v.to_str().ok())
                .map(String::from),
            etag: headers.get("etag")
                .and_then(|v| v.to_str().ok())
                .map(String::from),
            last_modified: headers.get("last-modified")
                .and_then(|v| v.to_str().ok())
                .map(String::from),
            expires: headers.get("expires")
                .and_then(|v| v.to_str().ok())
                .map(String::from),
            vary: headers.get("vary")
                .and_then(|v| v.to_str().ok())
                .map(String::from),
            age: headers.get("age")
                .and_then(|v| v.to_str().ok())
                .map(String::from),
            pragma: headers.get("pragma")
                .and_then(|v| v.to_str().ok())
                .map(String::from),
            custom_cache_headers: HashMap::new(),
        };

        // Look for custom cache headers
        for (name, value) in headers.iter() {
            let name_str = name.as_str().to_lowercase();
            if name_str.contains("cache") || name_str.starts_with("x-cache") {
                if let Ok(value_str) = value.to_str() {
                    info.custom_cache_headers.insert(
                        name_str,
                        value_str.to_string()
                    );
                }
            }
        }

        Ok(info)
    }
}

#[derive(Debug)]
pub struct ClientBuilder {
    timeout: Duration,
    follow_redirects: bool,
    max_redirects: u32,
    verify_ssl: bool,
    headers: HeaderMap,
    cookies: HashMap<String, String>,
}

impl ClientBuilder {
    pub fn new() -> Self {
        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, HeaderValue::from_static(DEFAULT_USER_AGENT));

        Self {
            timeout: Duration::from_secs(30),
            follow_redirects: true,
            max_redirects: 10,
            verify_ssl: true,
            headers,
            cookies: HashMap::new(),
        }
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn follow_redirects(mut self, follow: bool) -> Self {
        self.follow_redirects = follow;
        self
    }

    pub fn max_redirects(mut self, max: u32) -> Self {
        self.max_redirects = max;
        self
    }

    pub fn verify_ssl(mut self, verify: bool) -> Self {
        self.verify_ssl = verify;
        self
    }

    pub fn add_header(mut self, name: &str, value: &str) -> Result<Self> {
        let header_name = HeaderName::from_bytes(name.as_bytes())
            .context("Invalid header name")?;
        let header_value = HeaderValue::from_str(value)
            .context("Invalid header value")?;
        
        self.headers.insert(header_name, header_value);
        Ok(self)
    }

    pub fn add_headers(mut self, headers: Vec<String>) -> Result<Self> {
        for header in headers {
            let parts: Vec<&str> = header.splitn(2, ':').collect();
            if parts.len() != 2 {
                warn!("Invalid header format: {}", header);
                continue;
            }
            let name = parts[0].trim();
            let value = parts[1].trim();
            self = self.add_header(name, value)?;
        }
        Ok(self)
    }

    pub fn add_cookie(mut self, name: String, value: String) -> Self {
        self.cookies.insert(name, value);
        self
    }

    pub fn add_cookies(mut self, cookies: Vec<String>) -> Self {
        for cookie in cookies {
            let parts: Vec<&str> = cookie.splitn(2, '=').collect();
            if parts.len() != 2 {
                warn!("Invalid cookie format: {}", cookie);
                continue;
            }
            self.cookies.insert(parts[0].to_string(), parts[1].to_string());
        }
        self
    }

    pub fn build(self) -> Result<Client> {
        let redirect_policy = if self.follow_redirects {
            Policy::limited(self.max_redirects as usize)
        } else {
            Policy::none()
        };

        let client = ReqwestClient::builder()
            .timeout(self.timeout)
            .redirect(redirect_policy)
            .danger_accept_invalid_certs(!self.verify_ssl)
            .build()
            .context("Failed to build HTTP client")?;

        Ok(Client {
            inner: client,
            headers: self.headers,
            cookies: self.cookies,
        })
    }
}

#[derive(Debug, PartialEq)]
pub enum CacheBehavior {
    Cached,
    NotCached,
    PotentiallyCached,
    Dynamic,
}

#[derive(Debug)]
pub struct CacheHeaderInfo {
    pub cache_control: Option<String>,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub expires: Option<String>,
    pub vary: Option<String>,
    pub age: Option<String>,
    pub pragma: Option<String>,
    pub custom_cache_headers: HashMap<String, String>,
} 