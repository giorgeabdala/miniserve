use std::{
    collections::HashMap,
    future::{Ready, ready},
    net::IpAddr,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

use actix_web::{
    Error, Result,
    body::MessageBody,
    dev::{Service, ServiceRequest, ServiceResponse, Transform, forward_ready},
    http::header::{HeaderName, HeaderValue},
};
use futures::future::LocalBoxFuture;
use log::{debug, info, warn};

/// Configuration for security middleware
#[derive(Debug, Clone)]
pub struct SecurityConfig {
    /// Enable security headers
    pub enable_security_headers: bool,
    /// Enable rate limiting
    pub enable_rate_limiting: bool,
    /// Maximum request size in bytes
    pub max_request_size: usize,
    /// Rate limit configuration
    pub rate_limit_config: RateLimitConfig,
    /// Security headers configuration
    pub headers_config: SecurityHeadersConfig,
}

/// Rate limiting configuration
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Maximum requests per window
    pub max_requests: u32,
    /// Time window duration in seconds
    pub window_size: u64,
    /// Enable burst handling
    pub enable_burst: bool,
    /// Burst size limit
    pub burst_size: u32,
}

/// Security headers configuration
#[derive(Debug, Clone)]
pub struct SecurityHeadersConfig {
    /// Content Security Policy header value
    pub csp: Option<String>,
    /// HTTP Strict Transport Security max-age
    pub hsts_max_age: Option<u32>,
    /// Enable HSTS includeSubDomains
    pub hsts_include_subdomains: bool,
    /// X-Frame-Options value
    pub x_frame_options: String,
    /// X-Content-Type-Options value
    pub x_content_type_options: String,
    /// X-XSS-Protection value
    pub x_xss_protection: String,
    /// Referrer-Policy value
    pub referrer_policy: String,
    /// Permissions-Policy value
    pub permissions_policy: Option<String>,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            enable_security_headers: true,
            enable_rate_limiting: false,
            max_request_size: 100 * 1024 * 1024, // 100MB
            rate_limit_config: RateLimitConfig::default(),
            headers_config: SecurityHeadersConfig::default(),
        }
    }
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_requests: 60,
            window_size: 60, // 1 minute
            enable_burst: true,
            burst_size: 10,
        }
    }
}

impl Default for SecurityHeadersConfig {
    fn default() -> Self {
        Self {
            csp: Some("default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none';".to_string()),
            hsts_max_age: Some(31536000), // 1 year
            hsts_include_subdomains: true,
            x_frame_options: "DENY".to_string(),
            x_content_type_options: "nosniff".to_string(),
            x_xss_protection: "1; mode=block".to_string(),
            referrer_policy: "strict-origin-when-cross-origin".to_string(),
            permissions_policy: Some("geolocation=(), microphone=(), camera=()".to_string()),
        }
    }
}

/// Rate limiting data structure using sliding window algorithm
#[derive(Debug)]
pub struct SlidingWindow {
    requests: Vec<Instant>,
    last_cleanup: Instant,
    burst_count: u32,
    last_burst_reset: Instant,
}

impl SlidingWindow {
    fn new() -> Self {
        let now = Instant::now();
        Self {
            requests: Vec::new(),
            last_cleanup: now,
            burst_count: 0,
            last_burst_reset: now,
        }
    }

    fn check_rate_limit(&mut self, config: &RateLimitConfig) -> bool {
        let now = Instant::now();
        let window_duration = Duration::from_secs(config.window_size);

        // Clean up old requests (sliding window)
        if now.duration_since(self.last_cleanup) > Duration::from_secs(5) {
            self.requests
                .retain(|&time| now.duration_since(time) <= window_duration);
            self.last_cleanup = now;
        }

        // Reset burst counter every window
        if now.duration_since(self.last_burst_reset) >= window_duration {
            self.burst_count = 0;
            self.last_burst_reset = now;
        }

        // Check burst limit
        if config.enable_burst && self.burst_count >= config.burst_size {
            return false;
        }

        // Check sliding window limit
        if self.requests.len() as u32 >= config.max_requests {
            return false;
        }

        // Record the request
        self.requests.push(now);
        if config.enable_burst {
            self.burst_count += 1;
        }

        true
    }
}

/// Rate limiter state
type RateLimiterState = Arc<RwLock<HashMap<IpAddr, SlidingWindow>>>;

/// Security middleware factory
#[derive(Clone)]
pub struct SecurityMiddleware {
    config: SecurityConfig,
    pub rate_limiter: RateLimiterState,
}

impl SecurityMiddleware {
    pub fn new(config: SecurityConfig) -> Self {
        Self {
            config,
            rate_limiter: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl<S, B> Transform<S, ServiceRequest> for SecurityMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = SecurityMiddlewareService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(SecurityMiddlewareService {
            service,
            config: self.config.clone(),
            rate_limiter: self.rate_limiter.clone(),
        }))
    }
}

pub struct SecurityMiddlewareService<S> {
    service: S,
    config: SecurityConfig,
    rate_limiter: RateLimiterState,
}

impl<S, B> Service<ServiceRequest> for SecurityMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let start_time = Instant::now();

        // Check request size limit
        if let Some(content_length) = req.headers().get("content-length") {
            if let Ok(size_str) = content_length.to_str() {
                if let Ok(size) = size_str.parse::<usize>() {
                    if size > self.config.max_request_size {
                        warn!(
                            "Request size {} exceeds limit {}",
                            size, self.config.max_request_size
                        );
                        // Use simplified error return
                        return Box::pin(async {
                            Err(actix_web::error::ErrorPayloadTooLarge(
                                "Request size exceeds limit",
                            ))
                        });
                    }
                }
            }
        }

        let client_ip = extract_client_ip(&req);

        // Check rate limit
        if self.config.enable_rate_limiting {
            let mut rate_limiter = match self.rate_limiter.write() {
                Ok(limiter) => limiter,
                Err(_) => {
                    warn!("Failed to acquire rate limiter lock");
                    return Box::pin(async {
                        Err(actix_web::error::ErrorInternalServerError(
                            "Rate limiter error",
                        ))
                    });
                }
            };

            let window = rate_limiter
                .entry(client_ip)
                .or_insert_with(SlidingWindow::new);

            if !window.check_rate_limit(&self.config.rate_limit_config) {
                warn!("Rate limit exceeded for IP: {client_ip}");

                // Log security event
                log_security_event("RATE_LIMIT_EXCEEDED", &client_ip, &req);

                return Box::pin(async {
                    Err(actix_web::error::ErrorTooManyRequests(
                        "Rate limit exceeded",
                    ))
                });
            }
        }

        let config = self.config.clone();
        let fut = self.service.call(req);

        Box::pin(async move {
            let mut res = fut.await?;

            // Add security headers
            if config.enable_security_headers {
                add_security_headers(&mut res, &config.headers_config);
            }

            // Log performance if request took too long
            let duration = start_time.elapsed();
            if duration > Duration::from_millis(100) {
                debug!("Security middleware processing time: {duration:?} for IP: {client_ip}");
            }

            Ok(res)
        })
    }
}

/// Extract client IP address from request
fn extract_client_ip(req: &ServiceRequest) -> IpAddr {
    // Check X-Forwarded-For header first (for proxy setups)
    if let Some(xff) = req.headers().get("x-forwarded-for") {
        if let Ok(xff_str) = xff.to_str() {
            if let Some(ip_str) = xff_str.split(',').next() {
                if let Ok(ip) = ip_str.trim().parse::<IpAddr>() {
                    return ip;
                }
            }
        }
    }

    // Check X-Real-IP header
    if let Some(xri) = req.headers().get("x-real-ip") {
        if let Ok(xri_str) = xri.to_str() {
            if let Ok(ip) = xri_str.parse::<IpAddr>() {
                return ip;
            }
        }
    }

    // Fall back to connection info
    req.connection_info()
        .realip_remote_addr()
        .and_then(|addr| addr.parse::<IpAddr>().ok())
        .unwrap_or_else(|| "127.0.0.1".parse().unwrap())
}

/// Add security headers to response
fn add_security_headers<B>(res: &mut ServiceResponse<B>, config: &SecurityHeadersConfig) {
    let headers = res.headers_mut();

    // Content Security Policy
    if let Some(csp) = &config.csp {
        if let Ok(header_value) = HeaderValue::from_str(csp) {
            headers.insert(
                HeaderName::from_static("content-security-policy"),
                header_value,
            );
        }
    }

    // HTTP Strict Transport Security
    if let Some(max_age) = config.hsts_max_age {
        let hsts_value = if config.hsts_include_subdomains {
            format!("max-age={max_age}; includeSubDomains")
        } else {
            format!("max-age={max_age}")
        };

        if let Ok(header_value) = HeaderValue::from_str(&hsts_value) {
            headers.insert(
                HeaderName::from_static("strict-transport-security"),
                header_value,
            );
        }
    }

    // X-Frame-Options
    if let Ok(header_value) = HeaderValue::from_str(&config.x_frame_options) {
        headers.insert(HeaderName::from_static("x-frame-options"), header_value);
    }

    // X-Content-Type-Options
    if let Ok(header_value) = HeaderValue::from_str(&config.x_content_type_options) {
        headers.insert(
            HeaderName::from_static("x-content-type-options"),
            header_value,
        );
    }

    // X-XSS-Protection
    if let Ok(header_value) = HeaderValue::from_str(&config.x_xss_protection) {
        headers.insert(HeaderName::from_static("x-xss-protection"), header_value);
    }

    // Referrer-Policy
    if let Ok(header_value) = HeaderValue::from_str(&config.referrer_policy) {
        headers.insert(HeaderName::from_static("referrer-policy"), header_value);
    }

    // Permissions-Policy
    if let Some(permissions_policy) = &config.permissions_policy {
        if let Ok(header_value) = HeaderValue::from_str(permissions_policy) {
            headers.insert(HeaderName::from_static("permissions-policy"), header_value);
        }
    }
}

/// Log security events for monitoring
fn log_security_event(event_type: &str, client_ip: &IpAddr, req: &ServiceRequest) {
    let user_agent = req
        .headers()
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown");

    let path = req.path();
    let method = req.method().as_str();

    info!(
        "SECURITY_EVENT: {event_type} - IP: {client_ip} - Method: {method} - Path: {path} - User-Agent: {user_agent}"
    );
}

/// Cleanup old rate limiter entries periodically
pub fn cleanup_rate_limiter(rate_limiter: &RateLimiterState, max_age: Duration) {
    if let Ok(mut limiter) = rate_limiter.write() {
        let now = Instant::now();
        limiter.retain(|_, window| {
            // Remove entries that haven't been accessed recently
            now.duration_since(window.last_cleanup) < max_age
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_sliding_window_rate_limit() {
        let mut window = SlidingWindow::new();
        let config = RateLimitConfig {
            max_requests: 5,
            window_size: 1,
            enable_burst: true,
            burst_size: 3,
        };

        // First 3 requests should pass (within burst limit)
        assert!(window.check_rate_limit(&config));
        assert!(window.check_rate_limit(&config));
        assert!(window.check_rate_limit(&config));

        // Fourth request should fail (exceeds burst)
        assert!(!window.check_rate_limit(&config));

        // Wait for window to reset
        thread::sleep(Duration::from_secs(2));

        // Should work again after window reset
        assert!(window.check_rate_limit(&config));
    }

    #[test]
    fn test_security_config_defaults() {
        let config = SecurityConfig::default();
        assert!(config.enable_security_headers);
        assert!(!config.enable_rate_limiting);
        assert_eq!(config.max_request_size, 100 * 1024 * 1024);
    }

    #[test]
    fn test_security_headers_config_defaults() {
        let config = SecurityHeadersConfig::default();
        assert!(config.csp.is_some());
        assert_eq!(config.hsts_max_age, Some(31536000));
        assert!(config.hsts_include_subdomains);
        assert_eq!(config.x_frame_options, "DENY");
        assert_eq!(config.x_content_type_options, "nosniff");
    }

    #[test]
    fn test_rate_limit_config_defaults() {
        let config = RateLimitConfig::default();
        assert_eq!(config.max_requests, 60);
        assert_eq!(config.window_size, 60);
        assert!(config.enable_burst);
        assert_eq!(config.burst_size, 10);
    }
}
