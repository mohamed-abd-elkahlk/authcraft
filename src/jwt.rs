//! JWT Authentication Module
//!
//! This module provides functionality for issuing and verifying JSON Web Tokens (JWT).
//!
//! ## Example Usage
//!
//! ```rust
//! use authcarft::jwt::{JwtConfig, issue_jwt, verify_jwt};
//! use serde::{Deserialize, Serialize};
//!
//! #[derive(Debug, Clone, Serialize, Deserialize)]
//! struct CustomPayload {
//!     role: String,
//! }
//!
//! let config = JwtConfig::new("my_secret_key".to_string(), 7);
//! let token = issue_jwt(config.clone(), "user123".to_string(), Some(CustomPayload { role: "admin".to_string() }), vec!["admin".to_string()]).unwrap();
//!
//! let claims: Claims<CustomPayload> = verify_jwt(&config, &token).unwrap();
//! println!("Decoded JWT Claims: {:?}", claims);
//! ```

use chrono::{Duration, Utc};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};

use crate::error::AuthCraftError;

/// Struct representing JWT claims, which includes standard fields and a custom payload.
///
/// # Generic Parameters
/// * `C` - Optional custom payload data.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Claims<C> {
    /// Subject (user ID or identifier).
    pub sub: String,
    /// Expiration timestamp (Unix epoch time).
    pub exp: usize,
    /// Issued-at timestamp (Unix epoch time).
    pub iat: usize,
    /// Optional custom payload.
    pub payload: Option<C>,
    /// List of roles assigned to the subject.
    pub roles: Vec<String>,
}

/// Configuration for JWT token generation and validation.
#[derive(Debug, Clone)]
pub struct JwtConfig {
    /// Secret key used for signing and verifying tokens.
    pub secret: String,
    /// Expiration period in days.
    pub expiration_days: i64,
}

impl JwtConfig {
    /// Creates a new JWT configuration.
    ///
    /// # Arguments
    ///
    /// * `secret` - The secret key used for signing JWTs.
    /// * `expiration_days` - Number of days before the token expires.
    ///
    /// # Example
    ///
    /// ```
    /// use authcraft::jwt::JwtConfig;
    ///
    /// let config = JwtConfig::new("super_secret_key".to_string(), 7);
    /// ```
    pub fn new(secret: String, expiration_days: i64) -> Self {
        Self {
            secret,
            expiration_days,
        }
    }
}

/// Issues a new JWT token.
///
/// # Arguments
///
/// * `config` - The JWT configuration.
/// * `sub` - The subject (user identifier).
/// * `payload` - Optional custom payload.
/// * `roles` - A list of roles assigned to the subject.
///
/// # Returns
///
/// Returns a JWT as a `String`, or an error if token generation fails.
///
/// # Example
///
/// ```
/// use authcraft::jwt::{JwtConfig, issue_jwt};
///
/// let config = JwtConfig::new("my_secret".to_string(), 7);
/// let token = issue_jwt(config, "user123".to_string(), None::<()>, vec!["user".to_string()]).unwrap();
/// println!("Generated JWT: {}", token);
/// ```
pub fn issue_jwt<C: Serialize>(
    config: JwtConfig,
    sub: String,
    payload: Option<C>,
    roles: Vec<String>,
) -> Result<String, AuthCraftError> {
    let expiration = Utc::now()
        .checked_add_signed(Duration::days(config.expiration_days))
        .expect("Invalid timestamp")
        .timestamp() as usize;

    let claims = Claims {
        sub,
        exp: expiration,
        iat: Utc::now().timestamp() as usize,
        payload,
        roles,
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(config.secret.as_ref()),
    )
    .map_err(|e| AuthCraftError::CustomError(e.to_string()))?;
    Ok(token)
}

/// Verifies a JWT token and extracts its claims.
///
/// # Arguments
///
/// * `config` - The JWT configuration.
/// * `token` - The JWT token as a string.
///
/// # Returns
///
/// Returns the decoded `Claims` struct if the token is valid.
///
/// # Example
///
/// ```
/// use authcraft::jwt::{JwtConfig, issue_jwt, verify_jwt};
///
/// let config = JwtConfig::new("my_secret".to_string(), 7);
/// let token = issue_jwt(config.clone(), "user123".to_string(), None::<()>, vec!["user".to_string()]).unwrap();
///
/// let claims = verify_jwt::<()>(&config, &token).unwrap();
/// println!("Decoded Claims: {:?}", claims);
/// ```
pub fn verify_jwt<C: for<'de> Deserialize<'de>>(
    config: &JwtConfig,
    token: &str,
) -> Result<Claims<C>, jsonwebtoken::errors::Error> {
    let token_data = decode::<Claims<C>>(
        token,
        &DecodingKey::from_secret(config.secret.as_ref()),
        &Validation::default(),
    )?;

    Ok(token_data.claims)
}
