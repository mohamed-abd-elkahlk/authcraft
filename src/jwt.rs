use chrono::{Duration, Utc};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};

use super::*;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Claims<C> {
    pub sub: String,
    pub exp: usize,
    pub iat: usize,
    pub extra_data: Option<C>,
}
#[derive(Debug, Clone)]
pub struct JwtConfig {
    pub secret: String,
    pub expiration_days: i64,
}

impl JwtConfig {
    pub fn new(secret: String, expiration_days: i64) -> Self {
        Self {
            secret,
            expiration_days,
        }
    }
}

/// Issue a JWT
pub fn issue_jwt<C: Serialize>(
    config: JwtConfig,
    sub: String,
    extra_data: Option<C>,
) -> Result<String, AuthError> {
    let expiration = Utc::now()
        .checked_add_signed(Duration::days(config.expiration_days))
        .expect("Invalid timestamp")
        .timestamp() as usize;

    let claims = Claims {
        sub,
        exp: expiration,
        iat: Utc::now().timestamp() as usize,
        extra_data,
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(config.secret.as_ref()),
    )
    .map_err(|e| AuthError::CustomError(e.to_string()))?;
    Ok(token)
}

/// Verify a JWT
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
