//! # Session Management Module
//!
//! This module provides utilities for handling session management in an authentication system.
//! It includes functionalities to issue, store, validate, and remove access and refresh tokens
//! using JWT and Redis. This allows secure authentication with token-based sessions.
//!
//! ## Features
//! - Generate short-lived access tokens (15 minutes)
//! - Generate long-lived refresh tokens (7 days)
//! - Store refresh tokens in Redis
//! - Validate refresh tokens against stored values
//! - Remove refresh tokens upon logout
//!
//! ## Example Usage
//!
//! ```rust
//! use crate::session::{SessionManager, JwtConfig};
//! use tokio; // Ensure you have Tokio runtime for async operations
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let redis_url = "redis://127.0.0.1/"; // Redis instance
//!     let session_manager = SessionManager::new(redis_url)?;
//!
//!     let jwt_config = JwtConfig {
//!         secret: "super_secret_key".to_string(),
//!     };
//!
//!     // Issue an access token
//!     let access_token = session_manager.issue_access_token(
//!         &jwt_config,
//!         "user123".to_string(),
//!         None::<()>,
//!         vec!["admin".to_string()],
//!     )?;
//!     println!("Access Token: {}", access_token);
//!
//!     // Issue and store a refresh token
//!     let refresh_token = session_manager.issue_refresh_token(&jwt_config, "user123".to_string())?;
//!     session_manager.store_refresh_token("user123", &refresh_token).await?;
//!     println!("Refresh Token stored in Redis");
//!
//!     // Validate the refresh token
//!     let is_valid = session_manager.validate_refresh_token("user123", &refresh_token).await?;
//!     println!("Is refresh token valid? {}", is_valid);
//!
//!     // Remove refresh token on logout
//!     session_manager.remove_refresh_token("user123").await?;
//!     println!("Refresh token removed from Redis");
//!
//!     Ok(())
//! }
//! ```

use crate::error::AuthError;
use crate::jwt::JwtConfig;
use chrono::{Duration, Utc};
use jsonwebtoken::{EncodingKey, Header, encode};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};

/// Represents JWT session claims, including user ID, expiration, roles, and optional payload.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SessionClaims<C> {
    /// Subject identifier (User ID).
    pub sub: String,
    /// Expiration timestamp.
    pub exp: usize,
    /// Issued timestamp.
    pub iat: usize,
    /// Optional custom payload.
    pub payload: Option<C>,
    /// User roles.
    pub roles: Vec<String>,
    /// Indicates whether the token is a refresh token.
    pub refresh: bool,
}

/// Manages session-related tasks, such as issuing tokens and interacting with Redis.
#[derive(Clone)]
pub struct SessionManager {
    client: redis::Client,
}

impl SessionManager {
    /// Creates a new session manager with a Redis client.
    ///
    /// # Arguments
    /// * `redis_url` - The Redis connection string.
    ///
    /// # Returns
    /// * `Result<Self, redis::RedisError>` - The session manager instance or an error.
    pub fn new(redis_url: &str) -> Result<Self, redis::RedisError> {
        let client = redis::Client::open(redis_url)?;
        Ok(Self { client })
    }

    /// Issues an access token with a short lifespan (15 minutes).
    ///
    /// # Arguments
    /// * `config` - JWT configuration.
    /// * `sub` - The user ID.
    /// * `payload` - Optional custom payload.
    /// * `roles` - The user's roles.
    ///
    /// # Returns
    /// * `Result<String, AuthError>` - The generated JWT or an authentication error.
    pub fn issue_access_token<C: Serialize>(
        &self,
        config: &JwtConfig,
        sub: String,
        payload: Option<C>,
        roles: Vec<String>,
    ) -> Result<String, AuthError> {
        let expiration = Utc::now()
            .checked_add_signed(Duration::minutes(15))
            .expect("Invalid timestamp")
            .timestamp() as usize;

        let claims = SessionClaims {
            sub,
            exp: expiration,
            iat: Utc::now().timestamp() as usize,
            payload,
            roles,
            refresh: false, // Access token
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(config.secret.as_ref()),
        )
        .map_err(|e| AuthError::CustomError(e.to_string()))?;
        Ok(token)
    }

    /// Issues a refresh token with a lifespan of 7 days.
    ///
    /// # Arguments
    /// * `config` - JWT configuration.
    /// * `sub` - The user ID.
    ///
    /// # Returns
    /// * `Result<String, AuthError>` - The generated JWT or an authentication error.
    pub fn issue_refresh_token(
        &self,
        config: &JwtConfig,
        sub: String,
    ) -> Result<String, AuthError> {
        let expiration = Utc::now()
            .checked_add_signed(Duration::days(7))
            .expect("Invalid timestamp")
            .timestamp() as usize;

        let claims = SessionClaims::<()> {
            sub,
            exp: expiration,
            iat: Utc::now().timestamp() as usize,
            payload: None,
            roles: vec![],
            refresh: true, // Refresh token
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(config.secret.as_ref()),
        )
        .map_err(|e| AuthError::CustomError(e.to_string()))?;
        Ok(token)
    }

    /// Stores a refresh token in Redis with a 7-day expiration.
    ///
    /// # Arguments
    /// * `user_id` - The user ID.
    /// * `refresh_token` - The refresh token to store.
    ///
    /// # Returns
    /// * `Result<(), redis::RedisError>` - Success or Redis error.
    pub async fn store_refresh_token(
        &self,
        user_id: &str,
        refresh_token: &str,
    ) -> Result<(), redis::RedisError> {
        let mut con = self.client.get_multiplexed_async_connection().await?;
        let key = format!("refresh_token:{}", user_id);
        let expiry = 7 * 24 * 60 * 60; // 7 days expiry
        let _: () = con.set(key.clone(), refresh_token).await?;
        let _: () = con.expire(key, expiry).await?;
        Ok(())
    }

    /// Validates a refresh token by checking it in Redis.
    ///
    /// # Arguments
    /// * `user_id` - The user ID.
    /// * `token` - The token to validate.
    ///
    /// # Returns
    /// * `Result<bool, redis::RedisError>` - `true` if valid, `false` if invalid or missing.
    pub async fn validate_refresh_token(
        &self,
        user_id: &str,
        token: &str,
    ) -> Result<bool, redis::RedisError> {
        let mut con = self.client.get_multiplexed_async_connection().await?;
        let key = format!("refresh_token:{}", user_id);

        match con.get::<_, Option<String>>(&key).await {
            Ok(Some(stored_token)) => Ok(stored_token == token),
            Ok(None) => Ok(false), // No token stored
            Err(err) => Err(err),  // Propagate Redis error
        }
    }

    /// Removes a refresh token from Redis.
    ///
    /// # Arguments
    /// * `user_id` - The user ID.
    ///
    /// # Returns
    /// * `Result<(), redis::RedisError>` - Success or Redis error.
    pub async fn remove_refresh_token(&self, user_id: &str) -> Result<(), redis::RedisError> {
        let mut con = self.client.get_multiplexed_async_connection().await?;
        let key = format!("refresh_token:{}", user_id);
        let _: i32 = con.del(&key).await?; // Discard returned integer
        Ok(())
    }
}
