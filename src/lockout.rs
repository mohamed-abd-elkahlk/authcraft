//! # Lockout Manager
//!
//! This module provides a login lockout mechanism using Redis to prevent brute-force attacks.
//! It tracks failed login attempts, enforces lockout policies, and resets counts after a duration.
//!
//! ## Features
//! - Tracks failed login attempts per user
//! - Enforces a lockout policy after `N` attempts
//! - Auto-resets after a configurable duration
//! - Uses Redis for fast in-memory tracking
//!
//! ## Example Usage
//! ```rust
//! use authcraft::lockout::{LockoutStorage, RedisLockout};
//!
//! #[tokio::main]
//! async fn main() {
//!     let lockout = RedisLockout::new("redis://127.0.0.1/", 5, 300);
//!     let user_key = "failed_login:user123";
//!
//!     // Record failed attempt
//!     lockout.record_failure(user_key).await.unwrap();
//!
//!     // Check if locked out
//!     let locked = lockout.is_locked_out(user_key).await.unwrap();
//!     println!("User locked out? {}", locked);
//!
//!     // Reset failed attempts
//!     lockout.reset_attempts(user_key).await.unwrap();
//! }
//! ```

use async_trait::async_trait;
use redis::{AsyncCommands, RedisError};

/// Trait for managing login lockout mechanisms.
/// This abstracts the storage backend (e.g., Redis).
#[async_trait]
pub trait LockoutStorage: Send + Sync {
    /// Records a failed login attempt for the given user key.
    /// Increments the attempt count and sets an expiration time.
    async fn record_failure(&self, key: &str) -> Result<(), RedisError>;

    /// Checks if the user is locked out based on the number of failed attempts.
    async fn is_locked_out(&self, key: &str) -> Result<bool, RedisError>;

    /// Resets the failed login attempts for the given user key.
    async fn reset_attempts(&self, key: &str) -> Result<(), RedisError>;
}

/// Redis-based implementation of `LockoutStorage`.
/// It tracks failed login attempts and determines if an account should be locked.
pub struct RedisLockout {
    client: redis::Client,
    max_attempts: i32,
    lockout_duration: usize, // in seconds
}

impl RedisLockout {
    /// Creates a new `RedisLockout` instance with a Redis URL.
    ///
    /// # Arguments
    ///
    /// * `redis_url` - The Redis connection string.
    /// * `max_attempts` - The number of failed attempts before lockout.
    /// * `lockout_duration` - The time (in seconds) before failed attempts reset.
    ///
    /// # Example
    /// ```rust
    /// use authcraft::lockout::RedisLockout;
    /// let lockout = RedisLockout::new("redis://127.0.0.1/", 5, 300);
    /// ```
    pub fn new(redis_url: &str, max_attempts: i32, lockout_duration: usize) -> Self {
        let client = redis::Client::open(redis_url).expect("Failed to connect to Redis");
        Self {
            client,
            max_attempts,
            lockout_duration,
        }
    }
    /// Creates a new `RedisLockout` instance from environment variables.
    ///
    /// Expected environment variables:
    /// - REDIS_URL: Redis connection string
    /// - MAX_ATTEMPTS: Maximum number of failed attempts before lockout
    /// - LOCKOUT_DURATION: Duration in seconds before attempts reset
    ///
    /// # Example
    /// ```rust
    /// use authcraft::lockout::RedisLockout;
    /// let lockout = RedisLockout::from_env().expect("Failed to init lockout");
    /// ```
    pub fn from_env() -> Result<Self, String> {
        dotenv::dotenv().ok();
        let redis_url = std::env::var("REDIS_URL").map_err(|_| "REDIS_URL not set")?;

        let max_attempts = std::env::var("MAX_ATTEMPTS")
            .map_err(|_| "MAX_ATTEMPTS not set")?
            .parse::<i32>()
            .map_err(|_| "Invalid MAX_ATTEMPTS value")?;

        let lockout_duration = std::env::var("LOCKOUT_DURATION")
            .map_err(|_| "LOCKOUT_DURATION not set")?
            .parse::<usize>()
            .map_err(|_| "Invalid LOCKOUT_DURATION value")?;

        Ok(Self::new(&redis_url, max_attempts, lockout_duration))
    }
}
#[async_trait]
impl LockoutStorage for RedisLockout {
    /// Records a failed authentication attempt in Redis.
    ///
    /// # Arguments
    /// - `key`: A unique key identifying the user (e.g., email or IP address).
    ///
    /// # Returns
    /// - `Ok(())` if the failure is recorded successfully.
    /// - `Err(RedisError)` if there is an issue with Redis.
    ///
    /// # Behavior
    /// - Increments the failure count.
    /// - If it's the first failure, sets an expiration time on the key.
    ///
    async fn record_failure(&self, key: &str) -> Result<(), RedisError> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let count: i32 = conn.incr(key, 1).await?;
        if count == 1 {
            let _: () = conn.expire(key, self.lockout_duration as i64).await?; // Set expiry only on first attempt
        }
        Ok(())
    }

    /// Checks if a user is locked out due to excessive failed attempts.
    ///
    /// # Arguments
    /// - `key`: A unique key identifying the user.
    ///
    /// # Returns
    /// - `Ok(true)` if the user is locked out.
    /// - `Ok(false)` if the user is not locked out.
    /// - `Err(RedisError)` if there is an issue with Redis.

    async fn is_locked_out(&self, key: &str) -> Result<bool, RedisError> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let count: Option<i32> = conn.get(key).await.ok(); // Handle missing key gracefully
        Ok(count.unwrap_or(0) >= self.max_attempts)
    }

    /// Resets the failed attempt count for a user.
    ///
    /// # Arguments
    /// - `key`: A unique key identifying the user.
    ///
    /// # Returns
    /// - `Ok(())` if the attempts are reset successfully.
    /// - `Err(RedisError)` if there is an issue with Redis.
    async fn reset_attempts(&self, key: &str) -> Result<(), RedisError> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let _: () = conn.del(key).await?;
        Ok(())
    }
}
