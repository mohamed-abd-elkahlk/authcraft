extern crate bcrypt;

use bcrypt::{DEFAULT_COST, hash, verify};
use chrono::{Duration, Utc};
use rand::{Rng, distr::Alphanumeric, rng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::AuthError;

#[derive(Debug, Deserialize, Serialize)]
pub struct RequestPasswordResetRequest {
    pub email: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ResetPasswordRequest {
    pub token: String,
    pub new_password: String,
}

// Generate a secure random token
pub fn generate_reset_token() -> String {
    generate_secure_token() // Use the combined approach
}

// Generate a random string
pub fn generate_random_string(length: usize) -> String {
    let rng = rng();
    let random_string: String = rng
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect();
    random_string
}

// Generate a secure digest (SHA-256 hash)
pub fn generate_secure_digest(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let result = hasher.finalize();
    format!("{:x}", result)
}

// Generate a secure token (random string + hash)
pub fn generate_secure_token() -> String {
    let random_string = generate_random_string(32); // Generate a random string
    generate_secure_digest(&random_string) // Hash the random string
}

// Calculate token expiration (e.g., 24 hours from now) using chrono
pub fn calculate_expiry(duration: Duration) -> i64 {
    let now = Utc::now(); // Get the current time in UTC
    let expiry = now + duration; // Add the duration to the current time
    expiry.timestamp() // Convert to a Unix timestamp (seconds since epoch)
}

// Check if a token is expired using chrono
pub fn is_token_expired(expires_at: i64) -> bool {
    let now = Utc::now().timestamp(); // Get the current time in UTC as a timestamp
    now >= expires_at // Check if the current time is greater than or equal to the expiration time
}

pub fn hash_password(password: &str) -> Result<String, AuthError> {
    let hashed_password =
        hash(password, DEFAULT_COST).map_err(|e| AuthError::HashingError(e.to_string()))?;
    Ok(hashed_password)
}

pub fn verify_password(password: &str, hash: &str) -> Result<bool, AuthError> {
    let verified =
        verify(password, hash).map_err(|e| AuthError::InvalidCredentials(e.to_string()))?;
    Ok(verified)
}
