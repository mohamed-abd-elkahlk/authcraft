//! Password Reset and Authentication Utilities
//!
//! This module provides functionalities for password hashing, verification,
//! and secure token generation for password reset processes.
//!
//! ## Example Usage
//!
//! ```
//! use authcraft::security::{
//!     generate_reset_token, hash_password, verify_password,
//!     calculate_expiry, is_token_expired,
//! };
//! use chrono::Duration;
//!
//! // Generate a reset token
//! let token = generate_reset_token();
//! println!("Generated token: {}", token);
//!
//! // Hash a password
//! let password = "my_secure_password";
//! let hashed_password = hash_password(password).unwrap();
//!
//! // Verify password
//! assert!(verify_password(password, &hashed_password).unwrap());
//!
//! // Check token expiration
//! let expiry_time = calculate_expiry(Duration::hours(24));
//! assert!(!is_token_expired(expiry_time));
//! ```
extern crate bcrypt;

use bcrypt::{DEFAULT_COST, hash, verify};
use chrono::{Duration, Utc};
use rand::{Rng, distr::Alphanumeric, rng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::AuthCraftError;

/// Struct for requesting a password reset.
#[derive(Debug, Deserialize, Serialize)]
pub struct RequestPasswordResetRequest {
    /// The email address of the user requesting a password reset.
    pub email: String,
}

/// Struct for resetting a password.
#[derive(Debug, Deserialize, Serialize)]
pub struct ResetPasswordRequest {
    /// The reset token provided to the user.
    pub token: String,
    /// The new password the user wants to set.
    pub new_password: String,
}

/// Generates a secure random reset token.
///
/// # Returns
///
/// Returns a hashed random string that serves as a password reset token.
///
/// # Example
///
/// ```
/// use authcraft::security::generate_reset_token;
///
/// let token = generate_reset_token();
/// println!("Generated reset token: {}", token);
/// ```
pub fn generate_reset_token() -> String {
    generate_secure_token() // Use the combined approach
}

/// Generates a random alphanumeric string of the specified length.
///
/// # Arguments
///
/// * `length` - The length of the random string to generate.
///
/// # Returns
///
/// Returns a random string of the specified length.
///
/// # Example
///
/// ```
/// use authcraft::security::generate_random_string;
///
/// let random_str = generate_random_string(16);
/// println!("Generated string: {}", random_str);
/// assert_eq!(random_str.len(), 16);
/// ```
pub fn generate_random_string(length: usize) -> String {
    let rng = rng();
    let random_string: String = rng
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect();
    random_string
}

/// Generates a SHA-256 hash of a given input string.
///
/// # Arguments
///
/// * `input` - The input string to hash.
///
/// # Returns
///
/// Returns a hexadecimal string representing the SHA-256 hash of the input.
///
/// # Example
///
/// ```
/// use authcraft::security::generate_secure_digest;
///
/// let digest = generate_secure_digest("secure_input");
/// println!("SHA-256 digest: {}", digest);
/// ```
pub fn generate_secure_digest(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let result = hasher.finalize();
    format!("{:x}", result)
}

/// Generates a secure token by creating a random string and hashing it.
///
/// # Returns
///
/// Returns a hashed secure token.
///
/// # Example
///
/// ```
/// use authcraft::security::generate_secure_token;
///
/// let token = generate_secure_token();
/// println!("Generated secure token: {}", token);
/// ```
pub fn generate_secure_token() -> String {
    let random_string = generate_random_string(32); // Generate a random string
    generate_secure_digest(&random_string) // Hash the random string
}

/// Calculates the expiration timestamp for a token.
///
/// # Arguments
///
/// * `duration` - The duration (e.g., 24 hours) for token validity.
///
/// # Returns
///
/// Returns the Unix timestamp representing the expiration time.
///
/// # Example
///
/// ```
/// use chrono::Duration;
/// use authcraft::security::calculate_expiry;
///
/// let expiry_time = calculate_expiry(Duration::hours(24));
/// println!("Token expires at: {}", expiry_time);
/// ```
pub fn calculate_expiry(duration: Duration) -> i64 {
    let now = Utc::now(); // Get the current time in UTC
    let expiry = now + duration; // Add the duration to the current time
    expiry.timestamp() // Convert to a Unix timestamp (seconds since epoch)
}

/// Checks if a given token has expired.
///
/// # Arguments
///
/// * `expires_at` - The Unix timestamp representing the expiration time.
///
/// # Returns
///
/// Returns `true` if the token has expired, otherwise `false`.
///
/// # Example
///
/// ```
/// use chrono::Duration;
/// use authcraft::security::{calculate_expiry, is_token_expired};
///
/// let expiry_time = calculate_expiry(Duration::hours(24));
/// assert!(!is_token_expired(expiry_time));
/// ```
pub fn is_token_expired(expires_at: i64) -> bool {
    let now = Utc::now().timestamp(); // Get the current time in UTC as a timestamp
    now >= expires_at // Check if the current time is greater than or equal to the expiration time
}

/// Hashes a password securely using bcrypt.
///
/// # Arguments
///
/// * `password` - The plaintext password to hash.
///
/// # Returns
///
/// Returns a `Result` containing the hashed password, or an error if hashing fails.
///
/// # Example
///
/// ```
/// use authcraft::security::hash_password;
///
/// let hashed_password = hash_password("my_password").unwrap();
/// println!("Hashed password: {}", hashed_password);
/// ```

pub fn hash_password(password: &str) -> Result<String, AuthCraftError> {
    let hashed_password =
        hash(password, DEFAULT_COST).map_err(|e| AuthCraftError::HashingError(e.to_string()))?;
    Ok(hashed_password)
}

/// Verifies a plaintext password against a hashed password.
///
/// # Arguments
///
/// * `password` - The plaintext password.
/// * `hash` - The hashed password to compare against.
///
/// # Returns
///
/// Returns a `Result` indicating whether the password is correct.
///
/// # Example
///
/// ```
/// use authcraft::security::{hash_password, verify_password};
///
/// let password = "super_secret";
/// let hashed = hash_password(password).unwrap();
///
/// assert!(verify_password(password, &hashed).unwrap());
/// ```
pub fn verify_password(password: &str, hash: &str) -> Result<bool, AuthCraftError> {
    let verified =
        verify(password, hash).map_err(|e| AuthCraftError::InvalidCredentials(e.to_string()))?;
    Ok(verified)
}
