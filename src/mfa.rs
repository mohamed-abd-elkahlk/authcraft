//! Multi-Factor Authentication (MFA) Module
//!
//! This module provides support for multiple MFA methods, including:
//! - Time-based One-Time Passwords (TOTP) using Google Authenticator.
//! - Email-based OTP verification.
//! - Backup codes for account recovery.
//!
//! # Example Usage
//! ```rust
//! use crate::mfa::{MfaSettings, MfaType};
//!
//! let mut settings = MfaSettings {
//!     method: MfaType::Totp,
//!     secret: Some(MfaSettings::generate_totp_secret().unwrap()),
//!     backup_codes: Some(MfaSettings::generate_backup_codes(5, 10)),
//! };
//!
//! let code = "123456"; // Example TOTP code
//! let is_valid = MfaSettings::verify_totp_code(settings.secret.as_ref().unwrap(), code).unwrap();
//! println!("Is the TOTP code valid? {}", is_valid);
//! ```

use crate::error::AuthCraftError;
use rand::{Rng, RngCore, distr::Alphanumeric};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use totp_rs::{Algorithm, TOTP};

/// Enumeration of supported MFA types.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub enum MfaType {
    /// Time-based One-Time Passwords (TOTP) using Google Authenticator.
    Totp,
    /// One-time passcodes sent via email.
    Email,
    /// A set of predefined backup codes for account recovery.
    BackupCodes,
}

/// Configuration settings for Multi-Factor Authentication (MFA).
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct MfaSettings {
    /// The selected MFA method.
    pub method: MfaType,
    /// The secret key used for TOTP.
    pub secret: Option<String>,
    /// A list of backup codes for account recovery.
    pub backup_codes: Option<Vec<String>>,
}

impl MfaSettings {
    /// Generates a new TOTP secret for Google Authenticator.
    ///
    /// # Returns
    /// * `Ok(String)` - The generated Base32-encoded secret key.
    /// * `Err(AuthError)` - If secret generation fails.
    pub fn generate_totp_secret() -> Result<String, AuthCraftError> {
        let mut seed = [0u8; 20]; // 20 bytes = 160 bits
        rand::rng().fill_bytes(&mut seed);

        let totp = TOTP::new(
            Algorithm::SHA1,
            6,  // OTP Length
            1,  // Time step (30 seconds)
            30, // Expiry (seconds)
            seed.to_vec(),
        )
        .map_err(|e| AuthCraftError::InternalServerError(e.to_string()))?;
        Ok(totp.get_secret_base32())
    }

    /// Verifies a TOTP code using a given secret.
    ///
    /// # Arguments
    /// * `secret` - The Base32-encoded secret key.
    /// * `user_code` - The TOTP code provided by the user.
    ///
    /// # Returns
    /// * `Ok(true)` if the code is valid.
    /// * `Ok(false)` if the code is invalid.
    /// * `Err(AuthError)` if there is an internal error.
    pub fn verify_totp_code(secret: &str, user_code: &str) -> Result<bool, AuthCraftError> {
        let secret_bytes =
            match base32::decode(base32::Alphabet::Rfc4648 { padding: false }, secret) {
                Some(bytes) => bytes,
                None => return Ok(false),
            };

        let totp = match TOTP::new(Algorithm::SHA1, 6, 1, 30, secret_bytes) {
            Ok(t) => t,
            Err(_) => return Ok(false),
        };

        let time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| AuthCraftError::InvalidOtp(e.to_string()))?
            .as_secs();

        Ok(totp.check(user_code, time))
    }

    /// Generates a list of alphanumeric backup codes.
    ///
    /// # Arguments
    /// * `count` - The number of backup codes to generate.
    /// * `length` - The length of each backup code.
    ///
    /// # Returns
    /// * `Vec<String>` - A vector containing the generated backup codes.
    pub fn generate_backup_codes(count: usize, length: usize) -> Vec<String> {
        let mut rng = rand::rng();
        let mut codes = Vec::with_capacity(count);

        for _ in 0..count {
            let code: String = (0..length)
                .map(|_| rng.sample(Alphanumeric) as char)
                .collect();
            codes.push(code);
        }

        codes
    }

    /// Verifies if a provided backup code is valid.
    ///
    /// # Arguments
    /// * `code` - The backup code to verify.
    ///
    /// # Returns
    /// * `Ok(true)` if the code is valid.
    /// * `Err(AuthError)` if the code is invalid or no backup codes are available.
    pub fn verify_backup_code(&self, code: &str) -> Result<bool, AuthCraftError> {
        if let Some(backup_codes) = &self.backup_codes {
            if backup_codes.contains(&code.to_string()) {
                Ok(true)
            } else {
                Err(AuthCraftError::InvalidBackupCode(
                    "Invalid backup code".to_string(),
                ))
            }
        } else {
            Err(AuthCraftError::InvalidBackupCode(
                "No backup codes available".to_string(),
            ))
        }
    }

    /// Marks a backup code as used by removing it from the list.
    ///
    /// # Arguments
    /// * `code` - The backup code to mark as used.
    ///
    /// # Returns
    /// * `Ok(())` if the operation was successful.
    /// * `Err(AuthError)` if the code was not found or no backup codes are available.
    pub fn mark_backup_code_as_used(&mut self, code: &str) -> Result<(), AuthCraftError> {
        if let Some(backup_codes) = &mut self.backup_codes {
            if let Some(index) = backup_codes.iter().position(|c| c == code) {
                backup_codes.remove(index);
                Ok(())
            } else {
                Err(AuthCraftError::InvalidBackupCode(
                    "Backup code not found".to_string(),
                ))
            }
        } else {
            Err(AuthCraftError::InvalidBackupCode(
                "No backup codes available".to_string(),
            ))
        }
    }
}
