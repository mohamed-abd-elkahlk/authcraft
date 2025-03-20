use crate::error::AuthError;
use rand::{Rng, RngCore, distr::Alphanumeric};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use totp_rs::{Algorithm, TOTP};

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub enum MfaType {
    Totp,        // Google Authenticator (TOTP)
    Email,       // OTP via Email
    BackupCodes, // Backup codes for MFA recovery
}
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct MfaSettings {
    pub method: MfaType,                   // Which MFA type (TOTP or Email)
    pub secret: Option<String>,            // Used for TOTP (Google Authenticator)
    pub backup_codes: Option<Vec<String>>, // Backup codes for MFA recovery
}

impl MfaSettings {
    /// Generate a TOTP secret for Google Authenticator
    pub fn generate_totp_secret() -> Result<String, AuthError> {
        let mut seed = [0u8; 20]; // 20 bytes = 160 bits
        rand::rng().fill_bytes(&mut seed);

        let totp = TOTP::new(
            Algorithm::SHA1,
            6,  // OTP Length
            1,  // Time step (30 seconds)
            30, // Expiry (seconds)
            seed.to_vec(),
        )
        .map_err(|e| AuthError::InternalServerError(e.to_string()))?;
        Ok(totp.get_secret_base32())
    }

    /// Verify a TOTP code
    pub fn verify_totp_code(secret: &str, user_code: &str) -> Result<bool, AuthError> {
        let secret_bytes =
            match base32::decode(base32::Alphabet::Rfc4648 { padding: false }, secret) {
                Some(bytes) => bytes,
                None => return Ok(false), // Instead of returning an error, return false
            };

        let totp = match TOTP::new(Algorithm::SHA1, 6, 1, 30, secret_bytes) {
            Ok(t) => t,
            Err(_) => return Ok(false), // Invalid TOTP setup → return false
        };

        let time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| AuthError::InvalidOtp(e.to_string()))?
            .as_secs();

        Ok(totp.check(user_code, time))
    }

    /// Generate a set of alphanumeric backup codes
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

    /// Verify a backup code
    pub fn verify_backup_code(&self, code: &str) -> Result<bool, AuthError> {
        if let Some(backup_codes) = &self.backup_codes {
            if backup_codes.contains(&code.to_string()) {
                Ok(true)
            } else {
                Err(AuthError::InvalidBackupCode(
                    "Invalid backup code".to_string(),
                ))
            }
        } else {
            Err(AuthError::InvalidBackupCode(
                "No backup codes available".to_string(),
            ))
        }
    }

    /// Mark a backup code as used
    pub fn mark_backup_code_as_used(&mut self, code: &str) -> Result<(), AuthError> {
        if let Some(backup_codes) = &mut self.backup_codes {
            if let Some(index) = backup_codes.iter().position(|c| c == code) {
                backup_codes.remove(index);
                Ok(())
            } else {
                Err(AuthError::InvalidBackupCode(
                    "Backup code not found".to_string(),
                ))
            }
        } else {
            Err(AuthError::InvalidBackupCode(
                "No backup codes available".to_string(),
            ))
        }
    }
}
