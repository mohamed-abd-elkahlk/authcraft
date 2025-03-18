use rand::RngCore;

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

use totp_rs::{Algorithm, TOTP};

use crate::error::AuthError;
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub enum MfaType {
    Totp,  // Google Authenticator (TOTP)
    Email, // OTP via Email
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct MfaSettings {
    pub enabled: bool,
    pub method: MfaType,        // Which MFA type (TOTP or Email)
    pub secret: Option<String>, // Used for TOTP (Google Authenticator)
}

impl MfaSettings {
    pub fn generate_totp_secret() -> String {
        let mut seed = [0u8; 20]; // 20 bytes = 160 bits
        rand::rng().fill_bytes(&mut seed);

        let totp = TOTP::new(
            Algorithm::SHA1,
            6,  // OTP Length
            1,  // Time step (30 seconds)
            30, // Expiry (seconds)
            seed.to_vec(),
        )
        .unwrap();
        totp.get_secret_base32()
    }
    pub fn verify_totp_code(secret: &str, user_code: &str) -> Result<bool, AuthError> {
        let secret_bytes = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, secret)
            .ok_or(AuthError::InvalidSecret("Invalid Secret".to_string()))?;
        let totp = TOTP::new(Algorithm::SHA1, 6, 1, 30, secret_bytes)
            .map_err(|e| AuthError::InvalidSecret(e.to_string()))?;

        let time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| AuthError::InvalidOtp(e.to_string()))?
            .as_secs();

        Ok(totp.check(user_code, time))
    }
}
