extern crate bcrypt;

use bcrypt::{DEFAULT_COST, hash, verify};

use crate::error::AuthError;

pub fn hash_password(password: &str) -> Result<String, AuthError> {
    let hasehd_password =
        hash(password, DEFAULT_COST).map_err(|e| AuthError::HashingError(e.to_string()))?;
    Ok(hasehd_password)
}

pub fn verify_password(password: &str, hash: &str) -> Result<bool, AuthError> {
    let verified = verify(password, hash).map_err(|_| AuthError::InvalidCredentials)?;
    Ok(verified)
}
