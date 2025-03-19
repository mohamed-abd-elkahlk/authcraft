pub mod email;
#[allow(unused)]
pub mod error;
pub mod jwt;
pub mod mfa;
pub mod security;

use async_trait::*;
use chrono::{DateTime, Utc};
use error::AuthError;
use jwt::{Claims, JwtConfig};
use mfa::MfaType;
use security::{RequestPasswordResetRequest, ResetPasswordRequest};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct User<U = (), R = Role> {
    // Core user fields
    pub id: String,
    pub username: String,
    pub is_verified: bool,
    pub email: String,
    pub password_hash: String,
    pub role: R,
    pub data: Option<U>,

    // Multi-Factor Authentication (MFA)
    pub mfa_enabled: bool,
    pub mfa_type: Option<MfaType>,
    pub totp_secret: Option<String>, // TOTP Secret (Google Authenticator)
    pub email_otp: Option<String>,   // Last generated Email OTP
    pub backup_codes: Option<Vec<String>>, // Backup codes for MFA recovery
    pub mfa_recovery_codes_used: Option<Vec<String>>, // Used backup codes

    // Password reset fields
    pub password_reset_token: Option<String>,
    pub password_reset_expiry: Option<DateTime<Utc>>,

    // Email verification fields
    pub email_verification_token: Option<String>,
    pub email_verification_expiry: Option<DateTime<Utc>>,

    // Session management fields
    pub last_login_at: Option<DateTime<Utc>>,
    pub failed_login_attempts: u32,
    pub account_locked_until: Option<DateTime<Utc>>,

    // Refresh token fields
    pub refresh_token: Option<String>,
    pub refresh_token_expiry: Option<DateTime<Utc>>,

    // Security fields
    pub last_password_change: Option<DateTime<Utc>>,
    pub password_history: Option<Vec<String>>, // List of previously used password hashes
}
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub enum Role {
    Admin,
    User,
    Guest,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RegisterUserRequest {
    pub username: String,
    pub email: String,
    pub password: String,
}

/// Request payload for user login
#[derive(Debug, Deserialize, Serialize)]
pub struct LoginUserRequest {
    pub email: String,
    pub password: String,
}
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct UpdateUser<U = ()> {
    pub id: String,
    pub username: Option<String>,
    pub email: Option<String>,
    pub password: Option<String>,
    pub role: Option<Role>,
    pub data: Option<U>,
}
#[async_trait]
pub trait UserRepository<U>: Send + Sync {
    async fn find_user_by_id(&self, id: &str) -> Result<User<U>, AuthError>;
    async fn find_user_by_email(&self, email: &str) -> Result<User<U>, AuthError>;
    async fn create_user(&self, user: RegisterUserRequest) -> Result<User<U>, AuthError>;
    async fn update_user(&self, user: UpdateUser<U>) -> Result<User<U>, AuthError>;
    async fn delete_user(&self, email: &str) -> Result<(), AuthError>;
    async fn create_verification_token(
        &self,
        user_id: &str,
        jwt: JwtConfig,
    ) -> Result<(String, User<U>), AuthError>;
    async fn verify_email(&self, token: &str, jwt: JwtConfig) -> Result<Claims<U>, AuthError>;
    async fn mark_user_as_verified(&self, user_id: &str) -> Result<(), AuthError>;
    // MFA methods
    async fn enable_mfa(&self, user_id: &str, method: MfaType) -> Result<(), AuthError>;
    async fn disable_mfa(&self, user_id: &str) -> Result<(), AuthError>;
    async fn update_totp_secret(&self, user_id: &str, secret: String) -> Result<String, AuthError>;
    async fn generate_backup_codes(&self, user_id: &str) -> Result<Vec<String>, AuthError>;
    async fn use_backup_code(&self, user_id: &str, code: String) -> Result<(), AuthError>;

    // Password reset methods
    async fn forgot_password(&self, email: RequestPasswordResetRequest) -> Result<(), AuthError>;
    async fn verify_reset_token(&self, user_id: &str, token: &str) -> Result<bool, AuthError>;
    async fn reset_password(
        &self,
        user_id: &str,
        request: ResetPasswordRequest,
    ) -> Result<(), AuthError>;

    // Session management methods
    async fn update_last_login(&self, user_id: &str) -> Result<(), AuthError>;
    async fn increment_failed_login_attempts(&self, user_id: &str) -> Result<(), AuthError>;
    async fn reset_failed_login_attempts(&self, user_id: &str) -> Result<(), AuthError>;
    async fn lock_account(&self, user_id: &str, until: DateTime<Utc>) -> Result<(), AuthError>;
    async fn unlock_account(&self, user_id: &str) -> Result<(), AuthError>;

    // Refresh token methods
    async fn update_refresh_token(
        &self,
        user_id: &str,
        token: String,
        expiry: DateTime<Utc>,
    ) -> Result<(), AuthError>;
    async fn clear_refresh_token(&self, user_id: &str) -> Result<(), AuthError>;

    // Security methods
    async fn update_password_history(
        &self,
        user_id: &str,
        password_hash: String,
    ) -> Result<(), AuthError>;
    async fn update_last_password_change(&self, user_id: &str) -> Result<(), AuthError>;
}

impl From<Role> for String {
    fn from(value: Role) -> Self {
        match value {
            Role::Admin => "Admin".to_string(),
            Role::User => "User".to_string(),
            Role::Guest => "Guest".to_string(),
        }
    }
}

impl From<String> for Role {
    fn from(value: String) -> Self {
        match value.as_str() {
            "Admin" => Role::Admin,
            "User" => Role::User,
            "Guest" => Role::Guest,
            _ => panic!("Invalid role string"), // Alternatively, return a default value
        }
    }
}
