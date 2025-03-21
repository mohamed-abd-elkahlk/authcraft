//! # AuthCraft
//!
//! AuthCraft is a flexible authentication library for Rust that provides user management, JWT-based authentication,
//! multi-factor authentication (MFA), password recovery, and role-based access control.
//!
//! ## Features
//!
//! - **User Authentication**: Secure login & registration with password hashing.
//! - **Email Verification & Password Reset**: Send verification emails and password reset links.
//! - **Multi-Factor Authentication (MFA)**: Support for TOTP, email OTP, and backup codes.
//! - **JWT Authentication**: Token-based authentication with refresh token support.
//! - **Role-Based Access Control (RBAC)**: User roles and permissions management.
//! - **Account Security**: Lock accounts after failed login attempts and enforce password policies.
//!
//! ## Example Usage
//!
//! ```rust
//! use authcraft::{AuthError, UserRepository};
//! use async_trait::async_trait;
//!
//! struct MemoryUserRepo;
//!
//! #[async_trait]
//! impl UserRepository<()> for MemoryUserRepo {
//!     async fn enable_mfa(&self, user_id: &str) -> Result<(), AuthError> {
//!         println!("Enabling MFA for user: {}", user_id);
//!         Ok(())
//!     }
//! }
//! ```
//!
//! ## Modules
//!
//! - [`auth`](crate::auth) - User authentication logic.
//! - [`email`](crate::email) - Email-based authentication and verification.
//! - [`jwt`](crate::jwt) - JWT authentication and refresh token management.
//! - [`mfa`](crate::mfa) - Multi-factor authentication (MFA) support.
//! - [`rbac`](crate::rbac) - Role-based access control.
//! - [`security`](crate::security) - Account security and password policies.
//! - [`error`](crate::error) - Authentication error types.

pub mod email;
#[allow(unused)]
pub mod error;
pub mod jwt;
pub mod mfa;
pub mod rbac;
pub mod security;
use async_trait::*;
use chrono::{DateTime, Utc};
use error::AuthError;
use jwt::{Claims, JwtConfig};
use mfa::{MfaSettings, MfaType};
use rbac::RBACRole;
use security::{RequestPasswordResetRequest, ResetPasswordRequest};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    time::SystemTime,
};
use tera::Value;

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct AuthData<R = Role> {
    /// Unique identifier for the user.
    pub id: String,
    /// Username of the user.
    pub username: String,
    /// Indicates whether the user's email is verified.
    pub is_verified: bool,
    /// User's email address.
    pub email: String,
    /// Hashed password.
    pub password_hash: String,
    /// User role (Admin, User, Guest).
    pub role: R,
    /// Indicates if MFA is enabled for the user.
    pub mfa_enabled: bool,
    /// Type of MFA used.
    pub mfa_type: Option<MfaType>,
    /// Secret for TOTP-based MFA.
    pub totp_secret: Option<String>,
    /// Last generated email OTP.
    pub email_otp: Option<String>,
    /// Backup recovery codes for MFA.
    pub backup_codes: Option<Vec<String>>,
    /// Used backup codes.
    pub mfa_recovery_codes_used: Option<Vec<String>>,
    /// Password reset token.
    pub password_reset_token: Option<String>,
    /// Expiry time of the password reset token.
    pub password_reset_expiry: Option<DateTime<Utc>>,
    /// Email verification token.
    pub email_verification_token: Option<String>,
    /// Expiry time of the email verification token.
    pub email_verification_expiry: Option<DateTime<Utc>>,
    /// Timestamp of the last login.
    pub last_login_at: Option<DateTime<Utc>>,
    /// Number of failed login attempts.
    pub failed_login_attempts: u32,
    /// Account lockout expiration time.
    pub account_locked_until: Option<DateTime<Utc>>,
    /// Refresh token.
    pub refresh_token: Option<String>,
    /// Expiry time of the refresh token.
    pub refresh_token_expiry: Option<DateTime<Utc>>,
    /// Timestamp of the last password change.
    pub last_password_change: Option<DateTime<Utc>>,
    /// History of previously used password hashes.
    pub password_history: Option<Vec<String>>,
}

/// Defines possible user roles.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub enum Role {
    Admin,
    User,
    Guest,
}
/// The `AppUser` struct represents a user within the application.
///
/// This struct allows you to add extra fields through `app_data`, making it flexible for various use cases.
/// It also includes metadata for storing additional user-related information.
///
/// ## Example Usage
/// ```rust
/// use authcraft::{AppUser, AuthData, Role};
/// use std::collections::HashMap;
/// use tera::Value;
///
/// #[derive(Debug, Clone)]
/// struct CustomData {
///     pub preferences: String,
/// }
///
/// let user = AppUser {
///     auth_data: AuthData {
///         id: "user-123".to_string(),
///         username: "example_user".to_string(),
///         is_verified: true,
///         email: "user@example.com".to_string(),
///         password_hash: "hashed_password".to_string(),
///         role: Role::User,
///         mfa_enabled: false,
///         password_history: None,
///     },
///     app_data: CustomData {
///         preferences: "dark_mode".to_string(),
///     },
///     metadata: HashMap::new(),
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct AppUser<T = ()> {
    pub auth_data: AuthData,
    pub app_data: T,
    pub metadata: HashMap<String, Value>, // Optional extra data
}
/// Request payload for registering a new user.
#[derive(Debug, Deserialize, Serialize)]
pub struct RegisterUserRequest {
    pub username: String,
    pub email: String,
    pub password: String,
}

/// Request payload for user login.
#[derive(Debug, Deserialize, Serialize)]
pub struct LoginUserRequest {
    pub email: String,
    pub password: String,
}
/// Request payload for user to upate his data.

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct UpdateUser {
    pub id: String,
    pub username: Option<String>,
    pub email: Option<String>,
    pub password: Option<String>,
    pub role: Option<Role>,
}
#[async_trait]
pub trait UserRepository: Send + Sync {
    /// Finds a user by their ID.
    ///
    /// This method searches for a user in the repository using their unique identifier.
    ///
    /// ## Example Usage (Using sqlx with PostgreSQL)
    /// ```rust
    /// use authcraft::{AuthData, AuthError, Role, UserRepository};
    /// use async_trait::async_trait;
    /// use sqlx::PgPool;
    /// use std::collections::HashMap;
    /// use tera::Value;
    ///
    /// struct PostgresUserRepo {
    ///     pool: PgPool,
    /// }
    ///
    /// #[async_trait]
    /// impl UserRepository<()> for PostgresUserRepo {
    ///     async fn find_user_by_id(&self, id: &str) -> Result<AuthData<()>, AuthError> {
    ///         let row = sqlx::query!(
    ///             "SELECT id, username, email, password_hash, is_verified FROM users WHERE id = $1",
    ///             id
    ///         )
    ///         .fetch_one(&self.pool)
    ///         .await
    ///         .map_err(|e| AuthError::UserNotFound(e.to_string))?;
    ///
    ///         Ok(AuthData {
    ///             id: row.id,
    ///             username: row.username,
    ///             is_verified: row.is_verified,
    ///             email: row.email,
    ///             password_hash: row.password_hash,
    ///             role: Role::User, // Assuming default role, modify as needed
    ///             mfa_enabled: false,
    ///             mfa_type: None,
    ///             totp_secret: None,
    ///             email_otp: None,
    ///             backup_codes: None,
    ///             mfa_recovery_codes_used: None,
    ///             password_reset_token: None,
    ///             password_reset_expiry: None,
    ///             email_verification_token: None,
    ///             email_verification_expiry: None,
    ///             last_login_at: None,
    ///             failed_login_attempts: 0,
    ///             account_locked_until: None,
    ///             refresh_token: None,
    ///             refresh_token_expiry: None,
    ///             last_password_change: None,
    ///             password_history: None,
    ///         })
    ///     }
    /// }
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let pool = PgPool::connect("postgres://user:password@localhost/db_name").await.unwrap();
    ///     let repo = PostgresUserRepo { pool };
    ///     match repo.find_user_by_id("user-123").await {
    ///         Ok(user) => println!("Found user: {}", user.username),
    ///         Err(_) => println!("User not found"),
    ///     }
    /// }
    /// ```
    async fn find_user_by_id(&self, id: &str) -> Result<AuthData, AuthError>;
    /// Finds a user by their email.
    ///
    /// This method searches for a user in the repository using their unique email.
    ///
    /// ## Example Usage (Using sqlx with PostgreSQL)
    /// ```rust
    /// use authcraft::{AuthData, AuthError, Role, UserRepository};
    /// use async_trait::async_trait;
    /// use sqlx::PgPool;
    /// use std::collections::HashMap;
    /// use tera::Value;
    ///
    /// struct PostgresUserRepo {
    ///     pool: PgPool,
    /// }
    ///
    /// #[async_trait]
    /// impl UserRepository<()> for PostgresUserRepo {
    ///     async fn find_user_by_id(&self, email: &str) -> Result<AuthData<()>, AuthError> {
    ///         let row = sqlx::query!(
    ///             "SELECT id, username, email, password_hash, is_verified FROM users WHERE id = $1",
    ///             id
    ///         )
    ///         .fetch_one(&self.pool)
    ///         .await
    ///         .map_err(|e| AuthError::UserNotFound(e.to_string))?;
    ///
    ///         Ok(AuthData {
    ///             id: row.id,
    ///             username: row.username,
    ///             is_verified: row.is_verified,
    ///             email: row.email,
    ///             password_hash: row.password_hash,
    ///             role: Role::User, // Assuming default role, modify as needed
    ///             mfa_enabled: false,
    ///             mfa_type: None,
    ///             totp_secret: None,
    ///             email_otp: None,
    ///             backup_codes: None,
    ///             mfa_recovery_codes_used: None,
    ///             password_reset_token: None,
    ///             password_reset_expiry: None,
    ///             email_verification_token: None,
    ///             email_verification_expiry: None,
    ///             last_login_at: None,
    ///             failed_login_attempts: 0,
    ///             account_locked_until: None,
    ///             refresh_token: None,
    ///             refresh_token_expiry: None,
    ///             last_password_change: None,
    ///             password_history: None,
    ///         })
    ///     }
    /// }
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let pool = PgPool::connect("postgres://user:password@localhost/db_name").await.unwrap();
    ///     let repo = PostgresUserRepo { pool };
    ///     match repo.find_user_by_id("user@domin.com").await {
    ///         Ok(user) => println!("Found user: {}", user.username),
    ///         Err(_) => println!("User not found"),
    ///     }
    /// }
    /// ```
    async fn find_user_by_email(&self, email: &str) -> Result<AuthData, AuthError>;
    /// Creates a new user in the system.
    ///
    /// This function takes a `RegisterUserRequest`, hashes the provided password using `hash_password`,
    /// and inserts the new user into the database. The function returns an `AuthData<U>` struct containing
    /// the newly created user's details or an `AuthError` if something goes wrong.
    ///
    /// ## Example Usage (Using sqlx with PostgreSQL)
    /// ```rust
    /// use authcraft::{RegisterUserRequest, AuthData, AuthError, Role, UserRepository, security::hash_password};
    /// use async_trait::async_trait;
    /// use sqlx::PgPool;
    ///
    /// struct PostgresUserRepo {
    ///     pool: PgPool,
    /// }
    ///
    /// #[async_trait]
    /// impl UserRepository<()> for PostgresUserRepo {
    ///     async fn create_user(&self, user: RegisterUserRequest) -> Result<AuthData<()>, AuthError> {
    ///         // Hash the password securely
    ///         let hashed_password = hash_password(&user.password)?;
    ///
    ///         // Insert user into the database
    ///         let row = sqlx::query!(
    ///             "INSERT INTO users (id, username, email, password_hash, is_verified)
    ///              VALUES (gen_random_uuid(), $1, $2, $3, false)
    ///              RETURNING id, username, email, password_hash, is_verified",
    ///             user.username,
    ///             user.email,
    ///             hashed_password
    ///         )
    ///         .fetch_one(&self.pool)
    ///         .await
    ///         .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
    ///
    ///         Ok(AuthData {
    ///             id: row.id,
    ///             username: row.username,
    ///             is_verified: row.is_verified,
    ///             email: row.email,
    ///             password_hash: row.password_hash,
    ///             role: Role::User, // Default role, modify as needed
    ///             mfa_enabled: false,
    ///             mfa_type: None,
    ///             totp_secret: None,
    ///             email_otp: None,
    ///             backup_codes: None,
    ///             mfa_recovery_codes_used: None,
    ///             password_reset_token: None,
    ///             password_reset_expiry: None,
    ///             email_verification_token: None,
    ///             email_verification_expiry: None,
    ///             last_login_at: None,
    ///             failed_login_attempts: 0,
    ///             account_locked_until: None,
    ///             refresh_token: None,
    ///             refresh_token_expiry: None,
    ///             last_password_change: None,
    ///             password_history: None,
    ///         })
    ///     }
    /// }
    /// ```
    async fn create_user(&self, user: RegisterUserRequest) -> Result<AuthData, AuthError>;
    /// Updates an existing user in the system.
    ///
    /// This function takes an `UpdateUser<U>` struct, modifies the corresponding user record in the database,
    /// and returns the updated user information. If the user does not exist or an error occurs, it returns an `AuthError`.
    ///
    /// ## Example Usage (Using sqlx with PostgreSQL)
    /// ```rust
    /// use authcraft::{UpdateUser, AuthData, AuthError, UserRepository};
    /// use async_trait::async_trait;
    /// use sqlx::PgPool;
    ///
    /// struct PostgresUserRepo {
    ///     pool: PgPool,
    /// }
    ///
    /// #[async_trait]
    /// impl UserRepository<()> for PostgresUserRepo {
    ///     async fn update_user(&self, user: UpdateUser<()>) -> Result<AuthData<()>, AuthError> {
    ///         let row = sqlx::query!(
    ///             "UPDATE users SET username = $1, email = $2 WHERE id = $3 RETURNING id, username, email, password_hash, is_verified",
    ///             user.username,
    ///             user.email,
    ///             user.id
    ///         )
    ///         .fetch_one(&self.pool)
    ///         .await
    ///         .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
    ///
    ///         Ok(AuthData {
    ///             id: row.id,
    ///             username: row.username,
    ///             is_verified: row.is_verified,
    ///             email: row.email,
    ///             password_hash: row.password_hash,
    ///             role: user.role.unwrap_or_default(),
    ///             mfa_enabled: false,
    ///             mfa_type: None,
    ///             totp_secret: None,
    ///             email_otp: None,
    ///             backup_codes: None,
    ///             mfa_recovery_codes_used: None,
    ///             password_reset_token: None,
    ///             password_reset_expiry: None,
    ///             email_verification_token: None,
    ///             email_verification_expiry: None,
    ///             last_login_at: None,
    ///             failed_login_attempts: 0,
    ///             account_locked_until: None,
    ///             refresh_token: None,
    ///             refresh_token_expiry: None,
    ///             last_password_change: None,
    ///             password_history: None,
    ///         })
    ///     }
    /// }
    /// ```
    async fn update_user(&self, user: UpdateUser) -> Result<AuthData, AuthError>;
    /// Deletes a user from the system by their email.
    ///
    /// This function removes a user from the database based on their email address.
    /// If the user does not exist, it returns an `AuthError`.
    ///
    /// ## Example Usage (Using sqlx with PostgreSQL)
    /// ```rust
    /// use authcraft::{AuthError, UserRepository};
    /// use async_trait::async_trait;
    /// use sqlx::PgPool;
    ///
    /// struct PostgresUserRepo {
    ///     pool: PgPool,
    /// }
    ///
    /// #[async_trait]
    /// impl UserRepository<()> for PostgresUserRepo {
    ///     async fn delete_user(&self, email: &str) -> Result<(), AuthError> {
    ///         let result = sqlx::query!("DELETE FROM users WHERE email = $1", email)
    ///             .execute(&self.pool)
    ///             .await
    ///             .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
    ///
    ///         if result.rows_affected() == 0 {
    ///             return Err(AuthError::UserNotFound("User not found".to_string()));
    ///         }
    ///         Ok(())
    ///     }
    /// }
    /// ```
    async fn delete_user(&self, email: &str) -> Result<(), AuthError>;
    /// Creates a verification token for a user.
    ///
    /// This function generates a verification token and associates it with the user. The token
    /// is sent via email for verification purposes.
    ///
    /// ## Example Usage (Using sqlx with PostgreSQL and lettre for email sending)
    /// ```rust
    /// use authcraft::{AuthData, AuthError, JwtConfig, UserRepository};
    /// use async_trait::async_trait;
    /// use sqlx::PgPool;
    /// use lettre::AsyncSmtpTransport;
    ///
    /// struct PostgresUserRepo {
    ///     pool: PgPool,
    ///     email_service: EmailService,
    /// }
    ///
    /// #[async_trait]
    /// impl UserRepository<()> for PostgresUserRepo {
    ///     async fn create_verification_token(
    ///         &self,
    ///         user_id: &str,
    ///         jwt: JwtConfig,
    ///     ) -> Result<(String, AuthData), AuthError> {
    ///         let token = jwt.issue_jwt(user_id,jwt,())?;
    ///
    ///         let user = sqlx::query!("SELECT email, username FROM users WHERE id = $1", user_id)
    ///             .fetch_one(&self.pool)
    ///             .await
    ///             .map_err(|e| AuthError::UserNotFound(e.to_string()))?;
    ///
    ///         let verification_link = format!("https://example.com/verify?token={}", token);
    ///         self.email_service
    ///             .send_verification_email(&user.email, &user.username, &verification_link)
    ///             .await
    ///             .map_err(|e| AuthError::EmailSendFailed(e.to_string()))?;
    ///
    ///     }
    /// }
    /// ```

    async fn create_verification_token(
        &self,
        user_id: &str,
        jwt: JwtConfig,
    ) -> Result<(), AuthError>;

    /// Verifies a user's email using a verification token.
    ///
    /// This function decodes and validates the provided JWT token to confirm email ownership.
    /// If valid, the user's email verification status is updated in the database.
    ///
    /// ## Example Usage (Using sqlx with PostgreSQL)
    /// ```rust
    /// use authcraft::{AuthError, JwtConfig, UserRepository, Claims};
    /// use async_trait::async_trait;
    /// use sqlx::PgPool;
    ///
    /// struct PostgresUserRepo {
    ///     pool: PgPool,
    /// }
    ///
    /// #[async_trait]
    /// impl UserRepository<()> for PostgresUserRepo {
    ///     async fn verify_email(&self, token: &str, jwt: JwtConfig) -> Result<Claims<()>, AuthError> {
    ///         let claims = jwt.verify_token::<()>(&token)?;
    ///
    ///         sqlx::query!("UPDATE users SET is_verified = TRUE WHERE id = $1", claims.sub)
    ///             .execute(&self.pool)
    ///             .await
    ///             .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
    ///
    ///         Ok(claims)
    ///     }
    /// }
    /// ```
    async fn verify_email(&self, token: &str, jwt: JwtConfig) -> Result<Claims<()>, AuthError>;
    /// Enables Multi-Factor Authentication (MFA) for a user.
    ///
    /// This function enables MFA for a user by specifying the authentication method.
    ///
    /// ## Arguments
    /// * `user_id` - The unique identifier of the user.
    /// * `method` - The MFA method to enable (`Totp`, `Email`, or `BackupCodes`).
    ///
    /// ## Returns
    /// * `Ok(())` if MFA is successfully enabled.
    /// * `Err(AuthError)` if an error occurs.
    ///
    /// ## Example Usage (Using sqlx with PostgreSQL)
    /// ```rust
    /// use authcraft::{AuthError, mfa::MfaType, UserRepository};
    /// use async_trait::async_trait;
    /// use sqlx::PgPool;
    ///
    /// struct PostgresUserRepo {
    ///     pool: PgPool,
    /// }
    ///
    /// #[async_trait]
    /// impl UserRepository<()> for PostgresUserRepo {
    ///     async fn enable_mfa(&self, user_id: &str, method: MfaType) -> Result<(), AuthError> {
    ///         sqlx::query!(
    ///             "UPDATE users SET mfa_enabled = TRUE, mfa_type = $1 WHERE id = $2",
    ///             method as MfaType,
    ///             user_id
    ///         )
    ///         .execute(&self.pool)
    ///         .await
    ///         .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
    ///
    ///         Ok(())
    ///     }
    /// }
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let pool = PgPool::connect("postgres://user:password@localhost/db_name").await.unwrap();
    ///     let repo = PostgresUserRepo { pool };
    ///     
    ///     match repo.enable_mfa("user123", MfaType::Totp).await {
    ///         Ok(_) => println!("MFA enabled successfully"),
    ///         Err(err) => println!("Failed to enable MFA: {:?}", err),
    ///     }
    /// }
    /// ```
    async fn enable_mfa(&self, user_id: &str, method: MfaType) -> Result<(), AuthError>;

    /// Disables Multi-Factor Authentication (MFA) for a user.
    ///
    /// This function removes any existing MFA configuration for the given user.
    ///
    /// ## Arguments
    /// * `user_id` - The unique identifier of the user.
    ///
    /// ## Returns
    /// * `Ok(())` if MFA is successfully disabled.
    /// * `Err(AuthError)` if an error occurs.
    ///
    /// ## Example Usage (Using sqlx with PostgreSQL)
    /// ```rust
    /// use authcraft::{AuthError, UserRepository};
    /// use async_trait::async_trait;
    /// use sqlx::PgPool;
    ///
    /// struct PostgresUserRepo {
    ///     pool: PgPool,
    /// }
    ///
    /// #[async_trait]
    /// impl UserRepository<()> for PostgresUserRepo {
    ///     async fn disable_mfa(&self, user_id: &str) -> Result<(), AuthError> {
    ///         sqlx::query!(
    ///             "UPDATE users SET mfa_enabled = FALSE, mfa_type = NULL WHERE id = $1",
    ///             user_id
    ///         )
    ///         .execute(&self.pool)
    ///         .await
    ///         .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
    ///
    ///         Ok(())
    ///     }
    /// }
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let pool = PgPool::connect("postgres://user:password@localhost/db_name").await.unwrap();
    ///     let repo = PostgresUserRepo { pool };
    ///     
    ///     match repo.disable_mfa("user123").await {
    ///         Ok(_) => println!("MFA disabled successfully"),
    ///         Err(err) => println!("Failed to disable MFA: {:?}", err),
    ///     }
    /// }
    /// ```
    async fn disable_mfa(&self, user_id: &str) -> Result<(), AuthError>;
    /// Generates a new TOTP secret for a user.
    ///
    /// This function creates a new TOTP secret using the SHA1 algorithm and a 30-second time step.
    ///
    /// ## Returns
    /// * `Ok(String)` - The generated TOTP secret in Base32 format.
    /// * `Err(AuthError)` - If an error occurs.
    ///
    /// ## Example Usage
    /// ```rust
    /// use authcraft::UserRepository;
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let totp_secret = UserRepository::create_totp_secret().await.unwrap();
    ///     println!("Generated TOTP Secret: {}", totp_secret);
    /// }
    /// ```
    async fn create_totp_secret() -> Result<String, AuthError> {
        Ok(MfaSettings::generate_totp_secret()?)
    }

    /// Updates a user's TOTP secret in the database.
    ///
    /// This function updates the user's TOTP secret and enables TOTP-based MFA.
    ///
    /// ## Arguments
    /// * `user_id` - The unique identifier of the user.
    /// * `secret` - The new TOTP secret in Base32 format.
    ///
    /// ## Returns
    /// * `Ok(String)` - Returns the updated secret.
    /// * `Err(AuthError)` - If an error occurs.
    ///
    /// ## Example Usage (Using sqlx with PostgreSQL)
    /// ```rust
    /// use authcraft::{AuthError, UserRepository};
    /// use async_trait::async_trait;
    /// use sqlx::PgPool;
    ///
    /// struct PostgresUserRepo {
    ///     pool: PgPool,
    /// }
    ///
    /// #[async_trait]
    /// impl UserRepository<()> for PostgresUserRepo {
    ///     async fn update_totp_secret(&self, user_id: &str, secret: String) -> Result<String, AuthError> {
    ///         sqlx::query!(
    ///             "UPDATE users SET mfa_enabled = TRUE, mfa_type = 'Totp', totp_secret = $1 WHERE id = $2",
    ///             secret,
    ///             user_id
    ///         )
    ///         .execute(&self.pool)
    ///         .await
    ///         .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
    ///
    ///         Ok(secret)
    ///     }
    /// }
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let pool = PgPool::connect("postgres://user:password@localhost/db_name").await.unwrap();
    ///     let repo = PostgresUserRepo { pool };
    ///     
    ///     match repo.update_totp_secret("user123", "SECRET123".to_string()).await {
    ///         Ok(secret) => println!("TOTP secret updated: {}", secret),
    ///         Err(err) => println!("Failed to update TOTP secret: {:?}", err),
    ///     }
    /// }
    /// ```
    async fn update_totp_secret(&self, user_id: &str, secret: String) -> Result<String, AuthError>;

    /// Generates a new set of backup codes for a user.
    ///
    /// This function generates 10 alphanumeric backup codes, each 12 characters long.
    /// These codes can be used for multi-factor authentication (MFA) recovery.
    ///
    /// ## Returns
    /// * `Ok(Vec<String>)` - A vector of generated backup codes.
    /// * `Err(AuthError)` - If an error occurs.
    ///
    /// ## Example Usage
    /// ```rust
    /// use authcraft::UserRepository;
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let backup_codes = UserRepository::create_backup_codes().await.unwrap();
    ///     println!("Generated Backup Codes: {:?}", backup_codes);
    /// }
    /// ```
    async fn create_backup_codes() -> Result<Vec<String>, AuthError> {
        Ok(MfaSettings::generate_backup_codes(10, 12)) // Generate 10 backup codes of length 12
    }

    /// Uses a backup code for authentication and removes it from the stored codes.
    ///
    /// This function checks if the provided backup code exists in the user's stored backup codes.
    /// If it exists, it is marked as used (removed).
    ///
    /// ## Note:
    /// - If you store `backup_codes` as `JSONB`, **use `serde_json`** to parse and update the backup codes.
    /// - If you store `backup_codes` as `TEXT[]`, **do not use `serde_json`**—directly manipulate the array.
    ///
    /// ## Arguments
    /// * `user_id` - The unique identifier of the user.
    /// * `code` - The backup code being used.
    ///
    /// ## Returns
    /// * `Ok(())` - If the backup code was successfully used.
    /// * `Err(AuthError)` - If the code is invalid or an error occurs.
    ///
    /// ## Example Usage (Using `sqlx` with PostgreSQL)
    /// ```rust
    /// use authcraft::{AuthError, UserRepository};
    /// use async_trait::async_trait;
    /// use sqlx::PgPool;
    ///
    /// struct PostgresUserRepo {
    ///     pool: PgPool,
    /// }
    ///
    /// #[async_trait]
    /// impl UserRepository<()> for PostgresUserRepo {
    ///     async fn use_backup_code(&self, user_id: &str, code: String) -> Result<(), AuthError> {
    ///         // Fetch the backup codes from the database
    ///         let user = sqlx::query!(
    ///             "SELECT backup_codes FROM users WHERE id = $1",
    ///             user_id
    ///         )
    ///         .fetch_one(&self.pool)
    ///         .await
    ///         .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
    ///
    ///         // If backup_codes is stored as JSONB, use serde_json
    ///         let mut backup_codes: Vec<String> = serde_json::from_value(user.backup_codes)
    ///             .map_err(|_| AuthError::InvalidBackupCode("Failed to parse backup codes".to_string()))?;
    ///
    ///         // If stored as TEXT[], fetch as Vec<String> directly (DO NOT use serde_json)
    ///         // let backup_codes: Vec<String> = user.backup_codes;
    ///
    ///         // Check if the code exists
    ///         if let Some(index) = backup_codes.iter().position(|c| c == &code) {
    ///             backup_codes.remove(index);
    ///
    ///             // Update the user's backup codes in the database
    ///             sqlx::query!(
    ///                 "UPDATE users SET backup_codes = $1 WHERE id = $2",
    ///                 serde_json::to_value(&backup_codes).unwrap(), // Use this for JSONB
    ///                 // backup_codes, // Use this for TEXT[]
    ///                 user_id
    ///             )
    ///             .execute(&self.pool)
    ///             .await
    ///             .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
    ///
    ///             Ok(())
    ///         } else {
    ///             Err(AuthError::InvalidBackupCode("Invalid or expired backup code".to_string()))
    ///         }
    ///     }
    /// }
    /// ```
    async fn use_backup_code(&self, user_id: &str, code: String) -> Result<(), AuthError>;
    /// Initiates the password reset process for a user.
    ///
    /// This function generates a password reset token, stores it in the database,
    /// and sends an email with the reset link.
    ///
    /// ## Arguments
    /// * `jwt` - The JWT configuration used to generate the reset token.
    /// * `email` - The request containing the user's email.
    ///
    /// ## Returns
    /// * `Ok(())` if the password reset request was successfully processed.
    /// * `Err(AuthError)` if an error occurs (e.g., user not found, database error).
    ///
    /// ## Example Usage (Using sqlx with PostgreSQL)
    /// ```rust
    /// use authcraft::{error::AuthError, security::generate_reset_token ,JwtConfig, RequestPasswordResetRequest, UserRepository};
    /// use async_trait::async_trait;
    /// use sqlx::PgPool;
    ///
    /// struct PostgresUserRepo {
    ///     pool: PgPool,
    /// }
    ///
    /// #[async_trait]
    /// impl UserRepository<()> for PostgresUserRepo {
    ///     async fn forgot_password(
    ///         &self,
    ///         jwt: JwtConfig,
    ///         email: RequestPasswordResetRequest
    ///     ) -> Result<(), AuthError> {
    ///         let user = sqlx::query!(
    ///             "SELECT id FROM users WHERE email = $1",
    ///             email.email
    ///         )
    ///         .fetch_optional(&self.pool)
    ///         .await
    ///         .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
    ///
    ///         let user_id = match user {
    ///             Some(u) => u.id,
    ///             None => return Err(AuthError::UserNotFound),
    ///         };
    ///
    ///         let reset_token = generate_reset_token(&user_id)?;
    ///
    ///         sqlx::query!(
    ///             "INSERT INTO password_resets (user_id, token) VALUES ($1, $2)
    ///              ON CONFLICT (user_id) DO UPDATE SET token = $2, created_at = NOW()",
    ///             user_id, reset_token
    ///         )
    ///         .execute(&self.pool)
    ///         .await
    ///         .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
    ///
    ///         let reset_link = format!("https://yourapp.com/reset-password?token={}", reset_token);
    ///
    ///         self.email_service
    ///             .send_verification_email(&email.email, &username, &reset_link)
    ///             .await
    ///             .map_err(|e| AuthError::EmailError(e.to_string()))?;
    ///
    ///         Ok(())
    ///     }
    /// }
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let pool = PgPool::connect("postgres://user:password@localhost/db_name").await.unwrap();
    ///     let repo = PostgresUserRepo { pool };
    ///
    ///     let jwt_config = JwtConfig::default();
    ///     let request = RequestPasswordResetRequest { email: "user@example.com".to_string() };
    ///
    ///     match repo.forgot_password(jwt_config, request).await {
    ///         Ok(_) => println!("Password reset email sent."),
    ///         Err(err) => println!("Error: {:?}", err),
    ///     }
    /// }
    /// ```
    async fn forgot_password(
        &self,
        jwt: JwtConfig,
        email: RequestPasswordResetRequest,
    ) -> Result<(), AuthError>;

    /// Verifies a password reset token for a user.
    ///
    /// This function checks if the provided reset token is valid and corresponds to the given user.
    ///
    /// ## Arguments
    /// * `user_id` - The unique identifier of the user.
    /// * `token` - The reset token to be verified.
    ///
    /// ## Returns
    /// * `Ok(true)` if the token is valid.
    /// * `Ok(false)` if the token is invalid or expired.
    /// * `Err(AuthError)` if an error occurs.
    ///
    /// ## Example Usage (Using sqlx with PostgreSQL)
    /// ```rust
    /// use authcraft::{AuthError, UserRepository};
    /// use async_trait::async_trait;
    /// use sqlx::PgPool;
    ///
    /// struct PostgresUserRepo {
    ///     pool: PgPool,
    /// }
    ///
    /// #[async_trait]
    /// impl UserRepository<()> for PostgresUserRepo {
    ///     async fn verify_reset_token(&self, user_id: &str, token: &str) -> Result<bool, AuthError> {
    ///         let record = sqlx::query!(
    ///             "SELECT created_at FROM password_resets WHERE user_id = $1 AND token = $2",
    ///             user_id, token
    ///         )
    ///         .fetch_optional(&self.pool)
    ///         .await
    ///         .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
    ///
    ///         match record {
    ///             Some(r) => {
    ///                 let expiration_time = r.created_at + chrono::Duration::minutes(30);
    ///                 Ok(chrono::Utc::now() < expiration_time)
    ///             }
    ///             None => Ok(false),
    ///         }
    ///     }
    /// }
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let pool = PgPool::connect("postgres://user:password@localhost/db_name").await.unwrap();
    ///     let repo = PostgresUserRepo { pool };
    ///
    ///     let user_id = "user_123";
    ///     let token = "reset_token";
    ///
    ///     match repo.verify_reset_token(user_id, token).await {
    ///         Ok(true) => println!("Token is valid."),
    ///         Ok(false) => println!("Token is invalid or expired."),
    ///         Err(err) => println!("Error: {:?}", err),
    ///     }
    /// }
    /// ```
    async fn verify_reset_token(&self, user_id: &str, token: &str) -> Result<bool, AuthError>;
    /// Resets the user's password.
    ///
    /// This function verifies the reset token, updates the user's password in the database,
    /// and invalidates the used reset token.
    ///
    /// ## Arguments
    /// * `user_id` - The unique identifier of the user.
    /// * `request` - The password reset request containing the new password and reset token.
    ///
    /// ## Returns
    /// * `Ok(())` if the password reset was successful.
    /// * `Err(AuthError)` if an error occurs (e.g., invalid token, database error).
    ///
    /// ## Example Usage (Using sqlx with PostgreSQL)
    /// ```rust
    /// use authcraft::{AuthError,security::hash_password ResetPasswordRequest, UserRepository};
    /// use async_trait::async_trait;
    /// use sqlx::{PgPool, query};
    /// use rand::Rng;
    ///
    /// struct PostgresUserRepo {
    ///     pool: PgPool,
    /// }
    ///
    /// #[async_trait]
    /// impl UserRepository<()> for PostgresUserRepo {
    ///     async fn reset_password(
    ///         &self,
    ///         user_id: &str,
    ///         request: ResetPasswordRequest,
    ///     ) -> Result<(), AuthError> {
    ///         // Check if the token is valid
    ///         let reset_entry = sqlx::query!(
    ///             "SELECT token FROM password_resets WHERE user_id = $1",
    ///             user_id
    ///         )
    ///         .fetch_optional(&self.pool)
    ///         .await
    ///         .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
    ///
    ///         match reset_entry {
    ///             Some(entry) if entry.token == request.token => (),
    ///             _ => return Err(AuthError::InvalidToken),
    ///         }
    ///
    ///         // Hash the new password
    ///         let salt: [u8; 16] = rand::thread_rng().gen();
    ///         let config = Config::default();
    ///         let hashed_password = hash_password(request.new_password.)
    ///             .map_err(|_| AuthError::HashingError)?;
    ///
    ///         // Update the user's password
    ///         sqlx::query!(
    ///             "UPDATE users SET password = $1 WHERE id = $2",
    ///             hashed_password,
    ///             user_id
    ///         )
    ///         .execute(&self.pool)
    ///         .await
    ///         .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
    ///
    ///         // Remove the reset token
    ///         sqlx::query!(
    ///             "DELETE FROM password_resets WHERE user_id = $1",
    ///             user_id
    ///         )
    ///         .execute(&self.pool)
    ///         .await
    ///         .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
    ///
    ///         Ok(())
    ///     }
    /// }
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let pool = PgPool::connect("postgres://user:password@localhost/db_name").await.unwrap();
    ///     let repo = PostgresUserRepo { pool };
    ///
    ///     let request = ResetPasswordRequest {
    ///         token: "valid_reset_token".to_string(),
    ///         new_password: "new_secure_password".to_string(),
    ///     };
    ///
    ///     match repo.reset_password("user123", request).await {
    ///         Ok(_) => println!("Password reset successfully"),
    ///         Err(err) => println!("Failed to reset password: {:?}", err),
    ///     }
    /// }
    /// ```
    async fn reset_password(
        &self,
        user_id: &str,
        request: ResetPasswordRequest,
    ) -> Result<(), AuthError>;

    // Session management methods
    /// Updates the last login timestamp for a user.
    ///
    /// This function records the latest login timestamp for a given user,
    /// helping track account activity.
    ///
    /// ## Arguments
    /// * `user_id` - The unique identifier of the user.
    ///
    /// ## Returns
    /// * `Ok(())` if the timestamp was successfully updated.
    /// * `Err(AuthError)` if an error occurs (e.g., database failure).
    ///
    /// ## Example Usage (Using sqlx with PostgreSQL)
    /// ```rust
    /// use authcraft::{AuthError, UserRepository};
    /// use async_trait::async_trait;
    /// use sqlx::{PgPool, query};
    /// use chrono::Utc;
    ///
    /// struct PostgresUserRepo {
    ///     pool: PgPool,
    /// }
    ///
    /// #[async_trait]
    /// impl UserRepository<()> for PostgresUserRepo {
    ///     async fn update_last_login(&self, user_id: &str) -> Result<(), AuthError> {
    ///         sqlx::query!(
    ///             "UPDATE users SET last_login = $1 WHERE id = $2",
    ///             Utc::now(),
    ///             user_id
    ///         )
    ///         .execute(&self.pool)
    ///         .await
    ///         .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
    ///
    ///         Ok(())
    ///     }
    /// }
    /// ```
    async fn update_last_login(&self, user_id: &str) -> Result<(), AuthError>;
    /// Increments the failed login attempt counter for a user.
    ///
    /// This function tracks failed login attempts, which can be used for security
    /// mechanisms such as account lockout after multiple failures.
    ///
    /// ## Arguments
    /// * `user_id` - The unique identifier of the user.
    ///
    /// ## Returns
    /// * `Ok(())` if the counter was successfully incremented.
    /// * `Err(AuthError)` if an error occurs.
    ///
    /// ## Example Usage
    /// ```rust
    /// async fn increment_failed_login_attempts(&self, user_id: &str) -> Result<(), AuthError> {
    ///     sqlx::query!(
    ///         "UPDATE users SET failed_attempts = failed_attempts + 1 WHERE id = $1",
    ///         user_id
    ///     )
    ///     .execute(&self.pool)
    ///     .await
    ///     .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
    ///
    ///     Ok(())
    /// }
    /// ```
    async fn increment_failed_login_attempts(&self, user_id: &str) -> Result<(), AuthError>;
    /// Resets the failed login attempt counter for a user.
    ///
    /// This function clears the failed login attempt count, typically used
    /// after a successful login.
    ///
    /// ## Arguments
    /// * `user_id` - The unique identifier of the user.
    ///
    /// ## Returns
    /// * `Ok(())` if the counter was successfully reset.
    /// * `Err(AuthError)` if an error occurs.
    ///
    /// ## Example Usage
    /// ```rust
    /// async fn reset_failed_login_attempts(&self, user_id: &str) -> Result<(), AuthError> {
    ///     sqlx::query!(
    ///         "UPDATE users SET failed_attempts = 0 WHERE id = $1",
    ///         user_id
    ///     )
    ///     .execute(&self.pool)
    ///     .await
    ///     .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
    ///
    ///     Ok(())
    /// }
    /// ```
    async fn reset_failed_login_attempts(&self, user_id: &str) -> Result<(), AuthError>;
    /// Locks a user's account until a specified time.
    ///
    /// This function prevents a user from logging in until the specified lockout period expires.
    ///
    /// ## Arguments
    /// * `user_id` - The unique identifier of the user.
    /// * `until` - The time until which the account should remain locked.
    ///
    /// ## Returns
    /// * `Ok(())` if the account was successfully locked.
    /// * `Err(AuthError)` if an error occurs.
    ///
    /// ## Example Usage
    /// ```rust
    /// use std::time::{SystemTime, UNIX_EPOCH};
    ///
    /// async fn lock_account(&self, user_id: &str, until: SystemTime) -> Result<(), AuthError> {
    ///     let lock_until = until.duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    ///
    ///     sqlx::query!(
    ///         "UPDATE users SET locked_until = $1 WHERE id = $2",
    ///         lock_until,
    ///         user_id
    ///     )
    ///     .execute(&self.pool)
    ///     .await
    ///     .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
    ///
    ///     Ok(())
    /// }
    /// ```
    async fn lock_account(&self, user_id: &str, until: SystemTime) -> Result<(), AuthError>;
    /// Unlocks a user's account.
    ///
    /// This function removes any lock on the account, allowing the user to log in again.
    ///
    /// ## Arguments
    /// * `user_id` - The unique identifier of the user.
    ///
    /// ## Returns
    /// * `Ok(())` if the account was successfully unlocked.
    /// * `Err(AuthError)` if an error occurs.
    ///
    /// ## Example Usage
    /// ```rust
    /// async fn unlock_account(&self, user_id: &str) -> Result<(), AuthError> {
    ///     sqlx::query!(
    ///         "UPDATE users SET locked_until = NULL WHERE id = $1",
    ///         user_id
    ///     )
    ///     .execute(&self.pool)
    ///     .await
    ///     .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
    ///
    ///     Ok(())
    /// }
    /// ```
    async fn unlock_account(&self, user_id: &str) -> Result<(), AuthError>;

    // Refresh token
    /// Updates the refresh token for a user.
    ///
    /// This function stores a new refresh token and its expiry time, allowing
    /// users to refresh their authentication without logging in again.
    ///
    /// ## Arguments
    /// * `user_id` - The unique identifier of the user.
    /// * `token` - The new refresh token.
    /// * `expiry` - The expiration time of the refresh token.
    ///
    /// ## Returns
    /// * `Ok(())` if the refresh token was successfully updated.
    /// * `Err(AuthError)` if an error occurs (e.g., database failure).
    ///
    /// ## Example Usage
    /// ```rust
    /// use std::time::{SystemTime, UNIX_EPOCH};
    ///
    /// async fn update_refresh_token(
    ///     &self,
    ///     user_id: &str,
    ///     token: String,
    ///     expiry: SystemTime
    /// ) -> Result<(), AuthError> {
    ///     let expiry_timestamp = expiry.duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    ///
    ///     sqlx::query!(
    ///         "UPDATE users SET refresh_token = $1, refresh_token_expiry = $2 WHERE id = $3",
    ///         token,
    ///         expiry_timestamp,
    ///         user_id
    ///     )
    ///     .execute(&self.pool)
    ///     .await
    ///     .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
    ///
    ///     Ok(())
    /// }
    /// ```
    async fn update_refresh_token(
        &self,
        user_id: &str,
        token: String,
        expiry: SystemTime,
    ) -> Result<(), AuthError>;
    /// Clears the refresh token for a user.
    ///
    /// This function removes the stored refresh token, forcing the user to log in again.
    ///
    /// ## Arguments
    /// * `user_id` - The unique identifier of the user.
    ///
    /// ## Returns
    /// * `Ok(())` if the refresh token was successfully cleared.
    /// * `Err(AuthError)` if an error occurs.
    ///
    /// ## Example Usage
    /// ```rust
    /// async fn clear_refresh_token(&self, user_id: &str) -> Result<(), AuthError> {
    ///     sqlx::query!(
    ///         "UPDATE users SET refresh_token = NULL, refresh_token_expiry = NULL WHERE id = $1",
    ///         user_id
    ///     )
    ///     .execute(&self.pool)
    ///     .await
    ///     .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
    ///
    ///     Ok(())
    /// }
    /// ```
    async fn clear_refresh_token(&self, user_id: &str) -> Result<(), AuthError>;

    // Security methods
    /// Updates the password history for a user.
    ///
    /// This function stores a hash of the previous password, which can be used
    /// to prevent users from reusing old passwords.
    ///
    /// ## Arguments
    /// * `user_id` - The unique identifier of the user.
    /// * `password_hash` - The hashed password to be stored.
    ///
    /// ## Returns
    /// * `Ok(())` if the password history was successfully updated.
    /// * `Err(AuthError)` if an error occurs.
    ///
    /// ## Example Usage
    /// ```rust
    /// async fn update_password_history(
    ///     &self,
    ///     user_id: &str,
    ///     password_hash: String
    /// ) -> Result<(), AuthError> {
    ///     sqlx::query!(
    ///         "INSERT INTO password_history (user_id, password_hash, changed_at) VALUES ($1, $2, NOW())",
    ///         user_id,
    ///         password_hash
    ///     )
    ///     .execute(&self.pool)
    ///     .await
    ///     .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
    ///
    ///     Ok(())
    /// }
    /// ```
    async fn update_password_history(
        &self,
        user_id: &str,
        password_hash: String,
    ) -> Result<(), AuthError>;
    // Role-Based Access Control (RBAC) methods

    /// Assigns a role to a user.
    ///
    /// # Arguments
    /// * `user_id` - The unique identifier of the user.
    /// * `role` - The RBAC role to assign.
    ///
    /// # Example Usage
    /// ```rust
    /// async fn assign_role_to_user(
    ///     &self,
    ///     user_id: &str,
    ///     role: RBACRole,
    ///     pool: &PgPool
    /// ) -> Result<(), AuthError> {
    ///     sqlx::query!(
    ///         "INSERT INTO user_roles (user_id, role_name) VALUES ($1, $2)",
    ///         user_id,
    ///         role.name
    ///     )
    ///     .execute(pool)
    ///     .await
    ///     .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
    ///
    ///     Ok(())
    /// }
    /// ```
    async fn assign_role_to_user(&self, user_id: &str, role: RBACRole);

    /// Removes a role from a user.
    ///
    /// # Arguments
    /// * `user_id` - The unique identifier of the user.
    /// * `role_name` - The name of the role to be removed.
    ///
    /// # Example Usage
    /// ```rust
    /// async fn remove_role_from_user(
    ///     &self,
    ///     user_id: &str,
    ///     role_name: &str,
    ///     pool: &PgPool
    /// ) -> Result<(), AuthError> {
    ///     sqlx::query!(
    ///         "DELETE FROM user_roles WHERE user_id = $1 AND role_name = $2",
    ///         user_id,
    ///         role_name
    ///     )
    ///     .execute(pool)
    ///     .await
    ///     .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
    ///
    ///     Ok(())
    /// }
    /// ```
    async fn remove_role_from_user(&self, user_id: &str, role_name: &str);

    /// Checks if a user has a specific permission.
    ///
    /// # Arguments
    /// * `user_id` - The unique identifier of the user.
    /// * `permission` - The permission to check.
    ///
    /// # Returns
    /// * `true` if the user has the permission, `false` otherwise.
    async fn user_has_permission(&self, user_id: &str, permission: &str) -> bool;

    /// Retrieves all roles assigned to a user.
    ///
    /// # Arguments
    /// * `user_id` - The unique identifier of the user.
    ///
    /// # Returns
    /// * A vector containing the user's assigned roles.
    async fn get_user_roles(&self, user_id: &str) -> Vec<RBACRole>;

    /// Retrieves all permissions assigned to a user (merged from roles).
    ///
    /// # Arguments
    /// * `user_id` - The unique identifier of the user.
    ///
    /// # Returns
    /// * A `HashSet` containing all permissions the user has.
    async fn get_user_permissions(&self, user_id: &str) -> HashSet<String>;
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
