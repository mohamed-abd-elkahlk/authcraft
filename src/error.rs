#[derive(Debug)]
pub enum AuthError {
    // Common authentication errors
    UserNotFound,
    InvalidCredentials,
    TokenExpired,
    InvalidToken,
    Unauthorized,
    AccountLocked,
    AccountDisabled,
    PasswordTooWeak,
    PasswordResetRequired,

    // Token-related errors
    TokenNotProvided,
    TokenCreationFailed,
    TokenVerificationFailed,
    TokenRevoked,

    // Session-related errors
    SessionExpired,
    SessionNotFound,
    TooManySessions,

    // Registration and account management errors
    EmailTaken,
    InvalidEmail,
    InvalidUsername,
    RegistrationDisabled,

    // Security-related errors
    BruteForceAttempt,
    SuspiciousActivity,
    TwoFactorAuthRequired,
    TwoFactorAuthFailed,

    // System and configuration errors
    DatabaseError,
    ConfigurationError,
    InternalServerError,
    HashingError(String),

    // Custom errors
    CustomError(String),
    RateLimitExceeded,
    ThirdPartyServiceError,
}

use std::fmt;

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthError::UserNotFound => write!(f, "User not found"),
            AuthError::InvalidCredentials => write!(f, "Invalid credentials"),
            AuthError::TokenExpired => write!(f, "Token expired"),
            AuthError::InvalidToken => write!(f, "Invalid token"),
            AuthError::Unauthorized => write!(f, "Unauthorized"),
            AuthError::AccountLocked => write!(f, "Account locked"),
            AuthError::AccountDisabled => write!(f, "Account disabled"),
            AuthError::PasswordTooWeak => write!(f, "Password is too weak"),
            AuthError::PasswordResetRequired => write!(f, "Password reset required"),
            AuthError::TokenNotProvided => write!(f, "Token not provided"),
            AuthError::TokenCreationFailed => write!(f, "Token creation failed"),
            AuthError::TokenVerificationFailed => write!(f, "Token verification failed"),
            AuthError::TokenRevoked => write!(f, "Token revoked"),
            AuthError::SessionExpired => write!(f, "Session expired"),
            AuthError::SessionNotFound => write!(f, "Session not found"),
            AuthError::TooManySessions => write!(f, "Too many active sessions"),
            AuthError::EmailTaken => write!(f, "Email is already taken"),
            AuthError::InvalidEmail => write!(f, "Invalid email address"),
            AuthError::InvalidUsername => write!(f, "Invalid username"),
            AuthError::RegistrationDisabled => write!(f, "Registration is disabled"),
            AuthError::BruteForceAttempt => write!(f, "Brute force attempt detected"),
            AuthError::SuspiciousActivity => write!(f, "Suspicious activity detected"),
            AuthError::TwoFactorAuthRequired => write!(f, "Two-factor authentication required"),
            AuthError::TwoFactorAuthFailed => write!(f, "Two-factor authentication failed"),
            AuthError::DatabaseError => write!(f, "Database error"),
            AuthError::ConfigurationError => write!(f, "Configuration error"),
            AuthError::InternalServerError => write!(f, "Internal server error"),
            AuthError::CustomError(msg) => write!(f, "Custom error: {}", msg),
            AuthError::HashingError(msg) => write!(f, "Hashing error: {}", msg),
            AuthError::RateLimitExceeded => write!(f, "Rate limit exceeded"),
            AuthError::ThirdPartyServiceError => write!(f, "Third-party service error"),
        }
    }
}

impl std::error::Error for AuthError {}
