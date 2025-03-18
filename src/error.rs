use std::fmt;

#[derive(Debug)]
pub enum AuthError {
    UserNotFound(String),
    InvalidCredentials(String),
    TokenExpired(String),
    InvalidToken(String),
    Unauthorized(String),
    AccountLocked(String),
    AccountDisabled(String),
    PasswordTooWeak(String),
    PasswordResetRequired(String),

    TokenNotProvided(String),
    TokenCreationFailed(String),
    TokenVerificationFailed(String),
    TokenRevoked(String),

    SessionExpired(String),
    SessionNotFound(String),
    TooManySessions(String),

    EmailTaken(String),
    InvalidUsername(String),
    RegistrationDisabled(String),

    BruteForceAttempt(String),
    SuspiciousActivity(String),
    TwoFactorAuthRequired(String),
    TwoFactorAuthFailed(String),

    DatabaseError(String),
    ConfigurationError(String),
    InternalServerError(String),
    HashingError(String),

    CustomError(String),
    RateLimitExceeded(String),
    ThirdPartyServiceError(String),
    InvalidSecret(String),
    InvalidOtp(String),
    InvalidBackupCode(String),
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthError::UserNotFound(msg) => write!(f, "User not found: {}", msg),
            AuthError::InvalidCredentials(msg) => write!(f, "Invalid credentials: {}", msg),
            AuthError::TokenExpired(msg) => write!(f, "Token expired: {}", msg),
            AuthError::InvalidToken(msg) => write!(f, "Invalid token: {}", msg),
            AuthError::Unauthorized(msg) => write!(f, "Unauthorized: {}", msg),
            AuthError::AccountLocked(msg) => write!(f, "Account locked: {}", msg),
            AuthError::AccountDisabled(msg) => write!(f, "Account disabled: {}", msg),
            AuthError::PasswordTooWeak(msg) => write!(f, "Password is too weak: {}", msg),
            AuthError::PasswordResetRequired(msg) => write!(f, "Password reset required: {}", msg),
            AuthError::TokenNotProvided(msg) => write!(f, "Token not provided: {}", msg),
            AuthError::TokenCreationFailed(msg) => write!(f, "Token creation failed: {}", msg),
            AuthError::TokenVerificationFailed(msg) => {
                write!(f, "Token verification failed: {}", msg)
            }
            AuthError::TokenRevoked(msg) => write!(f, "Token revoked: {}", msg),
            AuthError::SessionExpired(msg) => write!(f, "Session expired: {}", msg),
            AuthError::SessionNotFound(msg) => write!(f, "Session not found: {}", msg),
            AuthError::TooManySessions(msg) => write!(f, "Too many active sessions: {}", msg),
            AuthError::EmailTaken(msg) => write!(f, "Email is already taken: {}", msg),
            AuthError::InvalidUsername(msg) => write!(f, "Invalid username: {}", msg),
            AuthError::RegistrationDisabled(msg) => write!(f, "Registration is disabled: {}", msg),
            AuthError::BruteForceAttempt(msg) => write!(f, "Brute force attempt detected: {}", msg),
            AuthError::SuspiciousActivity(msg) => {
                write!(f, "Suspicious activity detected: {}", msg)
            }
            AuthError::TwoFactorAuthRequired(msg) => {
                write!(f, "Two-factor authentication required: {}", msg)
            }
            AuthError::TwoFactorAuthFailed(msg) => {
                write!(f, "Two-factor authentication failed: {}", msg)
            }
            AuthError::DatabaseError(msg) => write!(f, "Database error: {}", msg),
            AuthError::ConfigurationError(msg) => write!(f, "Configuration error: {}", msg),
            AuthError::InternalServerError(msg) => write!(f, "Internal server error: {}", msg),
            AuthError::HashingError(msg) => write!(f, "Hashing error: {}", msg),
            AuthError::CustomError(msg) => write!(f, "Custom error: {}", msg),
            AuthError::RateLimitExceeded(msg) => write!(f, "Rate limit exceeded: {}", msg),
            AuthError::InvalidOtp(msg) => write!(f, "Invalid OTP: {}", msg),
            AuthError::InvalidSecret(msg) => write!(f, "Invalid TOTP Secret: {}", msg),
            AuthError::InvalidBackupCode(msg) => write!(f, "Invalid Backup Code: {}", msg),
            AuthError::ThirdPartyServiceError(msg) => {
                write!(f, "Third-party service error: {}", msg)
            }
        }
    }
}

impl std::error::Error for AuthError {}
