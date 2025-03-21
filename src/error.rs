use thiserror::Error;

/// Authentication and Authorization Errors
#[derive(Debug, Error, Clone, PartialEq)]
pub enum AuthError {
    #[error("User not found: {0}")]
    UserNotFound(String),

    #[error("Invalid credentials: {0}")]
    InvalidCredentials(String),

    #[error("Token expired: {0}")]
    TokenExpired(String),

    #[error("Invalid token: {0}")]
    InvalidToken(String),

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Account locked: {0}")]
    AccountLocked(String),

    #[error("Account disabled: {0}")]
    AccountDisabled(String),

    #[error("Password is too weak: {0}")]
    PasswordTooWeak(String),

    #[error("Password reset required: {0}")]
    PasswordResetRequired(String),

    #[error("Token not provided: {0}")]
    TokenNotProvided(String),

    #[error("Token creation failed: {0}")]
    TokenCreationFailed(String),

    #[error("Token verification failed: {0}")]
    TokenVerificationFailed(String),

    #[error("Token revoked: {0}")]
    TokenRevoked(String),

    #[error("Session expired: {0}")]
    SessionExpired(String),

    #[error("Session not found: {0}")]
    SessionNotFound(String),

    #[error("Too many active sessions: {0}")]
    TooManySessions(String),

    #[error("Email is already taken: {0}")]
    EmailTaken(String),

    #[error("Invalid username: {0}")]
    InvalidUsername(String),

    #[error("Registration is disabled")]
    RegistrationDisabled,

    #[error("Brute force attempt detected: {0}")]
    BruteForceAttempt(String),

    #[error("Suspicious activity detected: {0}")]
    SuspiciousActivity(String),

    #[error("Two-factor authentication required")]
    TwoFactorAuthRequired,

    #[error("Two-factor authentication failed: {0}")]
    TwoFactorAuthFailed(String),

    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Configuration error: {0}")]
    ConfigurationError(String),

    #[error("Internal server error: {0}")]
    InternalServerError(String),

    #[error("Hashing error: {0}")]
    HashingError(String),

    #[error("Custom error: {0}")]
    CustomError(String),

    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    #[error("Invalid OTP: {0}")]
    InvalidOtp(String),

    #[error("Invalid TOTP Secret: {0}")]
    InvalidSecret(String),

    #[error("Invalid Backup Code: {0}")]
    InvalidBackupCode(String),

    #[error("Third-party service error: {0}")]
    ThirdPartyServiceError(String),
}
