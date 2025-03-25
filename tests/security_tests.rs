#[cfg(test)]
mod tests {
    use authcraft::security::*;
    use chrono::{Duration, Utc};
    use regex::Regex;

    #[test]
    fn generate_reset_token_test() {
        let token = generate_reset_token();
        assert!(!token.is_empty(), "Generated token should not be empty");
    }

    #[test]
    fn generate_random_string_test() {
        let length = 16;
        let random_str = generate_random_string(length);
        assert_eq!(
            random_str.len(),
            length,
            "Generated string should have the correct length"
        );
    }

    #[test]
    fn generate_secure_digest_test() {
        let input = "secure_input";
        let digest = generate_secure_digest(input);
        let re = Regex::new(r"^[a-f0-9]{64}$").unwrap();
        assert!(
            re.is_match(&digest),
            "Generated digest should be a valid SHA-256 hash"
        );
    }

    #[test]
    fn generate_secure_token_test() {
        let token = generate_secure_token();
        assert_eq!(
            token.len(),
            64,
            "Generated secure token should be 64 characters long"
        );
    }

    #[test]
    fn calculate_expiry_test() {
        let duration = Duration::hours(24);
        let expiry_time = calculate_expiry(duration);
        let now = Utc::now().timestamp();
        assert!(expiry_time > now, "Expiry time should be in the future");
    }

    #[test]
    fn is_token_expired_test() {
        let past_time = Utc::now().timestamp() - 3600;
        let future_time = Utc::now().timestamp() + 3600;

        assert!(
            is_token_expired(past_time),
            "Token with past expiry should be expired"
        );
        assert!(
            !is_token_expired(future_time),
            "Token with future expiry should not be expired"
        );
    }

    #[test]
    fn hash_password_test() {
        let password = "secure_password";
        let hashed = hash_password(password).unwrap();
        assert!(
            hashed.len() > 20,
            "Hashed password should be longer than 20 characters"
        );
    }

    #[test]
    fn verify_password_test() {
        let password = "secure_password";
        let hashed = hash_password(password).unwrap();
        assert!(
            verify_password(password, &hashed).unwrap(),
            "Correct password should verify"
        );
    }

    #[test]
    fn verify_password_invalid_test() {
        let password = "secure_password";
        let wrong_password = "wrong_password";
        let hashed = hash_password(password).unwrap();
        assert!(
            !verify_password(wrong_password, &hashed).unwrap(),
            "Incorrect password should not verify"
        );
    }
}
