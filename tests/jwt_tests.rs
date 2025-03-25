#[cfg(test)]
mod tests {
    use authcraft::jwt::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    struct CustomPayload {
        role: String,
    }

    #[test]
    fn test_issue_and_verify_jwt() {
        let config = JwtConfig::new("my_secret_key".to_string(), 7);
        let payload = CustomPayload {
            role: "admin".to_string(),
        };
        let token = issue_jwt(
            config.clone(),
            "user123".to_string(),
            Some(payload.clone()),
            vec!["admin".to_string()],
        )
        .unwrap();

        let claims: Claims<CustomPayload> = verify_jwt(&config, &token).unwrap();
        assert_eq!(claims.sub, "user123");
        assert_eq!(claims.roles, vec!["admin"]);
        assert_eq!(claims.payload, Some(payload));
    }

    #[test]
    fn test_invalid_token() {
        let config = JwtConfig::new("my_secret_key".to_string(), 7);
        let invalid_token = "invalid.token.string";
        let result: Result<Claims<()>, _> = verify_jwt(&config, invalid_token);

        assert!(result.is_err());
    }

    #[test]
    fn test_expired_token() {
        let config = JwtConfig::new("my_secret_key".to_string(), -1); // Expired token
        let token = issue_jwt(
            config.clone(),
            "user123".to_string(),
            None::<()>,
            vec!["user".to_string()],
        )
        .unwrap();
        let result: Result<Claims<()>, _> = verify_jwt(&config, &token);

        assert!(result.is_err());
    }
}
