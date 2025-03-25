#[cfg(test)]
mod tests {
    use authcraft::jwt::JwtConfig;
    use authcraft::sessions::SessionManager;

    const TEST_REDIS_URL: &str = "redis://127.0.0.1/";

    #[tokio::test]
    async fn test_issue_access_token() {
        let session_manager = SessionManager::new(TEST_REDIS_URL).unwrap();
        let jwt_config = JwtConfig {
            secret: "test_secret_key".to_string(),
            expiration_days: 7,
        };

        let token = session_manager.issue_access_token(
            &jwt_config,
            "user123".to_string(),
            None::<()>,
            vec!["admin".to_string()],
        );

        assert!(token.is_ok());
    }

    #[tokio::test]
    async fn test_issue_refresh_token() {
        let session_manager = SessionManager::new(TEST_REDIS_URL).unwrap();
        let jwt_config = JwtConfig {
            secret: "test_secret_key".to_string(),
            expiration_days: 7,
        };

        let token = session_manager.issue_refresh_token(&jwt_config, "user123".to_string());

        assert!(token.is_ok());
    }

    #[tokio::test]
    async fn test_store_and_validate_refresh_token() {
        let session_manager = SessionManager::new(TEST_REDIS_URL).unwrap();
        let jwt_config = JwtConfig {
            secret: "test_secret_key".to_string(),
            expiration_days: 7,
        };

        let refresh_token = session_manager
            .issue_refresh_token(&jwt_config, "user123".to_string())
            .unwrap();

        session_manager
            .store_refresh_token("user123", &refresh_token)
            .await
            .unwrap();
        let is_valid = session_manager
            .validate_refresh_token("user123", &refresh_token)
            .await
            .unwrap();

        assert!(is_valid);
    }

    #[tokio::test]
    async fn test_remove_refresh_token() {
        let session_manager = SessionManager::new(TEST_REDIS_URL).unwrap();
        let jwt_config = JwtConfig {
            secret: "test_secret_key".to_string(),
            expiration_days: 7,
        };

        let refresh_token = session_manager
            .issue_refresh_token(&jwt_config, "user123".to_string())
            .unwrap();

        session_manager
            .store_refresh_token("user123", &refresh_token)
            .await
            .unwrap();
        session_manager
            .remove_refresh_token("user123")
            .await
            .unwrap();
        let is_valid = session_manager
            .validate_refresh_token("user123", &refresh_token)
            .await
            .unwrap();

        assert!(!is_valid);
    }
}
