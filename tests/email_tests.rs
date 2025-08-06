#[cfg(test)]
pub mod tests {

    use authcraft::email::*;

    #[tokio::test]
    async fn send_email_test() {
        let email_config = EmailConfig::from_env().unwrap();
        let email_service = EmailService::new(email_config.clone(), "templates").unwrap();
        let send = email_service
            .send_verification_email(
                &email_config.smtp_username,
                "username",
                "https://example.com/verify?token=abc123",
                "verification_email",
            )
            .await
            .map_err(|e| dbg!(e.to_string()));
        assert!(send.is_ok())
    }
    #[tokio::test]
    async fn send_custom_email_test() {
        let email_config = EmailConfig::from_env().unwrap();
        let email_service = EmailService::new(email_config.clone(), "templates").unwrap();
        let send = email_service
            .send_custom_email(
                &email_config.smtp_username,
                "username",
                "test mothods",
                "hi this just some tests",
                "<p>test html</p>",
            )
            .await;
        assert!(send.is_ok())
    }
}
