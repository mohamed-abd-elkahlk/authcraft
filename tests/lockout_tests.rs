#[cfg(test)]
mod tests {
    use authcraft::lockout::*;

    #[tokio::test]
    async fn record_failure_test() {
        let lockout = RedisLockout::from_env().expect("Failed to init lockout");
        let key = "test_user";

        let result = lockout.record_failure(key).await;
        assert!(
            result.is_ok(),
            "Failed to record failure: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn is_locked_out_test() {
        let lockout = RedisLockout::from_env().expect("Failed to init lockout");
        let key = "test_locked_user";

        for _ in 0..3 {
            lockout.record_failure(key).await.unwrap();
        }

        let locked = lockout.is_locked_out(key).await.unwrap();
        assert!(locked, "User should be locked out after max attempts");
    }

    #[tokio::test]
    async fn reset_attempts_test() {
        let lockout = RedisLockout::from_env().expect("Failed to init lockout");
        let key = "test_reset_user";

        lockout.record_failure(key).await.unwrap();
        lockout.reset_attempts(key).await.unwrap();

        let locked = lockout.is_locked_out(key).await.unwrap();
        assert!(!locked, "User should not be locked after reset");
    }
}
