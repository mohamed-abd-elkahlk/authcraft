use async_trait::async_trait;
use redis::AsyncCommands;

/// Trait for lockout storage (abstracts in-memory or Redis implementation)
#[async_trait]
pub trait LockoutStorage: Send + Sync {
    async fn record_failure(&self, key: &str);
    async fn is_locked_out(&self, key: &str) -> bool;
    async fn reset_attempts(&self, key: &str);
}

/// Redis-based lockout implementation
pub struct RedisLockout {
    client: redis::Client,
}

impl RedisLockout {
    pub fn new(redis_url: &str) -> Self {
        let client = redis::Client::open(redis_url).expect("Failed to connect to Redis");
        Self { client }
    }
}

#[async_trait]
impl LockoutStorage for RedisLockout {
    async fn record_failure(&self, key: &str) {
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .unwrap();
        let _: () = conn.incr(key, 1).await.unwrap();
        let _: () = conn.expire(key, 300).await.unwrap(); // Key expires in 5 minutes
    }

    async fn is_locked_out(&self, key: &str) -> bool {
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .unwrap();
        let count: i32 = conn.get(key).await.unwrap_or(0);
        count >= 5 // Lockout if 5+ failed attempts
    }

    async fn reset_attempts(&self, key: &str) {
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .unwrap();
        let _: () = conn.del(key).await.unwrap();
    }
}
