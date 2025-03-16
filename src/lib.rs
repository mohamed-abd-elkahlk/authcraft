#[allow(unused)]
pub mod error;
pub mod jwt;
pub mod security;
use async_trait::*;
use error::AuthError;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct User<U = (), R = Role> {
    pub id: String,
    pub username: String,
    pub email: String,
    pub password_hash: String,
    pub role: R,
    pub data: Option<U>,
}
#[derive(Debug, Clone, PartialEq)]
pub enum Role {
    Admin,
    User,
    Guest,
}

#[async_trait]
pub trait UserRepository<U>: Send + Sync {
    async fn find_user_by_id(&self, id: &str) -> Result<User<U>, AuthError>;
    async fn find_user_by_email(&self, email: &str) -> Result<User<U>, AuthError>;
    async fn create_user(&self, user: User<U>) -> Result<(), AuthError>;
    async fn update_user(&self, user: User<U>) -> Result<(), AuthError>;
    async fn delete_user(&self, id: &str) -> Result<(), AuthError>;
}
