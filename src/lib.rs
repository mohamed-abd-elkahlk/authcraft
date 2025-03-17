pub mod email;
#[allow(unused)]
pub mod error;
pub mod jwt;
pub mod security;
use async_trait::*;
use error::AuthError;
use jwt::JwtConfig;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct User<U = (), R = Role> {
    pub id: String,
    pub username: String,
    pub email: String,
    pub password_hash: String,
    pub role: R,
    pub data: Option<U>,
}
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub enum Role {
    Admin,
    User,
    Guest,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RegisterUserRequest {
    pub username: String,
    pub email: String,
    pub password: String,
}

/// Request payload for user login
#[derive(Debug, Deserialize, Serialize)]
pub struct LoginUserRequest {
    pub email: String,
    pub password: String,
}
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct UpdateUser<U = ()> {
    pub id: String,
    pub username: Option<String>,
    pub email: Option<String>,
    pub password: Option<String>,
    pub role: Option<Role>,
    pub data: Option<U>,
}
#[async_trait]
pub trait UserRepository<U>: Send + Sync {
    async fn find_user_by_id(&self, id: &str) -> Result<User<U>, AuthError>;
    async fn find_user_by_email(&self, email: &str) -> Result<User<U>, AuthError>;
    async fn create_user(&self, user: RegisterUserRequest) -> Result<User<U>, AuthError>;
    async fn update_user(&self, user: UpdateUser<U>) -> Result<User<U>, AuthError>;
    async fn delete_user(&self, email: &str) -> Result<(), AuthError>;
    async fn create_verification_token(
        &self,
        user_id: &str,
        jwt: JwtConfig,
    ) -> Result<(String, User<U>), AuthError>;
    async fn verify_email(&self, token: &str, jwt: JwtConfig) -> Result<(), AuthError>;
}
