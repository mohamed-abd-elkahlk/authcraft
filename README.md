# AuthCraft

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Crates.io](https://img.shields.io/crates/v/authcraft.svg)](https://crates.io/crates/authcraft)
[![Docs.rs](https://docs.rs/authcraft/badge.svg)](https://docs.rs/authcraft)
[![GitHub Stars](https://img.shields.io/github/stars/mohamed-abd-elkahlk/authcraft?style=social)](https://github.com/mohamed-abd-elkahlk/authcraft/stargazers)

AuthCraft is a comprehensive authentication and authorization library for Rust applications. Built with security and performance in mind, it provides a robust solution for managing user authentication, session handling, and access control in web services, APIs, and other Rust-based applications.

## Features

- **JWT Authentication**: Secure implementation of JSON Web Tokens for stateless authentication
- **User Registration and Login**: Pre-built handlers for user onboarding and authentication flows
- **Password Hashing and Security**: Industry-standard cryptographic algorithms using Rust's security-focused ecosystem
- **Role-Based Access Control**: Type-safe permission system to manage user access to resources
- **Token Management**: Comprehensive tools for token creation, validation, refreshing, and revocation
- **Session Handling**: Efficient and secure user session management with optional Redis integration

## Installation

Add AuthCraft to your Cargo.toml:

```toml
[dependencies]
authcraft = "0.1.0"
```

Or use cargo add:

```bash
cargo add authcraft
```

For development or latest features, you can use the Git repository:

```toml
[dependencies]
authcraft = { git = "https://github.com/mohamed-abd-elkahlk/authcraft" }
```

## Usage

Here's how to use AuthCraft in your Rust application:

```rust
use authcraft::{AuthCraft, AuthConfig, User, Claims, Role};
use std::collections::HashMap;

// Initialize the authentication service
let config = AuthConfig {
    jwt_secret: "your-secure-jwt-secret-key".to_string(),
    token_expiration: chrono::Duration::hours(1),
    refresh_token_expiration: chrono::Duration::days(7),
};

let auth = AuthCraft::new(config);

// Register a new user
async fn register_example(auth: &AuthCraft) -> Result<User, authcraft::Error> {
    let new_user = auth.register(
        "user@example.com",
        "securePassword123",
        Role::User,
    ).await?;
    
    Ok(new_user)
}

// Authenticate a user
async fn login_example(auth: &AuthCraft) -> Result<(String, String), authcraft::Error> {
    let (token, refresh_token) = auth.login(
        "user@example.com",
        "securePassword123"
    ).await?;
    
    Ok((token, refresh_token))
}

// Verify a token
fn verify_example(auth: &AuthCraft, token: &str) -> Result<Claims, authcraft::Error> {
    let claims = auth.verify_token(token)?;
    
    Ok(claims)
}

// Use with a web framework like Actix-web
use actix_web::{web, App, HttpServer, Responder, HttpResponse};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let auth = web::Data::new(AuthCraft::new(AuthConfig::default()));
    
    HttpServer::new(move || {
        App::new()
            .app_data(auth.clone())
            .service(web::resource("/register").route(web::post().to(register)))
            .service(web::resource("/login").route(web::post().to(login)))
            .service(
                web::resource("/protected")
                    .wrap(authcraft::middleware::JwtAuth::new(Role::User))
                    .route(web::get().to(protected_route))
            )
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}

async fn protected_route(claims: authcraft::Claims) -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "message": "Access granted",
        "user_id": claims.sub,
        "role": claims.role,
    }))
}
```

## How to Contribute

Contributions are always welcome! Here's how you can help:

1. Fork the repository
2. Create a new branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Commit your changes (`git commit -m 'Add some amazing feature'`)
5. Push to the branch (`git push origin feature/amazing-feature`)
6. Open a Pull Request

Please make sure to update tests as appropriate and follow the code style guidelines.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

If you find AuthCraft helpful, please consider giving it a ⭐️ on [GitHub](https://github.com/mohamed-abd-elkahlk/authcraft)! Your support helps to maintain and improve this Rust authentication library.

![GitHub stars](https://img.shields.io/github/stars/mohamed-abd-elkahlk/authcraft?style=social)

## Contact

Mohamed - Connect with me on [GitHub](https://github.com/mohamed-abd-elkahlk)

Project Link: [https://github.com/mohamed-abd-elkahlk/authcraft](https://github.com/mohamed-abd-elkahlk/authcraft)

