//! # Email Module
//!
//! This module provides functionality for sending emails using an SMTP server.
//! It supports templated emails (using the `tera` templating engine) and custom emails
//! with both plain text and HTML content.
//!
//! ## Features
//! - Send templated emails with dynamic data.
//! - Send custom emails with plain text and HTML content.
//! - Send verification emails with a predefined template.
//! - Configurable SMTP settings.
//!
//! ## Example Usage
//!
//! ```rust
//! use authcarft::email::{EmailConfig, EmailService};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Configure the email service
//!     let config = EmailConfig {
//!         smtp_server: "smtp.example.com".to_string(),
//!         smtp_username: "user@example.com".to_string(),
//!         smtp_password: "password".to_string(),
//!         sender_email: "noreply@example.com".to_string(),
//!         sender_name: "Example Corp".to_string(),
//!     };
//!
//!     // Initialize the email service
//!     let email_service = EmailService::new(config, "templates")?;
//!
//!     // Send a templated email
//!     email_service
//!         .send_templated_email(
//!             "recipient@example.com",
//!             "Recipient Name",
//!             "Welcome!",
//!             "welcome_email",
//!             &serde_json::json!({ "name": "Recipient Name" }),
//!         )
//!         .await?;
//!
//!     // Send a verification email
//!     email_service
//!         .send_verification_email(
//!             "recipient@example.com",
//!             "Recipient Name",
//!             "https://example.com/verify?token=abc123",
//!         )
//!         .await?;
//!
//!     Ok(())
//! }
//! ```

use std::env;

use dotenv::dotenv;
use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    message::{MultiPart, SinglePart, header},
    transport::smtp::authentication::Credentials,
};
use serde::Serialize;
use tera::{Context, Tera};

/// Configuration for the email service.
#[derive(Debug, Clone)]
pub struct EmailConfig {
    /// SMTP server address (e.g., "smtp.example.com").
    pub smtp_server: String,
    /// SMTP username for authentication.
    pub smtp_username: String,
    /// SMTP password for authentication.
    pub smtp_password: String,
    /// Sender's email address.
    pub sender_email: String,
    /// Sender's display name.
    pub sender_name: String,
}

impl EmailConfig {
    pub fn from_env() -> Result<Self, String> {
        dotenv().ok(); // Load .env file if present

        Ok(Self {
            smtp_server: env::var("SMTP_SERVER").map_err(|_| "Missing SMTP_SERVER".to_string())?,
            smtp_username: env::var("SMTP_USERNAME")
                .map_err(|_| "Missing SMTP_USERNAME".to_string())?,
            smtp_password: env::var("SMTP_PASSWORD")
                .map_err(|_| "Missing SMTP_PASSWORD".to_string())?,
            sender_email: env::var("SENDER_EMAIL")
                .map_err(|_| "Missing SENDER_EMAIL".to_string())?,
            sender_name: env::var("SENDER_NAME").map_err(|_| "Missing SENDER_NAME".to_string())?,
        })
    }
}

/// Email service for sending templated and custom emails.
#[derive(Debug, Clone)]
pub struct EmailService {
    mailer: AsyncSmtpTransport<Tokio1Executor>,
    templates: Tera,
    sender_email: String,
    sender_name: String,
}

impl EmailService {
    /// Creates a new `EmailService` instance.
    ///
    /// # Arguments
    /// - `config`: Configuration for the email service.
    /// - `templates_dir`: Directory containing email templates.
    ///
    /// # Returns
    /// - `Result<Self, Box<dyn std::error::Error>>`: The initialized `EmailService` or an error.
    ///
    /// ```rust
    /// use authcraft::email::{EmailConfig, EmailService};
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///     let config = EmailConfig {
    ///         smtp_server: "smtp.example.com".to_string(),
    ///         smtp_username: "user@example.com".to_string(),
    ///         smtp_password: "password".to_string(),
    ///         sender_email: "noreply@example.com".to_string(),
    ///         sender_name: "Example Corp".to_string(),
    ///     };
    ///     let email_service = EmailService::new(config, "templates")?;
    ///     Ok(())
    /// }
    /// ```
    pub fn new(
        config: EmailConfig,
        templates_dir: &str,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let mut templates = Tera::new(&format!("{}/{}", templates_dir, "*.html"))?; // Ensure only `.html` files are loaded
        templates.autoescape_on(vec!["html", "htm", "xml"]);
        templates.register_filter("json_encode", move |value: &tera::Value, _: &_| {
            Ok(serde_json::to_string(&value).unwrap_or_default().into())
        });

        let creds = Credentials::new(config.smtp_username, config.smtp_password);
        let mailer = AsyncSmtpTransport::<Tokio1Executor>::relay(&config.smtp_server)?
            .credentials(creds)
            .build();

        Ok(Self {
            mailer,
            templates,
            sender_email: config.sender_email,
            sender_name: config.sender_name,
        })
    }

    /// Sends a templated email.
    ///
    /// # Arguments
    /// - `recipient_email` - Email address of the recipient.
    /// - `recipient_name` - Name of the recipient.
    /// - `subject` - Email subject.
    /// - `template_name` - Name of the template (without extension).
    /// - `template_data` - Data to render the template.
    ///
    /// # Returns
    /// - `Result<(), Box<dyn std::error::Error>>` - Success or error.
    ///
    /// # Example
    /// ```rust
    /// use authcraft::email::{EmailConfig, EmailService};
    /// use serde_json::json;
    /// use tokio;
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///    let config = EmailConfig::from_env().unwrap();
    ///     let email_service = EmailService::new(config, "templates")?;
    ///
    ///     email_service.send_templated_email(
    ///         "recipient@example.com",
    ///         "Recipient Name",
    ///         "Welcome!",
    ///         "welcome_email",
    ///         &json!({ "name": "Recipient Name" }),
    ///     ).await?;
    ///
    ///     Ok(())
    /// }
    /// ```

    pub async fn send_templated_email<T: Serialize>(
        &self,
        recipient_email: &str,
        recipient_name: &str,
        subject: &str,
        template_name: &str,
        template_data: &T,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut context = Context::new();
        context.insert("data", template_data);

        let html_body = self
            .templates
            .render(&format!("{}.html", template_name), &context)?;

        let email = Message::builder()
            .from(format!("{} <{}>", self.sender_name, self.sender_email).parse()?)
            .to(format!("{} <{}>", recipient_name, recipient_email).parse()?)
            .subject(subject)
            .header(header::ContentType::TEXT_HTML)
            .body(html_body)?;

        self.mailer.send(email).await?;
        Ok(())
    }

    /// Sends a verification email using a predefined template.
    ///
    /// # Arguments
    /// - `recipient_email`: Email address of the recipient.
    /// - `recipient_name`: Name of the recipient.
    /// - `verification_link`: Link for email verification.
    /// - `template_name`: Name of the email template (without extension).
    ///
    /// # Returns
    /// - `Result<(), Box<dyn std::error::Error>>`: Success or error.
    ///
    /// # Example
    /// ```rust
    /// use authcraft::email::{EmailConfig, EmailService};
    /// use serde_json::json;
    /// use tokio;
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///     let config = EmailConfig::from_env().unwrap();
    ///     let email_service = EmailService::new(config, "templates")?;
    ///
    ///     email_service.send_verification_email(
    ///         "recipient@example.com",
    ///         "Recipient Name",
    ///         "https://example.com/verify?token=abc123",
    ///         "verification_email",
    ///     ).await?;
    ///
    ///     Ok(())
    /// }
    /// ```

    pub async fn send_verification_email(
        &self,
        recipient_email: &str,
        recipient_name: &str,
        verification_link: &str,
        template_name: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let data = serde_json::json!({
            "name": recipient_name,
            "verification_link": verification_link,
            "expires_in_hours": 24
        });

        self.send_templated_email(
            recipient_email,
            recipient_name,
            "Verify Your Email Address",
            template_name,
            &data,
        )
        .await
    }

    /// Sends a custom email with plain text and HTML content.
    ///
    /// # Arguments
    /// - `recipient_email`: Email address of the recipient.
    /// - `recipient_name`: Name of the recipient.
    /// - `subject`: Email subject.
    /// - `plain_text`: Plain text content of the email.
    /// - `html_content`: HTML content of the email.
    ///
    /// # Returns
    /// - `Result<(), Box<dyn std::error::Error>>`: Success or error.
    ///
    /// # Example
    /// ```rust
    /// use authcraft::email::{EmailConfig, EmailService};
    /// use tokio;
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///     let config = EmailConfig::from_env().unwrap();
    ///     let email_service = EmailService::new(config, "templates")?;
    ///
    ///     email_service.send_custom_email(
    ///         "recipient@example.com",
    ///         "Recipient Name",
    ///         "Hello!",
    ///         "This is a plain text email.",
    ///         "<p>This is an <strong>HTML</strong> email.</p>",
    ///     ).await?;
    ///
    ///     Ok(())
    /// }
    /// ```

    pub async fn send_custom_email(
        &self,
        recipient_email: &str,
        recipient_name: &str,
        subject: &str,
        plain_text: &str,
        html_content: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let email = Message::builder()
            .from(format!("{} <{}>", self.sender_name, self.sender_email).parse()?)
            .to(format!("{} <{}>", recipient_name, recipient_email).parse()?)
            .subject(subject)
            .multipart(
                MultiPart::alternative()
                    .singlepart(
                        SinglePart::builder()
                            .header(header::ContentType::TEXT_PLAIN)
                            .body(plain_text.to_string()),
                    )
                    .singlepart(
                        SinglePart::builder()
                            .header(header::ContentType::TEXT_HTML)
                            .body(html_content.to_string()),
                    ),
            )?;

        self.mailer.send(email).await?;
        Ok(())
    }
}
