use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    message::{MultiPart, SinglePart, header},
    transport::smtp::authentication::Credentials,
};
use serde::Serialize;
use tera::{Context, Tera};

// Configuration for the email service

#[derive(Debug, Clone)]
pub struct EmailConfig {
    pub smtp_server: String,
    pub smtp_username: String,
    pub smtp_password: String,
    pub sender_email: String,
    pub sender_name: String,
}
// Email service that handles template rendering and sending

#[derive(Debug, Clone)]
pub struct EmailService {
    mailer: AsyncSmtpTransport<Tokio1Executor>,
    templates: Tera,
    sender_email: String,
    sender_name: String,
}

impl EmailService {
    pub fn new(
        config: EmailConfig,
        templates_dir: &str,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        // Initialize the template engine
        let mut templates = Tera::new(&format!("{}/**/*", templates_dir))?;
        templates.autoescape_on(vec!["html", "htm", "xml"]);
        templates.register_filter("json_encode", move |value: &tera::Value, _: &_| {
            Ok(serde_json::to_string(&value).unwrap_or_default().into())
        });

        // Configure the SMTP transport
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

    // Method to send emails with template
    pub async fn send_templated_email<T: Serialize>(
        &self,
        recipient_email: &str,
        recipient_name: &str,
        subject: &str,
        template_name: &str,
        template_data: &T,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Create template context
        let mut context = Context::new();
        context.insert("data", template_data);

        // Render both HTML and text versions
        let html_body = self
            .templates
            .render(&format!("{}.html", template_name), &context)?;
        let text_body = self
            .templates
            .render(&format!("{}.txt", template_name), &context)?;

        // Build email message
        let email = Message::builder()
            .from(format!("{} <{}>", self.sender_name, self.sender_email).parse()?)
            .to(format!("{} <{}>", recipient_name, recipient_email).parse()?)
            .subject(subject)
            .multipart(
                MultiPart::alternative()
                    .singlepart(
                        SinglePart::builder()
                            .header(header::ContentType::TEXT_PLAIN)
                            .body(text_body),
                    )
                    .singlepart(
                        SinglePart::builder()
                            .header(header::ContentType::TEXT_HTML)
                            .body(html_body),
                    ),
            )?;

        // Send the email
        self.mailer.send(email).await?;

        Ok(())
    }

    // Method specifically for sending verification emails
    pub async fn send_verification_email(
        &self,
        recipient_email: &str,
        recipient_name: &str,
        verification_link: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Create the data for the verification template
        let data = serde_json::json!({
            "name": recipient_name,
            "verification_link": verification_link,
            "expires_in_hours": 24
        });

        self.send_templated_email(
            recipient_email,
            recipient_name,
            "Verify Your Email Address",
            "verification_email",
            &data,
        )
        .await
    }
    // Method to send a custom email without using predefined templates
    pub async fn send_custom_email(
        &self,
        recipient_email: &str,
        recipient_name: &str,
        subject: &str,
        plain_text: &str,
        html_content: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Build email message
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

        // Send the email
        self.mailer.send(email).await?;
        Ok(())
    }
}
