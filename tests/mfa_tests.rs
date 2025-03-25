#[cfg(test)]
mod tests {
    use std::time::SystemTime;
    use std::time::UNIX_EPOCH;

    use authcraft::error::*;
    use authcraft::mfa::*;

    #[test]
    fn generate_totp_secret_test() {
        let secret = MfaSettings::generate_totp_secret();
        assert!(secret.is_ok(), "Failed to generate TOTP secret");
    }

    #[test]
    fn verify_totp_code_test() {
        let secret = MfaSettings::generate_totp_secret().unwrap();
        let totp = totp_rs::TOTP::new(
            totp_rs::Algorithm::SHA1,
            6,
            1,
            30,
            base32::decode(base32::Alphabet::Rfc4648 { padding: false }, &secret).unwrap(),
        )
        .unwrap();

        let code = totp.generate(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        );
        let is_valid = MfaSettings::verify_totp_code(&secret, &code).unwrap();
        assert!(is_valid, "Valid TOTP code should pass verification");
    }

    #[test]
    fn invalid_totp_code_test() {
        let secret = MfaSettings::generate_totp_secret().unwrap();
        let is_valid = MfaSettings::verify_totp_code(&secret, "000000").unwrap();
        assert!(!is_valid, "Invalid TOTP code should not pass verification");
    }

    #[test]
    fn generate_backup_codes_test() {
        let codes = MfaSettings::generate_backup_codes(5, 10);
        assert_eq!(codes.len(), 5, "Incorrect number of backup codes generated");
        assert!(
            codes.iter().all(|code| code.len() == 10),
            "Incorrect backup code length"
        );
    }

    #[test]
    fn verify_valid_backup_code_test() {
        let backup_codes = MfaSettings::generate_backup_codes(5, 10);
        let settings = MfaSettings {
            method: MfaType::BackupCodes,
            secret: None,
            backup_codes: Some(backup_codes.clone()),
        };

        let valid_code = backup_codes[0].clone();
        assert!(
            settings.verify_backup_code(&valid_code).unwrap(),
            "Valid backup code should be verified"
        );
    }

    #[test]
    fn verify_invalid_backup_code_test() {
        let settings = MfaSettings {
            method: MfaType::BackupCodes,
            secret: None,
            backup_codes: Some(MfaSettings::generate_backup_codes(5, 10)),
        };

        let invalid_code = "INVALIDCODE".to_string();
        assert!(
            matches!(
                settings.verify_backup_code(&invalid_code),
                Err(AuthCraftError::InvalidBackupCode(_))
            ),
            "Invalid backup code should return an error"
        );
    }

    #[test]
    fn mark_backup_code_as_used_test() {
        let mut settings = MfaSettings {
            method: MfaType::BackupCodes,
            secret: None,
            backup_codes: Some(MfaSettings::generate_backup_codes(5, 10)),
        };

        let valid_code = settings.backup_codes.as_ref().unwrap()[0].clone();
        assert!(
            settings.mark_backup_code_as_used(&valid_code).is_ok(),
            "Should be able to mark code as used"
        );

        assert!(
            matches!(
                settings.verify_backup_code(&valid_code),
                Err(AuthCraftError::InvalidBackupCode(_))
            ),
            "Used backup code should not be valid anymore"
        );
    }
}
