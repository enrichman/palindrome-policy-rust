use crate::settings::{is_palindrome, Settings};
use kubewarden_policy_sdk::settings::Validatable;
use std::collections::HashSet;

#[test]
fn validate_settings_ok() {
    let settings = Settings {
        threshold: 0,
        whitelisted_labels: HashSet::new(),
    };

    assert!(settings.validate().is_ok());
}

#[test]
fn validate_settings_invalid_whitelisted_labels() {
    let settings = Settings {
        threshold: 0,
        whitelisted_labels: ["foo", "baz"]
            .iter()
            .cloned()
            .map(ToString::to_string)
            .collect(),
    };

    assert!(settings.validate().is_err());
}

#[test]
fn validate_settings_invalid_threshold() {
    let settings = Settings {
        threshold: -5,
        whitelisted_labels: HashSet::new(),
    };

    assert!(settings.validate().is_err());
}

#[test]
fn test_is_palindrome() {
    assert!(is_palindrome("level"));
    assert!(!is_palindrome("foo"));
    assert!(is_palindrome("a"));
    assert!(is_palindrome("aa"));
    assert!(is_palindrome("aba"));
}
