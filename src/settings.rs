use crate::LOG_DRAIN;
use serde::{Deserialize, Serialize};
use slog::info;
use std::collections::HashSet;

// Describe the settings your policy expects when
// loaded by the policy server.
#[derive(Serialize, Deserialize, Debug)]
#[serde(default)]
pub(crate) struct Settings {
    pub threshold: i32,
    pub whitelisted_labels: HashSet<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            threshold: Default::default(),
            whitelisted_labels: Default::default(),
        }
    }
}

impl kubewarden::settings::Validatable for Settings {
    fn validate(&self) -> Result<(), String> {
        info!(LOG_DRAIN, "starting settings validation");

        let non_palindrome_labels = self
            .whitelisted_labels
            .clone()
            .into_iter()
            .filter(|w| !is_palindrome(w.as_str()))
            .collect::<Vec<String>>();

        if !non_palindrome_labels.is_empty() {
            return Err(format!(
                "whitelisted_labels contains non palindrome labels: {}",
                non_palindrome_labels.join(",")
            ));
        }

        if self.threshold < 0 {
            return Err(format!("Threshold cannot be negative: {}", self.threshold));
        }

        Ok(())
    }
}

pub fn is_palindrome(word: &str) -> bool {
    let chars = word.as_bytes();
    let len = chars.len();

    for i in 0..len / 2 {
        if chars[i] != chars[len - i - 1] {
            return false;
        }
    }
    true
}
