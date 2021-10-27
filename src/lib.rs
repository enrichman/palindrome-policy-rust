use lazy_static::lazy_static;

extern crate wapc_guest as guest;
use guest::prelude::*;

use k8s_openapi::api::core::v1 as apicore;

extern crate kubewarden_policy_sdk as kubewarden;
use kubewarden::{logging, protocol_version_guest, request::ValidationRequest, validate_settings};

mod settings;
use settings::Settings;

use slog::{info, o, warn, Logger};

use crate::settings::is_palindrome;

lazy_static! {
    static ref LOG_DRAIN: Logger = Logger::root(
        logging::KubewardenDrain::new(),
        o!("policy" => "sample-policy")
    );
}

#[no_mangle]
pub extern "C" fn wapc_init() {
    register_function("validate", validate);
    register_function("validate_settings", validate_settings::<Settings>);
    register_function("protocol_version", protocol_version_guest);
}

fn validate(payload: &[u8]) -> CallResult {
    let validation_request: ValidationRequest<Settings> = ValidationRequest::new(payload)?;

    info!(LOG_DRAIN, "starting validation");

    let pod_result = serde_json::from_value::<apicore::Pod>(validation_request.request.object);
    match pod_result {
        Err(err) => {
            warn!(LOG_DRAIN, "cannot unmarshal resource [{}]: this policy does not know how to evaluate this resource; accept it", err);
            kubewarden::accept_request()
        }

        Ok(mut pod) => {
            if let Some(labels) = pod.metadata.labels.clone() {
                let whitelist = validation_request.settings.whitelisted_labels;

                let palindrome_labels = labels
                    .keys()
                    .cloned()
                    .into_iter()
                    .filter(|label| is_palindrome(label))
                    .collect::<Vec<String>>();
                let palindrome_count = palindrome_labels.len();

                let invalid_labels = palindrome_labels
                    .into_iter()
                    .filter(|label| !whitelist.contains(label))
                    .collect::<Vec<String>>();

                if invalid_labels.len() as i32 > validation_request.settings.threshold {
                    return kubewarden::reject_request(
                        Some(format!(
                            "Too many palindrome labels that are not-whitelisted: {:?}. Max allowed [{}]",
                            invalid_labels, validation_request.settings.threshold
                        )),
                        None,
                    );
                }

                let mut new_annotations = pod.metadata.annotations.clone().unwrap_or_default();
                new_annotations.insert(
                    String::from("kubewarden.policy.palindromes/count"),
                    palindrome_count.to_string(),
                );
                pod.metadata.annotations = Some(new_annotations);

                let mutated_object = serde_json::to_value(pod)?;
                return kubewarden::mutate_request(mutated_object);
            };

            info!(LOG_DRAIN, "accepting resource");
            kubewarden::accept_request()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use kubewarden_policy_sdk::test::Testcase;

    #[test]
    fn accept_pod_with_no_palindromes() {
        let request_file = "test_data/pod.json";
        let tc = Testcase {
            name: String::from("Valid labels"),
            fixture_file: String::from(request_file),
            expected_validation_result: true,
            settings: Settings::default(),
        };

        tc.eval(validate).unwrap();
    }

    #[test]
    fn reject_pod_with_palindromes() {
        let request_file = "test_data/pod-palindrome.json";
        let tc = Testcase {
            name: String::from("Palindrome labels"),
            fixture_file: String::from(request_file),
            expected_validation_result: false,
            settings: Settings::default(),
        };

        tc.eval(validate).unwrap();
    }

    #[test]
    fn reject_pod_with_only_one_whitelisted_palindrome() {
        let request_file = "test_data/pod-palindrome.json";
        let tc = Testcase {
            name: String::from("Palindrome labels"),
            fixture_file: String::from(request_file),
            expected_validation_result: false,
            settings: build_settings(0, vec!["level"]),
        };

        tc.eval(validate).unwrap();
    }

    #[test]
    fn accept_pod_with_whitelisted_palindromes() {
        let request_file = "test_data/pod-palindrome.json";
        let tc = Testcase {
            name: String::from("Valid labels"),
            fixture_file: String::from(request_file),
            expected_validation_result: true,
            settings: build_settings(0, vec!["level", "radar"]),
        };

        tc.eval(validate).unwrap();
    }

    #[test]
    fn accept_pod_with_whitelisted_and_threshold_palindromes() {
        let request_file = "test_data/pod-palindrome.json";
        let tc = Testcase {
            name: String::from("Valid labels"),
            fixture_file: String::from(request_file),
            expected_validation_result: true,
            settings: build_settings(1, vec!["level"]),
        };

        tc.eval(validate).unwrap();
    }

    fn build_settings(threshold: i32, whitelisted_labels: Vec<&str>) -> Settings {
        Settings {
            threshold,
            whitelisted_labels: whitelisted_labels.iter().map(ToString::to_string).collect(),
        }
    }
}
