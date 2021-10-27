use crate::settings::is_palindrome;
use crate::settings::Settings;
use crate::LOG_DRAIN;

use k8s_openapi::api::core::v1 as apicore;
use kubewarden::request::ValidationRequest;
use slog::{info, warn};
use wapc::prelude::*;

pub fn validate(payload: &[u8]) -> CallResult {
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
