use crate::settings::Settings;
use crate::validate::validate;
use kubewarden::test::Testcase;

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
