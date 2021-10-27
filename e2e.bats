#!/usr/bin/env bats

POLICY_WASM_FILE=target/wasm32-unknown-unknown/release/palindrome_policy_rust.wasm

@test "reject because pod has palindrome labels" {
  run kwctl run ${POLICY_WASM_FILE} -r test_data/pod-palindrome.json --settings-json '{}'

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  # request rejected
  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed.*false') -ne 0 ]
  [ $(expr "$output" : ".*Too many palindrome labels that are not-whitelisted:.*Max allowed") -ne 0 ]
}

@test "accept because pod has all whitelisted palindrome labels" {
  run kwctl run ${POLICY_WASM_FILE} -r test_data/pod-palindrome.json --settings-json '{"whitelisted_labels": ["level", "radar"]}'
  # this prints the output when one the checks below fails
  echo "output = ${output}"

  # request accepted
  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed.*true') -ne 0 ]
}

@test "reject because pod has some palindrome labels that are not whitelisted" {
  run kwctl run ${POLICY_WASM_FILE} -r test_data/pod-palindrome.json --settings-json '{"whitelisted_labels": ["level"]}'
  # this prints the output when one the checks below fails
  echo "output = ${output}"

  # request accepted
  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed.*false') -ne 0 ]
  [ $(expr "$output" : ".*Too many palindrome labels that are not-whitelisted:.*Max allowed") -ne 0 ]
}

@test "accept because pod has no palindrome labels" {
  run kwctl run ${POLICY_WASM_FILE} -r test_data/pod.json
  # this prints the output when one the checks below fails
  echo "output = ${output}"

  # request accepted
  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed.*true') -ne 0 ]
}

@test "accept because pod has some palindrome labels that are not whitelisted but inside the threshold" {
  run kwctl run ${POLICY_WASM_FILE} -r test_data/pod-palindrome.json --settings-json '{"whitelisted_labels": ["level"], "threshold": 1}'
  # this prints the output when one the checks below fails
  echo "output = ${output}"

  # request accepted
  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed.*true') -ne 0 ]
}