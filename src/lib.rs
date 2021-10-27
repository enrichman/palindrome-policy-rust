#[cfg(test)]
mod tests;

mod settings;
mod validate;

extern crate wapc_guest as guest;
use guest::prelude::*;

extern crate kubewarden_policy_sdk as kubewarden;
use kubewarden::{logging, protocol_version_guest, validate_settings};

use lazy_static::lazy_static;
use settings::Settings;
use slog::{o, Logger};
use validate::validate;

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
