use std::{env, process};

fn env_is_set(var_name: &str) -> bool {
    env::var_os(var_name).is_some()
}

fn ensure(cond: bool, err: &str) {
    if !cond {
        eprintln!(
            "\n\
            ┏━━━━━━━━{pad}━┓\n\
            ┃ error: {err} ┃\n\
            ┗━━━━━━━━{pad}━┛\n\
            ",
            pad = "━".repeat(err.len()),
        );
        process::exit(1);
    }
}

fn main() {
    let native_tls_set = env_is_set("CARGO_FEATURE_NATIVE_TLS");
    let rustls_tls_set = env_is_set("CARGO_FEATURE_RUSTLS_TLS");

    let native_reqwest_set = env_is_set("CARGO_FEATURE_REQWEST");
    if native_reqwest_set {
        ensure(
            native_tls_set || rustls_tls_set,
            "one of the features 'native-tls' or 'rustls-tls' must be enabled when reqwest is enabled",
        );
        ensure(
            !native_tls_set || !rustls_tls_set,
            "only one of the features 'native-tls' or 'rustls-tls' can be enabledd when reqwest is enabled",
        );
    }
    let native_isahc_set = env_is_set("CARGO_FEATURE_ISAHC");
    if native_isahc_set {
        ensure(
            native_tls_set || rustls_tls_set,
            "one of the features 'native-tls' or 'rustls-tls' must be enabled when isahc is enabled",
        );
        ensure(
            !native_tls_set || !rustls_tls_set,
            "only one of the features 'native-tls' or 'rustls-tls' can be enabledd when isahc is enabled",
        );
    }

    let is_wasm = env::var_os("CARGO_CFG_TARGET_ARCH").map_or(false, |arch| arch == "wasm32");
    if is_wasm {
        ensure(
            !env_is_set("CARGO_FEATURE_SSO_LOGIN"),
            "feature 'sso-login' is not available on target arch 'wasm32'",
        );
        ensure(
            !env_is_set("CARGO_FEATURE_IMAGE_RAYON"),
            "feature 'image-rayon' is not available on target arch 'wasm32'",
        );
    }
}
