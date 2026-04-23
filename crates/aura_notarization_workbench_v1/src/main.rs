use aura_notarization_workbench_v1::{
    complete_notarization_authorization_value_v1, compose_export_bundle_value_v1,
    compose_notarization_value_v1, inspect_notarization_record_value_v1,
    load_notarization_authorization_signer_launcher_response_value_v1,
    load_sample_compose_request_value_v1, load_sample_notarization_record_value_v1,
    local_dev_sign_notarization_authorization_value_v1,
    prepare_notarization_authorization_signer_launcher_value_v1,
    prepare_notarization_authorization_value_v1,
    run_local_notarization_authorization_signer_value_v1,
};
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};

const INDEX_HTML: &str = include_str!("static/index.html");
const APP_JS: &str = include_str!("static/app.js");
const STYLES_CSS: &str = include_str!("static/styles.css");

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:8787".to_owned());
    let listener = TcpListener::bind(&addr)?;
    println!("Aura notarization workbench running at http://{addr}");

    serve_requests(listener, None);

    Ok(())
}

fn serve_requests(listener: TcpListener, max_requests: Option<usize>) {
    let mut served = 0usize;
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if let Err(error) = handle_connection(stream) {
                    eprintln!("workbench request error: {error}");
                }
            }
            Err(error) => eprintln!("incoming connection error: {error}"),
        }

        served += 1;
        if max_requests.is_some_and(|limit| served >= limit) {
            break;
        }
    }
}

fn handle_connection(mut stream: TcpStream) -> Result<(), Box<dyn std::error::Error>> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let response = read_and_handle_http_request(&mut reader)?;
    write!(stream, "{response}")?;
    Ok(())
}

fn read_and_handle_http_request(
    reader: &mut impl BufRead,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;
    if request_line.trim().is_empty() {
        return Ok(String::new());
    }

    let mut content_length = 0usize;
    loop {
        let mut header = String::new();
        reader.read_line(&mut header)?;
        if header == "\r\n" || header.is_empty() {
            break;
        }
        if let Some((name, value)) = header.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                content_length = value.trim().parse::<usize>().unwrap_or(0);
            }
        }
    }

    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body)?;
    }

    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let path = parts.next().unwrap_or_default();

    Ok(build_http_response(method, path, &body)?)
}

fn build_http_response(
    method: &str,
    path: &str,
    body: &[u8],
) -> Result<String, Box<dyn std::error::Error>> {
    match (method, path) {
        ("GET", "/") => response_string(200, "text/html; charset=utf-8", INDEX_HTML),
        ("GET", "/app.js") => response_string(200, "text/javascript; charset=utf-8", APP_JS),
        ("GET", "/styles.css") => response_string(200, "text/css; charset=utf-8", STYLES_CSS),
        ("GET", "/api/sample") => match load_sample_notarization_record_value_v1() {
            Ok(sample) => json_response_string(200, &sample),
            Err(error) => {
                json_response_string(500, &serde_json::json!({ "error": error.to_string() }))
            }
        },
        ("GET", "/api/compose/sample") => match load_sample_compose_request_value_v1() {
            Ok(sample) => json_response_string(200, &sample),
            Err(error) => {
                json_response_string(500, &serde_json::json!({ "error": error.to_string() }))
            }
        },
        ("POST", "/api/inspect") => match serde_json::from_slice::<serde_json::Value>(body) {
            Ok(value) => match inspect_notarization_record_value_v1(value) {
                Ok(inspection) => json_response_string(200, &inspection),
                Err(error) => {
                    json_response_string(400, &serde_json::json!({ "error": error.to_string() }))
                }
            },
            Err(error) => json_response_string(
                400,
                &serde_json::json!({ "error": format!("invalid notarization record json: {error}") }),
            ),
        },
        ("POST", "/api/compose") => match serde_json::from_slice::<serde_json::Value>(body) {
            Ok(value) => match compose_notarization_value_v1(value) {
                Ok(composition) => json_response_string(200, &composition),
                Err(error) => {
                    json_response_string(400, &serde_json::json!({ "error": error.to_string() }))
                }
            },
            Err(error) => json_response_string(
                400,
                &serde_json::json!({ "error": format!("invalid composition request json: {error}") }),
            ),
        },
        ("POST", "/api/compose/prepare") => {
            match serde_json::from_slice::<serde_json::Value>(body) {
                Ok(value) => match prepare_notarization_authorization_value_v1(value) {
                    Ok(prepared) => json_response_string(200, &prepared),
                    Err(error) => json_response_string(
                        400,
                        &serde_json::json!({ "error": error.to_string() }),
                    ),
                },
                Err(error) => json_response_string(
                    400,
                    &serde_json::json!({ "error": format!("invalid authorization prepare request json: {error}") }),
                ),
            }
        }
        ("POST", "/api/compose/signer-launcher/prepare") => {
            match serde_json::from_slice::<serde_json::Value>(body) {
                Ok(value) => {
                    match prepare_notarization_authorization_signer_launcher_value_v1(value) {
                        Ok(launcher) => json_response_string(200, &launcher),
                        Err(error) => json_response_string(
                            400,
                            &serde_json::json!({ "error": error.to_string() }),
                        ),
                    }
                }
                Err(error) => json_response_string(
                    400,
                    &serde_json::json!({ "error": format!("invalid signer launcher prepare request json: {error}") }),
                ),
            }
        }
        ("POST", "/api/compose/signer-launcher/load") => {
            match serde_json::from_slice::<serde_json::Value>(body) {
                Ok(value) => {
                    match load_notarization_authorization_signer_launcher_response_value_v1(value) {
                        Ok(result) => json_response_string(200, &result),
                        Err(error) => json_response_string(
                            400,
                            &serde_json::json!({ "error": error.to_string() }),
                        ),
                    }
                }
                Err(error) => json_response_string(
                    400,
                    &serde_json::json!({ "error": format!("invalid signer launcher load request json: {error}") }),
                ),
            }
        }
        ("POST", "/api/compose/signer-launcher/run-local") => {
            match serde_json::from_slice::<serde_json::Value>(body) {
                Ok(value) => match run_local_notarization_authorization_signer_value_v1(value) {
                    Ok(result) => json_response_string(200, &result),
                    Err(error) => json_response_string(
                        400,
                        &serde_json::json!({ "error": error.to_string() }),
                    ),
                },
                Err(error) => json_response_string(
                    400,
                    &serde_json::json!({ "error": format!("invalid signer launcher run request json: {error}") }),
                ),
            }
        }
        ("POST", "/api/compose/complete") => {
            match serde_json::from_slice::<serde_json::Value>(body) {
                Ok(value) => match complete_notarization_authorization_value_v1(value) {
                    Ok(composition) => json_response_string(200, &composition),
                    Err(error) => json_response_string(
                        400,
                        &serde_json::json!({ "error": error.to_string() }),
                    ),
                },
                Err(error) => json_response_string(
                    400,
                    &serde_json::json!({ "error": format!("invalid completion request json: {error}") }),
                ),
            }
        }
        ("POST", "/api/compose/export") => {
            match serde_json::from_slice::<serde_json::Value>(body) {
                Ok(value) => match compose_export_bundle_value_v1(value) {
                    Ok(bundle) => json_response_string(200, &bundle),
                    Err(error) => json_response_string(
                        400,
                        &serde_json::json!({ "error": error.to_string() }),
                    ),
                },
                Err(error) => json_response_string(
                    400,
                    &serde_json::json!({ "error": format!("invalid composition request json: {error}") }),
                ),
            }
        }
        ("POST", "/api/dev/sign") => match serde_json::from_slice::<serde_json::Value>(body) {
            Ok(value) => match local_dev_sign_notarization_authorization_value_v1(value) {
                Ok(result) => json_response_string(200, &result),
                Err(error) => {
                    json_response_string(400, &serde_json::json!({ "error": error.to_string() }))
                }
            },
            Err(error) => json_response_string(
                400,
                &serde_json::json!({ "error": format!("invalid local dev sign request json: {error}") }),
            ),
        },
        _ => json_response_string(404, &serde_json::json!({ "error": "not found" })),
    }
}

fn json_response_string(
    status: u16,
    value: &impl serde::Serialize,
) -> Result<String, Box<dyn std::error::Error>> {
    let body = serde_json::to_string(value)?;
    response_string(status, "application/json; charset=utf-8", &body)
}

fn response_string(
    status: u16,
    content_type: &str,
    body: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "OK",
    };
    Ok(format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{body}",
        body.len()
    ))
}

#[cfg(test)]
mod tests {
    use super::read_and_handle_http_request;
    use aura_l2_execution_v1::TokenTransactionAuthorizationSignRequestWireV1;
    use aura_notarization_workbench_v1::{
        sign_notarization_authorization_carrier_request_v1,
        NotarizationAuthorizationSignCarrierRequestV1,
        NotarizationAuthorizationSignCarrierResponseV1,
    };
    use std::io::{BufReader, Cursor};

    #[derive(Debug)]
    struct HttpResponse {
        status_code: u16,
        body: String,
    }

    const AUTH_SIGNING_KEY_BYTES_V1: [u8; 32] = [0x42; 32];
    const AUTHORIZATION_NONCE_V1: [u8; 32] = [0x55; 32];
    const AUTH_SIGNER_PUBLIC_KEY_HEX_V1: &str =
        "2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12";

    fn encode_hex_lower_v1(bytes: &[u8]) -> String {
        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            use core::fmt::Write as _;
            write!(&mut output, "{byte:02x}").unwrap();
        }
        output
    }

    #[test]
    fn workbench_smoke_path_loads_sample_and_renders_canonical_receipt_previews() {
        let index = http_request("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
        assert_eq!(index.status_code, 200);
        assert!(index.body.contains("Aura Notarization Workbench"));
        assert!(index.body.contains("Compose"));
        assert!(index.body.contains("Inspect"));
        assert!(index.body.contains("Prepare Authorization"));
        assert!(index.body.contains("Download Sign Carrier Request"));
        assert!(index.body.contains("Run Local Signer"));
        assert!(index.body.contains("Import Sign Carrier Response"));
        assert!(index.body.contains("Complete Compose"));
        assert!(index.body.contains("Local Dev Sign (Dev Only)"));
        assert!(index.body.contains("Load Compose Sample"));
        assert!(index.body.contains("Export Compose Bundle"));
        assert!(index.body.contains("Download Export Bundle JSON"));
        assert!(index.body.contains("Copy Export Bundle JSON"));
        assert!(index.body.contains("Canonical Summary"));
        assert!(index.body.contains("Canonical Path"));
        assert!(index.body.contains("Receipt Preview"));
        assert!(index.body.contains("Authorization Boundary"));
        assert!(index.body.contains("About This Workbench"));
        assert!(index
            .body
            .contains("Local workbench for canonical notarization record inspection"));
        assert!(index.body.contains("transaction composition"));
        assert!(index.body.contains("receipt export"));
        assert!(index.body.contains("production wallet integration"));
        assert!(index.body.contains("browser-side signing"));
        assert!(index.body.contains("prepare frozen authorization requests"));
        assert!(index.body.contains("External signer responses"));
        assert!(index
            .body
            .contains("External signer responses are the real authorization model"));
        assert!(index
            .body
            .contains("crates/aura_notarization_workbench_v1/README.md"));
        assert!(index.body.contains("Copy Summary JSON"));
        assert!(index.body.contains("Copy Notarization Record Digest"));
        assert!(index.body.contains("Copy Markdown Receipt"));
        assert!(index.body.contains("Copy HTML Receipt"));
        assert!(index.body.contains("Clear Workbench"));
        assert!(index.body.contains("Export Receipt Pair"));

        let app_js = http_request("GET /app.js HTTP/1.1\r\nHost: localhost\r\n\r\n");
        assert_eq!(app_js.status_code, 200);
        assert!(app_js
            .body
            .contains("aura_notarization_workbench_v1.record_json"));
        assert!(app_js
            .body
            .contains("aura_notarization_workbench_v1.compose_request"));
        assert!(app_js
            .body
            .contains("aura_notarization_workbench_v1.preview_tab"));
        assert!(app_js.body.contains("state.lastDerivedMode"));
        assert!(app_js.body.contains("state.composeRequest"));
        assert!(app_js.body.contains("state.authorizationSession"));
        assert!(app_js
            .body
            .contains("state.authorizationSignCarrierResponse"));
        assert!(app_js.body.contains("state.authorizationSignResponse"));
        assert!(app_js.body.contains("composeTransaction"));
        assert!(app_js.body.contains("prepareAuthorization"));
        assert!(app_js.body.contains("downloadSignCarrierRequest"));
        assert!(app_js.body.contains("runLocalSigner"));
        assert!(app_js.body.contains("importSignCarrierResponse"));
        assert!(app_js.body.contains("importSignCarrierResponseFile"));
        assert!(app_js.body.contains("localDevSign"));
        assert!(app_js.body.contains("loadComposeSample"));
        assert!(app_js.body.contains("exportComposeBundle"));
        assert!(app_js.body.contains("downloadExportBundleJson"));
        assert!(app_js.body.contains("copyExportBundleJson"));
        assert!(app_js.body.contains("copySignRequestJson"));
        assert!(app_js.body.contains("copyPayloadBytes"));
        assert!(app_js.body.contains("buildSignCarrierRequest"));
        assert!(app_js.body.contains("buildSignCarrierResponse"));
        assert!(app_js
            .body
            .contains("parseAuthorizationCarrierResponseInputValue"));
        assert!(app_js.body.contains("buildComposeBundleFiles"));
        assert!(app_js.body.contains("buildPreparePayload"));
        assert!(app_js.body.contains("buildCompletionPayload"));
        assert!(app_js.body.contains("hasComposeBundleReady"));
        assert!(app_js.body.contains("renderAuthorizationState"));
        assert!(app_js.body.contains("clearDerivedOutputs"));
        assert!(app_js.body.contains("parseAuthorizationResponseInputValue"));
        assert!(app_js
            .body
            .contains("LOCAL_DEV_AUTHORIZATION_SIGNER_PUBLIC_KEY_HEX_V1"));
        assert!(app_js.body.contains("/api/compose/prepare"));
        assert!(app_js
            .body
            .contains("/api/compose/signer-launcher/run-local"));
        assert!(app_js.body.contains("/api/compose/complete"));
        assert!(app_js.body.contains("/api/compose/export"));
        assert!(app_js.body.contains("/api/dev/sign"));
        assert!(app_js
            .body
            .contains("aura_notarization_compose_export_bundle.json"));
        assert!(app_js.body.contains("Copy Export Bundle JSON"));
        assert!(app_js.body.contains("compose-request.json"));
        assert!(app_js.body.contains("public-statement.json"));
        assert!(app_js.body.contains("notarization-record.json"));
        assert!(app_js.body.contains("receipt.md"));
        assert!(app_js.body.contains("receipt.html"));
        assert!(app_js
            .body
            .contains("aura_authorization_sign_carrier_request_"));
        assert!(app_js.body.contains("restorePersistedRecordInput();"));
        assert!(app_js.body.contains("restorePersistedComposeDraft();"));
        assert!(app_js.body.contains("renderCanonicalPath"));
        assert!(app_js.body.contains("markInspectionStale"));
        assert!(app_js.body.contains("markCompositionStale"));
        assert!(app_js.body.contains("setActionAvailability"));
        assert!(app_js
            .body
            .contains("elements.copyExportBundleJson.disabled = !hasComposeBundleReady();"));
        assert!(app_js.body.contains("copySummaryJson"));
        assert!(app_js.body.contains("copyNotarizationRecordDigest"));
        assert!(app_js.body.contains("copyMarkdownReceipt"));
        assert!(app_js.body.contains("copyHtmlReceipt"));
        assert!(app_js.body.contains("await copyText("));
        assert!(app_js.body.contains("downloadReceiptPair"));
        assert!(app_js.body.contains("navigator.clipboard?.writeText"));
        assert!(app_js
            .body
            .contains("state.summary?.notarization_record_digest_hex"));
        assert!(app_js.body.contains("state.html"));
        assert!(app_js.body.contains("Clear Workbench"));
        assert!(app_js.body.contains("Export Receipt Pair"));

        let sample = http_request("GET /api/sample HTTP/1.1\r\nHost: localhost\r\n\r\n");
        assert_eq!(sample.status_code, 200);
        let sample_value: serde_json::Value = serde_json::from_str(&sample.body).unwrap();

        let compose_sample =
            http_request("GET /api/compose/sample HTTP/1.1\r\nHost: localhost\r\n\r\n");
        assert_eq!(compose_sample.status_code, 200);
        let compose_sample_value: serde_json::Value =
            serde_json::from_str(&compose_sample.body).unwrap();
        assert!(compose_sample_value["inputs"].is_array());
        assert!(compose_sample_value["outputs"].is_array());

        let missing_authorization = http_request(&format!(
            "POST /api/compose HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            compose_sample.body.len(),
            compose_sample.body
        ));
        assert_eq!(missing_authorization.status_code, 400);
        assert!(missing_authorization.body.contains("error"));

        let prepare_payload = serde_json::json!({
            "compose_request": compose_sample_value.clone(),
            "signer_public_key_hex": AUTH_SIGNER_PUBLIC_KEY_HEX_V1,
            "authorization_nonce_hex": encode_hex_lower_v1(&AUTHORIZATION_NONCE_V1),
        });
        let prepare_body = serde_json::to_string(&prepare_payload).unwrap();
        let prepared = http_request(&format!(
            "POST /api/compose/prepare HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            prepare_body.len(),
            prepare_body
        ));
        assert_eq!(prepared.status_code, 200);
        let prepared_value: serde_json::Value = serde_json::from_str(&prepared.body).unwrap();
        assert_eq!(prepared_value["session_version"], 1);
        assert_eq!(prepared_value["burn_summary"]["admission_burn"], 1);
        assert_eq!(
            prepared_value["transaction"]["public_statement"],
            prepared_value["public_statement"]
        );
        let sign_request: TokenTransactionAuthorizationSignRequestWireV1 =
            serde_json::from_value(prepared_value["authorization_sign_request"].clone()).unwrap();
        let payload = sign_request.validate().unwrap();
        assert_eq!(payload.authorization_nonce, AUTHORIZATION_NONCE_V1);

        let dev_sign = http_request(&format!(
            "POST /api/dev/sign HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            prepared.body.len(),
            prepared.body
        ));
        assert_eq!(dev_sign.status_code, 200);
        let dev_sign_value: serde_json::Value = serde_json::from_str(&dev_sign.body).unwrap();
        assert_eq!(dev_sign_value["scope"], "local_dev_only");
        assert_eq!(
            dev_sign_value["session_id_hex"],
            prepared_value["session_id_hex"]
        );

        let carrier_response = serde_json::json!({
            "carrier_version": 1,
            "session_id_hex": prepared_value["session_id_hex"].clone(),
            "authorization_sign_response": dev_sign_value["sign_response"].clone(),
        });
        let completion_payload = serde_json::json!({
            "session": prepared_value.clone(),
            "sign_carrier_response": carrier_response,
        });
        let completion_body = serde_json::to_string(&completion_payload).unwrap();
        let composition = http_request(&format!(
            "POST /api/compose/complete HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            completion_body.len(),
            completion_body
        ));
        assert_eq!(composition.status_code, 200);
        let composition_value: serde_json::Value = serde_json::from_str(&composition.body).unwrap();
        assert_eq!(composition_value["burn_summary"]["admission_burn"], 1);
        assert_eq!(composition_value["burn_summary"]["notary_burn"], 3);
        assert_eq!(composition_value["burn_summary"]["priority_weight"], 4);
        assert_eq!(
            composition_value["summary"]["notarization_record_digest_hex"],
            composition_value["notarization_record"]["notarization_record_digest_hex"]
        );
        assert_eq!(
            composition_value["transaction"]["public_statement"],
            composition_value["public_statement"]
        );

        let export = http_request(&format!(
            "POST /api/compose/export HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            completion_body.len(),
            completion_body
        ));
        assert_eq!(export.status_code, 200);
        let export_value: serde_json::Value = serde_json::from_str(&export.body).unwrap();
        assert_eq!(export_value["compose_request"], compose_sample_value);
        assert_eq!(
            export_value["transaction"],
            composition_value["transaction"]
        );
        assert_eq!(
            export_value["public_statement"],
            composition_value["public_statement"]
        );
        assert_eq!(
            export_value["notarization_record"],
            composition_value["notarization_record"]
        );
        assert_eq!(
            export_value["receipt_markdown"],
            composition_value["markdown_receipt"]
        );
        assert_eq!(
            export_value["receipt_html"],
            composition_value["html_receipt"]
        );

        let inspection = http_request(&format!(
            "POST /api/inspect HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            sample.body.len(),
            sample.body
        ));
        assert_eq!(inspection.status_code, 200);
        let inspection_value: serde_json::Value = serde_json::from_str(&inspection.body).unwrap();
        let summary = &inspection_value["summary"];

        assert_eq!(summary["record_version"], sample_value["record_version"]);
        assert_eq!(
            summary["proof_statement_type"],
            sample_value["proof_statement_type"]
        );
        assert_eq!(summary["proof_statement_label"], "private_transfer_burn_v1");
        assert_eq!(summary["ack_digest_hex"], sample_value["ack_digest_hex"]);
        assert_eq!(
            summary["seal_payload_digest_hex"],
            sample_value["seal_payload_digest_hex"]
        );
        assert_eq!(
            summary["udot_seed_digest_hex"],
            sample_value["udot_seed_digest_hex"]
        );
        assert_eq!(
            summary["notarization_record_digest_hex"],
            sample_value["notarization_record_digest_hex"]
        );
        assert!(inspection_value["markdown_receipt"]
            .as_str()
            .unwrap()
            .contains("## Token Notarization Summary"));
        assert!(inspection_value["html_receipt"]
            .as_str()
            .unwrap()
            .contains(r#"<section data-kind="token-notarization-summary-v1">"#));

        let bad_payload = r#"{"record_version":1,"ack_digest_hex":"abcd"}"#;
        let bad = http_request(&format!(
            "POST /api/inspect HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            bad_payload.len(),
            bad_payload
        ));
        assert_eq!(bad.status_code, 400);
        assert!(bad.body.contains("error"));

        let bad_compose_payload = r#"{"rollup_id_hex":"abcd"}"#;
        let bad_compose = http_request(&format!(
            "POST /api/compose HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            bad_compose_payload.len(),
            bad_compose_payload
        ));
        assert_eq!(bad_compose.status_code, 400);
        assert!(bad_compose.body.contains("error"));

        let bad_prepare = http_request(&format!(
            "POST /api/compose/prepare HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            bad_compose_payload.len(),
            bad_compose_payload
        ));
        assert_eq!(bad_prepare.status_code, 400);
        assert!(bad_prepare.body.contains("error"));

        let bad_complete = http_request(&format!(
            "POST /api/compose/complete HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            bad_compose_payload.len(),
            bad_compose_payload
        ));
        assert_eq!(bad_complete.status_code, 400);
        assert!(bad_complete.body.contains("error"));

        let bad_dev_sign = http_request(&format!(
            "POST /api/dev/sign HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            bad_compose_payload.len(),
            bad_compose_payload
        ));
        assert_eq!(bad_dev_sign.status_code, 400);
        assert!(bad_dev_sign.body.contains("error"));

        let bad_export = http_request(&format!(
            "POST /api/compose/export HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            bad_compose_payload.len(),
            bad_compose_payload
        ));
        assert_eq!(bad_export.status_code, 400);
        assert!(bad_export.body.contains("error"));
    }

    #[test]
    fn signer_launcher_routes_prepare_and_load_stable_carrier_files() {
        let compose_sample =
            http_request("GET /api/compose/sample HTTP/1.1\r\nHost: localhost\r\n\r\n");
        assert_eq!(compose_sample.status_code, 200);
        let compose_sample_value: serde_json::Value =
            serde_json::from_str(&compose_sample.body).unwrap();

        let prepare_payload = serde_json::json!({
            "compose_request": compose_sample_value,
            "signer_public_key_hex": AUTH_SIGNER_PUBLIC_KEY_HEX_V1,
            "authorization_nonce_hex": encode_hex_lower_v1(&AUTHORIZATION_NONCE_V1),
        });
        let prepare_body = serde_json::to_string(&prepare_payload).unwrap();
        let prepared = http_request(&format!(
            "POST /api/compose/prepare HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            prepare_body.len(),
            prepare_body
        ));
        assert_eq!(prepared.status_code, 200);
        let prepared_value: serde_json::Value = serde_json::from_str(&prepared.body).unwrap();

        let launcher = http_request(&format!(
            "POST /api/compose/signer-launcher/prepare HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            prepared.body.len(),
            prepared.body
        ));
        assert_eq!(launcher.status_code, 200);
        let launcher_value: serde_json::Value = serde_json::from_str(&launcher.body).unwrap();
        assert_eq!(launcher_value["scope"], "guided_file_carrier_v1");
        assert_eq!(
            launcher_value["session_id_hex"],
            prepared_value["session_id_hex"]
        );
        assert!(launcher_value["request_path"]
            .as_str()
            .unwrap()
            .ends_with("/aura_authorization_sign_carrier_request.json"));
        assert!(launcher_value["response_path"]
            .as_str()
            .unwrap()
            .ends_with("/aura_authorization_sign_carrier_response.json"));
        assert!(launcher_value["signer_command"]
            .as_str()
            .unwrap()
            .contains("aura_authorization_signer_v1"));

        let request_path = launcher_value["request_path"].as_str().unwrap();
        let response_path = launcher_value["response_path"].as_str().unwrap();
        let request_text = std::fs::read_to_string(request_path).unwrap();
        let carrier_request: NotarizationAuthorizationSignCarrierRequestV1 =
            serde_json::from_str(&request_text).unwrap();
        assert_eq!(
            carrier_request.session_id_hex,
            prepared_value["session_id_hex"].as_str().unwrap()
        );

        let carrier_response = sign_notarization_authorization_carrier_request_v1(
            carrier_request,
            AUTH_SIGNING_KEY_BYTES_V1,
        )
        .unwrap();
        std::fs::write(
            response_path,
            serde_json::to_string_pretty(&carrier_response).unwrap(),
        )
        .unwrap();

        let loaded = http_request(&format!(
            "POST /api/compose/signer-launcher/load HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            prepared.body.len(),
            prepared.body
        ));
        assert_eq!(loaded.status_code, 200);
        let loaded_value: serde_json::Value = serde_json::from_str(&loaded.body).unwrap();
        let loaded_carrier_response: NotarizationAuthorizationSignCarrierResponseV1 =
            serde_json::from_value(loaded_value["sign_carrier_response"].clone()).unwrap();
        assert_eq!(
            loaded_value["launcher"]["request_path"],
            launcher_value["request_path"]
        );
        assert_eq!(
            loaded_value["launcher"]["response_path"],
            launcher_value["response_path"]
        );
        assert_eq!(loaded_carrier_response, carrier_response);
    }

    #[test]
    fn signer_launcher_run_local_route_executes_helper_and_returns_carrier_response() {
        let compose_sample =
            http_request("GET /api/compose/sample HTTP/1.1\r\nHost: localhost\r\n\r\n");
        assert_eq!(compose_sample.status_code, 200);
        let compose_sample_value: serde_json::Value =
            serde_json::from_str(&compose_sample.body).unwrap();

        let prepare_payload = serde_json::json!({
            "compose_request": compose_sample_value,
            "signer_public_key_hex": AUTH_SIGNER_PUBLIC_KEY_HEX_V1,
            "authorization_nonce_hex": encode_hex_lower_v1(&[0x74; 32]),
        });
        let prepare_body = serde_json::to_string(&prepare_payload).unwrap();
        let prepared = http_request(&format!(
            "POST /api/compose/prepare HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            prepare_body.len(),
            prepare_body
        ));
        assert_eq!(prepared.status_code, 200);
        let prepared_value: serde_json::Value = serde_json::from_str(&prepared.body).unwrap();

        let run_payload = serde_json::json!({
            "session": prepared_value.clone(),
            "private_key_hex": encode_hex_lower_v1(&AUTH_SIGNING_KEY_BYTES_V1),
        });
        let run_body = serde_json::to_string(&run_payload).unwrap();
        let launched = http_request(&format!(
            "POST /api/compose/signer-launcher/run-local HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            run_body.len(),
            run_body
        ));
        assert_eq!(launched.status_code, 200);
        let launched_value: serde_json::Value = serde_json::from_str(&launched.body).unwrap();

        assert_eq!(launched_value["scope"], "local_subprocess_signer_v1");
        assert_eq!(
            launched_value["session_id_hex"],
            prepared_value["session_id_hex"]
        );
        let sign_carrier_response: NotarizationAuthorizationSignCarrierResponseV1 =
            serde_json::from_value(launched_value["sign_carrier_response"].clone()).unwrap();
        assert_eq!(
            sign_carrier_response.session_id_hex,
            prepared_value["session_id_hex"].as_str().unwrap()
        );

        let completion_payload = serde_json::json!({
            "session": prepared_value,
            "sign_carrier_response": sign_carrier_response,
        });
        let completion_body = serde_json::to_string(&completion_payload).unwrap();
        let composition = http_request(&format!(
            "POST /api/compose/complete HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            completion_body.len(),
            completion_body
        ));
        assert_eq!(composition.status_code, 200);
    }

    fn http_request(raw_request: &str) -> HttpResponse {
        let cursor = Cursor::new(raw_request.as_bytes());
        let mut reader = BufReader::new(cursor);
        let buffer = read_and_handle_http_request(&mut reader).unwrap();
        let (head, body) = buffer.split_once("\r\n\r\n").unwrap_or((&buffer, ""));
        let status_code = head
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|code| code.parse::<u16>().ok())
            .unwrap_or(0);
        HttpResponse {
            status_code,
            body: body.to_owned(),
        }
    }
}
