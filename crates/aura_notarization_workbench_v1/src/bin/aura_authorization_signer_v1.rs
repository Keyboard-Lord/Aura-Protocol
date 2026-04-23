use aura_notarization_workbench_v1::{
    sign_notarization_authorization_carrier_request_v1,
    NotarizationAuthorizationSignCarrierRequestV1,
};
use std::path::PathBuf;

struct Config {
    request_path: PathBuf,
    response_path: PathBuf,
    private_key_hex: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = match parse_args(std::env::args().skip(1)) {
        Ok(Some(config)) => config,
        Ok(None) => return Ok(()),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(2);
        }
    };

    let request_text = std::fs::read_to_string(&config.request_path)?;
    let carrier_request: NotarizationAuthorizationSignCarrierRequestV1 =
        serde_json::from_str(&request_text)?;
    let private_key = decode_private_key_hex(&config.private_key_hex)?;
    let carrier_response =
        sign_notarization_authorization_carrier_request_v1(carrier_request, private_key)?;

    std::fs::write(
        &config.response_path,
        format!("{}\n", serde_json::to_string_pretty(&carrier_response)?),
    )?;

    eprintln!(
        "wrote authorization sign carrier response for session_id_hex {} to {}",
        carrier_response.session_id_hex,
        config.response_path.display()
    );

    Ok(())
}

fn parse_args(
    mut args: impl Iterator<Item = String>,
) -> Result<Option<Config>, Box<dyn std::error::Error>> {
    let mut request_path = None;
    let mut response_path = None;
    let mut private_key_hex = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--help" | "-h" => {
                println!("{}", usage());
                return Ok(None);
            }
            "--request" => request_path = Some(next_arg(&mut args, "--request")?),
            "--response" => response_path = Some(next_arg(&mut args, "--response")?),
            "--private-key-hex" => {
                private_key_hex = Some(next_arg(&mut args, "--private-key-hex")?)
            }
            other => return Err(format!("unrecognized argument: {other}\n\n{}", usage()).into()),
        }
    }

    Ok(Some(Config {
        request_path: PathBuf::from(
            request_path.ok_or_else(|| format!("missing --request\n\n{}", usage()))?,
        ),
        response_path: PathBuf::from(
            response_path.ok_or_else(|| format!("missing --response\n\n{}", usage()))?,
        ),
        private_key_hex: private_key_hex
            .ok_or_else(|| format!("missing --private-key-hex\n\n{}", usage()))?,
    }))
}

fn next_arg(
    args: &mut impl Iterator<Item = String>,
    flag: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    args.next()
        .ok_or_else(|| format!("missing value for {flag}\n\n{}", usage()).into())
}

fn decode_private_key_hex(value: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    if value.len() != 64 {
        return Err("private key hex must be exactly 64 hex characters".into());
    }

    let mut output = [0u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (decode_hex_nibble(chunk[0])? << 4) | decode_hex_nibble(chunk[1])?;
    }
    Ok(output)
}

fn decode_hex_nibble(byte: u8) -> Result<u8, Box<dyn std::error::Error>> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err("private key hex must contain only hexadecimal characters".into()),
    }
}

fn usage() -> &'static str {
    "Usage:
  aura_authorization_signer_v1 --request <carrier-request.json> --response <carrier-response.json> --private-key-hex <64 hex chars>

Behavior:
  - reads a NotarizationAuthorizationSignCarrierRequestV1 file
  - validates the frozen authorization sign request
  - signs the exact frozen payload bytes with the supplied Ed25519 private key
  - writes a NotarizationAuthorizationSignCarrierResponseV1 file

Notes:
  - this helper uses local key material supplied manually via --private-key-hex
  - it is a file carrier helper, not wallet/account management"
}
