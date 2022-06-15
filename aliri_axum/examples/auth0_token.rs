use aliri::{jwt, JwtRef};
use aliri_braid::braid;
use aliri_oauth2::oauth2;

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    perform_device_login_flow(std::env::args().skip(1)).await
}

const ISSUER: &str = "https://aliri-demo.us.auth0.com/";
const AUDIENCE: &str = "https://aliri.example.com/";

#[braid(serde)]
struct ClientId;

#[braid(serde)]
struct DeviceCode;

#[braid(serde)]
struct UserCode;

#[derive(serde::Serialize)]
struct DeviceFlowRequest<'a> {
    client_id: &'a ClientIdRef,
    scope: &'a oauth2::Scope,
    audience: &'a jwt::AudienceRef,
}

#[derive(serde::Deserialize)]
struct DeviceFlowResponse<'a> {
    device_code: &'a DeviceCodeRef,
    user_code: &'a UserCodeRef,
    verification_uri_complete: &'a str,
    expires_in: aliri_clock::DurationSecs,
    interval: aliri_clock::DurationSecs,
}

#[derive(serde::Serialize)]
struct TokenRequest<'a> {
    grant_type: &'static str,
    device_code: &'a DeviceCodeRef,
    client_id: &'a ClientIdRef,
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
enum TokenResponse<'a> {
    #[serde(borrow)]
    Error(TokenError<'a>),
    #[serde(borrow)]
    Success(TokenSuccess<'a>),
}

#[derive(serde::Deserialize)]
struct TokenError<'a> {
    error: &'a str,
    error_description: &'a str,
}

#[derive(serde::Deserialize)]
struct TokenSuccess<'a> {
    #[serde(borrow)]
    access_token: &'a JwtRef,
    scope: oauth2::Scope,
    expires_in: aliri_clock::DurationSecs,
}

async fn perform_device_login_flow(
    scope: impl IntoIterator<Item = String>,
) -> color_eyre::Result<()> {
    let client_id = ClientIdRef::from_str("veSL5jxu4C8HKAuaBppqtmkgcpYyIUXM");

    let scope = scope
        .into_iter()
        .map(oauth2::ScopeToken::try_from)
        .collect::<Result<oauth2::Scope, _>>()?;

    let client = reqwest::Client::default();
    let resp = client
        .post(format!("{}oauth/device/code", ISSUER))
        .form(&DeviceFlowRequest {
            client_id,
            scope: &scope,
            audience: jwt::AudienceRef::from_str(AUDIENCE),
        })
        .send()
        .await?
        .error_for_status()?;

    let bytes = resp.text().await?;
    let response: DeviceFlowResponse = serde_json::from_str(&bytes)?;

    eprintln!("You are requesting a token with the following scopes: \"{scope}\"");
    eprintln!("In order to generate a token, visit the following url and, if requested, input the user code displayed.\nLogin URL: {}\nUser Code: {}", response.verification_uri_complete, response.user_code);
    eprintln!("\nLogin information:\nUsername: aliri-test\nPassword: 1super-secret-password!");
    eprintln!(
        "\nBe quick! You only have {} seconds to use this token.",
        response.expires_in
    );
    std::io::Write::flush(&mut std::io::stderr())?;

    eprint!("Waiting for login to complete");
    std::io::Write::flush(&mut std::io::stderr())?;
    let mut interval = tokio::time::interval(response.interval.into());
    // let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(1));
    loop {
        interval.tick().await;

        let resp = client
            .post(format!("{}oauth/token", ISSUER))
            .form(&TokenRequest {
                grant_type: "urn:ietf:params:oauth:grant-type:device_code",
                client_id,
                device_code: response.device_code,
            })
            .send()
            .await?;

        let bytes = resp.text().await?;
        let response: TokenResponse = serde_json::from_str(&bytes)?;

        match response {
            TokenResponse::Error(TokenError {
                error: "authorization_pending",
                ..
            }) => {
                eprint!(".");
                std::io::Write::flush(&mut std::io::stderr())?;
            }
            TokenResponse::Error(TokenError {
                error: "slow_down", ..
            }) => {
                eprint!(";");
                std::io::Write::flush(&mut std::io::stderr())?;
                let new_period = interval.period() + tokio::time::Duration::from_secs(1);
                interval =
                    tokio::time::interval_at(tokio::time::Instant::now() + new_period, new_period);
            }
            TokenResponse::Error(TokenError {
                error,
                error_description,
            }) => {
                eprintln!();
                return Err(color_eyre::Report::msg(format!(
                    "Error! {error}: {error_description}"
                )));
            }
            TokenResponse::Success(token) => {
                eprintln!();
                eprintln!();
                std::io::Write::flush(&mut std::io::stderr())?;

                eprintln!(
                    "Token received with the following scopes: \"{}\"",
                    token.scope
                );
                eprintln!(
                    "This token is good for {} seconds, so act fast!",
                    token.expires_in
                );
                eprintln!("Token will be written to stdout.");
                std::io::Write::flush(&mut std::io::stderr())?;

                // Print in alternate form because we really _do_ want to expose the token.
                println!("{:#}", token.access_token);
                return Ok(());
            }
        }
    }
}
