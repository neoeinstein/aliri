

use serde::{Deserialize, Serialize};

use reqwest::Client;



#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OidcConfiguration {
    pub issuer: String,
    pub jwks_uri: String,
}


/// Gets oidc configurations
#[cfg(feature = "reqwest")]
#[cfg_attr(docsrs, doc(cfg(feature = "reqwest")))]
pub async fn fetch_oidc_configuration(uri: &str) -> Result<OidcConfiguration, reqwest::Error>  {
    let client = Client::builder()
        .user_agent(concat!("aliri_oauth2/", env!("CARGO_PKG_VERSION")))
        .build()?;

    let response = client.get(uri).send().await?;
    response.error_for_status_ref()?;

    let oidc_document = response.json::<OidcConfiguration>().await?;

    Ok(oidc_document)
}
