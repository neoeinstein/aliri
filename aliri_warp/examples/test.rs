use std::{
    future::Future,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
};

use aliri_jose::{jwa, jwk, jws, jwt, Jwk, Jwks, Jwt};
use aliri_oauth2::{Directive, HasScopes, JwksAuthority, Scope, Scopes};
use aliri_warp as aliri;
use serde::{Deserialize, Serialize};
use warp::Filter;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Claims {
    #[serde(rename = "sub")]
    subject: String,
    #[serde(rename = "scope")]
    scopes: Scopes,
}

impl HasScopes for Claims {
    fn scopes(&self) -> &Scopes {
        &self.scopes
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let hi = warp::path!("hello" / String)
        .and(warp::get())
        .and(warp::header("user-agent"))
        .and(aliri::jwt::optional())
        .map(|param, agent: String, auth: Option<Jwt>| {
            if let Some(auth) = auth {
                format!("Hello {}, whose agent is {}, auth: {}", param, agent, auth)
            } else {
                format!(
                    "Hello {}, whose agent is {}, and isn't authorized!",
                    param, agent
                )
            }
        });

    let hi2 = warp::path!("hello2" / String)
        .and(warp::get())
        .and(warp::header("user-agent"))
        .and(aliri::jwt())
        .map(|param, agent: String, auth: Jwt| {
            format!("Hello {}, whose agent is {}, auth: {}", param, agent, auth)
        });

    let mut jwks = Jwks::default();

    let jwk = Jwk {
        id: Some(jwk::KeyId::new("key-id")),
        usage: Some(jwk::Usage::Signing),
        algorithm: Some(jws::Algorithm::HS256),
        params: jwk::Parameters::Hmac(jwa::Hmac::new("test".as_bytes())),
    };

    jwks.add_key(jwk);

    let jwks = Arc::new(jwks);

    let (addr, fut) = jwks_server(Arc::clone(&jwks));
    println!("jwks listening at: {}", addr);
    tokio::spawn(fut);

    let validator = jwt::Validation::default()
        .add_approved_algorithm(jws::Algorithm::HS256)
        .require_issuer(jwt::Issuer::new("authority"));

    let hi3 = warp::path!("hello3" / String)
        .and(warp::get())
        .and(warp::header("user-agent"))
        .and(aliri::jwks(
            aliri::jwt(),
            Arc::clone(&jwks),
            Arc::new(validator.clone()),
        ))
        .map(|param, agent: String, claims: Claims| {
            format!(
                "Hello {}, whose agent is {}, authorized as {}!",
                param, agent, claims.subject
            )
        });

    let mut authority = JwksAuthority::new(validator);
    authority.set_jwks_url(format!("http://{}/.well-known/jwks.json", addr));
    authority.refresh_jwks().await?;

    let directives = vec![
        Directive::new(vec![Scope::new("say:hello")]),
        Directive::new(vec![
            Scope::new("say:anything"),
            Scope::new("no-really:anything"),
        ]),
    ];

    let hi4 = warp::path!("hello4" / String)
        .and(warp::get())
        .and(warp::header("user-agent"))
        .and(aliri::oauth2::require_scopes(
            aliri::jwt(),
            Arc::new(authority),
            Arc::new(directives),
        ))
        .map(|param, agent: String, claims: Claims| {
            format!(
                "Hello {}, whose agent is {}, authorized as {} with scopes {:?}!",
                param, agent, claims.subject, claims.scopes
            )
        });

    let (addr, fut) =
        warp::serve(hi.or(hi2).or(hi3).or(hi4)).bind_ephemeral((Ipv4Addr::LOCALHOST, 0));

    println!("listening at: {}", addr);

    Ok(fut.await)
}

fn jwks_server(
    jwks: impl AsRef<Jwks> + Clone + Send + Sync + 'static,
) -> (SocketAddr, impl Future<Output = ()>) {
    let jwks = warp::path!(".well-known" / "jwks.json")
        .and(warp::get())
        .map(move || warp::reply::json(jwks.as_ref()));

    warp::serve(jwks).bind_ephemeral((Ipv4Addr::LOCALHOST, 0))
}
