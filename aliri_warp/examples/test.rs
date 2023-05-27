use std::{
    future::Future,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
};

use aliri::{jwa, jwk, jwt, jwt::CoreClaims as _, Jwk, Jwks, Jwt};
use aliri_oauth2::{scope, Authority, HasScope as _, ScopePolicy};
use color_eyre::Result;
use warp::{Filter, Reply};

async fn refresh_jwks(mut interval: tokio::time::Interval, authority: Authority) -> ! {
    interval.tick().await;
    loop {
        interval.tick().await;

        if let Err(err) = authority.refresh().await {
            println!("yuck, error: {}", err);
        } else {
            println!("refreshed JWKS");
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let hi = warp::path!("hello" / String)
        .and(warp::get())
        .and(warp::header("user-agent"))
        .and(aliri_warp::jwt::optional())
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
        .and(aliri_warp::jwt())
        .map(|param, agent: String, auth: Jwt| {
            format!("Hello {}, whose agent is {}, auth: {}", param, agent, auth)
        });

    let mut jwks = Jwks::default();

    let alg = jwa::hmac::SigningAlgorithm::HS256;
    let jwk = Jwk::from(jwa::Hmac::generate(alg).unwrap())
        .with_key_id(jwk::KeyId::from_static("key-id"))
        .with_algorithm(alg);

    jwks.add_key(jwk);

    let jwks = Arc::new(jwks);

    let (addr, fut) = jwks_server(Arc::clone(&jwks));
    println!("jwks listening at: {}", addr);
    tokio::spawn(fut);

    let validator = jwt::CoreValidator::default()
        .add_approved_algorithm(jwa::Algorithm::HS256)
        .check_not_before()
        .add_allowed_audience(jwt::Audience::from_static("aliri_warp"))
        .check_subject(regex::Regex::new(r"^aliri\|.{3,}").unwrap())
        .require_issuer(jwt::Issuer::from_static("authority"));

    let hi3 = warp::path!("hello3" / String)
        .and(warp::get())
        .and(warp::header("user-agent"))
        .and(aliri_warp::jwks(
            aliri_warp::jwt(),
            Arc::clone(&jwks),
            Arc::new(validator.clone()),
        ))
        .map(
            |param, agent: String, claims: scope::BasicClaimsWithScope| {
                format!(
                    "Hello {}, whose agent is {}, authorized as {}!",
                    param,
                    agent,
                    claims.sub().unwrap()
                )
            },
        );

    let jwks_url = format!("http://{}/.well-known/jwks.json", addr);
    let authority = Authority::new_from_url(jwks_url, validator).await?;

    tokio::spawn(refresh_jwks(
        tokio::time::interval(std::time::Duration::from_secs(30)),
        authority.clone(),
    ));

    let mut policy = ScopePolicy::deny_all();
    policy.allow(scope::Scope::single("say:hello".parse()?));
    policy.allow(scope::Scope::from_scope_tokens(vec![
        "say:anything".parse()?,
        "no-really:anything".parse()?,
    ]));

    let hi4 = warp::path!("hello4" / String)
        .and(warp::get())
        .and(warp::header("user-agent"))
        .and(aliri_warp::oauth2::require_scope(
            aliri_warp::jwt(),
            authority,
            Arc::new(policy),
        ))
        .map(
            |param, agent: String, claims: scope::BasicClaimsWithScope| {
                format!(
                    "Hello {}, whose agent is {}, authorized as {} with scope {:?}!",
                    param,
                    agent,
                    claims.sub().unwrap(),
                    claims.scope()
                )
            },
        );

    let (addr, fut) =
        warp::serve(hi.or(hi2).or(hi3).or(hi4)).bind_ephemeral((Ipv4Addr::LOCALHOST, 0));

    println!("listening at: {}", addr);

    fut.await;

    Ok(())
}

fn jwks_server(
    jwks: impl AsRef<Jwks> + Clone + Send + Sync + 'static,
) -> (SocketAddr, impl Future<Output = ()>) {
    let skip = warp::path!(".well-known" / "jwks.json")
        .and(warp::get())
        .and(warp::header::optional("if-none-match"))
        .map(move |inm: Option<String>| {
            if inm.as_deref() == Some(r#"W/"1""#) {
                warp::http::Response::builder()
                    .status(warp::http::StatusCode::NOT_MODIFIED)
                    .body(warp::hyper::Body::empty())
                    .unwrap()
            } else {
                warp::reply::json(jwks.as_ref()).into_response()
            }
        })
        .with(warp::reply::with::header("etag", r#"W/"1""#));

    // let jwks = warp::path!(".well-known" / "jwks.json")
    //     .and(warp::get())
    //     .map(move || warp::reply::json(jwks.as_ref()))
    //     .map(|r| warp::reply::with::header("etag", r#"W/"1""#));

    warp::serve(skip).bind_ephemeral((Ipv4Addr::LOCALHOST, 0))
}
