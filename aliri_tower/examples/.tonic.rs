//! Note: This example is non-functional until after a tonic release that
//! supports the `http` 1.0 stack of dependencies

use std::sync::atomic::{AtomicI32, Ordering};

use aliri::{jwa, jwk, jwt, Jwk, Jwks, Jwt};
use aliri_base64::Base64UrlRef;
use aliri_clock::{Clock, DurationSecs, UnixTime};
use aliri_oauth2::{policy, scope, Authority, HasScope};
use aliri_tower::Oauth2Authorizer;
use aliri_traits::Policy;
use counter::{
    counter_service_server::{CounterService, CounterServiceServer},
    CounterRequest, CounterResponse,
};
use tonic::{transport::Server, Request, Response, Status};

#[allow(clippy::derive_partial_eq_without_eq)]
pub mod counter {
    include!("proto/aliri.example.rs");
}

#[derive(Default)]
pub struct MyCounter {
    count: AtomicI32,
}

#[tonic::async_trait]
impl CounterService for MyCounter {
    async fn update(
        &self,
        request: Request<CounterRequest>,
    ) -> Result<Response<CounterResponse>, Status> {
        let policy = policy![scope!["update_count"]];
        policy
            .evaluate(
                request
                    .extensions()
                    .get::<CustomClaims>()
                    .ok_or_else(|| Status::permission_denied("missing claims"))?
                    .scope(),
            )
            .map_err(|_| {
                let message = format!(
                    "insufficient scopes, requires one of: [\"{}\"]",
                    (&policy)
                        .into_iter()
                        .map(|s| s.iter().map(|t| t.as_str()).collect::<Vec<_>>().join(" "))
                        .collect::<Vec<_>>()
                        .join("\" or \"")
                );
                Status::permission_denied(message)
            })?;

        let change = request.get_ref().change;
        let previous = self.count.fetch_add(change, Ordering::AcqRel);
        Ok(Response::new(CounterResponse {
            current_value: previous + change,
        }))
    }
}

#[derive(Clone, Copy, Debug)]
struct AuthorizedService<S>(S);

impl<S, T> tonic::server::NamedService
    for AuthorizedService<tower_http::validate_request::ValidateRequestHeader<S, T>>
where
    S: tonic::server::NamedService,
{
    const NAME: &'static str = S::NAME;
}

impl<S, R> tower::Service<R> for AuthorizedService<S>
where
    S: tower::Service<R>,
{
    type Error = S::Error;
    type Future = S::Future;
    type Response = S::Response;

    #[inline]
    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.0.poll_ready(cx)
    }

    #[inline]
    fn call(&mut self, req: R) -> Self::Future {
        self.0.call(req)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // let authority = construct_authority();

    // let authorizer = Oauth2Authorizer::new()
    //     .with_claims::<CustomClaims>()
    //     .with_terse_error_handler();

    // let addr = "[::1]:50051".parse().unwrap();
    // let counter = MyCounter::default();

    // println!("CounterServiceServer listening on {}", addr);

    // let svc = tower::ServiceBuilder::new()
    //     .layer(authorizer.jwt_layer(authority))
    //     .service(CounterServiceServer::new(counter));

    // Server::builder()
    //     .add_service(AuthorizedService(svc))
    //     .serve(addr)
    //     .await?;

    Ok(())
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct CustomClaims {
    iss: jwt::Issuer,
    aud: jwt::Audiences,
    sub: jwt::Subject,
    exp: UnixTime,
    scope: scope::Scope,
}

impl jwt::CoreClaims for CustomClaims {
    fn nbf(&self) -> Option<UnixTime> {
        None
    }
    fn exp(&self) -> Option<UnixTime> {
        Some(self.exp)
    }
    fn aud(&self) -> &jwt::Audiences {
        &self.aud
    }
    fn iss(&self) -> Option<&jwt::IssuerRef> {
        Some(&self.iss)
    }
    fn sub(&self) -> Option<&jwt::SubjectRef> {
        Some(&self.sub)
    }
}

impl HasScope for CustomClaims {
    fn scope(&self) -> &scope::Scope {
        &self.scope
    }
}

const ISSUER: &str = "authority";
const AUDIENCE: &str = "my_api";
const KEY_ID: &str = "test key";
const SHARED_SECRET: &[u8] = b"test";

fn construct_authority() -> Authority {
    // This authority might otherwise come from a well-known JWKS endpoint
    let secret = Base64UrlRef::from_slice(SHARED_SECRET).to_owned();
    let key = Jwk::from(jwa::Hmac::new(secret))
        .with_algorithm(jwa::Algorithm::HS256)
        .with_key_id(jwk::KeyId::from_static(KEY_ID));

    print_example_token(&key);

    let mut jwks = Jwks::default();
    jwks.add_key(key);

    let validator = jwt::CoreValidator::default()
        .add_approved_algorithm(jwa::Algorithm::HS256)
        .add_allowed_audience(jwt::Audience::from_static(AUDIENCE))
        .require_issuer(jwt::Issuer::from_static(ISSUER));

    Authority::new(jwks, validator)
}

fn print_example_token(key: &Jwk) {
    let headers =
        jwt::BasicHeaders::with_key_id(jwa::Algorithm::HS256, jwk::KeyId::from_static(KEY_ID));

    let payload = CustomClaims {
        sub: jwt::Subject::from_static("test"),
        iss: jwt::Issuer::from_static(ISSUER),
        aud: jwt::Audience::from_static(AUDIENCE).into(),
        exp: aliri_clock::System.now() + DurationSecs(300),
        scope: "update_count".parse().unwrap(),
    };

    let jwt = Jwt::try_from_parts_with_signature(&headers, &payload, key).unwrap();

    println!("Use the following JWT to access the service. It is good for the next 5 minutes, so use it fast!");
    println!(
        "The tool at https://jwt.io/ can be used to mess with the claims and see what happens."
    );
    println!("Token: {:#}", jwt);
}
