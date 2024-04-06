use aliri::{jwa, jwk, jwt, Jwk, Jwks, Jwt};
use aliri_axum::scope_guards;
use aliri_base64::Base64UrlRef;
use aliri_clock::{Clock, DurationSecs, UnixTime};
use aliri_oauth2::{Authority, HasScope, Scope};
use aliri_tower::Oauth2Authorizer;
use axum::{
    extract::Path,
    routing::{get, post},
    Router,
};

scope_guards! {
    type Claims = CustomClaims;

    scope PostUser = "post_user";
    scope GetUser = "get_user";
}

#[tokio::main]
async fn main() {
    let authority = construct_authority();

    let authorizer = Oauth2Authorizer::new()
        .with_claims::<CustomClaims>()
        .with_terse_error_handler();

    let app = Router::new()
        .route("/users", post(handle_post))
        .route("/users/:id", get(handle_get))
        .layer(authorizer.jwt_layer(authority));

    println!("Press Ctrl+C to exit");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:8080")
        .await
        .unwrap();
    axum::serve(listener, app).await.unwrap();
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct CustomClaims {
    iss: jwt::Issuer,
    aud: jwt::Audiences,
    sub: jwt::Subject,
    exp: UnixTime,
    scope: Scope,
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
    fn scope(&self) -> &Scope {
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

async fn handle_post(_: PostUser) -> &'static str {
    "Handled POST /users"
}

async fn handle_get(_: GetUser, Path(id): Path<u64>) -> String {
    format!("Handled GET /users/{}", id)
}

fn print_example_token(key: &Jwk) {
    let headers =
        jwt::BasicHeaders::with_key_id(jwa::Algorithm::HS256, jwk::KeyId::from_static(KEY_ID));

    let payload = CustomClaims {
        sub: jwt::Subject::from_static("test"),
        iss: jwt::Issuer::from_static(ISSUER),
        aud: jwt::Audience::from_static(AUDIENCE).into(),
        exp: aliri_clock::System.now() + DurationSecs(300),
        scope: aliri_oauth2::scope!["get_user", "post_user"],
    };

    let jwt = Jwt::try_from_parts_with_signature(&headers, &payload, key).unwrap();

    println!("Use the following JWT to access the service. It is good for the next 5 minutes, so use it fast!");
    println!(
        "The tool at https://jwt.io/ can be used to mess with the claims and see what happens."
    );
    println!("Token: {:#}", jwt);
}
