use aliri::jwa::Algorithm;
use aliri::{jwa, jwk, jwt, Jwk, Jwks, Jwt};
use aliri_base64::Base64UrlRef;
use aliri_clock::{Clock, DurationSecs, UnixTime};
use aliri_oauth2::{oauth2, Authority, Scope, ScopePolicy};
use aliri_tower::{DefaultErrorHandler, VerifyJwt};
use axum::extract::Path;
use axum::routing::{get, post};
use axum::Router;
use tower_http::auth::RequireAuthorizationLayer;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct CustomClaims {
    iss: jwt::Issuer,
    aud: jwt::Audiences,
    sub: jwt::Subject,
    exp: UnixTime,
    scope: oauth2::Scope,
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

impl oauth2::HasScope for CustomClaims {
    fn scope(&self) -> &oauth2::Scope {
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
        .with_key_id(jwk::KeyId::new(KEY_ID));

    print_example_token(&key);

    let mut jwks = Jwks::default();
    jwks.add_key(key);

    let validator = jwt::CoreValidator::default()
        .add_approved_algorithm(jwa::Algorithm::HS256)
        .add_allowed_audience(jwt::Audience::new(AUDIENCE))
        .require_issuer(jwt::Issuer::new(ISSUER));

    Authority::new(jwks, validator)
}

async fn handle_post() -> &'static str {
    "Handled POST /users"
}

async fn handle_get(Path(id): Path<u64>) -> String {
    format!("Handled GET /users/{}", id)
}

#[tokio::main]
async fn main() {
    let authority = construct_authority();

    let verify_jwt = VerifyJwt::<CustomClaims>::new(authority)
        .with_error_handler(DefaultErrorHandler::<_>::new());

    let require_scope = |scope: Scope| {
        let verify_scope = verify_jwt
            .scopes_verifier(ScopePolicy::allow_one(scope))
            .with_error_handler(DefaultErrorHandler::<_>::new());
        RequireAuthorizationLayer::custom(verify_scope)
    };

    let check_jwt = RequireAuthorizationLayer::custom(verify_jwt.clone());

    let app = Router::new()
        .route(
            "/users",
            post(handle_post).layer(require_scope("post_user".parse().unwrap())),
        )
        .route(
            "/users/:id",
            get(handle_get).layer(require_scope("get_user".parse().unwrap())),
        )
        .layer(&check_jwt);

    println!("Press Ctrl+C to exit");

    axum::Server::bind(&"127.0.0.1:8080".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}

fn print_example_token(key: &Jwk) {
    let headers = jwt::BasicHeaders::with_key_id(Algorithm::HS256, jwk::KeyId::new(KEY_ID));

    let payload = CustomClaims {
        sub: jwt::Subject::new("test"),
        iss: jwt::Issuer::new(ISSUER),
        aud: jwt::Audience::new(AUDIENCE).into(),
        exp: aliri_clock::System.now() + DurationSecs(300),
        scope: "get_user post_user".parse().unwrap(),
    };

    let jwt = Jwt::try_from_parts_with_signature(&headers, &payload, key).unwrap();

    println!("Use the following JWT to access the service. It is good for the next 5 minutes, so use it fast!");
    println!(
        "The tool at https://jwt.io/ can be used to mess with the claims and see what happens."
    );
    println!("Token: {:#}", jwt);
}
