use std::time::Duration;

use aliri::{error::JwtVerifyError, jwa, jwt};
use aliri_axum::scope_guards;
use aliri_clock::UnixTime;
use aliri_oauth2::{Authority, HasScope, Scope};
use aliri_tower::Oauth2Authorizer;
use axum::{
    extract::Path,
    response::IntoResponse,
    routing::{get, post},
    Extension, Router,
};
use http::{request::Parts, Response};
use time::format_description::well_known::Rfc3339;

scope_guards! {
    type Claims = CustomClaims;

    scope PostUser = "post_user";
    scope GetUser = "get_user";
    scope DeleteUser = "delete_user";
    scope AllowAny = *;
    scope DenyAll = [];
}

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    tracing_subscriber::fmt::init();

    let authority = construct_authority().await?;
    let authorizer = Oauth2Authorizer::new()
        .with_claims::<CustomClaims>()
        .with_error_handler(MyErrorHandler);
    //.with_terse_error_handler();
    //.with_verbose_error_handler();

    let unauthed_routes = Router::new().route("/login", get(|| async {
        "not implemented, but you can use the `auth0_token` example to generate a token for the authenticated APIs."
    }));

    let authed_routes = Router::new()
        .route("/users", post(handle_post))
        .route("/users/:id", get(handle_get).delete(handle_delete))
        .route("/info", get(handle_get_info))
        .route("/deny_all", get(handle_deny_all))
        .layer(authorizer.jwt_layer(authority))
        .layer(Extension(aliri_axum::VerboseAuthxErrors));

    let app = authed_routes.merge(unauthed_routes);

    println!(
        "Run the `auth0_token` program with the desired scopes as an argument to generate a token"
    );
    println!("Press Ctrl+C to exit");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:8080").await?;
    axum::serve(listener, app).await?;

    Ok(())
}

const ISSUER: &str = "https://aliri-demo.us.auth0.com/";
const AUDIENCE: &str = "https://aliri.example.com/";

async fn construct_authority() -> color_eyre::Result<Authority> {
    let validator = jwt::CoreValidator::default()
        .add_approved_algorithm(jwa::Algorithm::RS256)
        .add_allowed_audience(jwt::Audience::from_static(AUDIENCE))
        .require_issuer(jwt::Issuer::from_static(ISSUER));

    let authority =
        Authority::new_from_url(format!("{}.well-known/jwks.json", ISSUER), validator).await?;

    authority.spawn_refresh(Duration::from_secs(600));

    Ok(authority)
}

async fn handle_post(_: PostUser) -> &'static str {
    "Handled POST /users"
}

async fn handle_get(_: GetUser, Path(id): Path<u64>) -> String {
    format!("Handled GET /users/{}", id)
}

async fn handle_delete(_: DeleteUser, Path(id): Path<u64>) -> String {
    format!("Handled DELETE /users/{}", id)
}

async fn handle_get_info(
    LoginCount(login_count): LoginCount,
    AllowAny(claims): AllowAny,
) -> String {
    format!("\
            Token data:\n\
            User with ID `{}` has authorized client `{}` to access the following APIs: [{}]\n\
            This user was authenticated by `{}` and has logged in {} time{}!\n\
            This user is entitled the following permissions: \"{}\", but the current token only grants access to: \"{}\"\n\
            The token was generated at {} and will expire at {} (It is currently {}).\n\
        ",
        claims.sub,
        claims.azp,
        claims.aud.iter().map(|i| i.as_str()).collect::<Vec<_>>().join(", "),
        claims.iss,
        login_count,
        if login_count == 1 { "" } else { "s" },
        claims.permissions,
        claims.scope,
        time::OffsetDateTime::from_unix_timestamp(i64::try_from(claims.iat.0).unwrap()).unwrap().format(&Rfc3339).unwrap(),
        time::OffsetDateTime::from_unix_timestamp(i64::try_from(claims.exp.0).unwrap()).unwrap().format(&Rfc3339).unwrap(),
        time::OffsetDateTime::now_utc().format(&Rfc3339).unwrap(),
    )
}

async fn handle_deny_all(_: DenyAll) -> &'static str {
    "How did you get here?"
}

#[aliri_braid::braid(serde)]
struct ClientId;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct CustomClaims {
    #[serde(rename = "https://aliri.example.com/login_count")]
    login_count: u32,
    iss: jwt::Issuer,
    aud: jwt::Audiences,
    sub: jwt::Subject,
    exp: UnixTime,
    iat: UnixTime,
    azp: ClientId,
    scope: Scope,
    permissions: Scope,
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

#[derive(Clone, Copy)]
struct MyErrorHandler;

impl aliri_tower::OnJwtError for MyErrorHandler {
    type Body = axum::body::Body;

    fn on_missing_or_malformed(&self) -> Response<Self::Body> {
        let (parts, ()) =
            aliri_tower::util::unauthorized("authorization token is missing or malformed")
                .into_parts();

        (
            parts.status,
            parts.headers,
            "authorization token is missing or malformed\n",
        )
            .into_response()
    }

    fn on_no_matching_jwk(&self) -> Response<Self::Body> {
        let (parts, ()) =
            aliri_tower::util::unauthorized("token signing key (kid) is not trusted").into_parts();

        (
            parts.status,
            parts.headers,
            "token signing key (kid) is not trusted\n",
        )
            .into_response()
    }

    fn on_jwt_invalid(&self, error: JwtVerifyError) -> Response<Self::Body> {
        use std::fmt::Write;

        let mut header_description = String::new();
        let mut err: &dyn std::error::Error = &error;
        write!(&mut header_description, "{err}").unwrap();
        while let Some(next) = err.source() {
            write!(&mut header_description, ": {next}").unwrap();
            err = next;
        }

        let (parts, ()) = aliri_tower::util::unauthorized(&header_description).into_parts();

        let mut message = String::new();
        let mut err: &dyn std::error::Error = &error;
        write!(&mut message, "{err}\nDetails:\n").unwrap();
        while let Some(next) = err.source() {
            writeln!(&mut message, "\t{next}").unwrap();
            err = next;
        }

        (parts.status, parts.headers, message).into_response()
    }
}

/// Extracts the login count from the JWT claims
///
/// Note that this extractor needs to appear before any other extractors that
/// consume the claims from the request extensions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LoginCount(pub u32);

#[axum::async_trait]
impl<S: Sync> axum::extract::FromRequestParts<S> for LoginCount {
    type Rejection = (http::StatusCode, &'static str);

    async fn from_request_parts(req: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let inner = || -> Option<LoginCount> {
            Some(LoginCount(
                req.extensions.get::<CustomClaims>()?.login_count,
            ))
        };

        inner().ok_or((
            http::StatusCode::INTERNAL_SERVER_ERROR,
            "unable to access login count",
        ))
    }
}
