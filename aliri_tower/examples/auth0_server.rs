use aliri::error::JwtVerifyError;
use aliri::{jwa, jwt};
use aliri_clock::UnixTime;
use aliri_oauth2::{oauth2, Authority, ScopePolicy};
use aliri_tower::Oauth2Authorizer;
use axum::extract::{Extension, Path, RequestParts};
use axum::handler::Handler;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::Router;
use http::Response;
use time::format_description::well_known::Rfc3339;

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    let authority = construct_authority().await?;
    let authorizer = Oauth2Authorizer::new()
        .with_claims::<CustomClaims>()
        .with_error_handler(MyErrorHandler);
    //.with_terse_error_handler();
    //.with_verbose_error_handler();

    let app =
        Router::new()
            .route(
                "/users",
                post(handle_post.layer(
                    authorizer.scope_layer(ScopePolicy::allow_one_from_static("post_user")),
                )),
            )
            .route(
                "/users/:id",
                get(handle_get
                    .layer(authorizer.scope_layer(ScopePolicy::allow_one_from_static("get_user"))))
                .delete(handle_delete.layer(
                    authorizer.scope_layer(ScopePolicy::allow_one_from_static("delete_user")),
                )),
            )
            .route("/info", get(handle_get_info))
            .route(
                "/deny_all",
                get(handle_deny_all.layer(authorizer.scope_layer(ScopePolicy::deny_all()))),
            )
            .layer(authorizer.jwt_layer(authority));

    println!("Run this program with `token` as an argument to generate a token");
    println!("Press Ctrl+C to exit");

    axum::Server::bind(&"127.0.0.1:8080".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();

    Ok(())
}

const ISSUER: &str = "https://aliri-demo.us.auth0.com/";
const AUDIENCE: &str = "https://aliri.example.com/";

async fn construct_authority() -> color_eyre::Result<Authority> {
    let validator = jwt::CoreValidator::default()
        .add_approved_algorithm(jwa::Algorithm::RS256)
        .add_allowed_audience(jwt::Audience::new(AUDIENCE))
        .require_issuer(jwt::Issuer::new(ISSUER));

    let authority =
        Authority::new_from_url(format!("{}.well-known/jwks.json", ISSUER), validator).await?;

    Ok(authority)
}

async fn handle_post() -> &'static str {
    "Handled POST /users"
}

async fn handle_get(Path(id): Path<u64>) -> String {
    format!("Handled GET /users/{}", id)
}

async fn handle_delete(Path(id): Path<u64>) -> String {
    format!("Handled DELETE /users/{}", id)
}

async fn handle_get_info(
    Extension(claims): Extension<CustomClaims>,
    LoginCount(login_count): LoginCount,
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

async fn handle_deny_all() -> &'static str {
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
    scope: oauth2::Scope,
    permissions: oauth2::Scope,
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

#[derive(Clone, Copy)]
struct MyErrorHandler;

impl aliri_tower::OnJwtError for MyErrorHandler {
    type Body = axum::body::BoxBody;

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

impl aliri_tower::OnScopeError for MyErrorHandler {
    type Body = axum::body::BoxBody;

    fn on_missing_scope_claim(&self) -> Response<Self::Body> {
        let (parts, ()) = aliri_tower::util::forbidden(
            "authorization token is missing an expected scope claim",
            None,
        )
        .into_parts();

        (
            parts.status,
            parts.headers,
            "authorization token is missing an expected scope claim\n",
        )
            .into_response()
    }

    fn on_scope_policy_failure(
        &self,
        held: &oauth2::Scope,
        required: &ScopePolicy,
    ) -> Response<Self::Body> {
        use std::fmt::Write;

        let (parts, ()) = aliri_tower::util::forbidden(
            "authorization token has insufficient scope to access this endpoint",
            Some(required),
        )
        .into_parts();

        let mut message = String::new();
        write!(&mut message, "authorization token has insufficient scope to access this endpoint\nGrant: {held}\nAcceptable scopes:\n").unwrap();
        if required == &ScopePolicy::deny_all() {
            message.push_str("\tNONE (deny all)\n")
        } else {
            for scope in required {
                writeln!(&mut message, "\t{scope}").unwrap();
            }
        }

        (parts.status, parts.headers, message).into_response()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LoginCount(pub u32);

#[axum::async_trait]
impl<B: Send> axum::extract::FromRequest<B> for LoginCount {
    type Rejection = (http::StatusCode, &'static str);

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        let inner = || -> Option<LoginCount> {
            Some(LoginCount(
                req.extensions().get::<CustomClaims>()?.login_count,
            ))
        };

        inner().ok_or((
            http::StatusCode::INTERNAL_SERVER_ERROR,
            "unable to access login count",
        ))
    }
}
