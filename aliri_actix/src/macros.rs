//! Types used to assert that a presented token is authorized to access protected API scopes

// macro_rules! doc_comment {
//     ($x:expr) => {
//         #[doc = $x]
//         extern {}
//     };
//     ($x:expr, $($tt:tt)*) => {
//         #[doc = $x]
//         $($tt)*
//     };
// }

/// Constructs a pair of scoped types that enable easily asserting that a provided token
/// has the expected set of scopes.
///
/// This macro produces a type that does not provide access to any of the data that was
/// contained within the JWT. If that information is necessary, a custom scope guard may
/// be required.
///
/// In the simplest case, a single scope can be used:
///
/// ```
/// use aliri_actix::scope_policy;
///
/// scope_policy!(ReadProfile / ReadProfileScope; "read:profile");
/// # fn main() {}
/// ```
///
/// In more complex scenarios, multiple sets of scopes can be accepted by separating sets with
/// semicolons (`;`):
///
/// ```
/// use aliri_actix::scope_policy;
///
/// scope_policy!(
///     ReadProfileOrAdmin / ReadProfileOrAdminScope;
///     "read:profile";
///     "admin"
/// );
/// # fn main() {}
/// ```
///
/// In situations where multiple scopes must all be present, the scopes can be separated with
/// commas (`,`):
///
/// ```
/// use aliri_actix::scope_policy;
///
/// scope_policy!(
///     DeleteProfileAndAdmin / DeleteProfileAndAdminScope;
///     "delete:profile", "admin"
/// );
/// # fn main() {}
/// ```
///
/// These two different forms can be combined to add more complex scope guards:
///
/// ```
/// use aliri_actix::scope_policy;
///
/// scope_policy!(
///     DeleteProfileAndAdminOrSuperAdmin / DeleteProfileAndAdminOrSuperAdminScope;
///     "delete:profile", "admin";
///     "super_admin"
/// );
/// ```
///
/// These scope guards can then be used on an actix-web endpoint in order to assert that
/// the presented JWT token is valid according to the configured authority _and_ that it
/// has the necessary scopes.
///
/// ```
/// use aliri::{jwa, jwk, jwt, Jwk, Jwks};
/// use aliri_actix::scope_policy;
/// use aliri_base64::Base64UrlRef;
/// use aliri_oauth2::Authority;
/// use actix_web::{get, web, App, HttpServer, HttpResponse, Responder};
///
/// // Define our initial scope
/// scope_policy!(AdminOnly / AdminOnlyScope; "admin");
///
/// // Define an endpoint that will require this scope
/// #[get("/test")]
/// async fn test_endpoint(_: AdminOnly) -> impl Responder {
///     HttpResponse::Ok()
/// }
///
/// fn construct_authority() -> Authority {
///     // This authority might otherwise come from a well-known JWKS endpoint
///     let secret = Base64UrlRef::from_slice(b"test").to_owned();
///     let key = Jwk::from(jwa::Hmac::new(secret))
///         .with_algorithm(jwa::Algorithm::HS256)
///         .with_key_id(jwk::KeyId::new("test key"));
///
///     let mut jwks = Jwks::default();
///     jwks.add_key(key);
///
///     let validator = jwt::CoreValidator::default()
///         .ignore_expiration()
///         .add_approved_algorithm(jwa::Algorithm::HS256)
///         .add_allowed_audience(jwt::Audience::new("my_api"))
///         .require_issuer(jwt::Issuer::new("authority"));
///
///     Authority::new(jwks, validator)
/// }
///
/// // Construct our authority
/// let authority = construct_authority();
///
/// // Construct the server, providing the authority as `app_data`
/// let server = HttpServer::new(move || {
///     App::new()
///         .app_data(authority.clone())
///         .service(test_endpoint)
/// });
/// ```
///
/// A custom claim type can be used in order to better use the validated data:
///
/// ```
/// use aliri::jwt;
/// use aliri_actix::scope_policy;
/// use aliri_clock::UnixTime;
/// use aliri_oauth2::oauth2;
/// use serde::Deserialize;
/// use actix_web::{get, HttpResponse, Responder};
///
/// #[derive(Clone, Debug, Deserialize)]
/// pub struct CustomClaims {
///     iss: jwt::Issuer,
///     aud: jwt::Audiences,
///     sub: jwt::Subject,
///     scope: oauth2::Scope,
/// }
///
/// impl jwt::CoreClaims for CustomClaims {
///     fn nbf(&self) -> Option<UnixTime> { None }
///     fn exp(&self) -> Option<UnixTime> { None }
///     fn aud(&self) -> &jwt::Audiences { &self.aud }
///     fn iss(&self) -> Option<&jwt::IssuerRef> { Some(&self.iss) }
///     fn sub(&self) -> Option<&jwt::SubjectRef> { Some(&self.sub) }
/// }
///
/// impl oauth2::HasScope for CustomClaims {
///     fn scope(&self) -> &oauth2::Scope { &self.scope }
/// }
///
/// // Define our initial scope
/// scope_policy!(AdminOnly / AdminOnlyScope (CustomClaims); "admin");
///
/// // Define an endpoint that will require this scope
/// #[get("/test")]
/// async fn test_endpoint(token: AdminOnly) -> impl Responder {
///     println!("Token subject: {}", token.claims().sub);
///     HttpResponse::Ok()
/// }
///
/// // Or ignore the token if it isn't required
/// #[get("/test-ignore")]
/// async fn test_endpoint_but_ignore_token_payload(_: AdminOnly) -> impl Responder {
///     HttpResponse::Ok()
/// }
/// ```
// This would probably work nicer as a procedural macro, as then it could
// produce even better documentation.
#[macro_export]
macro_rules! scope_policy {
    ($i:ident/$s:ident; $($($scope:literal),*);*) => {
      scope_policy!($i/$s(::aliri_oauth2::oauth2::BasicClaimsWithScope); $($($scope),*);*);
    };
    ($i:ident/$s:ident($claim:ty); $($($scope:literal),*);*) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub struct $s;

        #[doc = "Verifies the JWT and ensures that it has an appropriate scope"]
        #[doc = ""]
        #[doc = "The JWT must have one of the following sets of scopes to be considered authorized."]
        #[doc = "Within each set, all scopes must be present, but only one set must be satisfied."]
        $(
            #[doc = ""]
            #[doc = "* Scopes: "]
            $(
                #[doc = $scope]
            )*
        )*
        pub type $i = ::aliri_actix::jwt::Scoped<$s>;

        impl ::aliri_actix::jwt::ScopeGuard for $s {
            type Claims = $claim;

            fn scope_policy() -> &'static ::aliri_oauth2::ScopePolicy {
                use ::once_cell::sync::OnceCell;

                static POLICY: OnceCell<::aliri_oauth2::ScopePolicy> = OnceCell::new();
                POLICY.get_or_init(|| {
                    ::aliri_oauth2::ScopePolicy::deny_all()
                    $(
                        .or_allow(
                            ::aliri_oauth2::Scope::empty()
                            $(
                                .and(::std::convert::TryFrom::try_from($scope).unwrap())
                            )*
                        )
                    )*
                })
            }
        }
    };
}
