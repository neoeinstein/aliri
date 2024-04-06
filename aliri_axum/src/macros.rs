//! Types used to assert that a presented token is authorized to access protected API scopes

/// Constructs an extractor that enables easily asserting that a provided token
/// has the expected set of scopes.
///
/// For an more concise way to construct several scope guards, see
/// [`scope_guards!`][crate::scope_guards!].
///
/// In the simplest case, a single scope can be used:
///
/// ```
/// use aliri_axum::scope_guard;
///
/// scope_guard!(ReadProfile; "read:profile");
/// ```
///
/// In more complex scenarios, multiple sets of scopes can be accepted by separating sets with
/// the logical or operator (`||`):
///
/// ```
/// use aliri_axum::scope_guard;
///
/// scope_guard!(
///     ReadProfileOrAdmin;
///     ["read:profile" || "admin"]
/// );
/// ```
///
/// In situations where multiple scope tokens must all be present, they should be combined into
/// a single space-separated scope:
///
/// ```
/// use aliri_axum::scope_guard;
///
/// scope_guard!(
///     DeleteProfileAndAdmin;
///     "delete:profile admin"
/// );
/// ```
///
/// These two different forms can be combined to add more complex scope guards:
///
/// ```
/// use aliri_axum::scope_guard;
///
/// scope_guard!(
///     DeleteProfileAndAdminOrSuperAdmin;
///     [ "delete:profile admin" || "super_admin" ]
/// );
/// ```
///
/// These scope guards can then be used on an axum handler endpoint in order to assert that
/// the presented JWT token is valid according to the configured authority _and_ that it
/// has the necessary scopes.
///
/// These handlers will expect that the relevant claims have already been validated and placed
/// into the request's extensions.
///
/// ```no_run
/// use aliri_axum::scope_guard;
/// use axum::routing::get;
/// use axum::Router;
/// use std::net::SocketAddr;
///
/// // Define our initial scope
/// scope_guard!(AdminOnly; "admin");
///
/// // Define an endpoint that will require this scope
/// async fn test_endpoint(_: AdminOnly) -> &'static str {
///     "You're an admin!"
/// }
///
/// # #[tokio::main(flavor = "current_thread")] async fn main() {
/// // Build the router
/// let router = Router::new()
///     .route("/test", get(test_endpoint));
///
/// // Construct the server
/// let listener = tokio::net::TcpListener::bind(&SocketAddr::new([0, 0, 0, 0].into(), 3000))
///     .await
///     .unwrap();
/// axum::serve(listener, router)
///     .await
///     .unwrap();
/// # }
/// ```
///
/// A custom claim type can be used in order to better use the validated data:
///
/// ```
/// use aliri::jwt;
/// use aliri_axum::scope_guard;
/// use aliri_clock::UnixTime;
/// use aliri_oauth2::{HasScope, Scope};
/// use serde::Deserialize;
///
/// #[derive(Clone, Debug, Deserialize)]
/// pub struct CustomClaims {
///     iss: jwt::Issuer,
///     aud: jwt::Audiences,
///     sub: jwt::Subject,
///     scope: Scope,
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
/// impl HasScope for CustomClaims {
///     fn scope(&self) -> &Scope { &self.scope }
/// }
///
/// // Define our initial scope
/// scope_guard!(AdminOnly(CustomClaims); "admin");
///
/// // Define an endpoint that will require this scope
/// async fn test_endpoint(AdminOnly(token): AdminOnly) -> String {
///     format!("Token subject: {}", token.sub)
/// }
///
/// // Or ignore the token if it isn't required
/// async fn test_endpoint_but_ignore_token_payload(_: AdminOnly) -> &'static str {
///     "You're an admin!"
/// }
/// ```
// This would probably work nicer as a procedural macro, as then it could
// produce even better documentation.
#[macro_export]
macro_rules! scope_guard {
    ($vis:vis $i:ident; *) => {
        $crate::scope_guard!($vis $i(::aliri_oauth2::scope::BasicClaimsWithScope); *);
    };
    ($vis:vis $i:ident; $scope:literal) => {
        $crate::scope_guard!($vis $i; [$scope]);
    };
    ($vis:vis $i:ident; [$($scope:literal)||* $(,)?]) => {
        $crate::scope_guard!($vis $i(::aliri_oauth2::scope::BasicClaimsWithScope); [$($scope)||*]);
    };
    ($vis:vis $i:ident($claim:ty); $scope:literal) => {
        $crate::scope_guard!($vis $i($claim); [$scope]);
    };
    ($vis:vis $i:ident($claim:ty); *) => {
        /// A scope guard that allows any request, extracting and returning the claims
        ///
        /// Note: This extractor will _consume_ the claims from request extensions. Place
        /// any extractors that may need to copy data from the claims before this extractor
        /// in handler definitions.
        $vis struct $i($vis $claim);

        impl $i {
            #[allow(dead_code)]
            $vis fn into_claims(self) -> $claim {
                self.0
            }

            #[allow(dead_code)]
            $vis fn claims(&self) -> &$claim {
                &self.0
            }
        }

        impl $crate::EndpointScopePolicy for $i {
            type Claims = $claim;

            fn scope_policy() -> &'static $crate::__private::ScopePolicy {
                static POLICY: $crate::__private::OnceCell<$crate::__private::ScopePolicy> = $crate::__private::OnceCell::new();
                POLICY.get_or_init(|| {
                    $crate::__private::ScopePolicy::allow_any()
                })
            }
        }

        #[::axum::async_trait]
        impl<S> ::axum::extract::FromRequestParts<S> for $i
        where
            S: Sync,
        {
            type Rejection = $crate::AuthFailed;

            async fn from_request_parts(
                req: &mut ::axum::http::request::Parts,
                _state: &S,
            ) -> Result<Self, Self::Rejection> {
                $crate::__private::from_request(req, <Self as $crate::EndpointScopePolicy>::scope_policy()).map(Self)
            }
        }
    };
    ($vis:vis $i:ident($claim:ty); [$($scope:literal)||* $(,)?]) => {
        /// Ensures that a claims object authorizes access to a given scope
        ///
        /// Note: This extractor will _consume_ the claims from request extensions. Place
        /// any extractors that may need to copy data from the claims before this extractor
        /// in handler definitions.
        ///
        /// The claims object must have one of the following sets of scopes to be considered authorized.
        /// Within each set, all scopes must be present, but only one set must be satisfied.
        ///
        /// In the event of authorization failures, more verbose messages can be generated by adding
        /// [`aliri_axum::VerboseAuthxErrors`] to the `extensions` of the request.
        ///
        /// Accepted scopes:
        $(
            #[doc = concat!("* `", $scope, "`")]
        )*
        $vis struct $i($vis $claim);

        impl $i {
            #[allow(dead_code)]
            $vis fn into_claims(self) -> $claim {
                self.0
            }

            #[allow(dead_code)]
            $vis fn claims(&self) -> &$claim {
                &self.0
            }
        }

        impl $crate::EndpointScopePolicy for $i {
            type Claims = $claim;

            fn scope_policy() -> &'static $crate::__private::ScopePolicy {
                static POLICY: $crate::__private::OnceCell<$crate::__private::ScopePolicy> = $crate::__private::OnceCell::new();
                POLICY.get_or_init(|| {
                    $crate::__private::ScopePolicy::deny_all()
                    $(
                        .or_allow($scope.parse().unwrap())
                    )*
                })
            }
        }

        #[::axum::async_trait]
        impl<S> ::axum::extract::FromRequestParts<S> for $i
        where
            S: Sync,
        {
            type Rejection = $crate::AuthFailed;

            async fn from_request_parts(
                req: &mut ::axum::http::request::Parts,
                _state: &S,
            ) -> Result<Self, Self::Rejection> {
                $crate::__private::from_request(req, <Self as $crate::EndpointScopePolicy>::scope_policy()).map(Self)
            }
        }
    };
}

/// Convenience macro for services that need to define many scopes.
///
/// # Example
///
/// ```
/// use aliri_axum::scope_guards;
///
/// scope_guards! {
///     scope AdminOnly = "admin";
///     scope List = "list";
///     scope Read = "read";
///     scope Write = "write";
///     scope ReadWrite = "read write";
///     scope ReadOrList = ["read" || "list"];
///     scope AllowAll = *;
///     scope DenyAll = [];
/// }
/// ```
///
/// The above will define a scope guard type for each of the scopes, similar to the [`scope_guard!`]
/// macro.
///
/// Using a custom claims type can be done with a `type Claims = <...>` declaration.
///
/// ```
/// use aliri_axum::scope_guards;
/// use aliri_oauth2::{HasScope, Scope};
///
/// struct CustomClaims {
///     scope: Scope,
/// }
///
/// impl HasScope for CustomClaims {
///     fn scope(&self) -> &Scope {
///        &self.scope
///     }
/// }
///
/// scope_guards! {
///     type Claims = CustomClaims;
///
///     scope AdminOnly = "admin";
///     scope List = "list";
///     scope Read = "read";
///     scope Write = "write";
///     scope ReadWrite = "read write";
///     scope ReadOrList = ["read" || "list"];
/// }
/// ```
#[macro_export]
macro_rules! scope_guards {
    ($($vis:vis scope $i:ident = $scope:tt);* $(;)?) => {
        $(
            $crate::scope_guard!($vis $i; $scope);
        )*
    };
    (type Claims = $claims:ty; $($vis:vis scope $i:ident = $scope:tt);* $(;)?) => {
        $(
            $crate::scope_guard!($vis $i($claims); $scope);
        )*
    };
}

#[cfg(test)]
mod tests {
    use aliri_oauth2::{scope, HasScope, Scope};
    use axum::{
        extract::FromRequestParts,
        http::{request::Parts, Request},
    };

    use crate::AuthFailed;

    scope_guard!(AdminOnly(MyClaims); "admin");

    scope_guards! {
        type Claims = MyClaims;

        scope AdminOnly2 = "admin";
        scope Testing = ["testing" || "testing2"];
        scope TestingAdmin = ["testing admin"];
    }

    #[derive(Clone)]
    struct MyClaims(Scope);

    impl HasScope for MyClaims {
        fn scope(&self) -> &Scope {
            &self.0
        }
    }

    fn request_with_no_claims() -> Parts {
        Request::new(()).into_parts().0
    }

    fn request_with_scope(scope: scope::Scope) -> Parts {
        let mut parts = Request::new(()).into_parts().0;
        parts.extensions.insert(MyClaims(scope));
        parts
    }

    fn request_with_admin_scope() -> Parts {
        request_with_scope(scope!["admin"])
    }

    fn request_with_no_scope() -> Parts {
        request_with_scope(scope![])
    }

    fn request_with_testing_scope() -> Parts {
        request_with_scope(scope!["testing"])
    }

    fn request_with_testing2_scope() -> Parts {
        request_with_scope(scope!["testing2"])
    }

    fn request_with_admin_and_testing_scope() -> Parts {
        request_with_scope(scope!["admin", "testing"])
    }

    #[tokio::test]
    async fn admin_only_scope_guard_without_claims_returns_error() {
        match AdminOnly::from_request_parts(&mut request_with_no_claims(), &()).await {
            Err(AuthFailed::MissingClaims) => {}
            Err(AuthFailed::InsufficientScopes { .. }) => panic!("Expected missing claims error"),
            Ok(_) => panic!("Expected AuthFailed"),
        }
    }

    #[tokio::test]
    async fn admin_only_scope_guard_with_admin_scope_claims() {
        AdminOnly::from_request_parts(&mut request_with_admin_scope(), &())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn admin_only_scope_guard_with_admin_and_testing_scope_claims() {
        AdminOnly::from_request_parts(&mut request_with_admin_and_testing_scope(), &())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn admin_only_scope_guard_with_no_scope_claims() {
        match AdminOnly::from_request_parts(&mut request_with_no_scope(), &()).await {
            Err(AuthFailed::InsufficientScopes { .. }) => {}
            Err(AuthFailed::MissingClaims) => panic!("Expected insufficient scopes error"),
            Ok(_) => panic!("Expected AuthFailed"),
        }
    }

    #[tokio::test]
    async fn testing_scope_guard_with_testing_scope_claims() {
        Testing::from_request_parts(&mut request_with_testing_scope(), &())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn testing_scope_guard_with_admin_and_testing_scope_claims() {
        Testing::from_request_parts(&mut request_with_admin_and_testing_scope(), &())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn testing_scope_guard_with_testing2_scope_claims() {
        Testing::from_request_parts(&mut request_with_testing2_scope(), &())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn testing_scope_guard_with_admin_scope_claims() {
        match Testing::from_request_parts(&mut request_with_admin_scope(), &()).await {
            Err(AuthFailed::InsufficientScopes { .. }) => {}
            Err(AuthFailed::MissingClaims) => panic!("Expected insufficient scopes error"),
            Ok(_) => panic!("Expected AuthFailed"),
        }
    }

    #[tokio::test]
    async fn testing_admin_scope_guard_with_testing_scope_claims() {
        match TestingAdmin::from_request_parts(&mut request_with_testing_scope(), &()).await {
            Err(AuthFailed::InsufficientScopes { .. }) => {}
            Err(AuthFailed::MissingClaims) => panic!("Expected insufficient scopes error"),
            Ok(_) => panic!("Expected AuthFailed"),
        }
    }

    #[tokio::test]
    async fn testing_admin_scope_guard_with_admin_scope_claims() {
        match TestingAdmin::from_request_parts(&mut request_with_admin_scope(), &()).await {
            Err(AuthFailed::InsufficientScopes { .. }) => {}
            Err(AuthFailed::MissingClaims) => panic!("Expected insufficient scopes error"),
            Ok(_) => panic!("Expected AuthFailed"),
        }
    }

    #[tokio::test]
    async fn testing_admin_scope_guard_with_admin_and_testing_scope_claims() {
        TestingAdmin::from_request_parts(&mut request_with_admin_and_testing_scope(), &())
            .await
            .unwrap();
    }
}
