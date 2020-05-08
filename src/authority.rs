use std::future::Future;

/// An authority that can verify the validity of a token
pub trait Authority<'a, Payload> {
    /// Directives for the authority
    type Directive;

    /// The token type expected by the authority
    type Token;

    /// The future type returned by the asynchronous verification function
    type VerifyFuture: Future<Output = Result<Payload, Self::VerifyError>> + 'a;

    /// The type returned in the event of a verification failure
    type VerifyError;

    /// Asynchronously verifies a token using the provided directive
    fn verify(&'a self, token: Self::Token, dir: Self::Directive) -> Self::VerifyFuture;
}
