use std::future::Future;

use super::Policy;

/// An authority that can verify the validity of a token
pub trait Authority<'a, Payload> {
    /// Policy for the authority
    type Policy: Policy;

    /// The token type expected by the authority
    type Token;

    /// The future type returned by the asynchronous verification function
    type VerifyFuture: Future<Output = Result<Payload, Self::VerifyError>> + 'a;

    /// The type returned in the event of a verification failure
    type VerifyError;

    /// Asynchronously verifies a token using the provided directive
    fn verify(&'a self, token: Self::Token, dir: Self::Policy) -> Self::VerifyFuture;
}
