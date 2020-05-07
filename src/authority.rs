use std::future::Future;

use anyhow::Result;

pub trait Authority<'a, Payload> {
    type Directive;
    type Token;
    type Verify: Future<Output = Result<Payload, Self::VerifyError>> + 'a;
    type VerifyError;

    fn verify(&'a mut self, token: Self::Token, dir: Self::Directive) -> Self::Verify;
}
