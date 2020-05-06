use std::future::Future;

use anyhow::Result;

use super::TokenRef;

pub trait Authority<'a, Payload> {
    type Directive;
    type Verify: Future<Output = Result<Payload, Self::VerifyError>> + 'a;
    type VerifyError;

    fn verify(&'a mut self, token: &'a TokenRef, dir: Self::Directive) -> Self::Verify;
}
