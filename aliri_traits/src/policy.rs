use std::fmt;

/// A policy against which a request will be evaluated
pub trait Policy {
    /// The request type evaluated by this policy
    type Request;

    /// The error returned when this policy denies a request
    type Denial: fmt::Debug + fmt::Display + Send + Sync + 'static;

    /// Evaluates the request, producing an effect
    fn evaluate(&self, request: &Self::Request) -> Result<(), Self::Denial>;
}

impl<T> Policy for &'_ T
where
    T: Policy,
{
    type Request = T::Request;
    type Denial = T::Denial;

    fn evaluate(&self, request: &Self::Request) -> Result<(), Self::Denial> {
        T::evaluate(self, request)
    }
}

impl<T> Policy for Box<T>
where
    T: Policy,
{
    type Request = T::Request;
    type Denial = T::Denial;

    fn evaluate(&self, request: &Self::Request) -> Result<(), Self::Denial> {
        T::evaluate(self, request)
    }
}

impl<T> Policy for std::rc::Rc<T>
where
    T: Policy,
{
    type Request = T::Request;
    type Denial = T::Denial;

    fn evaluate(&self, request: &Self::Request) -> Result<(), Self::Denial> {
        T::evaluate(self, request)
    }
}

impl<T> Policy for std::sync::Arc<T>
where
    T: Policy,
{
    type Request = T::Request;
    type Denial = T::Denial;

    fn evaluate(&self, request: &Self::Request) -> Result<(), Self::Denial> {
        T::evaluate(self, request)
    }
}
