use serde::{Deserialize, Deserializer};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MaybeUnsupported<T> {
    Supported(T),
    Unsupported,
}

impl<'de, T: 'de> Deserialize<'de> for MaybeUnsupported<T>
where
    Option<T>: Deserialize<'de>,
{
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        <Option<T>>::deserialize(deserializer)
            .map(|o| {
                if let Some(v) = o {
                    MaybeUnsupported::Supported(v)
                } else {
                    MaybeUnsupported::Unsupported
                }
            })
    }
}

impl<T> From<MaybeUnsupported<T>> for Option<T> {
    fn from(x: MaybeUnsupported<T>) -> Self {
        match x {
            MaybeUnsupported::Supported(y) => Some(y),
            MaybeUnsupported::Unsupported => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Deserialize, Eq, PartialEq, Debug)]
    #[serde(tag = "typ")]
    pub enum Test {
        A{ k: String },
        B { v: u32 },
        C {
            x: u32,
            y: u32,
        },
    }

    #[test]
    fn test_it() {
        let x: MaybeUnsupported<Test> = serde_json::from_str(r#"{"typ":"D","k":"123"}"#).unwrap();
        assert_eq!(x, MaybeUnsupported::Unsupported)
    }

    #[test]
    fn test_it_2() {
        let x: MaybeUnsupported<Test> = serde_json::from_str(r#"{"typ":"B","v":123}"#).unwrap();
        assert_eq!(x, MaybeUnsupported::Supported(Test::B{v:123}))
    }
    #[test]
    fn test_it_3() {
        let x: Result<MaybeUnsupported<Test>, _> = serde_json::from_str(r#"{"typ":"B","v":"123"}"#);
        assert!(x.is_err())
    }
}
