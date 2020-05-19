use aliri_macros::typed_string;

typed_string! {
    /// An identifier for a JWK
    pub struct KeyId(String);

    /// Reference to `KeyId`
    pub struct KeyIdRef(str);
}
