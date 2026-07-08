use std::borrow::Cow;
use std::fmt::Display;

use mbedtls::Error as MbedtlsError;
use pkix::types::ObjectIdentifier;
use pkix::ASN1Error;
use thiserror::Error;

pub type Result<T> = ::std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    // local errors
    #[error("Pki: {0}")]
    Pki(Cow<'static, str>),
    #[error("Validation failed")]
    Validation(ValidationErrorType),
    // from errors
    #[error("Mbedtls")]
    Mbedtls(#[from] MbedtlsError),
    #[error("ASN1")]
    ASN1(#[from] ASN1Error),
}

#[derive(Debug)]
pub enum ValidationErrorType {
    NotBeforeAfterNotAfter,
    DurationOverflow,
    PkAndSigAlgMismatch,
    DuplicateExtension(ObjectIdentifier),
    DuplicateAttribute(ObjectIdentifier),
}

impl Display for ValidationErrorType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ValidationErrorType::NotBeforeAfterNotAfter => f.write_str("certificate is not valid at any point in time"),
            ValidationErrorType::DurationOverflow => f.write_str("setting certificate validity period would overflow"),
            ValidationErrorType::PkAndSigAlgMismatch => {
                f.write_str("the signature algorithm does not match the provided private key")
            }
            ValidationErrorType::DuplicateExtension(oid) => write!(f, "extension with oid {} appears multiple times", oid),
            ValidationErrorType::DuplicateAttribute(oid) => write!(f, "attribute with oid {} appears multiple times", oid),
        }
    }
}
