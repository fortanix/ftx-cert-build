/* Copyright (c) Fortanix, Inc.
|*
|* This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
|* the MPL was not distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::fmt::Display;

use pkix::types::ObjectIdentifier;
use thiserror::Error;

pub type Result<T> = ::std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Validation failed")]
    Validation(ValidationErrorType),
    // from errors
    #[error("Crypto operation failed")]
    CryptoProvider(#[source] Box<dyn std::error::Error + Send + Sync>),
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
            ValidationErrorType::DuplicateExtension(oid) => {
                write!(f, "extension with oid {} appears multiple times", oid)
            }
            ValidationErrorType::DuplicateAttribute(oid) => {
                write!(f, "attribute with oid {} appears multiple times", oid)
            }
        }
    }
}
