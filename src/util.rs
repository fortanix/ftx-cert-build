use pkix::types::{Attribute, Extension, Extensions, GeneralName, GeneralNames, ObjectIdentifier};
use pkix::x509::SubjectAltName;
use pkix::yasna::construct_der;
use pkix::{oid, DerWrite};

use crate::error::{Error, Result, ValidationErrorType};

fn basic_constraints_ext(ca: bool) -> Extension {
    const BASIC_CONSTRAINTS_CA_FALSE: &[u8] = &[0x30, 0];
    const BASIC_CONSTRAINTS_CA_TRUE: &[u8] = &[0x30, 0x03, 0x01, 0x01, 0xFF];

    Extension {
        oid: oid::basicConstraints.clone(),
        critical: true,
        value: if ca {
            BASIC_CONSTRAINTS_CA_TRUE
        } else {
            BASIC_CONSTRAINTS_CA_FALSE
        }
        .to_owned(),
    }
}

pub(crate) fn extensions_contain_key(extensions: &[Extension], key: &ObjectIdentifier) -> bool {
    extensions.iter().any(|e| e.oid == *key)
}

pub(crate) fn attributes_contain_key(attributes: &[Attribute], key: &ObjectIdentifier) -> bool {
    attributes.iter().any(|a| a.oid == *key)
}

pub(crate) fn san_extension_from_general_names<'a>(sans: impl IntoIterator<Item = GeneralName<'a>>) -> Extension {
    let sans_dns_alt_names = SubjectAltName {
        names: GeneralNames(sans.into_iter().collect()),
    };

    let (oid, critical, value): (ObjectIdentifier, bool, Vec<u8>) = (
        oid::subjectAltName.clone(),
        false,
        construct_der(|w| sans_dns_alt_names.write(w)),
    );

    Extension {
        oid: oid.clone(),
        critical,
        value: value[..].to_owned(),
    }
}

pub(crate) fn build_extensions(
    mut base_extensions: Extensions,
    ca: bool,
    maybe_san_extension: Option<Extension>,
) -> Result<Extensions> {
    // Add basic constraint depending on whether we are a CA
    base_extensions.push(basic_constraints_ext(ca));
    // Add SAN extension if the san field is set
    if let Some(san_extension) = maybe_san_extension {
        if extensions_contain_key(&base_extensions, &oid::subjectAltName) {
            return Err(Error::Validation(ValidationErrorType::DuplicateExtension(
                oid::subjectAltName.clone(),
            )));
        }

        base_extensions.push(san_extension);
    }
    Ok(base_extensions)
}

pub(crate) fn build_attributes(mut attributes: Vec<Attribute<'_>>, cert_extensions: Extensions) -> Result<Vec<Attribute<'_>>> {
    let cert_extensions_der = pkix::yasna::construct_der(|w| cert_extensions.write(w));
    attributes.push(Attribute {
        oid: oid::extensionRequest.clone(),
        value: vec![cert_extensions_der.into()],
    });
    Ok(attributes)
}
