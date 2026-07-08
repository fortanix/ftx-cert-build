use std::sync::LazyLock;

use pkix::oid;
use pkix::types::{Name, ObjectIdentifier, TaggedDerValue};
use pkix::yasna::tags::TAG_UTF8STRING;

pub static ORGANIZATIONAL_UNIT_NAME: LazyLock<ObjectIdentifier> = LazyLock::new(|| vec![2, 5, 4, 4].into());
pub static SERIAL_NUMBER: LazyLock<ObjectIdentifier> = LazyLock::new(|| vec![2, 5, 4, 5].into());

#[derive(Clone)]
#[non_exhaustive]
pub enum DnType {
    CountryName,
    LocalityName,
    StateOrProvinceName,
    OrganizationName,
    OrganizationalUnitName,
    CommonName,
    Serial,
    /// Variant used for oids other than the 7 required in RFC5280#section-4.1.2.4
    ///
    /// The corresponding values are not necessarily strings.
    CustomType(ObjectIdentifier),
}

#[derive(Clone, Default)]
pub struct NoDnSet;
#[derive(Clone)]
pub struct WithDnSet(Name);

#[derive(Clone)]
pub struct NameBuilder<D = NoDnSet> {
    dn: D,
}

impl NameBuilder<NoDnSet> {
    #[must_use]
    pub const fn new() -> Self {
        Self { dn: NoDnSet }
    }
}

impl Default for NameBuilder<NoDnSet> {
    fn default() -> Self {
        Self::new()
    }
}

fn dn_type_to_oid(dn_type: DnType) -> ObjectIdentifier {
    match dn_type {
        DnType::CountryName => oid::countryName.clone(),
        DnType::LocalityName => oid::localityName.clone(),
        DnType::StateOrProvinceName => oid::stateOrProvinceName.clone(),
        DnType::OrganizationName => oid::organizationName.clone(),
        DnType::OrganizationalUnitName => ORGANIZATIONAL_UNIT_NAME.clone(),
        DnType::CommonName => oid::commonName.clone(),
        DnType::Serial => SERIAL_NUMBER.clone(),
        DnType::CustomType(oid_data) => oid_data,
    }
}

/// Internally used trait that allows us to be generic over whether our nambe builder has been
/// initialized
pub trait InitDn {
    fn init_dn(self) -> NameBuilder<WithDnSet>;
}

impl InitDn for NameBuilder<NoDnSet> {
    fn init_dn(self) -> NameBuilder<WithDnSet> {
        NameBuilder {
            dn: WithDnSet(Name { value: Vec::new() }),
        }
    }
}

impl InitDn for NameBuilder<WithDnSet> {
    fn init_dn(self) -> NameBuilder<WithDnSet> {
        self
    }
}

macro_rules! add_dn_fun {
    ($fun_name:ident,  $enum_variant:expr) => {
        #[must_use]
        pub fn $fun_name<I>(self, dn_data: I) -> NameBuilder<WithDnSet>
        where
            I: Into<String>,
        {
            self.add_dn($enum_variant, dn_data)
        }
    };
}

macro_rules! add_dn_fun_iter {
    ($fun_name:ident,  $enum_variant:expr) => {
        #[must_use]
        pub fn $fun_name<It, I>(self, dn_iter: It) -> NameBuilder<WithDnSet>
        where
            It: IntoIterator<Item = I>,
            I: Into<String>,
        {
            let initialized_builder = self.init_dn();
            dn_iter
                .into_iter()
                .fold(initialized_builder, |b, data| b.add_dn($enum_variant, data))
        }
    };
}

impl<D> NameBuilder<D>
where
    Self: InitDn,
{
    pub fn add_dn<I>(self, dn_type: DnType, dn_data: I) -> NameBuilder<WithDnSet>
    where
        I: Into<String>,
    {
        let mut initialized_builder = self.init_dn();
        initialized_builder.dn.0.value.push((
            dn_type_to_oid(dn_type),
            TaggedDerValue::from_tag_and_bytes(TAG_UTF8STRING, dn_data.into().into()),
        ));
        initialized_builder
    }

    add_dn_fun!(add_country_name, DnType::CountryName);
    add_dn_fun!(add_locality_name, DnType::LocalityName);
    add_dn_fun!(add_state_or_province_name, DnType::StateOrProvinceName);
    add_dn_fun!(add_organization_name, DnType::OrganizationName);
    add_dn_fun!(add_organizational_unit_name, DnType::OrganizationalUnitName);
    add_dn_fun!(add_common_name, DnType::CommonName);
    add_dn_fun!(add_serial_name, DnType::Serial);

    add_dn_fun_iter!(add_country_name_iter, DnType::CountryName);
    add_dn_fun_iter!(add_locality_name_iter, DnType::LocalityName);
    add_dn_fun_iter!(add_state_or_province_name_iter, DnType::StateOrProvinceName);
    add_dn_fun_iter!(add_organization_name_iter, DnType::OrganizationName);
    add_dn_fun_iter!(add_organizational_unit_name_iter, DnType::OrganizationalUnitName);
    add_dn_fun_iter!(add_common_name_iter, DnType::CommonName);
    add_dn_fun_iter!(add_serial_name_iter, DnType::Serial);

    // TODO: accepting a more general type than `TaggedDerValue` (e.g. `T: ToDer`) and avoiding
    // copies requires refactoring the `pkix` crate and redefining `pkix::Name`
    pub fn add_custom_oid(self, oid: ObjectIdentifier, tagged_der_value: TaggedDerValue) -> NameBuilder<WithDnSet> {
        let mut initialized_builder = self.init_dn();
        initialized_builder
            .dn
            .0
            .value
            .push((dn_type_to_oid(DnType::CustomType(oid)), tagged_der_value));
        initialized_builder
    }

    pub fn add_custom_oid_iter<It>(self, oid: ObjectIdentifier, der_value_iter: It) -> NameBuilder<WithDnSet>
    where
        It: IntoIterator<Item = TaggedDerValue>,
    {
        let initialized_builder = self.init_dn();
        der_value_iter
            .into_iter()
            .fold(initialized_builder, |b, data| b.add_custom_oid(oid.clone(), data))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Subject(pub(crate) Name);

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Issuer(pub(crate) Name);

impl From<Issuer> for Subject {
    fn from(value: Issuer) -> Self {
        Subject(value.0)
    }
}

impl From<Subject> for Issuer {
    fn from(value: Subject) -> Self {
        Issuer(value.0)
    }
}

// Required when we pull a `Name` out of another, parsed certificate
impl From<Name> for Subject {
    fn from(value: Name) -> Self {
        Subject(value)
    }
}

// Required when we pull a `Name` out of another, parsed certificate
impl From<Name> for Issuer {
    fn from(value: Name) -> Self {
        Issuer(value)
    }
}

impl NameBuilder<WithDnSet> {
    #[must_use]
    pub fn build_subject(self) -> Subject {
        self.build_name().into()
    }

    #[must_use]
    pub fn build_issuer(self) -> Issuer {
        self.build_name().into()
    }

    #[must_use]
    pub fn build_name(self) -> Name {
        self.dn.0
    }
}
