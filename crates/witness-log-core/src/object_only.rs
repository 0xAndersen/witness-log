//! Every struct of the wire format is a JSON object (spec/dossier.schema.json).
//!
//! serde's derived `Deserialize` for a struct also accepts a JSON array of
//! the field values in declaration order, and a struct variant the same,
//! so `["<identity hex>", [], {...}]` deserialised as a `Dossier` and
//! `{"threshold": ["2", "3"]}` as a threshold custody. The Go and
//! TypeScript verifiers never read those forms, so the same file was
//! verified by the reference and refused by the other two (outside review
//! III, H2; corpus/17_dossier_parsing.json). The wire types derive
//! their serde impls with `#[serde(remote = "Self")]` and deserialise
//! through [`ObjectOnly`], which reads a struct, and a struct variant, only
//! from a map. Nothing else changes: field names, defaults, duplicate-field
//! errors and unknown-field handling are serde's.

use serde::de::{DeserializeSeed, Deserializer, EnumAccess, VariantAccess, Visitor};

/// A deserializer that reads structs and struct variants only from maps
/// and forwards everything else unchanged. Used through
/// [`object_only_serde!`](crate::object_only_serde).
#[doc(hidden)]
pub struct ObjectOnly<D>(pub D);

macro_rules! forward {
    ($($method:ident)*) => {$(
        fn $method<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, D::Error> {
            self.0.$method(visitor)
        }
    )*};
}

impl<'de, D: Deserializer<'de>> Deserializer<'de> for ObjectOnly<D> {
    type Error = D::Error;

    forward! {
        deserialize_any deserialize_bool deserialize_i8 deserialize_i16 deserialize_i32
        deserialize_i64 deserialize_i128 deserialize_u8 deserialize_u16 deserialize_u32
        deserialize_u64 deserialize_u128 deserialize_f32 deserialize_f64 deserialize_char
        deserialize_str deserialize_string deserialize_bytes deserialize_byte_buf
        deserialize_option deserialize_unit deserialize_seq deserialize_map
        deserialize_identifier deserialize_ignored_any
    }

    fn deserialize_unit_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        visitor: V,
    ) -> Result<V::Value, D::Error> {
        self.0.deserialize_unit_struct(name, visitor)
    }

    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        visitor: V,
    ) -> Result<V::Value, D::Error> {
        self.0.deserialize_newtype_struct(name, visitor)
    }

    fn deserialize_tuple<V: Visitor<'de>>(
        self,
        len: usize,
        visitor: V,
    ) -> Result<V::Value, D::Error> {
        self.0.deserialize_tuple(len, visitor)
    }

    fn deserialize_tuple_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        len: usize,
        visitor: V,
    ) -> Result<V::Value, D::Error> {
        self.0.deserialize_tuple_struct(name, len, visitor)
    }

    /// The one change: a struct is read from a map, never a sequence.
    fn deserialize_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, D::Error> {
        self.0.deserialize_map(visitor)
    }

    fn deserialize_enum<V: Visitor<'de>>(
        self,
        name: &'static str,
        variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, D::Error> {
        self.0
            .deserialize_enum(name, variants, EnumVisitor(visitor))
    }

    fn is_human_readable(&self) -> bool {
        self.0.is_human_readable()
    }
}

/// Passes an enum through with its struct variants read from maps.
struct EnumVisitor<V>(V);

impl<'de, V: Visitor<'de>> Visitor<'de> for EnumVisitor<V> {
    type Value = V::Value;

    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        self.0.expecting(f)
    }

    fn visit_enum<A: EnumAccess<'de>>(self, data: A) -> Result<V::Value, A::Error> {
        self.0.visit_enum(ObjectOnlyEnum(data))
    }
}

struct ObjectOnlyEnum<A>(A);

impl<'de, A: EnumAccess<'de>> EnumAccess<'de> for ObjectOnlyEnum<A> {
    type Error = A::Error;
    type Variant = ObjectOnlyVariant<A::Variant>;

    fn variant_seed<S: DeserializeSeed<'de>>(
        self,
        seed: S,
    ) -> Result<(S::Value, Self::Variant), A::Error> {
        let (value, variant) = self.0.variant_seed(seed)?;
        Ok((value, ObjectOnlyVariant(variant)))
    }
}

struct ObjectOnlyVariant<A>(A);

impl<'de, A: VariantAccess<'de>> VariantAccess<'de> for ObjectOnlyVariant<A> {
    type Error = A::Error;

    fn unit_variant(self) -> Result<(), A::Error> {
        self.0.unit_variant()
    }

    fn newtype_variant_seed<S: DeserializeSeed<'de>>(self, seed: S) -> Result<S::Value, A::Error> {
        self.0.newtype_variant_seed(seed)
    }

    fn tuple_variant<V: Visitor<'de>>(self, len: usize, visitor: V) -> Result<V::Value, A::Error> {
        self.0.tuple_variant(len, visitor)
    }

    /// The variant's content is read as a map, never a sequence.
    fn struct_variant<V: Visitor<'de>>(
        self,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, A::Error> {
        self.0.newtype_variant_seed(MapSeed(visitor))
    }
}

/// Deserialises the variant's content with `deserialize_map`.
struct MapSeed<V>(V);

impl<'de, V: Visitor<'de>> DeserializeSeed<'de> for MapSeed<V> {
    type Value = V::Value;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<V::Value, D::Error> {
        deserializer.deserialize_map(self.0)
    }
}

/// `Serialize` and `Deserialize` for a type that derives them with
/// `#[serde(remote = "Self")]`, deserialising through [`ObjectOnly`].
#[doc(hidden)]
#[macro_export]
macro_rules! object_only_serde {
    ($ty:ty) => {
        impl ::serde::Serialize for $ty {
            fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                <$ty>::serialize(self, serializer)
            }
        }
        impl<'de> ::serde::Deserialize<'de> for $ty {
            fn deserialize<D: ::serde::Deserializer<'de>>(
                deserializer: D,
            ) -> Result<Self, D::Error> {
                <$ty>::deserialize($crate::object_only::ObjectOnly(deserializer))
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use crate::identity::KeyCustody;
    use crate::sth::SignedTreeHead;

    #[test]
    fn a_struct_is_read_from_an_object_and_never_from_an_array() {
        let obj = serde_json::json!({
            "tree_size": 1, "root_hash": "00", "timestamp_ms": 2,
            "sig_alg": "ed25519", "signer_pubkey": "11", "signature": "22",
        });
        let sth: SignedTreeHead = serde_json::from_value(obj.clone()).unwrap();
        assert_eq!(serde_json::to_value(&sth).unwrap(), obj);
        let arr = serde_json::json!([1, "00", 2, "ed25519", "11", "22"]);
        assert!(serde_json::from_value::<SignedTreeHead>(arr.clone()).is_err());
        assert!(serde_json::from_str::<SignedTreeHead>(&arr.to_string()).is_err());
        // serde's own rules are unchanged: duplicates and missing fields fail.
        let dup = r#"{"tree_size":1,"tree_size":1,"root_hash":"00","timestamp_ms":2,"sig_alg":"ed25519","signer_pubkey":"11","signature":"22"}"#;
        assert!(serde_json::from_str::<SignedTreeHead>(dup).is_err());
    }

    #[test]
    fn a_struct_variant_is_read_from_an_object_and_never_from_an_array() {
        let t: KeyCustody = serde_json::from_str(r#"{"threshold":{"k":"2","n":"3"}}"#).unwrap();
        assert_eq!(
            t,
            KeyCustody::Threshold {
                k: "2".into(),
                n: "3".into()
            }
        );
        assert!(serde_json::from_str::<KeyCustody>(r#"{"threshold":["2","3"]}"#).is_err());
        // Unit variants keep both of serde's forms.
        let h: KeyCustody = serde_json::from_str(r#""hsm""#).unwrap();
        assert_eq!(h, KeyCustody::Hsm);
        let h: KeyCustody = serde_json::from_str(r#"{"hsm":null}"#).unwrap();
        assert_eq!(h, KeyCustody::Hsm);
    }
}
