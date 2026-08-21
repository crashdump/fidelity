//! The optional export schema contract.
//!
//! The host selects the format. This serializer records only the Serde data
//! model, so a format choice cannot change the contract that this test locks.

use core::fmt;

use serde::ser::{
    Error as _, Serialize, SerializeMap, SerializeSeq, SerializeStruct, SerializeStructVariant,
    SerializeTuple, SerializeTupleStruct, SerializeTupleVariant,
};

use crate::{
    Action, AuthenticodeThumbprint, BoundedText, Category, CategorySet, CertificateSha256, Choice,
    CodeRequirement, ContentDigest, Detector, DetectorState, Evidence, ExpectedIdentity, Finding,
    IdentityError, Outcome, Platform, SignalStrength, Snapshot, TeamIdentifier, UiObservation,
};

#[derive(Debug)]
struct SchemaError(String);

impl fmt::Display for SchemaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for SchemaError {}

impl serde::ser::Error for SchemaError {
    fn custom<T: fmt::Display>(message: T) -> Self {
        Self(message.to_string())
    }
}

struct SchemaSerializer;

fn schema(value: &impl Serialize) -> Result<String, SchemaError> {
    value.serialize(SchemaSerializer)
}

impl serde::Serializer for SchemaSerializer {
    type Ok = String;
    type Error = SchemaError;
    type SerializeSeq = Compound;
    type SerializeTuple = Compound;
    type SerializeTupleStruct = Compound;
    type SerializeTupleVariant = Compound;
    type SerializeMap = Compound;
    type SerializeStruct = Compound;
    type SerializeStructVariant = Compound;

    fn serialize_bool(self, value: bool) -> Result<Self::Ok, Self::Error> {
        Ok(value.to_string())
    }

    fn serialize_i8(self, value: i8) -> Result<Self::Ok, Self::Error> {
        Ok(value.to_string())
    }

    fn serialize_i16(self, value: i16) -> Result<Self::Ok, Self::Error> {
        Ok(value.to_string())
    }

    fn serialize_i32(self, value: i32) -> Result<Self::Ok, Self::Error> {
        Ok(value.to_string())
    }

    fn serialize_i64(self, value: i64) -> Result<Self::Ok, Self::Error> {
        Ok(value.to_string())
    }

    fn serialize_u8(self, value: u8) -> Result<Self::Ok, Self::Error> {
        Ok(value.to_string())
    }

    fn serialize_u16(self, value: u16) -> Result<Self::Ok, Self::Error> {
        Ok(value.to_string())
    }

    fn serialize_u32(self, value: u32) -> Result<Self::Ok, Self::Error> {
        Ok(value.to_string())
    }

    fn serialize_u64(self, value: u64) -> Result<Self::Ok, Self::Error> {
        Ok(value.to_string())
    }

    fn serialize_f32(self, value: f32) -> Result<Self::Ok, Self::Error> {
        Ok(value.to_string())
    }

    fn serialize_f64(self, value: f64) -> Result<Self::Ok, Self::Error> {
        Ok(value.to_string())
    }

    fn serialize_char(self, value: char) -> Result<Self::Ok, Self::Error> {
        Ok(format!("'{value}'"))
    }

    fn serialize_str(self, value: &str) -> Result<Self::Ok, Self::Error> {
        Ok(format!("{value:?}"))
    }

    fn serialize_bytes(self, value: &[u8]) -> Result<Self::Ok, Self::Error> {
        Ok(format!("{value:?}"))
    }

    fn serialize_none(self) -> Result<Self::Ok, Self::Error> {
        Ok("None".to_owned())
    }

    fn serialize_some<T: ?Sized + Serialize>(self, value: &T) -> Result<Self::Ok, Self::Error> {
        Ok(format!("Some({})", value.serialize(Self)?))
    }

    fn serialize_unit(self) -> Result<Self::Ok, Self::Error> {
        Ok("()".to_owned())
    }

    fn serialize_unit_struct(self, name: &'static str) -> Result<Self::Ok, Self::Error> {
        Ok(name.to_owned())
    }

    fn serialize_unit_variant(
        self,
        name: &'static str,
        _index: u32,
        variant: &'static str,
    ) -> Result<Self::Ok, Self::Error> {
        Ok(format!("{name}::{variant}"))
    }

    fn serialize_newtype_struct<T: ?Sized + Serialize>(
        self,
        name: &'static str,
        value: &T,
    ) -> Result<Self::Ok, Self::Error> {
        Ok(format!("{name}({})", value.serialize(Self)?))
    }

    fn serialize_newtype_variant<T: ?Sized + Serialize>(
        self,
        name: &'static str,
        _index: u32,
        variant: &'static str,
        value: &T,
    ) -> Result<Self::Ok, Self::Error> {
        Ok(format!("{name}::{variant}({})", value.serialize(Self)?))
    }

    fn serialize_seq(self, _length: Option<usize>) -> Result<Self::SerializeSeq, Self::Error> {
        Ok(Compound::new("[", "]"))
    }

    fn serialize_tuple(self, _length: usize) -> Result<Self::SerializeTuple, Self::Error> {
        Ok(Compound::new("(", ")"))
    }

    fn serialize_tuple_struct(
        self,
        name: &'static str,
        _length: usize,
    ) -> Result<Self::SerializeTupleStruct, Self::Error> {
        Ok(Compound::new(&format!("{name}("), ")"))
    }

    fn serialize_tuple_variant(
        self,
        name: &'static str,
        _index: u32,
        variant: &'static str,
        _length: usize,
    ) -> Result<Self::SerializeTupleVariant, Self::Error> {
        Ok(Compound::new(&format!("{name}::{variant}("), ")"))
    }

    fn serialize_map(self, _length: Option<usize>) -> Result<Self::SerializeMap, Self::Error> {
        Ok(Compound::new("{", "}"))
    }

    fn serialize_struct(
        self,
        name: &'static str,
        _length: usize,
    ) -> Result<Self::SerializeStruct, Self::Error> {
        Ok(Compound::new(&format!("{name}{{"), "}"))
    }

    fn serialize_struct_variant(
        self,
        name: &'static str,
        _index: u32,
        variant: &'static str,
        _length: usize,
    ) -> Result<Self::SerializeStructVariant, Self::Error> {
        Ok(Compound::new(&format!("{name}::{variant}{{"), "}"))
    }
}

struct Compound {
    text: String,
    end: &'static str,
    first: bool,
    map_key: Option<String>,
}

impl Compound {
    fn new(start: &str, end: &'static str) -> Self {
        Self {
            text: start.to_owned(),
            end,
            first: true,
            map_key: None,
        }
    }

    fn push(&mut self, value: &str) {
        if !self.first {
            self.text.push(',');
        }
        self.first = false;
        self.text.push_str(value);
    }

    fn push_field(&mut self, name: &str, value: &str) {
        self.push(&format!("{name}:{value}"));
    }

    fn finish(mut self) -> String {
        self.text.push_str(self.end);
        self.text
    }
}

impl SerializeSeq for Compound {
    type Ok = String;
    type Error = SchemaError;

    fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Self::Error> {
        self.push(&value.serialize(SchemaSerializer)?);
        Ok(())
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(self.finish())
    }
}

impl SerializeTuple for Compound {
    type Ok = String;
    type Error = SchemaError;

    fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Self::Error> {
        SerializeSeq::serialize_element(self, value)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(self.finish())
    }
}

impl SerializeTupleStruct for Compound {
    type Ok = String;
    type Error = SchemaError;

    fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Self::Error> {
        SerializeSeq::serialize_element(self, value)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(self.finish())
    }
}

impl SerializeTupleVariant for Compound {
    type Ok = String;
    type Error = SchemaError;

    fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Self::Error> {
        SerializeSeq::serialize_element(self, value)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(self.finish())
    }
}

impl SerializeMap for Compound {
    type Ok = String;
    type Error = SchemaError;

    fn serialize_key<T: ?Sized + Serialize>(&mut self, key: &T) -> Result<(), Self::Error> {
        self.map_key = Some(key.serialize(SchemaSerializer)?);
        Ok(())
    }

    fn serialize_value<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Self::Error> {
        let Some(key) = self.map_key.take() else {
            return Err(SchemaError::custom("a map value has no key"));
        };
        self.push_field(&key, &value.serialize(SchemaSerializer)?);
        Ok(())
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(self.finish())
    }
}

impl SerializeStruct for Compound {
    type Ok = String;
    type Error = SchemaError;

    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), Self::Error> {
        self.push_field(key, &value.serialize(SchemaSerializer)?);
        Ok(())
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(self.finish())
    }
}

impl SerializeStructVariant for Compound {
    type Ok = String;
    type Error = SchemaError;

    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), Self::Error> {
        SerializeStruct::serialize_field(self, key, value)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(self.finish())
    }
}

const TEST_DETECTOR: Detector = Detector::new(7, "schema.detector", Category::Integrity);

const LOCKED_SCHEMA: &str = r#"Action=Action::Callback
AuthenticodeThumbprint=AuthenticodeThumbprint((1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1))
BoundedText=BoundedText{text:"detail",truncated:false}
Category=Category::Integrity
CategorySet=CategorySet(1)
CertificateSha256=CertificateSha256((2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2))
Choice=Choice::AcceptUnsupported
CodeRequirement=CodeRequirement("anchor apple")
ContentDigest=ContentDigest([1,2,3])
Detector="schema.detector"
DetectorState=DetectorState{detector:"schema.detector",outcome:Outcome::Finding(Finding{detector:"schema.detector",category:Category::Integrity,strength:SignalStrength::High,evidence:Evidence::TracerPresent{detail:BoundedText{text:"detail",truncated:false}},observed_at_unix_ms:42}),strongest:Some(Finding{detector:"schema.detector",category:Category::Integrity,strength:SignalStrength::High,evidence:Evidence::TracerPresent{detail:BoundedText{text:"detail",truncated:false}},observed_at_unix_ms:42}),first_unix_ms:Some(40),latest_unix_ms:Some(42),occurrences:2}
ExpectedIdentity=ExpectedIdentity{windows:Some(Choice::Value(AuthenticodeThumbprint((1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1)))),macos:Some(Choice::Value(CodeRequirement("anchor apple"))),ios:Some(Choice::Value(TeamIdentifier("ABCDE12345"))),android:Some(Choice::Value(CertificateSha256((2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2)))),linux:Some(Choice::Value(ContentDigest([1,2,3])))}
Finding=Finding{detector:"schema.detector",category:Category::Integrity,strength:SignalStrength::High,evidence:Evidence::TracerPresent{detail:BoundedText{text:"detail",truncated:false}},observed_at_unix_ms:42}
IdentityError=IdentityError::NotHex
Outcome=Outcome::Clean
Platform=Platform::MacOs
SignalStrength=SignalStrength::High
Snapshot=Snapshot{latched:CategorySet(1),host_latched:CategorySet(0),detectors:[DetectorState{detector:"schema.detector",outcome:Outcome::Finding(Finding{detector:"schema.detector",category:Category::Integrity,strength:SignalStrength::High,evidence:Evidence::TracerPresent{detail:BoundedText{text:"detail",truncated:false}},observed_at_unix_ms:42}),strongest:Some(Finding{detector:"schema.detector",category:Category::Integrity,strength:SignalStrength::High,evidence:Evidence::TracerPresent{detail:BoundedText{text:"detail",truncated:false}},observed_at_unix_ms:42}),first_unix_ms:Some(40),latest_unix_ms:Some(42),occurrences:2}]}
TeamIdentifier=TeamIdentifier("ABCDE12345")
UiObservation=UiObservation::Overlay
Evidence[0]=Evidence::DetectorHealth{detail:BoundedText{text:"detail",truncated:false}}
Evidence[1]=Evidence::ImageUntrusted{detail:BoundedText{text:"detail",truncated:false}}
Evidence[2]=Evidence::UnexpectedIdentity{detail:BoundedText{text:"detail",truncated:false}}
Evidence[3]=Evidence::TracerPresent{detail:BoundedText{text:"detail",truncated:false}}
Evidence[4]=Evidence::UnaccountedCode{detail:BoundedText{text:"detail",truncated:false}}
Evidence[5]=Evidence::CodeAddedAfterStart{detail:BoundedText{text:"detail",truncated:false}}
Evidence[6]=Evidence::CodeMadeWritable{detail:BoundedText{text:"detail",truncated:false}}
Evidence[7]=Evidence::DispatchRedirected{detail:BoundedText{text:"detail",truncated:false}}
Evidence[8]=Evidence::DevelopmentBuild{detail:BoundedText{text:"detail",truncated:false}}
Evidence[9]=Evidence::InterfaceObserved{detail:BoundedText{text:"detail",truncated:false}}
Evidence[10]=Evidence::VirtualMachineHost{detail:BoundedText{text:"detail",truncated:false}}"#;

fn named<T>(name: &str, value: &T, lines: &mut Vec<String>) -> Result<(), SchemaError>
where
    T: Serialize,
{
    lines.push(format!("{name}={}", schema(value)?));
    Ok(())
}

#[test]
fn public_export_schema_matches_the_locked_fixture() -> Result<(), Box<dyn std::error::Error>> {
    let detail = BoundedText::new("detail");
    let finding = Finding::new(
        TEST_DETECTOR,
        SignalStrength::High,
        Evidence::TracerPresent {
            detail: detail.clone(),
        },
        42,
    );
    let state = DetectorState::new(
        TEST_DETECTOR,
        Outcome::Finding(finding.clone()),
        Some(finding.clone()),
        Some(40),
        Some(42),
        2,
    );
    let mut categories = CategorySet::new();
    categories.insert(Category::Integrity);
    let snapshot = Snapshot::new(categories, CategorySet::new(), vec![state.clone()]);
    let code_requirement = CodeRequirement::new("anchor apple")?;
    let team = TeamIdentifier::new("ABCDE12345")?;
    let digest = ContentDigest::new([1, 2, 3])?;
    let expected_identity = ExpectedIdentity::new()
        .windows(Choice::Value(AuthenticodeThumbprint::from_bytes([1; 32])))
        .macos(Choice::Value(code_requirement.clone()))
        .ios(Choice::Value(team.clone()))
        .android(Choice::Value(CertificateSha256::from_bytes([2; 32])))
        .linux(Choice::Value(digest.clone()));

    let mut lines = Vec::new();
    named("Action", &Action::Callback, &mut lines)?;
    named(
        "AuthenticodeThumbprint",
        &AuthenticodeThumbprint::from_bytes([1; 32]),
        &mut lines,
    )?;
    named("BoundedText", &detail, &mut lines)?;
    named("Category", &Category::Integrity, &mut lines)?;
    named("CategorySet", &categories, &mut lines)?;
    named(
        "CertificateSha256",
        &CertificateSha256::from_bytes([2; 32]),
        &mut lines,
    )?;
    named("Choice", &Choice::<u8>::AcceptUnsupported, &mut lines)?;
    named("CodeRequirement", &code_requirement, &mut lines)?;
    named("ContentDigest", &digest, &mut lines)?;
    named("Detector", &TEST_DETECTOR, &mut lines)?;
    named("DetectorState", &state, &mut lines)?;
    named("ExpectedIdentity", &expected_identity, &mut lines)?;
    named("Finding", &finding, &mut lines)?;
    named("IdentityError", &IdentityError::NotHex, &mut lines)?;
    named("Outcome", &Outcome::Clean, &mut lines)?;
    named("Platform", &Platform::MacOs, &mut lines)?;
    named("SignalStrength", &SignalStrength::High, &mut lines)?;
    named("Snapshot", &snapshot, &mut lines)?;
    named("TeamIdentifier", &team, &mut lines)?;
    named("UiObservation", &UiObservation::Overlay, &mut lines)?;

    let variants = [
        Evidence::DetectorHealth {
            detail: detail.clone(),
        },
        Evidence::ImageUntrusted {
            detail: detail.clone(),
        },
        Evidence::UnexpectedIdentity {
            detail: detail.clone(),
        },
        Evidence::TracerPresent {
            detail: detail.clone(),
        },
        Evidence::UnaccountedCode {
            detail: detail.clone(),
        },
        Evidence::CodeAddedAfterStart {
            detail: detail.clone(),
        },
        Evidence::CodeMadeWritable {
            detail: detail.clone(),
        },
        Evidence::DispatchRedirected {
            detail: detail.clone(),
        },
        Evidence::DevelopmentBuild {
            detail: detail.clone(),
        },
        Evidence::InterfaceObserved {
            detail: detail.clone(),
        },
        Evidence::VirtualMachineHost { detail },
    ];
    for (index, variant) in variants.iter().enumerate() {
        named(&format!("Evidence[{index}]"), variant, &mut lines)?;
    }

    assert_eq!(lines.join("\n"), LOCKED_SCHEMA);
    Ok(())
}
