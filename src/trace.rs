//! Canonical semantic execution trace for the U30 execution contract.
//!
//! This module deliberately owns only deterministic trace representation and
//! identity. It does not change runtime dispatch or release authority.

use serde::{Serialize, Serializer};

use crate::exec::e7::sha256;

pub const TRACE_SCHEMA: &str = "unico-semantic-trace/v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SemanticTrace {
    schema: &'static str,
    events: Vec<TraceEvent>,
}

impl Default for SemanticTrace {
    fn default() -> Self {
        Self::new()
    }
}

impl SemanticTrace {
    pub fn new() -> Self {
        Self {
            schema: TRACE_SCHEMA,
            events: Vec::new(),
        }
    }

    /// Append one semantic operation. Sequence numbers are assigned here so
    /// callers cannot create gaps, duplicates, or non-zero starting indices.
    pub fn push(&mut self, operation: impl Into<String>, effects: Vec<TraceEffect>) -> u64 {
        let seq = self.events.len() as u64;
        self.events.push(TraceEvent {
            seq,
            operation: operation.into(),
            effects,
        });
        seq
    }

    pub fn events(&self) -> &[TraceEvent] {
        &self.events
    }

    /// Canonical bytes used for semantic trace identity.
    ///
    /// There are no map fields in the schema, so struct declaration order and
    /// Vec order fully determine field/event/effect ordering. serde_json's
    /// compact serializer emits no insignificant whitespace or trailing LF.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("semantic trace serialization is infallible")
    }

    pub fn digest(&self) -> [u8; 32] {
        sha256(&self.canonical_bytes())
    }

    pub fn digest_hex(&self) -> String {
        hex::encode(self.digest())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TraceEvent {
    seq: u64,
    operation: String,
    effects: Vec<TraceEffect>,
}

impl TraceEvent {
    pub fn seq(&self) -> u64 {
        self.seq
    }

    pub fn operation(&self) -> &str {
        &self.operation
    }

    pub fn effects(&self) -> &[TraceEffect] {
        &self.effects
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TraceEffect {
    kind: String,
    target: String,
    value: TraceValue,
}

impl TraceEffect {
    pub fn new(kind: impl Into<String>, target: impl Into<String>, value: TraceValue) -> Self {
        Self {
            kind: kind.into(),
            target: target.into(),
            value,
        }
    }

    pub fn kind(&self) -> &str {
        &self.kind
    }

    pub fn target(&self) -> &str {
        &self.target
    }

    pub fn value(&self) -> &TraceValue {
        &self.value
    }
}

/// Canonical typed effect value.
///
/// Integers use fixed-width lowercase hexadecimal. Signed integers use their
/// two's-complement bit pattern. Floats use their exact IEEE-754 bit pattern,
/// so NaN payloads and signed zero are not normalized by formatting. Byte
/// strings use lowercase hexadecimal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TraceValue {
    Unit,
    Bool(bool),
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    I64(i64),
    F32Bits(u32),
    F64Bits(u64),
    Bytes(Vec<u8>),
}

impl TraceValue {
    pub fn f32(value: f32) -> Self {
        Self::F32Bits(value.to_bits())
    }

    pub fn f64(value: f64) -> Self {
        Self::F64Bits(value.to_bits())
    }

    pub fn canonical_text(&self) -> String {
        match self {
            Self::Unit => "unit".to_string(),
            Self::Bool(false) => "bool:false".to_string(),
            Self::Bool(true) => "bool:true".to_string(),
            Self::U8(value) => format!("u8:{value:02x}"),
            Self::U16(value) => format!("u16:{value:04x}"),
            Self::U32(value) => format!("u32:{value:08x}"),
            Self::U64(value) => format!("u64:{value:016x}"),
            Self::I64(value) => format!("i64:{:016x}", *value as u64),
            Self::F32Bits(bits) => format!("f32:{bits:08x}"),
            Self::F64Bits(bits) => format!("f64:{bits:016x}"),
            Self::Bytes(bytes) => format!("bytes:{}", hex::encode(bytes)),
        }
    }
}

impl Serialize for TraceValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.canonical_text())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EMPTY_TRACE: &[u8] = br#"{"schema":"unico-semantic-trace/v1","events":[]}"#;
    const EMPTY_TRACE_SHA256: &str =
        "7237ae5f82a2081a557c32e809b15f07a7a01537f77941b9ec2deb96b05830bd";

    #[test]
    fn empty_pre_execution_reject_identity_is_exact() {
        let trace = SemanticTrace::new();

        assert_eq!(trace.canonical_bytes(), EMPTY_TRACE);
        assert_eq!(trace.canonical_bytes().len(), 48);
        assert_eq!(trace.digest_hex(), EMPTY_TRACE_SHA256);
    }

    #[test]
    fn event_and_effect_field_order_is_canonical() {
        let mut trace = SemanticTrace::new();
        assert_eq!(
            trace.push(
                "Const",
                vec![TraceEffect::new(
                    "register_write",
                    "r0",
                    TraceValue::U64(42),
                )],
            ),
            0
        );

        assert_eq!(
            String::from_utf8(trace.canonical_bytes()).unwrap(),
            r#"{"schema":"unico-semantic-trace/v1","events":[{"seq":0,"operation":"Const","effects":[{"kind":"register_write","target":"r0","value":"u64:000000000000002a"}]}]}"#
        );
    }

    #[test]
    fn sequence_numbers_are_contiguous_and_zero_based() {
        let mut trace = SemanticTrace::new();
        assert_eq!(trace.push("A", vec![]), 0);
        assert_eq!(trace.push("B", vec![]), 1);
        assert_eq!(trace.events()[0].seq(), 0);
        assert_eq!(trace.events()[1].seq(), 1);
    }

    #[test]
    fn typed_values_have_stable_bit_level_encodings() {
        assert_eq!(TraceValue::U8(0xab).canonical_text(), "u8:ab");
        assert_eq!(TraceValue::U16(1).canonical_text(), "u16:0001");
        assert_eq!(TraceValue::U32(1).canonical_text(), "u32:00000001");
        assert_eq!(TraceValue::U64(1).canonical_text(), "u64:0000000000000001");
        assert_eq!(TraceValue::I64(-1).canonical_text(), "i64:ffffffffffffffff");
        assert_eq!(TraceValue::f32(-0.0).canonical_text(), "f32:80000000");
        assert_eq!(
            TraceValue::f64(-0.0).canonical_text(),
            "f64:8000000000000000"
        );
        assert_eq!(
            TraceValue::Bytes(vec![0x00, 0xab, 0xff]).canonical_text(),
            "bytes:00abff"
        );
    }

    #[test]
    fn repeated_serialization_and_digest_are_deterministic() {
        let mut trace = SemanticTrace::new();
        trace.push(
            "StoreU32",
            vec![TraceEffect::new(
                "memory_write",
                "region0+00000004",
                TraceValue::U32(0x1234),
            )],
        );

        let bytes_a = trace.canonical_bytes();
        let bytes_b = trace.canonical_bytes();
        let digest_a = trace.digest();
        let digest_b = trace.digest();

        assert_eq!(bytes_a, bytes_b);
        assert_eq!(digest_a, digest_b);
        assert!(!bytes_a.ends_with(b"\n"));
        assert!(!bytes_a.contains(&b' '));
    }

    #[test]
    fn semantic_effect_change_changes_digest() {
        let mut a = SemanticTrace::new();
        a.push(
            "Const",
            vec![TraceEffect::new("register_write", "r0", TraceValue::U64(1))],
        );

        let mut b = SemanticTrace::new();
        b.push(
            "Const",
            vec![TraceEffect::new("register_write", "r0", TraceValue::U64(2))],
        );

        assert_ne!(a.digest(), b.digest());
    }

    #[test]
    fn effect_order_is_part_of_identity() {
        let first = TraceEffect::new("register_write", "r0", TraceValue::U64(1));
        let second = TraceEffect::new("register_write", "r1", TraceValue::U64(2));

        let mut a = SemanticTrace::new();
        a.push("Pair", vec![first.clone(), second.clone()]);

        let mut b = SemanticTrace::new();
        b.push("Pair", vec![second, first]);

        assert_ne!(a.canonical_bytes(), b.canonical_bytes());
        assert_ne!(a.digest(), b.digest());
    }
}
