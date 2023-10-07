use std::ops::Deref;

use arbitrary_json::ArbitraryValue;
use js_int::UInt;
use serde_json::{Number, Value};

use super::bool::BoolMutator;
use super::integer::U64Mutator;
use super::map::MapMutator;
use super::recursive::RecurToMutator;
use super::string::{string_mutator, StringMutator};
use super::tuples::{Tuple2, Tuple2Mutator, TupleMutatorWrapper};
use super::vector::VecMutator;
use crate::{make_mutator, DefaultMutator, Mutator};

extern crate self as fuzzcheck;

pub type ValueMutator = impl Mutator<ArbitraryValue>;

/// A Fuzzcheck mutator for [`serde_json::Value`].
///
/// Example usage with Fuzzcheck (see the
/// [guide](https://fuzzcheck.neocities.org/tutorial1_writing_fuzz_target.html)
/// if you're unsure on how this works).
///
/// ```ignore
///     use std::str::FromStr;
/// use fuzzcheck::fuzz_test;
/// let result = fuzz_test(|value: &Value| {
///     let v = value.to_string();
///     let new_v = Value::from_str(&v).unwrap();
///     value == &new_v
/// })
/// .mutator(json_value_mutator())
/// .serde_serializer()
/// .default_sensor_and_pool()
/// .arguments_from_cargo_fuzzcheck()
/// .launch();
/// assert!(!result.found_test_failure)
/// ```
pub fn json_value_mutator() -> ValueMutator {
    MapMutator::new(
        InternalJsonValue::default_mutator(),
        |value: &ArbitraryValue| map_serde_json_to_internal(value.clone()),
        |internal_json_value| map_internal_jv_to_serde(internal_json_value.clone()),
        |input, _| calculate_output_cplx(input),
    )
}

// each byte = 1 unit of complexity (?)
fn calculate_output_cplx(input: &ArbitraryValue) -> f64 {
    match input.deref() {
        Value::Null => 1.0,
        Value::Bool(_) => 1.0,
        Value::Number(_) => {
            // 64-bit
            1.0 + 8.0
        }
        Value::String(string) => 1.0 + string.len() as f64,
        Value::Array(array) => array.iter().fold(1.0, |acc, next| {
            acc + calculate_output_cplx(&ArbitraryValue::from(next.clone()))
        }),
        Value::Object(object) => object.iter().fold(1.0, |acc, (key, value)| {
            acc + 1.0 + key.len() as f64 + calculate_output_cplx(&ArbitraryValue::from(value.clone()))
        }),
    }
}

fn map_serde_json_to_internal(value: ArbitraryValue) -> Option<InternalJsonValue> {
    match value.deref() {
        Value::Null => Some(InternalJsonValue::Null),
        Value::Bool(bool) => Some(InternalJsonValue::Bool { inner: *bool }),
        Value::Number(n) => n.as_u64().map(|number| InternalJsonValue::Number { inner: number }),
        Value::String(string) => Some(InternalJsonValue::String { inner: string.clone() }),
        Value::Array(array) => {
            let array = array
                .iter()
                .map(|v| ArbitraryValue::from(v.clone()))
                .map(map_serde_json_to_internal)
                .collect::<Vec<_>>();
            if array.iter().all(Option::is_some) {
                Some(InternalJsonValue::Array {
                    inner: array.into_iter().map(|item| item.unwrap()).collect(),
                })
            } else {
                None
            }
        }
        Value::Object(object) => Some(InternalJsonValue::Object {
            inner: {
                let vec = object
                    .into_iter()
                    .map(|(key, value)| (key, map_serde_json_to_internal(ArbitraryValue::from(value.clone()))))
                    .collect::<Vec<_>>();
                if vec.iter().all(|(_, o)| o.is_some()) {
                    vec.into_iter().map(|(key, val)| (key.clone(), val.unwrap())).collect()
                } else {
                    return None;
                }
            },
        }),
    }
}

fn map_internal_jv_to_serde(internal: InternalJsonValue) -> ArbitraryValue {
    match internal {
        InternalJsonValue::Null => ArbitraryValue::from(Value::Null),
        InternalJsonValue::Bool { inner } => ArbitraryValue::from(Value::Bool(inner)),
        InternalJsonValue::Number { inner } => ArbitraryValue::from(Value::Number(Number::from(
            u64::try_from(UInt::new_wrapping(inner)).unwrap(),
        ))),
        InternalJsonValue::String { inner } => ArbitraryValue::from(Value::String(inner)),
        InternalJsonValue::Array { inner } => ArbitraryValue::from(Value::Array(
            inner
                .into_iter()
                .map(map_internal_jv_to_serde)
                .map(|x| x.deref().clone())
                .collect(),
        )),
        InternalJsonValue::Object { inner } => ArbitraryValue::from(Value::Object(
            inner
                .into_iter()
                .map(|(key, value)| (key, map_internal_jv_to_serde(value).deref().clone()))
                .collect(),
        )),
    }
}

#[derive(Clone)]
enum InternalJsonValue {
    Null,
    Bool { inner: bool },
    Number { inner: u64 },
    String { inner: String },
    Array { inner: Vec<InternalJsonValue> },
    Object { inner: Vec<(String, InternalJsonValue)> },
}

make_mutator! {
    name: InternalJsonValueMutator,
    recursive: true,
    default: true,
    type: enum InternalJsonValue {
        Null,
        Bool {
            #[field_mutator(BoolMutator)]
            inner: bool
        },
        Number {
            #[field_mutator(U64Mutator)]
            inner: u64
        },
        String {
            #[field_mutator(StringMutator = {string_mutator()})]
            inner: String
        },
        Array {
            #[field_mutator(
                VecMutator<
                    InternalJsonValue,
                    RecurToMutator<InternalJsonValueMutator>
                > = {
                    VecMutator::new(self_.into(), 1..=usize::MAX)
                }
            )]
            inner: Vec<InternalJsonValue>,
        },
        Object {
            #[field_mutator(
                VecMutator<
                    (String, InternalJsonValue),
                    TupleMutatorWrapper<
                        Tuple2Mutator<StringMutator, RecurToMutator<InternalJsonValueMutator>>,
                        Tuple2<String, InternalJsonValue>
                    >
                > = {
                    VecMutator::new(
                        TupleMutatorWrapper::new(
                            Tuple2Mutator::new(
                                string_mutator(),
                                self_.into()
                            )
                        ),
                        1..=usize::MAX
                    )
                }
            )]
            inner: Vec<(String, InternalJsonValue)>,
        },
    }
}

impl DefaultMutator for ArbitraryValue {
    type Mutator = ValueMutator;

    #[coverage(off)]
    fn default_mutator() -> Self::Mutator {
        json_value_mutator()
    }
}
