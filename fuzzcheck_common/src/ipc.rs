
use decent_serde_json_alternative::{FromJson, ToJson};

use std::io::prelude::*;
use std::net::TcpStream;

pub fn write(stream: &mut TcpStream, message: &str) {
    let bytes = message.as_bytes();
    let len = bytes.len() as u32;
    let be_len = len.to_be_bytes();

    stream.write_all(&be_len).unwrap();
    stream.write_all(&bytes).unwrap();

    stream.flush().unwrap();
}

pub fn read(stream: &mut TcpStream) -> Option<String> {
    let mut be_len = [0u8; std::mem::size_of::<u32>()];
    stream.read_exact(&mut be_len).ok()?;

    let len = u32::from_be_bytes(be_len);
    let mut buffer = std::iter::repeat(0u8).take(len as usize).collect::<Box<[_]>>();
    stream.read_exact(&mut buffer).ok()?;

    Some(String::from_utf8_lossy(&buffer).to_string())
}


#[derive(Clone, FromJson, ToJson)]
pub enum TuiMessage {
    AddInput { hash: String, input: String },
    RemoveInput { hash: String, input: String },
    ReportEvent { event: FuzzerEvent, stats: FuzzerStats },
}


#[derive(Clone, Copy, Default, FromJson, ToJson)]
pub struct FuzzerStats {
    pub total_number_of_runs: usize,
    pub number_of_runs_since_last_reset_time: usize,
    pub score: f64,
    pub pool_size: usize,
    pub exec_per_s: usize,
    pub avg_cplx: f64,
}

impl FuzzerStats {
    pub fn new() -> FuzzerStats {
        FuzzerStats {
            total_number_of_runs: 0,
            number_of_runs_since_last_reset_time: 0,
            score: 0.0,
            pool_size: 0,
            exec_per_s: 0,
            avg_cplx: 0.0,
        }
    }
}

#[derive(Clone, Copy, FromJson, ToJson)]
pub enum FuzzerEvent {
    Start,
    End,
    CrashNoInput,
    Done,
    New,
    Replace(usize),
    ReplaceLowestStack(usize),
    Remove,
    DidReadCorpus,
    CaughtSignal(i32),
    TestFailure,
}
