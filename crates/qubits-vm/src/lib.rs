//! The sandbox contracts run in. A contract is a WebAssembly module with no floats and no start
//! function; it reaches the chain only through the host calls in the `qubits` import module.
//! Everything here is consensus: the same code and input must give the same result, gas
//! included, on every validator, so the interpreter is pinned to an exact version and nothing
//! it says in words goes into a result.
#![forbid(unsafe_code)]

mod host;

use std::fmt;
use std::sync::OnceLock;

use qubits_types::limits::MAX_ARGS_BYTES;
use qubits_types::{Address, Amount, Outcome};
use wasmi::{
    CompilationMode, Config, Engine, Error, Module, Store, StoreLimits, StoreLimitsBuilder,
    TrapCode,
};

/// Gas prices. One gas is about one interpreted instruction. Part of the on-chain format;
/// `tests/gas.rs` in `qubits-execution` measures what each price buys.
pub mod gas {
    /// Crossing into the host at all. No host call is free.
    pub const HOST: u64 = 100;
    /// Starting any run, and reaching for another contract.
    pub const CALL: u64 = 2_000;
    /// Reading the code and translating it, per byte.
    pub const LOAD_BYTE: u64 = 16;
    /// Instantiating a page of 64 KiB of memory.
    pub const PAGE: u64 = 500;
    /// Copying between the contract's memory and the host, per byte.
    pub const COPY_BYTE: u64 = 1;
    /// Priced for a read that misses the cache on a network disk, not for the usual one.
    pub const READ: u64 = 20_000;
    pub const WRITE: u64 = 15_000;
    /// Per byte written to state.
    pub const STATE_BYTE: u64 = 64;
    pub const TRANSFER: u64 = 20_000;
    pub const EVENT: u64 = 500;
    pub const EVENT_BYTE: u64 = 8;
    pub const HASH: u64 = 500;
    pub const VERIFY_ML_DSA: u64 = 100_000;
    pub const VERIFY_SLH_DSA: u64 = 800_000;
}

/// What a single run may hold.
pub mod limits {
    pub const MAX_MEMORY_BYTES: usize = 4 * 1024 * 1024;
    /// Entries in the one table a contract may have. A table this size costs less to set up
    /// than starting a run, so it isn't priced on its own.
    pub const MAX_TABLE_ELEMENTS: usize = 4096;
    pub const MAX_KEY_BYTES: usize = 128;
    pub const MAX_VALUE_BYTES: usize = 16 * 1024;
    pub const MAX_TOPIC_BYTES: usize = 64;
    pub const MAX_EVENT_BYTES: usize = 4 * 1024;
    pub const MAX_OUTPUT_BYTES: usize = super::MAX_ARGS_BYTES;
    pub const MAX_RECURSION: usize = 256;
}

/// The node itself failed: a database error, not anything a contract did. Stops the block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fatal(pub String);

impl fmt::Display for Fatal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Fatal {}

/// What came of a contract calling another. A failed callee has already been undone.
pub struct Called {
    pub ok: bool,
    pub output: Vec<u8>,
    pub gas_left: u64,
}

/// The chain as a contract sees it. `qubits-execution` implements this, with undo.
pub trait Host {
    fn height(&self) -> u64;
    fn timestamp_ms(&self) -> u64;
    fn balance(&mut self, who: &Address) -> Result<Amount, Fatal>;
    fn read(&mut self, contract: &Address, key: &[u8]) -> Result<Option<Vec<u8>>, Fatal>;
    fn write(&mut self, contract: &Address, key: &[u8], value: Option<&[u8]>) -> Result<(), Fatal>;
    /// Only a contract's own balance can leave; returns false if it is too low.
    fn transfer(&mut self, from: &Address, to: &Address, amount: Amount) -> Result<bool, Fatal>;
    fn emit(&mut self, contract: &Address, topic: Vec<u8>, data: Vec<u8>);
    fn call(
        &mut self,
        from: &Address,
        to: &Address,
        function: &str,
        args: &[u8],
        value: Amount,
        gas: u64,
    ) -> Result<Called, Fatal>;
}

pub struct Invocation<'a> {
    pub code: &'a [u8],
    pub function: &'a str,
    pub input: &'a [u8],
    pub contract: Address,
    pub caller: Address,
    pub value: Amount,
    pub gas: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finish {
    pub outcome: Outcome,
    pub output: Vec<u8>,
    pub gas_left: u64,
}

impl Finish {
    /// Ended before anything ran. `gas` is what is left.
    pub fn early(outcome: Outcome, gas: u64) -> Self {
        Finish {
            outcome,
            output: Vec::new(),
            gas_left: gas,
        }
    }
}

/// Why a host call stopped the contract.
#[derive(Debug)]
pub(crate) enum Stop {
    Revert(Vec<u8>),
    OutOfGas,
    /// Broke a limit or handed the host something that makes no sense.
    Misuse,
    Fatal(Fatal),
}

impl fmt::Display for Stop {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl wasmi::errors::HostError for Stop {}

/// One run's view: the contract it is, and the host it reaches through.
pub(crate) struct Frame<'h> {
    pub host: &'h mut dyn Host,
    pub limits: StoreLimits,
    pub contract: Address,
    pub caller: Address,
    pub value: Amount,
    pub input: Vec<u8>,
    pub output: Vec<u8>,
    /// What the last contract called gave back.
    pub result: Vec<u8>,
}

/// Each run gets its own engine: an engine keeps all code it ever translated until it is
/// dropped, so a shared one grows by about 23 KB per call.
fn engine() -> Engine {
    static CONFIG: OnceLock<Config> = OnceLock::new();
    let config = CONFIG.get_or_init(|| {
        let mut config = Config::default();
        config
            .consume_fuel(true)
            .floats(false)
            .allow_start_fn(false)
            .wasm_saturating_float_to_int(false)
            .wasm_multi_memory(false)
            .wasm_tail_call(false)
            .wasm_custom_page_sizes(false)
            .wasm_wide_arithmetic(false)
            .set_max_recursion_depth(limits::MAX_RECURSION)
            .compilation_mode(CompilationMode::Eager);
        config
    });
    Engine::new(config)
}

/// Runs an exported `function` of the code. A contract with no `init` deploys doing nothing.
pub fn run(call: Invocation<'_>, host: &mut dyn Host) -> Result<Finish, Fatal> {
    let Some(mut gas) = call
        .gas
        .checked_sub(gas::CALL + call.code.len() as u64 * gas::LOAD_BYTE)
    else {
        return Ok(Finish::early(Outcome::OutOfGas, 0));
    };
    let engine = engine();
    let Ok(module) = Module::new(&engine, call.code) else {
        return Ok(Finish::early(Outcome::Invalid, 0));
    };
    let frame = Frame {
        host,
        limits: StoreLimitsBuilder::new()
            .memory_size(limits::MAX_MEMORY_BYTES)
            .memories(1)
            .tables(1)
            .table_elements(limits::MAX_TABLE_ELEMENTS)
            .instances(1)
            .build(),
        contract: call.contract,
        caller: call.caller,
        value: call.value,
        input: call.input.to_vec(),
        output: Vec::new(),
        result: Vec::new(),
    };
    let mut store = Store::new(&engine, frame);
    store.limiter(|frame| &mut frame.limits);
    let linker = host::linker(&engine);
    let Ok(instance) = linker
        .instantiate_and_start(&mut store, &module)
        .map_err(|_| ())
    else {
        return Ok(Finish::early(Outcome::Invalid, 0));
    };
    let Some(memory) = instance.get_memory(&store, "memory") else {
        return Ok(Finish::early(Outcome::Invalid, 0));
    };
    let pages = memory.size(&store);
    let Some(left) = gas.checked_sub(pages.saturating_mul(gas::PAGE)) else {
        return Ok(Finish::early(Outcome::OutOfGas, 0));
    };
    gas = left;
    let Ok(function) = instance.get_typed_func::<(), ()>(&store, call.function) else {
        let outcome = if call.function == "init" && instance.get_func(&store, "init").is_none() {
            Outcome::Done
        } else {
            Outcome::Invalid
        };
        return Ok(Finish::early(outcome, gas));
    };
    store
        .set_fuel(gas)
        .expect("the engine meters fuel, and this is the only store using it");
    let result = function.call(&mut store, ());
    let gas_left = store.get_fuel().expect("the engine meters fuel");
    let output = std::mem::take(&mut store.data_mut().output);
    match result {
        Ok(()) => Ok(Finish {
            outcome: Outcome::Done,
            output,
            gas_left,
        }),
        Err(error) => stopped(error, gas_left),
    }
}

fn stopped(mut error: Error, gas_left: u64) -> Result<Finish, Fatal> {
    if error.as_trap_code() == Some(TrapCode::OutOfFuel) {
        return Ok(Finish::early(Outcome::OutOfGas, 0));
    }
    match error.downcast_mut::<Stop>() {
        Some(Stop::Fatal(fatal)) => Err(fatal.clone()),
        Some(Stop::OutOfGas) => Ok(Finish::early(Outcome::OutOfGas, 0)),
        // the one way to stop that hands the unused gas back
        Some(Stop::Revert(reason)) => Ok(Finish::early(
            Outcome::Reverted {
                reason: std::mem::take(reason),
            },
            gas_left,
        )),
        Some(Stop::Misuse) | None => Ok(Finish::early(Outcome::Trapped, 0)),
    }
}
