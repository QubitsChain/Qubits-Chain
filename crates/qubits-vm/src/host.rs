//! The host calls: all a contract can do besides compute. Each charges for what it costs before
//! doing it, so anything it allocates is bounded by the gas already paid.

use qubits_crypto::{Domain, PublicKey, SchemeId, Signature};
use qubits_types::{Address, Amount, contract_hash};
use wasmi::{Caller, Engine, Error, Extern, Linker, Memory};

use crate::{Fatal, Frame, Stop, gas, limits};

type Ctx<'a, 'h> = Caller<'a, Frame<'h>>;
type Host<T> = Result<T, Error>;

fn stop(reason: Stop) -> Error {
    Error::host(reason)
}

fn fatal(error: Fatal) -> Error {
    stop(Stop::Fatal(error))
}

fn charge(ctx: &mut Ctx<'_, '_>, cost: u64) -> Host<()> {
    let fuel = ctx.get_fuel()?;
    match fuel.checked_sub(cost) {
        Some(left) => ctx.set_fuel(left),
        None => {
            ctx.set_fuel(0)?;
            Err(stop(Stop::OutOfGas))
        }
    }
}

fn memory(ctx: &Ctx<'_, '_>) -> Host<Memory> {
    match ctx.get_export("memory") {
        Some(Extern::Memory(memory)) => Ok(memory),
        _ => Err(stop(Stop::Misuse)),
    }
}

fn load(ctx: &mut Ctx<'_, '_>, ptr: u32, len: u32, max: usize) -> Host<Vec<u8>> {
    let len = len as usize;
    if len > max {
        return Err(stop(Stop::Misuse));
    }
    charge(ctx, gas::HOST + len as u64 * gas::COPY_BYTE)?;
    let memory = memory(ctx)?;
    let mut bytes = vec![0; len];
    memory
        .read(&*ctx, ptr as usize, &mut bytes)
        .map_err(|_| stop(Stop::Misuse))?;
    Ok(bytes)
}

fn store(ctx: &mut Ctx<'_, '_>, ptr: u32, bytes: &[u8]) -> Host<()> {
    charge(ctx, gas::HOST + bytes.len() as u64 * gas::COPY_BYTE)?;
    let memory = memory(ctx)?;
    memory
        .write(&mut *ctx, ptr as usize, bytes)
        .map_err(|_| stop(Stop::Misuse))
}

fn load_address(ctx: &mut Ctx<'_, '_>, ptr: u32) -> Host<Address> {
    let bytes = load(ctx, ptr, 32, 32)?;
    Ok(Address(bytes.try_into().expect("read 32 bytes")))
}

fn load_amount(ctx: &mut Ctx<'_, '_>, ptr: u32) -> Host<Amount> {
    let bytes = load(ctx, ptr, 16, 16)?;
    Ok(Amount::from_le_bytes(
        bytes.try_into().expect("read 16 bytes"),
    ))
}

fn input_size(mut ctx: Ctx<'_, '_>) -> Host<u32> {
    charge(&mut ctx, gas::HOST)?;
    Ok(ctx.data().input.len() as u32)
}

fn input(mut ctx: Ctx<'_, '_>, ptr: u32) -> Host<()> {
    let bytes = std::mem::take(&mut ctx.data_mut().input);
    let stored = store(&mut ctx, ptr, &bytes);
    ctx.data_mut().input = bytes;
    stored
}

fn output(mut ctx: Ctx<'_, '_>, ptr: u32, len: u32) -> Host<()> {
    let bytes = load(&mut ctx, ptr, len, limits::MAX_OUTPUT_BYTES)?;
    ctx.data_mut().output = bytes;
    Ok(())
}

fn revert(mut ctx: Ctx<'_, '_>, ptr: u32, len: u32) -> Host<()> {
    let reason = load(&mut ctx, ptr, len, limits::MAX_TOPIC_BYTES * 4)?;
    Err(stop(Stop::Revert(reason)))
}

fn caller(mut ctx: Ctx<'_, '_>, ptr: u32) -> Host<()> {
    let address = ctx.data().caller;
    store(&mut ctx, ptr, address.as_bytes())
}

fn this(mut ctx: Ctx<'_, '_>, ptr: u32) -> Host<()> {
    let address = ctx.data().contract;
    store(&mut ctx, ptr, address.as_bytes())
}

fn value(mut ctx: Ctx<'_, '_>, ptr: u32) -> Host<()> {
    let amount = ctx.data().value;
    store(&mut ctx, ptr, &amount.to_le_bytes())
}

fn height(mut ctx: Ctx<'_, '_>) -> Host<u64> {
    charge(&mut ctx, gas::HOST)?;
    Ok(ctx.data().host.height())
}

fn timestamp_ms(mut ctx: Ctx<'_, '_>) -> Host<u64> {
    charge(&mut ctx, gas::HOST)?;
    Ok(ctx.data().host.timestamp_ms())
}

fn balance(mut ctx: Ctx<'_, '_>, who: u32, out: u32) -> Host<()> {
    charge(&mut ctx, gas::READ)?;
    let who = load_address(&mut ctx, who)?;
    let amount = ctx.data_mut().host.balance(&who).map_err(fatal)?;
    store(&mut ctx, out, &amount.to_le_bytes())
}

/// Returns -1 for no value, or the value's length; at most `cap` bytes of it are copied.
fn get(mut ctx: Ctx<'_, '_>, key: u32, key_len: u32, out: u32, cap: u32) -> Host<i32> {
    charge(&mut ctx, gas::READ)?;
    let key = load(&mut ctx, key, key_len, limits::MAX_KEY_BYTES)?;
    let frame = ctx.data_mut();
    let contract = frame.contract;
    let Some(value) = frame.host.read(&contract, &key).map_err(fatal)? else {
        return Ok(-1);
    };
    let copied = value.len().min(cap as usize);
    store(&mut ctx, out, &value[..copied])?;
    Ok(value.len() as i32)
}

fn set(mut ctx: Ctx<'_, '_>, key: u32, key_len: u32, value: u32, value_len: u32) -> Host<()> {
    let bytes = u64::from(key_len) + u64::from(value_len);
    let cost = gas::WRITE.saturating_add(bytes.saturating_mul(gas::STATE_BYTE));
    charge(&mut ctx, cost)?;
    let key = load(&mut ctx, key, key_len, limits::MAX_KEY_BYTES)?;
    let value = load(&mut ctx, value, value_len, limits::MAX_VALUE_BYTES)?;
    let frame = ctx.data_mut();
    let contract = frame.contract;
    frame
        .host
        .write(&contract, &key, Some(&value))
        .map_err(fatal)
}

fn del(mut ctx: Ctx<'_, '_>, key: u32, key_len: u32) -> Host<()> {
    charge(&mut ctx, gas::WRITE)?;
    let key = load(&mut ctx, key, key_len, limits::MAX_KEY_BYTES)?;
    let frame = ctx.data_mut();
    let contract = frame.contract;
    frame.host.write(&contract, &key, None).map_err(fatal)
}

/// From this contract's own balance. Returns 0 if it went, 1 if the balance is too low.
fn transfer(mut ctx: Ctx<'_, '_>, to: u32, amount: u32) -> Host<u32> {
    charge(&mut ctx, gas::TRANSFER)?;
    let to = load_address(&mut ctx, to)?;
    let amount = load_amount(&mut ctx, amount)?;
    let frame = ctx.data_mut();
    let from = frame.contract;
    let moved = frame.host.transfer(&from, &to, amount).map_err(fatal)?;
    Ok(u32::from(!moved))
}

fn emit(mut ctx: Ctx<'_, '_>, topic: u32, topic_len: u32, data: u32, data_len: u32) -> Host<()> {
    let bytes = u64::from(topic_len) + u64::from(data_len);
    let cost = gas::EVENT.saturating_add(bytes.saturating_mul(gas::EVENT_BYTE));
    charge(&mut ctx, cost)?;
    let topic = load(&mut ctx, topic, topic_len, limits::MAX_TOPIC_BYTES)?;
    let data = load(&mut ctx, data, data_len, limits::MAX_EVENT_BYTES)?;
    let frame = ctx.data_mut();
    let contract = frame.contract;
    frame.host.emit(&contract, topic, data);
    Ok(())
}

/// Calls another contract with all the gas left. Returns 0 if it finished, 1 if it failed, in
/// which case everything it did is undone. Its output is at `result`.
#[allow(clippy::too_many_arguments)]
fn call(
    mut ctx: Ctx<'_, '_>,
    to: u32,
    name: u32,
    name_len: u32,
    args: u32,
    args_len: u32,
    value: u32,
) -> Host<u32> {
    // finding the callee and its code is two reads, whether or not they find anything
    charge(&mut ctx, gas::CALL + 2 * gas::READ)?;
    let to = load_address(&mut ctx, to)?;
    let max = qubits_types::limits::MAX_FUNCTION_NAME;
    let name = load(&mut ctx, name, name_len, max)?;
    let name = String::from_utf8(name).map_err(|_| stop(Stop::Misuse))?;
    let args = load(
        &mut ctx,
        args,
        args_len,
        qubits_types::limits::MAX_ARGS_BYTES,
    )?;
    let value = load_amount(&mut ctx, value)?;
    let gas = ctx.get_fuel()?;
    let frame = ctx.data_mut();
    let from = frame.contract;
    let called = frame
        .host
        .call(&from, &to, &name, &args, value, gas)
        .map_err(fatal)?;
    frame.result = called.output;
    ctx.set_fuel(called.gas_left)?;
    Ok(u32::from(!called.ok))
}

fn result_size(mut ctx: Ctx<'_, '_>) -> Host<u32> {
    charge(&mut ctx, gas::HOST)?;
    Ok(ctx.data().result.len() as u32)
}

fn result(mut ctx: Ctx<'_, '_>, ptr: u32) -> Host<()> {
    let bytes = std::mem::take(&mut ctx.data_mut().result);
    let stored = store(&mut ctx, ptr, &bytes);
    ctx.data_mut().result = bytes;
    stored
}

fn hash(mut ctx: Ctx<'_, '_>, ptr: u32, len: u32, out: u32) -> Host<()> {
    charge(&mut ctx, gas::HASH)?;
    let bytes = load(&mut ctx, ptr, len, limits::MAX_VALUE_BYTES)?;
    let digest = contract_hash(&bytes);
    store(&mut ctx, out, &digest.0)
}

/// Checks a post-quantum signature made with `qubits sign`: scheme 1 is ML-DSA-65, 2 is
/// SLH-DSA-SHA2-192s. Returns 0 if it is good, 1 if not.
#[allow(clippy::too_many_arguments)]
fn verify(
    mut ctx: Ctx<'_, '_>,
    scheme: u32,
    key: u32,
    key_len: u32,
    msg: u32,
    msg_len: u32,
    sig: u32,
    sig_len: u32,
) -> Host<u32> {
    let (scheme, cost) = match scheme {
        1 => (SchemeId::MlDsa65, gas::VERIFY_ML_DSA),
        2 => (SchemeId::SlhDsaSha2_192s, gas::VERIFY_SLH_DSA),
        _ => return Err(stop(Stop::Misuse)),
    };
    charge(&mut ctx, cost)?;
    let key = load(&mut ctx, key, key_len, scheme.public_key_len())?;
    let msg = load(&mut ctx, msg, msg_len, limits::MAX_VALUE_BYTES)?;
    let sig = load(&mut ctx, sig, sig_len, scheme.signature_len())?;
    let good = PublicKey::from_raw(scheme, &key)
        .and_then(|key| {
            let sig = Signature::from_raw(scheme, &sig)?;
            key.verify(Domain::Message, &msg, &sig)
        })
        .is_ok();
    Ok(u32::from(!good))
}

pub(crate) fn linker<'h>(engine: &Engine) -> Linker<Frame<'h>> {
    let mut linker = Linker::new(engine);
    let module = "qubits";
    macro_rules! provide {
        ($($name:literal => $function:ident),* $(,)?) => {
            $(linker
                .func_wrap(module, $name, $function)
                .expect("each name is provided once");)*
        };
    }
    provide!(
        "input_size" => input_size,
        "input" => input,
        "output" => output,
        "revert" => revert,
        "caller" => caller,
        "self" => this,
        "value" => value,
        "height" => height,
        "timestamp_ms" => timestamp_ms,
        "balance" => balance,
        "get" => get,
        "set" => set,
        "del" => del,
        "transfer" => transfer,
        "emit" => emit,
        "call" => call,
        "result_size" => result_size,
        "result" => result,
        "hash" => hash,
        "verify" => verify,
    );
    linker
}
