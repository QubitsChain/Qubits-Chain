//! What a Qubits contract is written with. A contract is a `no_std` crate that exports one
//! `extern "C" fn()` per function; `init` runs once, at deployment. Arguments are concatenated
//! values: an address is 32 bytes, a `u128` 16 and a `u64` 8, little-endian, and bytes carry a
//! `u32` length in front. There are no floats on this chain. A panic reverts.
#![no_std]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

pub type Address = [u8; 32];

pub const NOBODY: Address = [0; 32];

mod sys {
    #[link(wasm_import_module = "qubits")]
    unsafe extern "C" {
        pub fn input_size() -> u32;
        pub fn input(ptr: *mut u8);
        pub fn output(ptr: *const u8, len: u32);
        pub fn revert(ptr: *const u8, len: u32) -> !;
        pub fn caller(ptr: *mut u8);
        #[link_name = "self"]
        pub fn this(ptr: *mut u8);
        pub fn value(ptr: *mut u8);
        pub fn height() -> u64;
        pub fn timestamp_ms() -> u64;
        pub fn balance(who: *const u8, out: *mut u8);
        pub fn get(key: *const u8, key_len: u32, out: *mut u8, cap: u32) -> i32;
        pub fn set(key: *const u8, key_len: u32, value: *const u8, value_len: u32);
        pub fn del(key: *const u8, key_len: u32);
        pub fn transfer(to: *const u8, amount: *const u8) -> u32;
        pub fn emit(topic: *const u8, topic_len: u32, data: *const u8, data_len: u32);
        pub fn call(
            to: *const u8,
            name: *const u8,
            name_len: u32,
            args: *const u8,
            args_len: u32,
            value: *const u8,
        ) -> u32;
        pub fn create(
            code: *const u8,
            args: *const u8,
            args_len: u32,
            value: *const u8,
            out: *mut u8,
        ) -> u32;
        pub fn result_size() -> u32;
        pub fn result(ptr: *mut u8);
        pub fn hash(ptr: *const u8, len: u32, out: *mut u8);
        pub fn verify(
            scheme: u32,
            key: *const u8,
            key_len: u32,
            msg: *const u8,
            msg_len: u32,
            sig: *const u8,
            sig_len: u32,
        ) -> u32;
    }
}

/// Stops here and undoes everything this call did. Unused gas goes back.
pub fn revert(reason: &str) -> ! {
    unsafe { sys::revert(reason.as_ptr(), reason.len() as u32) }
}

pub fn require(condition: bool, reason: &str) {
    if !condition {
        revert(reason);
    }
}

/// The arguments of this call, read in order.
pub struct Args {
    bytes: Vec<u8>,
    at: usize,
}

pub fn args() -> Args {
    let mut bytes = vec![0; unsafe { sys::input_size() } as usize];
    unsafe { sys::input(bytes.as_mut_ptr()) };
    Args { bytes, at: 0 }
}

impl Args {
    /// Reads stored values the same way.
    pub fn over(bytes: Vec<u8>) -> Args {
        Args { bytes, at: 0 }
    }

    fn take(&mut self, len: usize) -> &[u8] {
        let end = self.at.checked_add(len);
        let Some(part) = end.and_then(|end| self.bytes.get(self.at..end)) else {
            revert("missing arguments");
        };
        self.at += len;
        part
    }

    pub fn address(&mut self) -> Address {
        self.take(32).try_into().expect("took 32")
    }

    pub fn u128(&mut self) -> u128 {
        u128::from_le_bytes(self.take(16).try_into().expect("took 16"))
    }

    pub fn u64(&mut self) -> u64 {
        u64::from_le_bytes(self.take(8).try_into().expect("took 8"))
    }

    pub fn bytes(&mut self) -> Vec<u8> {
        let len = u32::from_le_bytes(self.take(4).try_into().expect("took 4"));
        self.take(len as usize).to_vec()
    }
}

/// Values in the order a function reads them.
pub fn pack(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

pub fn finish(output: &[u8]) {
    unsafe { sys::output(output.as_ptr(), output.len() as u32) }
}

pub fn finish_u128(value: u128) {
    finish(&value.to_le_bytes());
}

pub fn caller() -> Address {
    let mut address = NOBODY;
    unsafe { sys::caller(address.as_mut_ptr()) };
    address
}

/// This contract's own address.
pub fn this() -> Address {
    let mut address = NOBODY;
    unsafe { sys::this(address.as_mut_ptr()) };
    address
}

/// The native tokens that came with this call. They are already in this contract's balance.
pub fn value() -> u128 {
    let mut bytes = [0; 16];
    unsafe { sys::value(bytes.as_mut_ptr()) };
    u128::from_le_bytes(bytes)
}

pub fn height() -> u64 {
    unsafe { sys::height() }
}

/// The block's time. Validators agree on it to within seconds, so don't lean on seconds.
pub fn now_ms() -> u64 {
    unsafe { sys::timestamp_ms() }
}

pub fn balance(who: &Address) -> u128 {
    let mut bytes = [0; 16];
    unsafe { sys::balance(who.as_ptr(), bytes.as_mut_ptr()) };
    u128::from_le_bytes(bytes)
}

pub fn get(key: &[u8]) -> Option<Vec<u8>> {
    let mut value = vec![0; 64];
    let len = unsafe { sys::get(key.as_ptr(), key.len() as u32, value.as_mut_ptr(), 64) };
    let len = usize::try_from(len).ok()?;
    if len > value.len() {
        value.resize(len, 0);
        unsafe {
            sys::get(
                key.as_ptr(),
                key.len() as u32,
                value.as_mut_ptr(),
                len as u32,
            )
        };
    }
    value.truncate(len);
    Some(value)
}

pub fn set(key: &[u8], value: &[u8]) {
    unsafe {
        sys::set(
            key.as_ptr(),
            key.len() as u32,
            value.as_ptr(),
            value.len() as u32,
        )
    }
}

pub fn del(key: &[u8]) {
    unsafe { sys::del(key.as_ptr(), key.len() as u32) }
}

pub fn get_u128(key: &[u8]) -> u128 {
    match get(key) {
        Some(value) => u128::from_le_bytes(value.try_into().expect("stored as 16 bytes")),
        None => 0,
    }
}

/// Zero isn't kept: state is paid for by the byte, and a missing key already reads as zero.
pub fn set_u128(key: &[u8], value: u128) {
    if value == 0 {
        del(key);
    } else {
        set(key, &value.to_le_bytes());
    }
}

/// Sends native tokens from this contract. False if it doesn't have them.
pub fn pay(to: &Address, amount: u128) -> bool {
    let amount = amount.to_le_bytes();
    unsafe { sys::transfer(to.as_ptr(), amount.as_ptr()) == 0 }
}

pub fn emit(topic: &str, data: &[u8]) {
    unsafe {
        sys::emit(
            topic.as_ptr(),
            topic.len() as u32,
            data.as_ptr(),
            data.len() as u32,
        )
    }
}

/// What `call` gives back when the callee failed.
#[derive(Debug)]
pub struct CallFailed;

/// `contract.function(args)`. If it fails, all it did is undone and this returns `Err`. A
/// contract already running can't be called again, so a callee can't come back in here.
pub fn call(
    contract: &Address,
    function: &str,
    args: &[u8],
    value: u128,
) -> Result<Vec<u8>, CallFailed> {
    let value = value.to_le_bytes();
    let failed = unsafe {
        sys::call(
            contract.as_ptr(),
            function.as_ptr(),
            function.len() as u32,
            args.as_ptr(),
            args.len() as u32,
            value.as_ptr(),
        )
    };
    if failed != 0 {
        return Err(CallFailed);
    }
    let mut output = vec![0; unsafe { sys::result_size() } as usize];
    unsafe { sys::result(output.as_mut_ptr()) };
    Ok(output)
}

/// A new contract running `code`, the hash of code already on chain, with this contract as its
/// deployer: its `init` gets `args` and `value`. If `init` fails, nothing of it stays.
pub fn create(code: &[u8; 32], args: &[u8], value: u128) -> Result<Address, CallFailed> {
    let value = value.to_le_bytes();
    let mut address = NOBODY;
    let failed = unsafe {
        sys::create(
            code.as_ptr(),
            args.as_ptr(),
            args.len() as u32,
            value.as_ptr(),
            address.as_mut_ptr(),
        )
    };
    if failed != 0 {
        return Err(CallFailed);
    }
    Ok(address)
}

pub fn hash(data: &[u8]) -> [u8; 32] {
    let mut digest = [0; 32];
    unsafe { sys::hash(data.as_ptr(), data.len() as u32, digest.as_mut_ptr()) };
    digest
}

pub enum Scheme {
    MlDsa65 = 1,
    SlhDsaSha2_192s = 2,
}

/// True if `signature` over `message` was made by `key`, as `qubits sign` makes them.
pub fn verify(scheme: Scheme, key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let failed = unsafe {
        sys::verify(
            scheme as u32,
            key.as_ptr(),
            key.len() as u32,
            message.as_ptr(),
            message.len() as u32,
            signature.as_ptr(),
            signature.len() as u32,
        )
    };
    failed == 0
}

#[cfg(target_arch = "wasm32")]
mod runtime {
    use core::alloc::{GlobalAlloc, Layout};
    use core::cell::UnsafeCell;

    const PAGE: usize = 64 * 1024;

    unsafe extern "C" {
        static __heap_base: u8;
    }

    /// A run is short and pays for memory by the page, so nothing is ever given back.
    struct Bump {
        next: UnsafeCell<usize>,
    }

    // contracts have one thread
    unsafe impl Sync for Bump {}

    unsafe impl GlobalAlloc for Bump {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            let next = unsafe { &mut *self.next.get() };
            if *next == 0 {
                *next = &raw const __heap_base as usize;
            }
            let start = next.next_multiple_of(layout.align());
            let end = start + layout.size();
            let have = core::arch::wasm32::memory_size(0) * PAGE;
            if end > have {
                let pages = (end - have).div_ceil(PAGE);
                if core::arch::wasm32::memory_grow(0, pages) == usize::MAX {
                    return core::ptr::null_mut();
                }
            }
            *next = end;
            start as *mut u8
        }

        unsafe fn dealloc(&self, _: *mut u8, _: Layout) {}
    }

    #[global_allocator]
    static ALLOCATOR: Bump = Bump {
        next: UnsafeCell::new(0),
    };

    #[panic_handler]
    fn panic(_: &core::panic::PanicInfo) -> ! {
        crate::revert("panic")
    }
}
