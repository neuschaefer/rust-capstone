#![crate_name="capstone"]
#![crate_type="rlib"]

#![feature(int_uint, libc, core, rustc_private)]

extern crate libc;
extern crate core;
extern crate serialize;

#[macro_use] extern crate bitflags;

use libc::{c_int, c_void, size_t};
use std::ffi::CStr;
use std::{slice, str};

mod ll;

#[cfg(test)]
mod tests;

#[derive(Debug, Copy)]
pub enum Arch {
    Arm = 0,
    Arm64,
    MIPS,
    X86,
    PowerPC,
    Sparc,
    SystemZ,
    XCore,
}

bitflags!(
    #[derive(Debug)]
    flags Mode: u32 {
        const MODE_LITTLE_ENDIAN= 0,
        const MODE_ARM          = 0,
        const MODE_16           = 1 << 1,
        const MODE_32           = 1 << 2,
        const MODE_64           = 1 << 3,
        const MODE_THUMB        = 1 << 4,
        const MODE_MCLASS       = 1 << 5,
        const MODE_V8           = 1 << 6,
        const MODE_MICRO        = 1 << 4,
        const MODE_MIPS3        = 1 << 5,
        const MODE_MIPS32R6     = 1 << 6,
        const MODE_MIPSGP64     = 1 << 7,
        const MODE_V9           = 1 << 4,
        const MODE_BIG_ENDIAN   = 1 << 31,
        const MODE_MIPS32       = 1 << 2,
        const MODE_MIPS64       = 1 << 3,
    }
);

#[derive(Debug, Copy)]
pub enum Opt {
    Syntax = 1,
    Detail,
    Mode,
    // OptMem
}

#[derive(Debug)]
pub struct Error {
    pub code: uint,
    pub desc: Option<String>,
}

impl Error {
    fn new(err: uint) -> Error {
        let desc_cstr = unsafe { CStr::from_ptr(ll::cs_strerror(err as i32)) };
        Error{
            code: err,
            desc: str::from_utf8(desc_cstr.to_bytes())
                    .ok().map(|s| s.to_string())
        }
    }
}

pub struct Insn {
    pub addr: u64,
    pub bytes: Vec<u8>,
    pub mnemonic: String,
    pub op_str: String,
    //pub detail: Option<Detail>,
}

unsafe fn make_string(buf: &[u8]) -> String {
    str::from_utf8(buf)
        .unwrap_or("<invalid UTF-8>")
        .to_string()
}

impl Insn {
    pub unsafe fn new(ci: &ll::cs_insn) -> Insn {
        Insn {
            addr:     ci.address,
            bytes:    ci.bytes[0..ci.size as usize].to_vec(),
            mnemonic: make_string(&ci.mnemonic),
            op_str:   make_string(&ci.op_str),
            //detail:   None
        }
    }
}

pub struct Detail;

pub struct Engine {
    handle: *const c_void
}

impl Engine {
    pub fn new(arch: Arch, mode: Mode) -> Result<Engine, Error> {
        let mut handle : *const c_void = 0 as *const c_void;
        unsafe {
            match ll::cs_open(arch as c_int, mode.bits as c_int, &mut handle) {
                0 => Ok(Engine{handle: handle}),
                e => Err(Error::new(e as uint)),
            }
        }
    }

    pub fn set_option(&self, option: Opt, value: uint) -> Result<(), Error> {
        unsafe {
            match ll::cs_option(self.handle, option as c_int, value as size_t) {
                0 => Ok(()),
                e => Err(Error::new(e as uint)),
            }
        }
    }

    pub fn disasm(&self, code: &[u8], addr: u64, count: uint) -> Result<Vec<Insn>, Error> {
        unsafe {
            let mut cinsn : *mut ll::cs_insn = 0 as *mut ll::cs_insn;
            match ll::cs_disasm(self.handle, code.as_ptr(), code.len() as size_t, addr, count as size_t, &mut cinsn) {
                0 => Err(Error::new(self.errno())),
                n => {
//                  let mut v = Vec::with_capacity(n as uint);
//                  v.extend(CVec::new(cinsn, n as uint).as_slice().iter().map(
//                      |ci| Insn::new(ci)
//                  ));

                    let v = slice::from_raw_parts(cinsn, n as usize)
                        .iter().map(|ci| Insn::new(ci)).collect();

                    ll::cs_free(cinsn, n);
                    Ok(v)
                },
            }
        }
    }

    fn errno(&self) -> uint {
        unsafe{ ll::cs_errno(self.handle) as uint }
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        unsafe{ ll::cs_close(&mut self.handle) };
    }
}

pub fn version() -> (int, int) {
    let mut major : c_int = 0;
    let mut minor : c_int = 0;
    unsafe{ ll::cs_version(&mut major, &mut minor);}
    (major as int, minor as int)
}

pub fn supports(arch: Arch) -> bool {
    unsafe{ ll::cs_support(arch as c_int) == 0 }
}
