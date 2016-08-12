extern crate backtrace;
#[macro_use]
extern crate lazy_static;

use std::ffi::{CStr, CString};
use std::mem;
use std::os::raw::{c_char, c_int, c_uint, c_void};
use std::process::Command;
use std::str::FromStr;
use std::sync::{Once, ONCE_INIT};
use std::ptr;

static BFD_INITIALIZED: Once = ONCE_INIT;

#[repr(C)]
struct ResolutionCtx {
    abfd: *mut c_void,
    symtab: *mut c_void,
    section: *mut c_void,
    loadaddr: u64,
    slide: u64,
}
unsafe impl Sync for ResolutionCtx {}

struct ResolutionCtxWrapper {
    inner: ResolutionCtx,
}

impl ResolutionCtxWrapper {
    pub fn new(loadaddr: u64, slide: u64) -> Option<Self> {
        BFD_INITIALIZED.call_once(|| unsafe {bfd_init()});
        let binary_path = unsafe {
            let mut buf = vec![0u8; 1024];
            if get_executable_path((&mut buf).as_mut_ptr(), buf.len()) != 0 {
                return None;
            }
            CStr::from_ptr(buf.as_ptr() as *const i8).to_owned()
        };
        let section_name = CString::new(".text").unwrap();
        unsafe {
            // If we fail below, the destructor will run on zero'd memory, but that should be fine
            let mut me: ResolutionCtx = mem::zeroed();
            if stoa2_initialize(binary_path.as_ptr(), section_name.as_ptr(), loadaddr, slide, &mut me) != 0 {
                return None;
            }
            Some(ResolutionCtxWrapper {inner: me})
        }
    }

    fn resolve(&self, ptr: *const c_void) -> Option<(String, u32)> {
        unsafe {
            let mut filename: *mut c_char = ptr::null_mut();
            let mut functionname: *mut c_char = ptr::null_mut();
            let mut lineno: usize = 0;
            if stoa2_resolve(&self.inner, ptr as u64, &mut filename, &mut functionname, &mut lineno) != 0 {
                return None;
            }
            let filename_s = CStr::from_ptr(filename).to_string_lossy().into_owned();
            let functionname_s = CStr::from_ptr(functionname).to_string_lossy().into_owned();
            return Some((filename_s, lineno as u32));
        }
    }
}

impl Drop for ResolutionCtxWrapper {
    fn drop(&mut self) {
        unsafe {stoa2_destroy(&mut self.inner)};
    }
}

lazy_static! {
    static ref CTX: ResolutionCtxWrapper = unsafe {ResolutionCtxWrapper::new(load_address(), addr_slide())}.unwrap();
}


#[derive(PartialEq, Debug)]
pub struct StackFrame {
    pub filename: String,
    pub lineno: u64,
    pub sym: String,
}

#[derive(Debug)]
pub struct Traceback {
    pub frames: Vec<StackFrame>,
}

fn stoa_resolve(ptr: *const c_void) -> Option<(String, u32)> {
    let hex_ptr = format!("{:?}", ptr);
    // TODO: cache this since it doesn't change (?)
    let loadaddr = unsafe {load_address()};
    let hex_loadaddr = format!("{:#X}", loadaddr);
    // TODO: cache this too
    let binary_path = unsafe {
        let mut buf = vec![0u8; 1024];
        let code = get_executable_path((&mut buf).as_mut_ptr(), buf.len());
        if code != 0 {
            panic!("_NSGetExecutablePath failed");
        }
        CStr::from_ptr(buf.as_ptr() as *const c_char).to_string_lossy().into_owned()
    };

    // TODO: reverse engineer this so we don't have to fork...
    let output = Command::new("atos")
        .arg("-o").arg(binary_path)
        .arg("-l").arg(hex_loadaddr)
        .arg(hex_ptr)
        .output()
        .expect("atos failed");

    // ...and do all this ridiculous parsing
    let out = String::from_utf8_lossy(&output.stdout);
    let pieces: Vec<_> = out.trim().split('(').collect();
    if pieces.len() != 3 {
        return None;
    }
    let last_piece = pieces[2].trim_matches(')');
    let filename_lineno: Vec<_> = last_piece.split(':').collect();
    if filename_lineno.len() != 2 {
        return None;
    }

    if let Ok(lineno) = FromStr::from_str(filename_lineno[1]) {
        Some((filename_lineno[0].to_owned(), lineno))
    } else {
        None
    }
}

pub fn get_da_traceback() -> Traceback {
    let mut frames = Vec::new();
    backtrace::trace(|frame: &backtrace::Frame| {
        println!("Resolving {:#X}...", frame.ip() as u64);
        println!("stoa:  {:?}", stoa_resolve(frame.ip()));
        println!("stoa3: {:?}", CTX.resolve(frame.ip()));
        println!("");
        return true;
    });
    Traceback { frames: frames }
}

#[link(name="loadaddress")]
extern "C" {
    fn base_address() -> u64;
    fn load_address() -> u64;
    fn addr_slide() -> u64;
    fn get_executable_path(buf: *mut u8, buflen: usize) -> c_int;
}

#[link(name="stoa2")]
extern "C" {
    fn stoa2_initialize(binary_path: *const c_char, section_name: *const c_char, loadaddr: u64, slide: u64, out: *mut ResolutionCtx) -> c_int;
    fn stoa2_resolve(ctx: *const ResolutionCtx, addr: u64, filename: *mut *mut c_char, functionname: *mut *mut c_char, lineno: *mut usize) -> c_int;
    fn stoa2_destroy(ctx: *mut ResolutionCtx);
}

#[link(name="bfd")]
extern "C" {
    fn bfd_init();
}

fn main() {
    let ref ctx = *CTX;
    get_da_traceback();
}
