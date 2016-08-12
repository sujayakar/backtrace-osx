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
}
unsafe impl Sync for ResolutionCtx {}

struct ResolutionCtxWrapper {
    inner: ResolutionCtx,
}

impl ResolutionCtxWrapper {
    pub fn new() -> Option<Self> {
        BFD_INITIALIZED.call_once(|| unsafe {bfd_init()});
        let binary_path = unsafe {
            let mut buf = vec![0u8; 1024];
            if get_executable_path((&mut buf).as_mut_ptr(), buf.len()) != 0 {
                return None;
            }
            CStr::from_ptr(buf.as_ptr() as *const i8).to_owned()
        };
        let section_name = CString::new(".text").unwrap();
        let loadaddr = unsafe {load_address()};
        println!("Load address: {:#X}", loadaddr);
        unsafe {
            // If we fail below, the destructor will run on zero'd memory, but that should be fine
            let mut me: ResolutionCtx = mem::zeroed();
            if stoa2_initialize(binary_path.as_ptr(), section_name.as_ptr(), loadaddr, &mut me) != 0 {
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
            println!("function: {}", functionname_s);
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
    static ref CTX: ResolutionCtxWrapper = ResolutionCtxWrapper::new().unwrap();
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

fn resolve2(ptr: *const c_void) -> Option<(String, u32)> {
    unsafe {
        let loadaddr = load_address();

        let mut buf = vec![0u8; 1024];
        if get_executable_path(buf.as_mut_ptr(), buf.len()) != 0 {
            panic!("_NSGetExecutablePath failed");
        }
        let binary_path = CStr::from_ptr(buf.as_ptr() as *const c_char);

        let mut filename: *mut c_char = ptr::null_mut();
        let mut functionname: *mut c_char = ptr::null_mut();
        let mut lineno: usize = 0;
        let found = stoa2_resolve2(binary_path.as_ptr(), ptr as u64, loadaddr,
                                   &mut filename, &mut functionname, &mut lineno);
        if found == 0 {
            return None;
        }
        let functionname_s = CStr::from_ptr(functionname).to_string_lossy().into_owned();
        println!("function: {}", functionname_s);

        let filename_s = CStr::from_ptr(filename).to_string_lossy().into_owned();
        return Some((filename_s, lineno as u32));
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
        // backtrace::resolve(frame.ip(), |symbol: &backtrace::Symbol| {
        //     // println!("name: {:?}", symbol.name());
        //     // println!("addr: {:?}", symbol.addr());
        //     // println!("filename: {:?}", symbol.filename());
        //     // println!("lineno: {:?}", symbol.lineno());

        //     let name = match symbol.name() {
        //         None => return,
        //         Some(n) => n.as_str().unwrap().to_owned(),
        //     };
        //     let filename = match symbol.filename() {
        //         None => return,
        //         Some(f) => f.to_owned(),
        //     };
        //     let lineno = match symbol.lineno() {
        //         None => return,
        //         Some(lineno) => lineno,
        //     };
        //     let frame = StackFrame {
        //         filename: filename.to_string_lossy().into_owned(),
        //         lineno: lineno as u64,
        //         sym: name,
        //     };
        //     frames.push(frame);
        // });
        true
    });
    Traceback { frames: frames }
}

#[link(name="loadaddress")]
extern "C" {
    fn load_address() -> u64;
    fn get_executable_path(buf: *mut u8, buflen: usize) -> c_int;
}

#[link(name="stoa2")]
extern "C" {
    fn stoa2_resolve2(binary_path: *const c_char, addr: u64, loadaddr: u64, filename: *mut *mut c_char, functionname: *mut *mut c_char, lineno: *mut usize) -> c_int;

    fn stoa2_initialize(binary_path: *const c_char, section_name: *const c_char, loadaddr: u64, out: *mut ResolutionCtx) -> c_int;
    fn stoa2_resolve(ctx: *const ResolutionCtx, addr: u64, filename: *mut *mut c_char, functionname: *mut *mut c_char, lineno: *mut usize) -> c_int;
    fn stoa2_destroy(ctx: *mut ResolutionCtx);
}

// #[repr(C)]
// struct bfd;

// #[repr(C)]
// struct asection;

// #[repr(C)]
// struct asymbol;

#[link(name="bfd")]
extern "C" {
    fn bfd_init();
}
//     fn bfd_openr(filename: *const c_char, target: *const c_char) -> *mut bfd;
//     fn bfd_get_section_by_name(bfd: *mut bfd, name: *const c_char) -> *mut asection;
//     fn bfd_close(bfd: *mut bfd);

//     // macros
//     // bfd_get_file_flags



//     fn bfd_mach_o_find_nearest_line(
//         bfd: *mut bfd,
//         symbols: *mut *mut asymbol,
//         section: *mut asection,
//         filename: *const *mut c_char,
//         functionname: *const *mut c_char,
//         line: *mut c_uint,
//         discriminator: *mut c_uint) -> c_int;
// }

fn main() {
    let ref ctx = *CTX;
    get_da_traceback();
    // bfd_init()
    // bfd_openr() -> *bfd;
    // bfd_get_section_by_name() -> *asection;

    // to get **asymbol (symbol table)... (no dynamic?)
    //     bfd_get_file_flags() & HAS_SYMS
    //     bfd_get_symtab_upper_bound()
    //     bfd_canonicalize_symtab()
    //     https://github.com/bminor/binutils-gdb/blob/master/binutils/addr2line.c#L107

    // open bfd  -> abfd
    // get section

    // println!("fak: {}", unsafe{bfd_mach_o_find_nearest_line()});
}
