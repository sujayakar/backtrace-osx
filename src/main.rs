extern crate backtrace;

use std::ffi::CStr;
use std::os::raw::{c_char, c_int, c_void};
use std::process::Command;
use std::str::FromStr;

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
    let hex_loadaddr = format!("{:#X}", unsafe {load_address()});

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


pub fn get() -> Traceback {
    let mut frames = Vec::new();
    backtrace::trace(|frame: &backtrace::Frame| {
        println!("stoa: {:?}", stoa_resolve(frame.ip()));
	backtrace::resolve(frame.ip(), |symbol: &backtrace::Symbol| {
	    println!("name: {:?}", symbol.name());
	    println!("addr: {:?}", symbol.addr());
	    println!("filename: {:?}", symbol.filename());
	    println!("lineno: {:?}", symbol.lineno());
	    
	    let name = match symbol.name() {
	        None => return,
		Some(n) => n.as_str().unwrap().to_owned(),
	    };
	    let filename = match symbol.filename() {
	        None => return,
		Some(f) => f.to_owned(),
	    };
	    let lineno = match symbol.lineno() {
	        None => return,
		Some(lineno) => lineno,
	    };
	    let frame = StackFrame {
	    	filename: filename.to_string_lossy().into_owned(),
		lineno: lineno as u64,
        	sym: name,
	    };
	    frames.push(frame);
	});
	true
    });
    Traceback { frames: frames }
}

#[link(name="loadaddress")]
extern "C" {
    fn load_address() -> u64;
    fn get_executable_path(buf: *mut u8, buflen: usize) -> c_int;
}

fn main() {
    println!("{:?}", get());
}