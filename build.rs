extern crate gcc;

fn main() {
    // First build our own loadaddress
    gcc::Config::new()
        .file("src/loadaddress.c")
	.compile("libloadaddress.a");

    // Next, link against libiberty
    println!("cargo:rustc-link-lib=static={}", "iberty"); // fuck you rms
    println!("cargo:rustc-link-search=native={}", "/Users/sujayakar/src/binutils-gdb/libiberty");

    // Holy shit, zlib too
    println!("cargo:rustc-link-lib=static={}", "z");
    println!("cargo:rustc-link-search=native={}", "/Users/sujayakar/src/binutils-gdb/zlib");

    // Next, link against libbfd
    println!("cargo:rustc-link-lib=static={}", "bfd");
    println!("cargo:rustc-link-search=native={}", "/Users/sujayakar/src/binutils-gdb/bfd");
}