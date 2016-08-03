extern crate gcc;

fn main() {
    gcc::Config::new()
        .file("src/loadaddress.c")
	.compile("libloadaddress.a")
}