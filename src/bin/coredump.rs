use std::{env, fs};

use licore::Core;

fn main() {
    let path = env::args().nth(1).expect("no path supplied");
    let data = fs::read(path).expect("error reading core file");
    let core = Core::parse(&data).expect("error parsing core file");
    dbg!(core);
}
