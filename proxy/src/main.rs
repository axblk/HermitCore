#![feature(untagged_unions)]
#![feature(core_intrinsics)]
#![feature(unique)]
#![allow(dead_code)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]

extern crate libc;
extern crate memmap;
extern crate elf;
extern crate errno;
extern crate inotify;
extern crate byteorder;

#[macro_use]
extern crate nix;

#[macro_use]
extern crate log;
extern crate env_logger;

mod hermit;

use std::env;

use hermit::Isle;
use hermit::IsleParameter;
use hermit::qemu::QEmu;
use hermit::multi::Multi;
use hermit::uhyve::Uhyve;
use hermit::error::Result;

fn create_isle(path: &str, specs: IsleParameter) -> Result<Box<Isle>> {
    let mut isle: Box<Isle> = match specs {
        IsleParameter::QEmu { mem_size, num_cpus, additional} => Box::new(QEmu::new(&path, mem_size, num_cpus, additional)?),
        IsleParameter::UHyve{ mem_size, num_cpus } => Box::new(Uhyve::new(&path, mem_size, num_cpus)?),
        IsleParameter::Multi{ mem_size, num_cpus } => Box::new(Multi::new(0, &path, mem_size, num_cpus)?)
    };

    isle.run()?;

    Ok(isle)
}

fn main() {
    env_logger::init();
    let verbose = env::var("HERMIT_VERBOSE").map(|x| x.parse::<i32>().unwrap_or(0) != 0).unwrap_or(false);
    unsafe { hermit::verbose = verbose; }

    let args: Vec<String> = env::args().collect();
    create_isle(&args[1], IsleParameter::from_env());
}
