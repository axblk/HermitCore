#![feature(untagged_unions)]
#![feature(core_intrinsics)]
#![feature(unique)]
#![allow(dead_code)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]

#[macro_use]
extern crate clap;

#[macro_use]
extern crate serde_derive;
extern crate bincode;

extern crate libc;
extern crate memmap;
extern crate elf;
extern crate errno;
extern crate inotify;
extern crate byteorder;
extern crate chrono;

#[macro_use]
extern crate nix;

#[macro_use]
extern crate log;
extern crate env_logger;

mod hermit;

use std::{env, fs};

use hermit::Isle;
use hermit::IsleParameter;
use hermit::qemu::QEmu;
use hermit::multi::Multi;
use hermit::uhyve::Uhyve;
use hermit::error::Result;

fn create_isle(path: String, specs: IsleParameter) -> Result<Box<Isle>> {
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

    let matches = clap_app!(HermitProxy => 
        (version: "0.0.1")
        (author: "Lorenz Schmidt <bytesnake@mailbox.org>")
        (about: "Allows you to start and manage HermitCore isles")
        (@arg file: +required "The binary to be executed")
        (@arg isle: --isle +takes_value "Choose the hypervisor [uhyve/qemu/multi]")
        (@arg debug: -d --debug "Enables debugging information")
        (@arg cpus: --num_cpus +takes_value "Sets the number of cpus")
        (@arg mem_size: --mem_size +takes_value "Sets the memory size")
        (@arg qemu_binary: --qemu_binary +takes_value "Overrides the default qemu binary")
        (@arg port: --port +takes_value "Overrides the default port [qemu only]")
        (@arg app_port: --app_port +takes_value "Overrides the default app port [qemu only]")
    ).get_matches();

    // create the isle
    if let Some(isle) = matches.value_of("isle") {
        env::set_var("HERMIT_ISLE", isle);
    }

    if matches.is_present("debug") {
        env::set_var("RUST_LOG", "trace");
        env::set_var("HERMIT_VERBOSE", "1");
    }

    if let Some(num_cpus) = matches.value_of("cpus") {
        env::set_var("HERMIT_CPUS",num_cpus);
    }

    if let Some(mem_size) = matches.value_of("mem_size") {
        env::set_var("HERMIT_MEM", mem_size);
    }

    if let Some(qemu_binary) = matches.value_of("qemu_binary") {
        env::set_var("HERMIT_QEMU", qemu_binary);
    }

    if let Some(port) = matches.value_of("port") {
        env::set_var("HERMIT_PORT",port);
    }

    if let Some(app_port) = matches.value_of("app_port") {
        env::set_var("HERMIT_APP_PORT",app_port);
    }

    let relative_path: String = matches.value_of("file").unwrap().into();
    let path = fs::canonicalize(relative_path).unwrap();

    create_isle(path.to_str().unwrap().into(), IsleParameter::from_env());
}
