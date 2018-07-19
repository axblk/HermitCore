pub mod error;
mod utils;
pub mod qemu;
pub mod multi;
mod proto;
mod socket;
pub mod uhyve;

use std::fs::File;
use std::path::{Path, PathBuf};
use std::io::{BufReader, BufRead};
use inotify::{Inotify, WatchMask};
use std::env;
use std::net::Ipv4Addr;

use hermit::error::*;

const BASE_PORT: u16 = 18766;

pub static mut verbose: bool = false;

pub fn is_verbose() -> bool {
    return unsafe { verbose };
}

#[derive(Debug, Clone)]
pub struct IsleParameterQEmu {
    binary: String,
    use_kvm: bool,
    monitor: bool,
    capture_net: bool,
    port: u16,
    should_debug: bool,
    app_port: u16
}

#[derive(Debug, Clone)]
pub struct IsleParameterUhyve {
    netif: Option<String>,
    ip: Option<Ipv4Addr>,
    gateway: Option<Ipv4Addr>,
    mask: Option<Ipv4Addr>,
}

#[derive(Debug, Clone)]
pub enum IsleParameter {
    QEmu {
        mem_size: u64,
        num_cpus: u32,
        additional: IsleParameterQEmu
    },
    UHyve {
        mem_size: u64,
        num_cpus: u32,
        additional: IsleParameterUhyve
    },
    Multi {
        num_cpus: u32
    }
}

impl IsleParameter {
    pub fn from_env() -> IsleParameter {
        let isle_kind = env::var("HERMIT_ISLE").unwrap_or("qemu".into());
        let mem_size: u64 = env::var("HERMIT_MEM").map(|x| utils::parse_mem(&x).unwrap_or(512*1024*1024)).unwrap_or(512*1024*1024);
        let num_cpus: u32 = env::var("HERMIT_CPUS").map(|x| x.parse().unwrap_or(1)).unwrap_or(1);

        match isle_kind.as_str() {
            "multi" | "MULTI" | "Multi" => {
                IsleParameter::Multi {
                    num_cpus: num_cpus
                }
            },
            "uhyve" | "UHyve" | "UHYVE" => {
                let netif = env::var("HERMIT_NETIF").map(|x| Some(x)).unwrap_or(None);
                let ip: Option<Ipv4Addr> = env::var("HERMIT_IP").map(|x| x.parse().map(|n| Some(n)).unwrap_or(None)).unwrap_or(None);
                let gateway: Option<Ipv4Addr> = env::var("HERMIT_GATEWAY").map(|x| x.parse().map(|n| Some(n)).unwrap_or(None)).unwrap_or(None);
                let mask: Option<Ipv4Addr> = env::var("HERMIT_MASK").map(|x| x.parse().map(|n| Some(n)).unwrap_or(None)).unwrap_or(None);

                IsleParameter::UHyve {
                    mem_size: mem_size,
                    num_cpus: num_cpus,
                    additional: IsleParameterUhyve {
                        netif: netif,
                        ip: ip,
                        gateway: gateway,
                        mask: mask
                    }
                }
            },
            _ => {
                let binary = env::var("HERMIT_QEMU").unwrap_or("qemu-system-x86_64".into());
                let kvm = env::var("HERMIT_KVM").map(|x| x.parse::<i32>().unwrap_or(1) != 0).unwrap_or(true);
                let monitor = env::var("HERMIT_MONITOR").map(|x| x.parse::<i32>().unwrap_or(0) != 0).unwrap_or(false);
                let capture_net = env::var("HERMIT_CAPTURE_NET").map(|x| x.parse::<i32>().unwrap_or(0) != 0).unwrap_or(false);
                let port = env::var("HERMIT_PORT").map(|x| x.parse().unwrap_or(0)).unwrap_or(0);
                let app_port = env::var("HERMIT_APP_PORT").map(|x| x.parse().unwrap_or(0)).unwrap_or(0);
                let debug = env::var("HERMIT_DEBUG").map(|x| x.parse::<i32>().unwrap_or(0) != 0).unwrap_or(false);

                IsleParameter::QEmu {
                    mem_size: mem_size,
                    num_cpus: num_cpus,
                    additional: IsleParameterQEmu {
                        binary: binary,
                        use_kvm: kvm,
                        monitor: monitor,
                        capture_net: capture_net,
                        port: port,
                        app_port: app_port,
                        should_debug: debug
                    }
                }
            }
        }
    }
}

pub trait Isle {
    fn num(&self) -> u8;
    fn log_file(&self) -> Option<&Path>;

    fn output(&self) -> String;

    fn run(&mut self) -> Result<()>;
    fn stop(&mut self) -> Result<i32>;

    fn is_available(&self) -> Result<bool> {
        let log = match self.log_file() {
            Some(f) => f,
            None => return Ok(true)
        };

        // open the log file
        let file = File::open(log)
            .map_err(|x| Error::InvalidFile(format!("{:?}",x)))?;

        let reader = BufReader::new(file);
       
        for line in reader.lines() {
            if line.unwrap().contains("TCP server is listening.") {
                debug!("Found key token, continue");
                return Ok(true);
            }
        }

        Ok(false)
    }

    fn wait_until_available(&self) -> Result<()> {
        if self.is_available()? {
            return Ok(());
        }
        
        debug!("Wait for the HermitIsle to be available");

        let mut ino = Inotify::init().map_err(|_| Error::InotifyError)?;

        // watch on the log path
        let log_path = match self.log_file() {
            Some(f) => {
                let mut path = PathBuf::from(f);
                path.pop();
                path
            },
            None => return Ok(())
        };

        ino.add_watch(log_path, WatchMask::MODIFY | WatchMask::CREATE).map_err(|_| Error::InotifyError)?;

        let mut buffer = [0; 1024];
        loop {
            let mut events = ino.read_events(&mut buffer).map_err(|_| Error::InotifyError)?;
            if let Some(_) = events.next() {
                if self.is_available()? {
                    return Ok(());
                }
            }

            /*
            if let IsleKind::QEMU(ref mut obj) = *self {
                let (stdout,stderr) = obj.output();
                
                if stderr != "" {
                    return Err(Error::QEmu((stdout, stderr)));
                }

                if stdout != "" {
                    debug!("stdout: {}", stdout);
                }
            }*/
        }
    }
}
