use std::fs::{File, remove_file};
use std::io::Read;
use std::path::{Path, PathBuf};

use nix::unistd::{mkstemp, close};
use raw_cpuid::CpuId;

use hermit::error::*;

pub unsafe fn any_as_u8_mut_slice<T: Sized>(p: &mut T) -> &mut [u8] {
    ::std::slice::from_raw_parts_mut(
        (p as *mut T) as *mut u8,
        ::std::mem::size_of::<T>()
    )
}

pub unsafe fn any_as_u8_slice<T: Sized>(p: &T) -> &[u8] {
    ::std::slice::from_raw_parts(
        (p as *const T) as *const u8,
        ::std::mem::size_of::<T>()
    )
}

/// Returns the CPU frequency
pub fn cpufreq() -> Result<u32> {
    let cpuid = CpuId::new();

    if let Some(freq) = cpuid.get_processor_frequency_info() {
        return Ok(freq.processor_base_frequency() as u32);
    }

    let mut content = String::new();
   
    // If the file cpuinfo_max_freq exists, parse the content and return the frequency
    if let Ok(mut file) = File::open("/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq") {
        file.read_to_string(&mut content).map_err(|_| Error::MissingFrequency)?;
        return content.trim().parse::<u32>().map_err(|_| Error::MissingFrequency).map(|x| x / 1000);
    } 
    // otherwise use the more acurate cpuinfo file and search for the right line
    else if let Ok(mut file) = File::open("/proc/cpuinfo") {
        file.read_to_string(&mut content).expect("Couldnt read!");
    
        for line in content.lines() {
            if line.starts_with("cpu MHz") {
                return line.split(':').skip(1).next().ok_or(Error::MissingFrequency)?
                    .trim().parse::<f32>().map_err(|_| Error::MissingFrequency).map(|x| x as u32);
            }
        }
    }

    // ups shouldn't happened ..
    Err(Error::MissingFrequency)
}

pub fn parse_mem(mem: &str) -> Result<u64> {
    let (num, postfix): (String, String) = mem.chars().partition(|&x| x.is_numeric());
    let num = num.parse::<u64>().map_err(|_| Error::ParseMemory)?;

    let factor = match postfix.as_str() {
        "E" | "e" => 1 << 60,
        "P" | "p" => 1 << 50,
        "T" | "t" => 1 << 40,
        "G" | "g" => 1 << 30,
        "M" | "m" => 1 << 20,
        "K" | "k" => 1 << 10,
        _ => return Err(Error::ParseMemory)
    };
   
    Ok(num*factor)
}

#[derive(Debug)]
pub struct TmpFile {
    path: PathBuf
}

impl TmpFile {
    pub fn create(name: &str) -> Result<TmpFile> {
        match mkstemp(name) {
            Ok((fd, path)) => {
                close(fd).map_err(|_| Error::CannotCreateTmpFile)?;
                debug!("Created tmp file with name {}", path.display());
                Ok(TmpFile { path: path })
            },
            Err(_) => Err(Error::CannotCreateTmpFile)
        }
    }

    pub fn read_to_string(&self, buf: &mut String) -> Result<usize> {
        match File::open(self.path.as_path()) {
            Ok(mut file) => {
                Ok(file.read_to_string(buf).map_err(|_| Error::CannotReadTmpFile(format!("{}", self.path.display())))?)
            },
            Err(_) => Err(Error::CannotReadTmpFile(format!("{}", self.path.display())))
        }
    }

    pub fn get_path(&self) -> &Path {
        self.path.as_path()
    }

    pub fn delete(&self) {
        match remove_file(self.path.as_path()) {
            Ok(_) => debug!("Deleted tmp file {}", self.path.display()),
            Err(_) => {}
        };
    }
}

impl Drop for TmpFile {
    fn drop(&mut self) {
        self.delete();
    }
}
