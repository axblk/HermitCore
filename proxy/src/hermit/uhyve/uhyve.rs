//! This file contains the entry point to the Unikernel Hypervisor. The uhyve utilizes KVM to
//! create a Virtual Machine and load the kernel.

use std::fs::{File,OpenOptions};
use std::path::Path;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::{AsRawFd, RawFd};
use std::ptr;
use std::rc::Rc;

use libc;

use hermit::{Isle, IsleParameterUhyve};
use hermit::error::*;
use super::kvm::*;
use super::vm::VirtualMachine;
use super::checkpoint::FileCheckpoint;
use super::migration::MigrationServer;

/// The normal way of defining a IOCTL interface is provided by C macros. In Rust we have our own
/// flawed macro system. The module below wraps a bunch of functions which are generated by the
/// ioctl! macro and need to be wrapped further to provide a safe interface.
pub mod ioctl {
    use hermit::uhyve::kvm::*;

    ioctl_write_ptr_bad!(get_version, request_code_none!(KVMIO, 0x00), u8);
    ioctl_write_int_bad!(create_vm, request_code_none!(KVMIO, 0x01));
    ioctl_readwrite!(get_msr_index_list, KVMIO, 0x02, kvm_msr_list);

    ioctl_write_ptr_bad!(get_vcpu_mmap_size, request_code_none!(KVMIO, 0x04), u8);
    ioctl_readwrite!(get_supported_cpuid, KVMIO, 0x05, kvm_cpuid2);
    ioctl_readwrite!(get_emulated_cpuid, KVMIO, 0x09, kvm_cpuid2);
    ioctl_write_ptr!(set_cpuid2, KVMIO, 0x90, kvm_cpuid2);

    ioctl_write_int_bad!(create_vcpu, request_code_none!(KVMIO, 0x41));
    ioctl_write_ptr!(get_dirty_log, KVMIO, 0x42, kvm_dirty_log);
    ioctl_write_ptr!(set_memory_alias, KVMIO, 0x43, kvm_memory_alias);
    ioctl_write_ptr_bad!(set_nr_mmu_pages, request_code_none!(KVMIO, 0x44), u8);
    ioctl_write_ptr_bad!(get_nr_mmu_pages, request_code_none!(KVMIO, 0x45), u8);
    
    ioctl_write_ptr!(set_memory_region, KVMIO, 0x40, kvm_memory_region);
    ioctl_write_ptr!(set_user_memory_region, KVMIO, 0x46, kvm_userspace_memory_region);

    ioctl_write_ptr_bad!(create_irqchip, request_code_none!(KVMIO, 0x60), u8);

    ioctl_write_ptr_bad!(run, request_code_none!(KVMIO, 0x80), u8);
    ioctl_read!(get_regs, KVMIO, 0x81, kvm_regs);
    ioctl_write_ptr!(set_regs, KVMIO, 0x82, kvm_regs);
    ioctl_read!(get_sregs, KVMIO, 0x83, kvm_sregs);
    ioctl_write_ptr!(set_sregs, KVMIO, 0x84, kvm_sregs);

    ioctl_readwrite!(get_msrs, KVMIO, 0x88, kvm_msrs);
    ioctl_write_ptr!(set_msrs, KVMIO, 0x89, kvm_msrs);

    ioctl_write_ptr!(set_signal_mask, KVMIO, 0x8b, kvm_signal_mask);

    ioctl_read!(get_fpu, KVMIO, 0x8c, kvm_fpu);
    ioctl_write_ptr!(set_fpu, KVMIO, 0x8d, kvm_fpu);

    ioctl_read!(get_lapic, KVMIO, 0x8e, kvm_lapic_state);
    ioctl_write_ptr!(set_lapic, KVMIO, 0x8f, kvm_lapic_state);

    ioctl_read!(get_mp_state, KVMIO, 0x98, kvm_mp_state);
    ioctl_write_ptr!(set_mp_state, KVMIO, 0x99, kvm_mp_state);

    ioctl_read!(get_vcpu_events, KVMIO, 0x9f, kvm_vcpu_events);
    ioctl_write_ptr!(set_vcpu_events, KVMIO, 0xa0, kvm_vcpu_events);

    ioctl_read!(get_xsave, KVMIO, 0xa4, kvm_xsave);
    ioctl_write_ptr!(set_xsave, KVMIO, 0xa5, kvm_xsave);

    ioctl_read!(get_xcrs, KVMIO, 0xa6, kvm_xcrs);
    ioctl_write_ptr!(set_xcrs, KVMIO, 0xa7, kvm_xcrs);

    ioctl_read_bad!(check_extension, request_code_none!(KVMIO, 0x03), u8);
    ioctl_read_bad!(set_tss_addr, request_code_none!(KVMIO, 0x47), u8);
    ioctl_write_ptr!(set_identity_map_addr, KVMIO, 0x48, u64);
    ioctl_write_ptr!(enable_cap, KVMIO, 0xa3, kvm_enable_cap);

    ioctl_readwrite!(get_irqchip, KVMIO, 0x62, kvm_irqchip);
    ioctl_read!(set_irqchip, KVMIO, 0x63, kvm_irqchip);

    ioctl_write_ptr!(set_clock, KVMIO, 0x7b, kvm_clock_data);
    ioctl_read!(get_clock, KVMIO, 0x7c, kvm_clock_data);
}

/// KVM is freezed at version 12, so all others are invalid
#[derive(Debug)]
pub enum Version{
    Version12,
    Unsupported(i32)
}

/// This is the entry point of our module, it connects to the KVM device and wraps the functions
/// which accept the global file descriptor.
pub struct KVM {
    file: File
}

impl KVM {
    // Connects to the KVM hypervisor, by opening the virtual device /dev/kvm
    pub fn new() -> Result<KVM> {
        let kvm_file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_CLOEXEC)
            .open("/dev/kvm")
            .map_err(|_| Error::KVMConnection)?;
        
        Ok(KVM { file: kvm_file })
    }

    // Acquires the KVM version to seperate ancient systems
    pub fn version(&self) -> Result<Version> {
        unsafe {
            match ioctl::get_version(self.file.as_raw_fd(), ptr::null_mut()) {
                Ok(12) => Ok(Version::Version12),
                Ok(v)  => Ok(Version::Unsupported(v)),
                Err(_) => Err(Error::IOCTL(NameIOCTL::GetVersion))
            }
        }
    }

    // Creates a new virtual machine and forwards the new fd to an object
    pub fn create_vm(&self) -> Result<RawFd> {
        unsafe {
            ioctl::create_vm(self.file.as_raw_fd(), 0)
                .map_err(|_| Error::IOCTL(NameIOCTL::CreateVM))
        }
    }

    pub fn get_supported_cpuid(&self) -> Result<kvm_cpuid2_data> {
        let mut cpuid = kvm_cpuid2_data { header: kvm_cpuid2::default(), data: [kvm_cpuid_entry2::default();100] };
        cpuid.header.nent = 100;

        unsafe {
            ioctl::get_supported_cpuid(self.file.as_raw_fd(), (&mut cpuid.header) as *mut kvm_cpuid2)
                .map_err(|_| Error::IOCTL(NameIOCTL::GetSupportedCpuID))?;
        }

        Ok(cpuid)
    }

    pub fn get_mmap_size(&self) -> Result<usize> {
        unsafe {
            ioctl::get_vcpu_mmap_size(self.file.as_raw_fd(), ptr::null_mut())
                .map_err(|_| Error::IOCTL(NameIOCTL::GetVCPUMMAPSize)).map(|x| { x as usize })
        }
    }
}

pub struct Uhyve {
    kvm: Rc<KVM>,
    vm: VirtualMachine,
}

impl Uhyve {
    pub fn new(path: Option<String>, mut mem_size: u64, mut num_cpus: u32, mut additional: IsleParameterUhyve) -> Result<Uhyve> {
        let mut mig_server: Option<MigrationServer> = None;
        let mut chk: Option<FileCheckpoint> = None;

        if additional.migration_server {
            let migration_server = MigrationServer::wait_for_incoming()?;
            {
                let metadata = migration_server.get_metadata();
                num_cpus = metadata.get_num_cpus();
                mem_size = metadata.get_mem_size();
                additional.full_checkpoint = metadata.get_full();
            }

            mig_server = Some(migration_server)
        } else if let Ok(chk_file) = FileCheckpoint::load() {
            {
                let cfg = chk_file.get_config();
                num_cpus = cfg.get_num_cpus();
                mem_size = cfg.get_mem_size();
                additional.full_checkpoint = cfg.get_full();
            }

            chk = Some(chk_file);
        }

        let kvm = Rc::new(KVM::new()?);
        match kvm.version()? {
            Version::Version12 => debug!("Connection to KVM is established."),
            Version::Unsupported(v) => return Err(Error::KVMApiVersion(v))
        }

        let vm_fd = kvm.create_vm()?;
        let mut vm = VirtualMachine::new(kvm.clone(), vm_fd, mem_size as usize, num_cpus, additional)?;
        vm.init()?;

        if let Some(mig) = &mut mig_server {
            vm.load_migration(mig)?;
        } else if let Some(chk) = &chk {
            vm.load_checkpoint(chk.get_config())?;
        } else {
            vm.load_kernel(&path.ok_or(Error::FileMissing)?)?;
        }

        vm.create_cpus()?;

        if let Some(mig) = &mut mig_server {
            vm.restore_cpus(mig.get_cpu_states())?;
        } else if let Some(chk) = &mut chk {
            vm.restore_cpus(chk.get_cpu_states())?;
        } else {
            vm.init_cpus()?;
        }
    
        Ok(Uhyve {
            kvm: kvm,
            vm: vm,
        })
    }
}

impl Isle for Uhyve {
    fn num(&self) -> u8 {
        0
    }

    fn log_file(&self) -> Option<&Path> {
        None
    }

    fn run(&mut self) -> Result<()> {
        self.vm.run()
    }

    fn stop(&mut self) -> Result<()> {
        self.vm.stop()
    }

    fn output(&self) -> String {
        self.vm.output()
    }
}
