use libc;
use libc::c_void;
use std::mem;
use std::ptr;
use std::fs::File;
use std::os::unix::io::{FromRawFd, RawFd};
use std::intrinsics::{volatile_load,volatile_store};
use std::thread;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::sync::atomic::Ordering;

use nix::sys::signal;
use nix::sys::pthread;
use nix::errno::Errno;
use nix;

use memmap::{MmapMut, MmapOptions};

use hermit::uhyve;
use hermit::uhyve::kvm_header::*;
use super::{Result, Error, NameIOCTL};
use super::gdt;
use super::proto;
use super::checkpoint::vcpu_state;
use super::vm::{KVMExtensions, ControlData};
use super::utils;

pub const GUEST_OFFSET: usize = 0x0;
pub const CPUID_FUNC_PERFMON: usize = 0x0A;
pub const GUEST_PAGE_SIZE: usize = 0x200000;

// TODO configuration missing
pub const GUEST_SIZE: usize = 0x20000000;

pub const BOOT_GDT:  usize = 0x1000;
pub const BOOT_INFO: usize = 0x2000;
pub const BOOT_PML4: usize = 0x10000;
pub const BOOT_PDPTE:usize = 0x11000;
pub const BOOT_PDE:  usize = 0x12000;

/// Basic CPU control in CR0
pub const X86_CR0_PE: u64 = (1 << 0);
pub const X86_CR0_PG: u64 = (1 << 31);

/// Intel long mode page directory/table entries
pub const X86_CR4_PAE: u64 = (1u64 << 5);

/// Intel long mode page directory/table entries
pub const X86_PDPT_P:  u64 = (1 << 0);
pub const X86_PDPT_RW: u64 = (1 << 1);
pub const X86_PDPT_PS: u64 = (1 << 7);

/* x86-64 specific MSRs */
pub const MSR_EFER:		            u32 = 0xc0000080; /* extended feature register */
pub const MSR_STAR:		            u32 = 0xc0000081; /* legacy mode SYSCALL target */
pub const MSR_LSTAR:	        	u32 = 0xc0000082; /* long mode SYSCALL target */
pub const MSR_CSTAR:		        u32 = 0xc0000083; /* compat mode SYSCALL target */
pub const MSR_SYSCALL_MASK:	        u32 = 0xc0000084; /* EFLAGS mask for syscall */
pub const MSR_FS_BASE:		        u32 = 0xc0000100; /* 64bit FS base */
pub const MSR_GS_BASE:		        u32 = 0xc0000101; /* 64bit GS base */
pub const MSR_KERNEL_GS_BASE:	    u32 = 0xc0000102; /* SwapGS GS shadow */
pub const MSR_TSC_AUX:	        	u32 = 0xc0000103; /* Auxiliary TSC */

pub const MSR_IA32_CR_PAT:          u32 = 0x00000277;
pub const MSR_PEBS_FRONTEND:        u32 = 0x000003f7;

pub const MSR_IA32_POWER_CTL:       u32 = 0x000001fc;

pub const MSR_IA32_MC0_CTL:         u32 = 0x00000400;
pub const MSR_IA32_MC0_STATUS:      u32 = 0x00000401;
pub const MSR_IA32_MC0_ADDR:        u32 = 0x00000402;
pub const MSR_IA32_MC0_MISC:        u32 = 0x00000403;

pub const MSR_IA32_SYSENTER_CS:     u32 = 0x00000174;
pub const MSR_IA32_SYSENTER_ESP:    u32 = 0x00000175;
pub const MSR_IA32_SYSENTER_EIP:    u32 = 0x00000176;

pub const MSR_IA32_APICBASE:        u32 = 0x0000001b;
pub const MSR_IA32_APICBASE_BSP:    u32 = 1<<8;
pub const MSR_IA32_APICBASE_ENABLE: u32 = 1<<11;
pub const MSR_IA32_APICBASE_BASE:   u32 = 0xfffff<<12;

pub const MSR_IA32_MISC_ENABLE:     u32 = 0x000001a0;
pub const MSR_IA32_TSC:             u32 = 0x00000010;


/// EFER bits:
pub const _EFER_SCE:    u64 = 0;  /* SYSCALL/SYSRET */
pub const _EFER_LME:    u64 = 8;  /* Long mode enable */
pub const _EFER_LMA:    u64 = 10; /* Long mode active (read-only) */
pub const _EFER_NX:     u64 = 11; /* No execute enable */
pub const _EFER_SVME:   u64 = 12; /* Enable virtualization */
pub const _EFER_LMSLE:  u64 = 13; /* Long Mode Segment Limit Enable */
pub const _EFER_FFXSR:  u64 = 14; /* Enable Fast FXSAVE/FXRSTOR */

pub const EFER_SCE:     u64 = (1<<_EFER_SCE);
pub const EFER_LME:     u64 = (1<<_EFER_LME);
pub const EFER_LMA:     u64 = (1<<_EFER_LMA);
pub const EFER_NX:      u64 = (1<<_EFER_NX);
pub const EFER_SVME:    u64 = (1<<_EFER_SVME);
pub const EFER_LMSLE:   u64 = (1<<_EFER_LMSLE);
pub const EFER_FFXSR:   u64 = (1<<_EFER_FFXSR);

pub const IOAPIC_DEFAULT_BASE:  u32 = 0xfec00000;
pub const APIC_DEFAULT_BASE:    u32 = 0xfee00000;

pub enum ExitCode {
    Cause(Result<i32>),
    Innocent
}

pub struct SharedState {
    run_mem: MmapMut,
    mboot: *mut u8,
    guest_mem: *mut u8,
    control: Arc<ControlData>,
}

pub struct VirtualCPU {
    id: u32,
    kvm_fd: RawFd,
    vm_fd: RawFd,
    vcpu_fd: RawFd,
    state: Arc<SharedState>,
    extensions: KVMExtensions
}

#[repr(C)]
struct kvm_cpuid2_data {
    header: kvm_cpuid2,
    data: [kvm_cpuid_entry2; 100]
}

#[repr(C)]
#[derive(Default)]
pub struct kvm_msr_data {
	info: kvm_msrs,
	entries: [kvm_msr_entry; 25]
}

#[repr(C)]
pub struct kvm_signal_mask_data {
	info: kvm_signal_mask,
	sigset: libc::sigset_t
}

extern "C" fn empty_handler(_: libc::c_int) {}

impl VirtualCPU {
    pub fn new(kvm_fd: RawFd, vm_fd: RawFd, id: u32, mem: &mut MmapMut, mboot: *mut u8, control: Arc<ControlData>, extensions: KVMExtensions) -> Result<VirtualCPU> {

        // create a new VCPU and save the file descriptor
        let fd = VirtualCPU::create_vcpu(vm_fd, id as i32)?;
        debug!("New virtual CPU with id {} and FD {}", id, fd);

        let file = unsafe { File::from_raw_fd(fd) };

        let size = VirtualCPU::get_mmap_size(kvm_fd)?;
        let mut run_mem = unsafe { MmapOptions::new().len(size).map_mut(&file) }
            .map_err(|_| Error::NotEnoughMemory)?;
      
        // forget the file, we don't want to close the file descriptor
        mem::forget(file);

        unsafe {
            let ref mut run = *(run_mem.as_mut_ptr() as *mut kvm_run);
            run.apic_base = APIC_DEFAULT_BASE as u64;
        }

        let state = SharedState {
            run_mem: run_mem,
            mboot: mboot,
            guest_mem: mem.as_mut_ptr(),
            control: control,
        };

        let cpu = VirtualCPU {
            kvm_fd: kvm_fd, 
            vm_fd: vm_fd, 
            vcpu_fd: fd, 
            id: id, 
            state: Arc::new(state),
            extensions: extensions
        };
        
        Ok(cpu)
    }

    pub fn get_id(&self) -> u32 {
        self.id
    }

    pub fn init(&self, entry: u64) -> Result<()> {
        debug!("Set the CPUID");
        
        self.setup_cpuid()?;

        debug!("Set MP state");

        self.set_mp_state(kvm_mp_state { mp_state: KVM_MP_STATE_RUNNABLE })?;

        let mut msr_data = kvm_msr_data { info: kvm_msrs::default(), entries: [kvm_msr_entry::default(); 25] };
        msr_data.entries[0].index = MSR_IA32_MISC_ENABLE;
        msr_data.entries[0].data = 1;
        msr_data.info.nmsrs = 1;
        self.set_msrs(&mut msr_data)?;

        debug!("Initialize the register of {} with start address {:?}", self.id, entry);

        let mut regs = kvm_regs::default();
        regs.rip = entry;
        regs.rflags = 0x2;
        self.set_regs(regs)?;

        Ok(())
    }

    pub fn restore_cpu_state(&self, cpu_state: &mut vcpu_state) -> Result<()> {
        cpu_state.mp_state.mp_state = KVM_MP_STATE_RUNNABLE;

        //run.apic_base = APIC_DEFAULT_BASE as u64;
        self.setup_cpuid()?;

        self.set_sregs(cpu_state.sregs)?;
        self.set_regs(cpu_state.regs)?;
        self.set_msrs(&mut cpu_state.msr_data)?;
        self.set_xcrs(cpu_state.xcrs)?;
        self.set_mp_state(cpu_state.mp_state)?;
        self.set_lapic(cpu_state.lapic)?;
        self.set_fpu(cpu_state.fpu)?;
        self.set_xsave(cpu_state.xsave)?;
        self.set_vcpu_events(cpu_state.events)?;

        Ok(())
    }

    pub fn save_cpu_state(&self) -> Result<vcpu_state> {
        let mut cpu_state = vcpu_state::default();

        /* define the list of required MSRs */
        cpu_state.msr_data.entries[0].index = MSR_IA32_APICBASE;
        cpu_state.msr_data.entries[1].index = MSR_IA32_SYSENTER_CS;
        cpu_state.msr_data.entries[2].index = MSR_IA32_SYSENTER_ESP;
        cpu_state.msr_data.entries[3].index = MSR_IA32_SYSENTER_EIP;
        cpu_state.msr_data.entries[4].index = MSR_IA32_CR_PAT;
        cpu_state.msr_data.entries[5].index = MSR_IA32_MISC_ENABLE;
        cpu_state.msr_data.entries[6].index = MSR_IA32_TSC;
        cpu_state.msr_data.entries[7].index = MSR_CSTAR;
        cpu_state.msr_data.entries[8].index = MSR_STAR;
        cpu_state.msr_data.entries[9].index = MSR_EFER;
        cpu_state.msr_data.entries[10].index = MSR_LSTAR;
        cpu_state.msr_data.entries[11].index = MSR_GS_BASE;
        cpu_state.msr_data.entries[12].index = MSR_FS_BASE;
        cpu_state.msr_data.entries[13].index = MSR_KERNEL_GS_BASE;

        cpu_state.msr_data.info.nmsrs = 14;

        // run.apic_base = APIC_DEFAULT_BASE as u64;

        cpu_state.sregs = self.get_sregs()?;
        cpu_state.regs = self.get_regs()?;
        self.get_msrs(&mut cpu_state.msr_data)?;
        cpu_state.xcrs = self.get_xcrs()?;
        cpu_state.mp_state = self.get_mp_state()?;
        cpu_state.lapic = self.get_lapic()?;
        cpu_state.fpu = self.get_fpu()?;
        cpu_state.xsave = self.get_xsave()?;
        cpu_state.events = self.get_vcpu_events()?;

        Ok(cpu_state)
    }

    pub fn print_registers(id: u32, vcpu_fd: i32) -> Result<()> {
        utils::show_registers(id, &VirtualCPU::get_regs_fd(vcpu_fd)?, &VirtualCPU::get_sregs_fd(vcpu_fd)?);
        Ok(())
    }

    fn create_vcpu(fd: RawFd, id: i32) -> Result<RawFd> {
        unsafe {
            uhyve::ioctl::create_vcpu(fd, id)
                .map_err(|_| Error::IOCTL(NameIOCTL::CreateVcpu))
        }
    }   

    fn get_sregs_fd(vcpu_fd: i32) -> Result<kvm_sregs> {
        let mut sregs = kvm_sregs::default();
        unsafe {
            uhyve::ioctl::get_sregs(vcpu_fd, (&mut sregs) as *mut kvm_sregs)
                .map_err(|_| Error::IOCTL(NameIOCTL::GetSRegs))?;
        }

        Ok(sregs)
    }

    fn get_sregs(&self) -> Result<kvm_sregs> {
        VirtualCPU::get_sregs_fd(self.vcpu_fd)
    }

    pub fn set_sregs(&self, mut sregs: kvm_sregs) -> Result<()> {
        unsafe {
            uhyve::ioctl::set_sregs(self.vcpu_fd, (&mut sregs) as *mut kvm_sregs)
                .map_err(|_| Error::IOCTL(NameIOCTL::SetSRegs))?;
        }

        Ok(())
    }

    fn get_regs_fd(vcpu_fd: i32) -> Result<kvm_regs> {
        let mut regs = kvm_regs::default();
        unsafe {
            uhyve::ioctl::get_regs(vcpu_fd, (&mut regs) as *mut kvm_regs)
                .map_err(|_| Error::IOCTL(NameIOCTL::GetRegs))?;
        }

        Ok(regs)
    }

    fn get_regs(&self) -> Result<kvm_regs> {
        VirtualCPU::get_regs_fd(self.vcpu_fd)
    }

    fn set_regs(&self, mut regs: kvm_regs) -> Result<()> {
        unsafe {
            uhyve::ioctl::set_regs(self.vcpu_fd, (&mut regs) as *mut kvm_regs)
                .map_err(|_| Error::IOCTL(NameIOCTL::SetSRegs))?;
        }

        Ok(())
    }

    fn get_supported_cpuid(&self) -> Result<kvm_cpuid2_data> {
        let mut cpuid = kvm_cpuid2_data { header: kvm_cpuid2::default(), data: [kvm_cpuid_entry2::default();100] };
        cpuid.header.nent = 100;

        unsafe {
            uhyve::ioctl::get_supported_cpuid(self.kvm_fd, (&mut cpuid.header) as *mut kvm_cpuid2)
                .map_err(|_| Error::IOCTL(NameIOCTL::GetSupportedCpuID))?;
        }

        Ok(cpuid)
    }

    fn set_cpuid2(&self, mut cpuid: kvm_cpuid2_data) -> Result<()> {
        unsafe {
            uhyve::ioctl::set_cpuid2(self.vcpu_fd, (&mut cpuid.header) as *mut kvm_cpuid2)
                .map_err(|_| Error::IOCTL(NameIOCTL::SetCpuID2))?;
        }

        Ok(())
    }
   
    fn get_mmap_size(vcpu_fd: RawFd) -> Result<usize> {
        unsafe {
            uhyve::ioctl::get_vcpu_mmap_size(vcpu_fd, ptr::null_mut())
                .map_err(|_| Error::IOCTL(NameIOCTL::GetVCPUMMAPSize)).map(|x| { x as usize})
        }
    }

    fn get_mp_state(&self) -> Result<kvm_mp_state> {
        let mut data = kvm_mp_state::default();
        unsafe {
            uhyve::ioctl::get_mp_state(self.vcpu_fd, (&mut data) as *mut kvm_mp_state)
                .map_err(|_| Error::IOCTL(NameIOCTL::GetMPState))?;
        }

        Ok(data)
    }
    
    fn set_mp_state(&self, mp_state: kvm_mp_state) -> Result<()> {
        unsafe {
            uhyve::ioctl::set_mp_state(self.vcpu_fd, (&mp_state) as *const kvm_mp_state)
                .map_err(|_| Error::IOCTL(NameIOCTL::SetMPState)).map(|_| ())
        }
    }

    fn get_msrs(&self, msr: &mut kvm_msr_data) -> Result<()> {
        unsafe {
            uhyve::ioctl::get_msrs(self.kvm_fd, (&mut msr.info) as *mut kvm_msrs)
                .map_err(|_| Error::IOCTL(NameIOCTL::GetMSRS))?;
        }

        Ok(())
    }

    pub fn set_msrs(&self, msr: &mut kvm_msr_data) -> Result<()> {
        unsafe {
            uhyve::ioctl::set_msrs(self.vcpu_fd, (&mut msr.info) as *mut kvm_msrs)
                .map_err(|_| Error::IOCTL(NameIOCTL::SetMSRS))?;
        }

        Ok(())
    }

    fn get_fpu(&self) -> Result<kvm_fpu> {
        let mut data = kvm_fpu::default();
        unsafe {
            uhyve::ioctl::get_fpu(self.vcpu_fd, (&mut data) as *mut kvm_fpu)
                .map_err(|_| Error::IOCTL(NameIOCTL::GetFPU))?;
        }

        Ok(data)
    }

    fn set_fpu(&self, mut data: kvm_fpu) -> Result<()> {
        unsafe {
            uhyve::ioctl::set_fpu(self.vcpu_fd, (&mut data) as *mut kvm_fpu)
                .map_err(|_| Error::IOCTL(NameIOCTL::SetFPU))?;
        }

        Ok(())
    }

    fn get_lapic(&self) -> Result<kvm_lapic_state> {
        let mut data = kvm_lapic_state::default();
        unsafe {
            uhyve::ioctl::get_lapic(self.vcpu_fd, (&mut data) as *mut kvm_lapic_state)
                .map_err(|_| Error::IOCTL(NameIOCTL::GetLapic))?;
        }

        Ok(data)
    }

    fn set_lapic(&self, mut data: kvm_lapic_state) -> Result<()> {
        unsafe {
            uhyve::ioctl::set_lapic(self.vcpu_fd, (&mut data) as *mut kvm_lapic_state)
                .map_err(|_| Error::IOCTL(NameIOCTL::SetLapic))?;
        }

        Ok(())
    }

    fn get_vcpu_events(&self) -> Result<kvm_vcpu_events> {
        let mut data = kvm_vcpu_events::default();
        unsafe {
            uhyve::ioctl::get_vcpu_events(self.vcpu_fd, (&mut data) as *mut kvm_vcpu_events)
                .map_err(|_| Error::IOCTL(NameIOCTL::GetVCPUEvents))?;
        }

        Ok(data)
    }

    fn set_vcpu_events(&self, mut data: kvm_vcpu_events) -> Result<()> {
        unsafe {
            uhyve::ioctl::set_vcpu_events(self.vcpu_fd, (&mut data) as *mut kvm_vcpu_events)
                .map_err(|_| Error::IOCTL(NameIOCTL::SetVCPUEvents))?;
        }

        Ok(())
    }

    fn get_xsave(&self) -> Result<kvm_xsave> {
        let mut data = kvm_xsave::default();
        unsafe {
            uhyve::ioctl::get_xsave(self.vcpu_fd, (&mut data) as *mut kvm_xsave)
                .map_err(|_| Error::IOCTL(NameIOCTL::GetXSave))?;
        }

        Ok(data)
    }

    fn set_xsave(&self, mut data: kvm_xsave) -> Result<()> {
        unsafe {
            uhyve::ioctl::set_xsave(self.vcpu_fd, (&mut data) as *mut kvm_xsave)
                .map_err(|_| Error::IOCTL(NameIOCTL::SetXSave))?;
        }

        Ok(())
    }

    fn get_xcrs(&self) -> Result<kvm_xcrs> {
        let mut data = kvm_xcrs::default();
        unsafe {
            uhyve::ioctl::get_xcrs(self.vcpu_fd, (&mut data) as *mut kvm_xcrs)
                .map_err(|_| Error::IOCTL(NameIOCTL::GetXCRS))?;
        }

        Ok(data)
    }

    fn set_xcrs(&self, mut data: kvm_xcrs) -> Result<()> {
        unsafe {
            uhyve::ioctl::set_xcrs(self.vcpu_fd, (&mut data) as *mut kvm_xcrs)
                .map_err(|_| Error::IOCTL(NameIOCTL::SetXCRS))?;
        }

        Ok(())
    }

    fn set_signal_mask_fd(vcpu_fd: i32, mut data: kvm_signal_mask_data) -> Result<()> {
        unsafe {
            uhyve::ioctl::set_signal_mask(vcpu_fd, (&mut data.info) as *mut kvm_signal_mask)
                .map_err(|_| Error::IOCTL(NameIOCTL::SetSignalMask))?;
        }

        Ok(())
    }

    pub fn single_run(fd: RawFd, id: u32, state: &Arc<SharedState>) -> Result<proto::Return> {
        let mut newset = signal::SigSet::empty();
        let mut oldset = signal::SigSet::empty();
        newset.add(signal::Signal::SIGUSR2);
        let _ = signal::pthread_sigmask(signal::SigmaskHow::SIG_BLOCK, Some(&newset), Some(&mut oldset));

        let ret = unsafe { uhyve::ioctl::run(fd, ptr::null_mut()) };

        let _ = signal::pthread_sigmask(signal::SigmaskHow::SIG_SETMASK, Some(&oldset), None);

        debug!("Single Run CPU {}", id);

        if let Err(e) = ret {
            return match e {
                nix::Error::Sys(errno) => match errno {
                    Errno::EINTR => Ok(proto::Return::Interrupt),
                    Errno::EFAULT => {
                        let regs = VirtualCPU::get_regs_fd(fd)?;
                        Err(Error::TranslationFault(regs.rip))
                    },
                    _ => Err(Error::IOCTL(NameIOCTL::Run))
                },
                _ => Err(Error::IOCTL(NameIOCTL::Run))
            }
        }

        unsafe {
            let res = proto::Syscall::from_mem(state.run_mem.as_ptr(), state.guest_mem)?.run(state.guest_mem);
            if let Err(e) = &res {
                match e {
                    Error::KVMDebug => { let _ = VirtualCPU::print_registers(id, fd); },
                    _ => {}
                };
            }

            res
        }
    }

    pub fn run_vcpu(state: Arc<SharedState>, id: u32, fd: i32) -> ExitCode {
        unsafe {
            while volatile_load(state.mboot.offset(0x20)) < id as u8 {
                thread::yield_now();
            }

            volatile_store(state.mboot.offset(0x30), id as u8);
        }

        let tmp = signal::SigSet::empty();
        let sigset = tmp.as_ref().clone();

        let mut sig_mask = kvm_signal_mask::default();
        sig_mask.len = 8;
        let sig_mask_data = kvm_signal_mask_data { info: sig_mask, sigset: sigset };

        let _ = VirtualCPU::set_signal_mask_fd(fd, sig_mask_data);

        let sigaction = signal::SigAction::new(
            signal::SigHandler::Handler(empty_handler),
            signal::SaFlags::empty(),
            signal::SigSet::empty(),
        );
        unsafe { let _ = signal::sigaction(signal::Signal::SIGUSR2, &sigaction); }

        while state.control.running.load(Ordering::Relaxed) {
            match VirtualCPU::single_run(fd, id, &state) {
                Ok(proto::Return::Interrupt) => {
                    if state.control.interrupt.load(Ordering::Relaxed) {
                        state.control.barrier.wait();
                        state.control.barrier.wait();
                    }
                },
                Ok(proto::Return::Exit(code)) => {
                    state.control.running.store(false, Ordering::Relaxed);

                    return ExitCode::Cause(Ok(code));
                },
                Err(err) => {
                    state.control.running.store(false, Ordering::Relaxed);
                    
                    return ExitCode::Cause(Err(err));
                },
                _ => {}
            }
        }

        ExitCode::Innocent
    }

    pub fn run(&self) -> (JoinHandle<ExitCode>, pthread::Pthread, ::chan::Receiver<()>) {
        debug!("Run CPU {}", self.id);

        let state = self.state.clone();
        let id = self.id;
        let fd = self.vcpu_fd;

        let (spthread, rpthread) = ::chan::sync(0);
        let (sdone, rdone) = ::chan::sync(1);

        let handle = thread::spawn(move || {
            let _ = spthread.send(pthread::pthread_self());
            let ret = VirtualCPU::run_vcpu(state, id, fd);
            sdone.send(());
            ret
        });

        (handle, rpthread.recv().unwrap(), rdone)
    }
    
    pub fn init_sregs(&self) -> Result<kvm_sregs> {
        let mut sregs = self.get_sregs()?;

        debug!("Setup GDT");
        self.setup_system_gdt(&mut sregs, 0)?;
        debug!("Setup the page tables");
        self.setup_system_page_tables(&mut sregs)?;
        debug!("Set the system to 64bit");
        self.setup_system_64bit(&mut sregs)?;

        Ok(sregs)
    }

    pub fn setup_system_gdt(&self, sregs: &mut kvm_sregs, offset: u64) -> Result<()> {
        let (mut data_seg, mut code_seg) = (kvm_segment::default(), kvm_segment::default());               

        // create the GDT entries
        let gdt_null = gdt::Entry::new(0, 0, 0);
        let gdt_code = gdt::Entry::new(0xA09B, 0, 0xFFFFF);
        let gdt_data = gdt::Entry::new(0xC093, 0, 0xFFFFF);

        // apply the new GDTs to our guest memory
        unsafe {
            let ptr = self.state.guest_mem.offset(offset as isize) as *mut u64;
            
            *(ptr.offset(gdt::BOOT_NULL)) = gdt_null.as_u64();
            *(ptr.offset(gdt::BOOT_CODE)) = gdt_code.as_u64();
            *(ptr.offset(gdt::BOOT_DATA)) = gdt_data.as_u64();
        }

        gdt_code.apply_to_kvm(gdt::BOOT_CODE, &mut code_seg);
        gdt_data.apply_to_kvm(gdt::BOOT_DATA, &mut data_seg);

        sregs.gdt.base = offset;
        sregs.gdt.limit = ((mem::size_of::<u64>() * gdt::BOOT_MAX) - 1) as u16;
        sregs.cs = code_seg;
        sregs.ds = data_seg;
        sregs.es = data_seg;
        sregs.fs = data_seg;
        sregs.gs = data_seg;
        sregs.ss = data_seg;

        Ok(())
    }

    pub fn setup_system_page_tables(&self, sregs: &mut kvm_sregs) -> Result<()> {
        unsafe {
            let pml4 = self.state.guest_mem.offset(BOOT_PML4 as isize) as *mut u64;
            let pdpte = self.state.guest_mem.offset(BOOT_PDPTE as isize) as *mut u64;
            let pde = self.state.guest_mem.offset(BOOT_PDE as isize) as *mut u64;
            
            libc::memset(pml4 as *mut c_void, 0x00, 4096);
            libc::memset(pdpte as *mut c_void, 0x00, 4096);
            libc::memset(pde as *mut c_void, 0x00, 4096);
            
            *pml4 = (BOOT_PDPTE as u64) | (X86_PDPT_P | X86_PDPT_RW);
            *pdpte = (BOOT_PDE as u64) | (X86_PDPT_P | X86_PDPT_RW);
           
            for i in 0..(GUEST_SIZE/GUEST_PAGE_SIZE) {
                *(pde.offset(i as isize)) = (i*GUEST_PAGE_SIZE) as u64 | (X86_PDPT_P | X86_PDPT_RW | X86_PDPT_PS);
            }
        }

        sregs.cr3 = BOOT_PML4 as u64;
        sregs.cr4 |= X86_CR4_PAE;
        sregs.cr0 |= X86_CR0_PG;

        Ok(())
    }

    pub fn setup_system_64bit(&self, sregs: &mut kvm_sregs) -> Result<()> {
        sregs.cr0 |= X86_CR0_PE;
        sregs.cr4 |= X86_CR4_PAE;
        sregs.efer |= EFER_LME|EFER_LMA;

        Ok(())
    }

    pub fn setup_cpuid(&self) -> Result<()> {
        let mut kvm_cpuid = self.get_supported_cpuid()?;

        for entry in kvm_cpuid.data[0 .. kvm_cpuid.header.nent as usize].iter_mut() {
            match entry.function {
                1 => {
                    entry.ecx |= 1u32 << 31; // propagate that we are running on a hypervisor
                    if self.extensions.cap_tsc_deadline {
                        entry.eax |= 1u32 << 24; // enable TSC deadline feature
                    }
                    entry.edx |= 1u32 << 5; // enable msr support
                },
                0x0A => {
                    // disable it
                    entry.eax = 0x00;
                },
                _ => {}
            }
        }

        self.set_cpuid2(kvm_cpuid)?;

        Ok(())
    }
}

impl Drop for VirtualCPU {
    fn drop(&mut self) {
        let _ = ::nix::unistd::close(self.vcpu_fd);
    }
}

unsafe impl Sync for SharedState {}
unsafe impl Send for SharedState {}
