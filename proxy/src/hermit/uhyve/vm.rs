//! By calling create_vm KVM returns a fd, this file wraps all relevant functions belonging to the
//! VM layer

use libc;
use std::io::Cursor;
use memmap::{Mmap, MmapMut};
use elf;
use elf::types::{ELFCLASS64, OSABI, PT_LOAD, ET_EXEC, EM_X86_64};
use std::ffi::CStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::ptr;
use std::fs::File;
use std::io::{BufReader, Read};

use byteorder::{ReadBytesExt, NativeEndian};

use hermit::is_verbose;
use hermit::IsleParameterUhyve;
use hermit::utils;
use hermit::uhyve;
use super::kvm_header::*;
use super::{Result, Error, NameIOCTL};
use super::vcpu::{ExitCode, VirtualCPU};
use super::proto::PORT_UART;
use super::checkpoint::{CheckpointConfig, vcpu_state};
use super::migration::MigrationServer;

pub const KVM_32BIT_MAX_MEM_SIZE:   usize = 1 << 32;
pub const KVM_32BIT_GAP_SIZE:       usize = 768 << 20;
pub const KVM_32BIT_GAP_START:      usize = KVM_32BIT_MAX_MEM_SIZE - KVM_32BIT_GAP_SIZE;

/// Page offset bits
pub const PAGE_BITS:        usize = 12;
pub const PAGE_2M_BITS:     usize = 21;
pub const PAGE_SIZE:        usize = 1 << PAGE_BITS;
/// Mask the page address without page map flags and XD flag

pub const PAGE_MASK:        u32 = ((!0u64) << PAGE_BITS) as u32 & !PG_XD;
pub const PAGE_2M_MASK:     u32 = ((!0u64) << PAGE_2M_BITS) as u32 & !PG_XD;

// Page is present
pub const PG_PRESENT:	    u32 = 1 << 0;
// Page is read- and writable
pub const PG_RW:			u32 = 1 << 1;
// Page is addressable from userspace
pub const PG_USER:			u32 = 1 << 2;
// Page write through is activated
pub const PG_PWT:			u32 = 1 << 3;
// Page cache is disabled
pub const PG_PCD:			u32 = 1 << 4;
// Page was recently accessed (set by CPU)
pub const PG_ACCESSED:		u32 = 1 << 5;
// Page is dirty due to recent write-access (set by CPU)
pub const PG_DIRTY:		    u32 = 1 << 6;
// Huge page: 4MB (or 2MB, 1GB)
pub const PG_PSE:			u32 = 1 << 7;
// Page attribute table
pub const PG_PAT:			u32 = PG_PSE;

/* @brief Global TLB entry (Pentium Pro and later)
 *
 * HermitCore is a single-address space operating system
 * => CR3 never changed => The flag isn't required for HermitCore
 */
pub const PG_GLOBAL:	    u32 = 0;

// This table is a self-reference and should skipped by page_map_copy()
pub const PG_SELF:			u32 = 1 << 9;

/// Disable execution for this page
pub const PG_XD:            u32 = 0; //(1u32 << 63);

// guest offset?
//pub const GUEST_OFFSET = 0;

#[derive(Default, Clone)]
pub struct KVMExtensions {
    pub cap_tsc_deadline: bool,
	pub cap_irqchip: bool,
	pub cap_adjust_clock_stable: bool,
	pub cap_irqfd: bool,
	pub cap_vapic: bool,
}

pub struct VirtualMachine {
    kvm_fd: libc::c_int,
    vm_fd: libc::c_int,
    mem: MmapMut,
    elf_entry: Option<u64>,
    klog: Option<*const i8>,
    mboot: Option<*mut u8>,
    vcpus: Vec<VirtualCPU>,
    num_cpus: u32,
    sregs: kvm_sregs,
    running_state: Arc<AtomicBool>,
    thread_handles: Vec<JoinHandle<ExitCode>>,
    extensions: KVMExtensions
}

fn determine_dest_offset(src_addr: isize) -> isize {
    let mask = if src_addr & PG_PSE as isize != 0 { PAGE_2M_MASK } else { PAGE_MASK };
	src_addr & mask as isize
}

impl VirtualMachine {
    pub fn new(kvm_fd: libc::c_int, fd: libc::c_int, size: usize, num_cpus: u32) -> Result<VirtualMachine> {
        debug!("New virtual machine with memory size {}", size);

        // create a new memory region to map the memory of our guest
        let mut mem;
        if size < KVM_32BIT_GAP_START {
            mem = MmapMut::map_anon(size)
                .map_err(|_| Error::NotEnoughMemory)?;
        } else {
            mem = MmapMut::map_anon(size + KVM_32BIT_GAP_START)
                .map_err(|_| Error::NotEnoughMemory)?;
            
            unsafe { libc::mprotect((mem.as_mut_ptr() as *mut libc::c_void).offset(KVM_32BIT_GAP_START as isize), KVM_32BIT_GAP_START, libc::PROT_NONE); }
        }
        
        Ok(VirtualMachine {
            kvm_fd: kvm_fd,
            vm_fd: fd,
            mem: mem,
            elf_entry: None,
            klog: None,
            vcpus: Vec::new(),
            mboot: None,
            num_cpus: num_cpus,
            sregs: kvm_sregs::default(),
            running_state: Arc::new(AtomicBool::new(false)),
            thread_handles: Vec::new(),
            extensions: KVMExtensions::default()
        })
    }

    /// Loads a kernel from path and initialite mem and elf_entry
    pub fn load_kernel(&mut self, path: &str, add: IsleParameterUhyve) -> Result<()> {
        debug!("Load kernel from {}", path);

        // open the file in read only
        let kernel_file = File::open(path).map_err(|_| Error::InvalidFile(path.into()))?;
        let file = unsafe { Mmap::map(&kernel_file) }.map_err(|_| Error::InvalidFile(path.into()))? ;

        // parse the header with ELF module
        let file_elf = {
            let mut data = Cursor::new(file.as_ref());
            
            elf::File::open_stream(&mut data)
                .map_err(|_| Error::InvalidFile(path.into()))
        }?;

        if file_elf.ehdr.class != ELFCLASS64
            || file_elf.ehdr.osabi != OSABI(0x42)
            || file_elf.ehdr.elftype != ET_EXEC
            || file_elf.ehdr.machine != EM_X86_64 {
            return Err(Error::InvalidFile(path.into()));
        }

        self.elf_entry = Some(file_elf.ehdr.entry);

        let mem_addr = self.mem.as_ptr() as u64;

        // acquire the slices of the user memory and kernel file
        let vm_mem_length = self.mem.len() as u64;
        let vm_mem = self.mem.as_mut();
        let kernel_file  = file.as_ref();

        let mut first_load = true;

        for header in file_elf.phdrs {
            if header.progtype != PT_LOAD {
                continue;
            }

            let vm_start = header.paddr as usize;
            let vm_end   = vm_start + header.filesz as usize;

            let kernel_start = header.offset as usize;
            let kernel_end   = kernel_start + header.filesz as usize;

            debug!("Load segment with start addr {} and size {} to {}", header.paddr, header.filesz, header.offset);

            vm_mem[vm_start..vm_end].copy_from_slice(&kernel_file[kernel_start..kernel_end]);
            
            unsafe {
                libc::memset(vm_mem.as_mut_ptr().offset(vm_end as isize) as *mut libc::c_void, 0x00, (header.memsz - header.filesz) as usize);
            }

            let ptr = vm_mem[vm_start..vm_end].as_mut_ptr();

            unsafe {
                *(ptr.offset(0x38) as *mut u64) += header.memsz; // total kernel size

                if !first_load {
                    continue;
                }

                first_load = false;

                *(ptr.offset(0x08) as *mut u64) = header.paddr;   // physical start addr
                *(ptr.offset(0x10) as *mut u64) = vm_mem_length;  // physical size limit
                *(ptr.offset(0x18) as *mut u32) = utils::cpufreq()?; // CPU frequency
                *(ptr.offset(0x24) as *mut u32) = 1;              // number of used CPUs
                *(ptr.offset(0x30) as *mut u32) = 0;              // apicid (?)
                *(ptr.offset(0x60) as *mut u32) = 1;              // NUMA nodes
                *(ptr.offset(0x94) as *mut u32) = 1;              // announce uhyve
                if is_verbose() {
                    *(ptr.offset(0x98) as *mut u64) = PORT_UART as u64;              // announce uhyve
                }

                if let Some(ip) = add.ip {
                    let data = ip.octets();
                    *(ptr.offset(0xB0) as *mut u8) = data[0];
                    *(ptr.offset(0xB1) as *mut u8) = data[1];
                    *(ptr.offset(0xB2) as *mut u8) = data[2];
                    *(ptr.offset(0xB3) as *mut u8) = data[3];
                }

                if let Some(gateway) = add.gateway {
                    let data = gateway.octets();
                    *(ptr.offset(0xB4) as *mut u8) = data[0];
                    *(ptr.offset(0xB5) as *mut u8) = data[1];
                    *(ptr.offset(0xB6) as *mut u8) = data[2];
                    *(ptr.offset(0xB7) as *mut u8) = data[3];
                }

                if let Some(mask) = add.mask {
                    let data = mask.octets();
                    *(ptr.offset(0xB8) as *mut u8) = data[0];
                    *(ptr.offset(0xB9) as *mut u8) = data[1];
                    *(ptr.offset(0xBA) as *mut u8) = data[2];
                    *(ptr.offset(0xBB) as *mut u8) = data[3];
                }

                *(ptr.offset(0xBC) as *mut u64) = mem_addr;

                self.klog = Some(vm_mem.as_ptr().offset(header.paddr as isize + 0x5000) as *const i8);
                self.mboot = Some(vm_mem.as_mut_ptr().offset(header.paddr as isize) as *mut u8);
            }
        }

        debug!("Kernel loaded");

        Ok(())
    }

    pub fn load_checkpoint(&mut self, chk: &CheckpointConfig) -> Result<()> {
        unsafe {
            self.klog = Some(self.mem.as_ptr().offset(chk.get_elf_entry() as isize + 0x5000) as *const i8);
            self.mboot = Some(self.mem.as_mut_ptr().offset(chk.get_elf_entry() as isize) as *mut u8);
        }

        let chk_num = chk.get_checkpoint_number();
        let start = if chk.get_full() { chk_num } else { 0 };

        for i in start .. chk_num+1 {
            let file_name = format!("checkpoint/chk{}_mem.dat", i);
            let file = File::open(&file_name).map_err(|_| Error::InvalidFile(file_name.clone()))?;
            let mut reader = BufReader::new(file);
            
            let mut clock = kvm_clock_data::default();
            reader.read_exact(unsafe { utils::any_as_u8_slice(&mut clock) }).map_err(|_| Error::InvalidFile(file_name.clone()))?;

            if self.extensions.cap_adjust_clock_stable && i == chk_num {
                let mut data = kvm_clock_data::default();
                data.clock = clock.clock;

                let _ = self.set_clock(data);
            }

            while let Ok(location) = reader.read_i64::<NativeEndian>() {
                let location = location as isize;
                let dest_addr = unsafe { self.mem.as_mut_ptr().offset(determine_dest_offset(location)) };
                let len = if location & PG_PSE as isize != 0 { 1 << PAGE_2M_BITS } else { 1 << PAGE_BITS };
                let dest = unsafe { ::std::slice::from_raw_parts_mut(dest_addr, len) };
                reader.read_exact(dest).map_err(|_| Error::InvalidFile(file_name.clone()))?;
            }
        }

        debug!("Loaded checkpoint {}", chk_num);

        Ok(())
    }

    pub fn load_migration(&mut self, mig: &mut MigrationServer) -> Result<()> {
        unsafe {
            let entry = mig.get_metadata().get_elf_entry();
            self.klog = Some(self.mem.as_ptr().offset(entry as isize + 0x5000) as *const i8);
            self.mboot = Some(self.mem.as_mut_ptr().offset(entry as isize) as *mut u8);
        }

        mig.recv_data(self.mem.as_mut())?;
        debug!("Guest memory received");

        mig.recv_cpu_states()?;
        debug!("CPU states received");

        if self.extensions.cap_adjust_clock_stable {
            let mut clock = kvm_clock_data::default();
            mig.recv_data(unsafe { utils::any_as_u8_slice(&mut clock) })?;

            let mut data = kvm_clock_data::default();
            data.clock = clock.clock;

            let _ = self.set_clock(data);
        }

        debug!("Loaded migration");

        Ok(())
    }

    /// Initialize the virtual machine
    pub fn init(&mut self) -> Result<()> {
        let mut identity_base: u64 = 0xfffbc000;
        
        if let Ok(true) = self.check_extension(KVM_CAP_SYNC_MMU) {
            identity_base = 0xfeffc000;

            self.set_identity_map_addr(identity_base)?;
        }
        
        self.set_tss_addr(identity_base+0x1000)?;

        let mut kvm_region = kvm_userspace_memory_region {
            slot: 0,
            guest_phys_addr: 0,
            flags: 0,
            memory_size: self.mem_size() as u64,
            userspace_addr: self.mem.as_ptr() as u64
        };

        if self.mem_size() <= KVM_32BIT_GAP_START {
            self.set_user_memory_region(kvm_region)?;
        } else {
            kvm_region.memory_size = KVM_32BIT_GAP_START as u64;
            self.set_user_memory_region(kvm_region)?;

            kvm_region.slot = 1;
            kvm_region.guest_phys_addr = (KVM_32BIT_GAP_START+KVM_32BIT_GAP_SIZE) as u64;
            kvm_region.memory_size = (self.mem_size() - KVM_32BIT_GAP_SIZE - KVM_32BIT_GAP_START) as u64;
            self.set_user_memory_region(kvm_region)?;
        }

        self.create_irqchip()?;

        // KVM_CAP_X2APIC_API
        let mut cap = kvm_enable_cap::default();
        cap.cap = KVM_CAP_X2APIC_API;
        cap.args[0] = (KVM_X2APIC_API_USE_32BIT_IDS|KVM_X2APIC_API_DISABLE_BROADCAST_QUIRK) as u64;
        self.enable_cap(cap)?;

        let mut chip = kvm_irqchip::default();
        chip.chip_id = KVM_IRQCHIP_IOAPIC;

        let mut chip = kvm_irqchip::default();
        self.get_irqchip(&mut chip)?;
        for i in 0 .. KVM_IOAPIC_NUM_PINS as usize {
            unsafe {
            chip.chip.ioapic.redirtbl[i].fields.vector = 0x20+i as u8;
            chip.chip.ioapic.redirtbl[i].fields._bitfield_1 = kvm_ioapic_state__bindgen_ty_1__bindgen_ty_1::new_bitfield_1(
                0, // delivery_mode
                0, // dest_mode
                0, // delivery_status
                0, // polarity
                0, // remote_irr
                0, // trig_mode
                if i != 2 { 0 } else { 1 }, // mask
                0, // reserve
            );
            chip.chip.ioapic.redirtbl[i].fields.dest_id = 0;
            }
        }
        self.set_irqchip(chip)?;

        self.extensions.cap_tsc_deadline = self.check_extension(KVM_CAP_TSC_DEADLINE_TIMER)?;
        self.extensions.cap_irqchip = self.check_extension(KVM_CAP_IRQCHIP)?;
        self.extensions.cap_adjust_clock_stable = self.check_extension_int(KVM_CAP_ADJUST_CLOCK)? == KVM_CLOCK_TSC_STABLE as i32;
        self.extensions.cap_irqfd = self.check_extension(KVM_CAP_IRQFD)?;
        self.extensions.cap_vapic = self.check_extension(KVM_CAP_VAPIC)?;

        if !self.extensions.cap_irqfd {
            return Err(Error::CAPIRQFD)
        }

        Ok(())
    }

    pub fn create_cpus(&mut self) -> Result<()> {
        for i in 0..self.num_cpus {
            self.create_vcpu(i as u32)?;
        }

        Ok(())
    }

    pub fn init_cpus(&mut self) -> Result<()> {
        let entry = self.elf_entry.ok_or(Error::KernelNotLoaded)?;

        for cpu in &self.vcpus {
            cpu.init(entry)?;

            if cpu.get_id() == 0 {
                self.sregs = cpu.init_sregs()?;
            }

            cpu.set_sregs(self.sregs)?;
        }

        Ok(())
    }

    pub fn restore_cpus(&mut self, cpu_states: &mut Vec<vcpu_state>) -> Result<()> {
        if cpu_states.len() < self.vcpus.len() {
            return Err(Error::VCPUStatesNotInitialized)
        }

        for cpu in &self.vcpus {
            cpu.restore_cpu_state(&mut cpu_states[cpu.get_id() as usize])?;
        }

        Ok(())
    }

    pub fn set_user_memory_region(&self, mut region: kvm_userspace_memory_region) -> Result<()> {
        unsafe {
            uhyve::ioctl::set_user_memory_region(self.vm_fd, (&mut region) as *mut kvm_userspace_memory_region)
                .map_err(|_| Error::IOCTL(NameIOCTL::SetUserMemoryRegion)).map(|_| ())
        }
    }

    pub fn create_irqchip(&self) -> Result<()> {
        unsafe {
            uhyve::ioctl::create_irqchip(self.vm_fd, ptr::null_mut())
                .map_err(|_| Error::IOCTL(NameIOCTL::CreateIRQChip)).map(|_| ())
        }
    }

    pub fn check_extension(&self, extension: u32) -> Result<bool> {
        self.check_extension_int(extension).map(|x| x > 0)
    }

    pub fn check_extension_int(&self, extension: u32) -> Result<i32> {
        unsafe {
            uhyve::ioctl::check_extension(self.vm_fd, extension as *mut u8)
                .map_err(|_| Error::IOCTL(NameIOCTL::CheckExtension))
        }
    }

    pub fn set_identity_map_addr(&self, identity_base: u64) -> Result<()> {
        unsafe {
            uhyve::ioctl::set_identity_map_addr(self.vm_fd, (&identity_base) as *const u64)
                .map_err(|_| Error::IOCTL(NameIOCTL::SetTssIdentity)).map(|_| ())
        }
    }

    pub fn set_tss_addr(&self, identity_base: u64) -> Result<()> {
        unsafe {
            uhyve::ioctl::set_tss_addr(self.vm_fd, identity_base as *mut u8)
                .map_err(|_| Error::IOCTL(NameIOCTL::SetTssAddr)).map(|_| ())
        }
    }

    pub fn enable_cap(&self, mut region: kvm_enable_cap) -> Result<()> {
        unsafe {
            uhyve::ioctl::enable_cap(self.vm_fd, (&mut region) as *mut kvm_enable_cap)
                .map_err(|_| Error::IOCTL(NameIOCTL::EnableCap)).map(|_| ())
        }
    }

    fn get_irqchip(&self, chip: &mut kvm_irqchip) -> Result<()> {
        unsafe {
            uhyve::ioctl::get_irqchip(self.vm_fd, chip as *mut kvm_irqchip)
                .map_err(|_| Error::IOCTL(NameIOCTL::GetIRQChip))?;
        }

        Ok(())
    }

    pub fn set_irqchip(&self, mut chip: kvm_irqchip) -> Result<()> {
        unsafe {
            uhyve::ioctl::set_irqchip(self.vm_fd, (&mut chip) as *mut kvm_irqchip)
                .map_err(|_| Error::IOCTL(NameIOCTL::SetIRQChip))?;
        }

        Ok(())
    }

    pub fn set_clock(&self, mut clock: kvm_clock_data) -> Result<()> {
        unsafe {
            uhyve::ioctl::set_clock(self.vm_fd, (&mut clock) as *mut kvm_clock_data)
                .map_err(|_| Error::IOCTL(NameIOCTL::SetClock))?;
        }

        Ok(())
    }

    pub fn create_vcpu(&mut self, id: u32) -> Result<()> {
        let cpu = VirtualCPU::new(self.kvm_fd, self.vm_fd, id, &mut self.mem, self.mboot.unwrap(), self.running_state.clone(), self.extensions.clone())?;
        self.vcpus.insert(id as usize, cpu);

        Ok(())
    }

    pub fn output(&self) -> String {
        match self.klog {
            Some(paddr) => {
                let c_str = unsafe { CStr::from_ptr(paddr) };
                c_str.to_str().unwrap_or("").into()
            },
            None => "".into()
        }

    }

    pub fn run(&mut self) -> Result<()> {
        //let mut guest_mem = unsafe { self.mem.as_mut_slice() };
       
        unsafe { *(self.mboot.unwrap().offset(0x24) as *mut u32) = self.num_cpus; }
        self.running_state.store(true, Ordering::Relaxed);

        let mut count = 1;
        for vcpu in &self.vcpus {
            if count == self.vcpus.len() {
                vcpu.run();
            } else {
                self.thread_handles.push(vcpu.run_threaded());
            }
            count += 1;
        }

        Ok(())
    }

    pub fn stop(&mut self) -> Result<i32> {
        self.running_state.store(false, Ordering::Relaxed);

        let mut reason = Ok(0);
        while let Some(handle) = self.thread_handles.pop() {
            if let Ok(ret) = handle.join() {
                match ret {
                    ExitCode::Innocent => continue,
                    ExitCode::Cause(cause) => {
                        reason = cause;
                    }
                }
            }
        }

        reason
    }

    pub fn is_running(&mut self) -> Result<bool> {
        Ok(self.running_state.load(Ordering::Relaxed))
    }

    pub fn mem_size(&self) -> usize {
        self.mem.len()
    }
}

impl Drop for VirtualMachine {
    fn drop(&mut self) {
        debug!("Drop the Virtual Machine");
        //debug!("-------- Output --------");
        //debug!("{}", self.output());
    }
}
