use std::{result, fmt};
use errno::errno;

pub type Result<T> = result::Result<T, Error>;

#[derive(Debug, Clone)]
pub enum Error {
    InternalError,
    NotEnoughMemory,
    InvalidFile(String),
    IOCTL(NameIOCTL),
    KernelNotLoaded,
    MissingFrequency,
    MultiIsleFailed,
    CannotCreateTmpFile,
    CannotReadTmpFile(String),
    MissingQEmuBinary,
    Protocol(String),
    ParseMemory,
    ProxyConnect,
    ProxyPacket,
    InotifyError,
    UnsupportedMigrationType(String),
    KVMConnection,
    InvalidCheckpoint,
    KVMApiVersion(i32),
    CAPIRQFD,
    MigrationConnection,
    MigrationStream,
    NoCheckpointFile,
    VCPUStatesNotInitialized,
    TranslationFault(u64),
    KVMRunFailed(u32),
    KVMDebug
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::InternalError => write!(f, "An internal error has occurred, please report."),
            Error::NotEnoughMemory => write!(f, "The host system has not enough memory, please check your memory usage."),
            Error::InvalidFile(ref file) => write!(f, "The file {} was not found or is invalid.", file),
            Error::IOCTL(ref name) => write!(f, "The IOCTL command {:?} has failed: {}", name, errno()),
            Error::KernelNotLoaded => write!(f, "Please load the kernel before you start the virtual machine."),
            Error::MissingFrequency => write!(f, "Couldn't get the CPU frequency from your system. (is /proc/cpuinfo missing?)"),
            Error::MultiIsleFailed => write!(f, "The Multi isle was selected on a system without support, please load the kernel driver."),
            Error::CannotCreateTmpFile => write!(f, "Could not create a tmp file."),
            Error::CannotReadTmpFile(ref file) => write!(f, "Could not read tmp file: {}", file),
            Error::MissingQEmuBinary => write!(f, "Could not find the qemu binary."),
            Error::Protocol(ref err) => write!(f, "{}", err),
            Error::ParseMemory => write!(f, "Couldn't parse the guest memory size from the environment"),
            Error::ProxyConnect => write!(f, "Proxy: connection error"),
            Error::ProxyPacket => write!(f, "Could not read proxy packet"),
            Error::InotifyError => write!(f, "Inotify error"),
            Error::UnsupportedMigrationType(ref name) => write!(f, "Migration type '{}' not supported.", name),
            Error::KVMConnection => write!(f, "Could not open: /dev/kvm"),
            Error::InvalidCheckpoint => write!(f, "Invalid checkpoint data"),
            Error::KVMApiVersion(version) => write!(f, "KVM: API version is {}, uhyve requires version 12", version),
            Error::CAPIRQFD => write!(f, "The support of KVM_CAP_IRQFD is curently required"),
            Error::MigrationConnection => write!(f, "Migration connection error"),
            Error::MigrationStream => write!(f, "Migration stream error"),
            Error::NoCheckpointFile => write!(f, "Could notfind a checkpoint file"),
            Error::VCPUStatesNotInitialized => write!(f, "vcpu states not initialized"),
            Error::TranslationFault(rip) => write!(f, "KVM: host/guest translation fault: rip={:#x}", rip),
            Error::KVMRunFailed(cpuid) => write!(f, "KVM: ioctl KVM_RUN in vcpu_loop for cpuid {} failed", cpuid),
            Error::KVMDebug => write!(f, "KVM: debug")
        }
    }
}

#[derive(Debug, Clone)]
pub enum NameIOCTL {
    GetVersion,
    CreateVM,
    GetMsrIndexList,
    CheckExtension,
    GetVCPUMMAPSize,
    GetSupportedCpuID,
    SetCpuID2,
    CreateVcpu,
    SetMemoryAlias,
    SetNRMMUPages,
    GetNRMMUPages,
    SetMemoryRegion,
    SetUserMemoryRegion,
    CreateIRQChip,
    Run,
    GetRegs,
    SetRegs,
    GetSRegs,
    SetSRegs,
    SetTssIdentity,
    SetTssAddr,
    GetMPState,
    SetMPState,
    EnableCap,
    GetIRQChip,
    SetIRQChip,
    SetClock,
    GetMSRS,
    SetMSRS,
    GetFPU,
    SetFPU,
    GetLapic,
    SetLapic,
    GetVCPUEvents,
    SetVCPUEvents,
    GetXSave,
    SetXSave,
    GetXCRS,
    SetXCRS
}
