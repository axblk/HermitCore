use std::process::{Stdio, Child, Command};
use std::fs::File;
use std::io::{Read, BufReader, BufRead};
use std::process::{ChildStdout, ChildStderr};
use std::env;
use nix::sys::signal::{kill, SIGINT};

use hermit::{Isle, IsleParameterQEmu};
use hermit::utils;
use hermit::error::*;
use hermit::socket::Socket;
use hermit::is_verbose;

const PIDNAME: &'static str = "/tmp/hpid-XXXXXX";
const TMPNAME: &'static str = "/tmp/hermit-XXXXXX";

const BASE_PORT: u16 = 18766;

#[derive(Debug)]
pub struct QEmu {
    socket: Option<Socket>,
    child: Child,
    stdout: ChildStdout,
    stderr: ChildStderr,
    tmp_file: String,
    pid_file: String,
}

impl QEmu {
    pub fn new(path: &str, mem_size: u64, num_cpus: u32, additional: IsleParameterQEmu) -> Result<QEmu> {
        let tmpf = utils::create_tmp_file(TMPNAME)?;
        let pidf = utils::create_tmp_file(PIDNAME)?;
        
        let port = if additional.port == 0 || additional.port >= u16::max_value() {
            BASE_PORT
        } else {
            additional.port
        };

        debug!("port number: {}", port);

        let mut child = QEmu::start_with(path, port, mem_size, num_cpus, additional, &tmpf, &pidf)?.spawn().expect("Couldn't find qemu binary!");
        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();
        let socket = Socket::new(port);

        Ok(QEmu {
            socket: Some(socket),
            child: child,
            stdout: stdout,
            stderr: stderr,
            tmp_file: tmpf,
            pid_file: pidf,
        })
    }
    
    pub fn start_with(path: &str, port: u16, mem_size: u64, num_cpus: u32, add: IsleParameterQEmu, tmp_file: &str, pid_file: &str) -> Result<Command> {
        let mut hostfwd = format!("user,hostfwd=tcp:127.0.0.1:{}-:{}", port, BASE_PORT);
        let monitor_str = format!("telnet:127.0.0.1:{},server,nowait", port+1);
        let chardev = format!("file,id=gnc0,path={}", &tmp_file);
        let freq = format!("\"-freq{} -proxy\"",(utils::cpufreq().unwrap()/1000).to_string());
        let num_cpus = num_cpus.to_string();
        let mem_size = format!("{}B", mem_size);

        if add.app_port != 0 {
            hostfwd = format!("{},hostfwd=tcp::{}-:{}", hostfwd, add.app_port, add.app_port);
        }

        let mut exe = env::current_exe().unwrap();
        exe.pop();
        exe.push("ldhermit.elf");
        let kernel = exe.to_str().unwrap();

        let mut args: Vec<&str> = vec![
            "-daemonize",
            "-display", "none",
            "-smp", &num_cpus,
            "-m", &mem_size,
            "-pidfile", pid_file,
            "-net", "nic,model=rtl8139",
            "-net", &hostfwd,
            "-chardev", &chardev,
            "-device", "pci-serial,chardev=gnc0",
            "-kernel", kernel,
            "-initrd", path,
            "-append", &freq,
            "-no-acpi"];

        if add.use_kvm {
            args.push("-machine");
            args.push("accel=kvm");
            args.push("-cpu");
            args.push("host");
        }

        if add.monitor {
            args.push("-monitor");
            args.push(&monitor_str);
        }

        if add.should_debug {
            args.push("-s");
        }

        if add.capture_net {
            args.push("-net");
            args.push("dump");
        }

        debug!("Execute {} with {}", add.binary, args.join(" "));

        let mut cmd = Command::new(add.binary);

        cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());

        Ok(cmd)
    }

    pub fn qemu_log(&mut self) -> (String, String) {
        let mut stderr = String::new();
        let mut stdout = String::new();

        self.stdout.read_to_string(&mut stdout);
        self.stderr.read_to_string(&mut stderr);

        (stdout, stderr)
    }
}

impl Isle for QEmu {
    fn num(&self) -> u8 { 0 }
    fn log_file(&self) -> Option<String> {
        Some(self.tmp_file.clone())
    }
    fn log_path(&self) -> Option<String> {
        Some("/tmp".into())
    }
    fn cpu_path(&self) -> Option<String> {
        None 
    }

    fn run(&mut self) -> Result<()> {
        let mut socket = self.socket.take().ok_or(Error::InternalError)?;
        socket.connect()?;

        socket.run()?;

        Ok(())
    }

    fn output(&self) -> Result<String> {
        let mut file = File::open(&self.tmp_file).unwrap();
        let mut content = String::new();

        file.read_to_string(&mut content);

        Ok(content)
    }
}

impl Drop for QEmu {
    fn drop(&mut self) {
        let mut id_str = String::new();
        let mut file = File::open(&self.pid_file).unwrap();
        file.read_to_string(&mut id_str);
        id_str.pop();

        let id = id_str.parse::<i32>().unwrap();

        if id >= 0 {
            kill(id, SIGINT);
        }

        if is_verbose() {
            match File::open(&self.tmp_file) {
                Ok(file) => {
                    println!("Dump kernel log:");
                    println!("================");
                    for line in BufReader::new(file).lines() {
                        println!("{}", line.unwrap());
                    }
                },
                Err(_) => debug!("Could not read kernel log")
            };
        }

        utils::delete_tmp_file(&self.pid_file);
        utils::delete_tmp_file(&self.tmp_file);
    }
}
