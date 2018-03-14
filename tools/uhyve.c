/* Copyright (c) 2015, IBM
 * Author(s): Dan Williams <djwillia@us.ibm.com>
 *            Ricardo Koller <kollerr@us.ibm.com>
 * Copyright (c) 2017, RWTH Aachen University
 * Author(s): Stefan Lankes <slankes@eonerc.rwth-aachen.de>
 *
 * Permission to use, copy, modify, and/or distribute this software
 * for any purpose with or without fee is hereby granted, provided
 * that the above copyright notice and this permission notice appear
 * in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
 * OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* We used several existing projects as guides
 * kvmtest.c: http://lwn.net/Articles/658512/
 * Solo5: https://github.com/Solo5/solo5
 */

/*
 * 15.1.2017: extend original version (https://github.com/Solo5/solo5)
 *            for HermitCore
 * 25.2.2017: add SMP support to enable more than one core
 * 24.4.2017: add checkpoint/restore support,
 *            remove memory limit
 */

#define _GNU_SOURCE

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <limits.h>
#include <pthread.h>
#include <semaphore.h>
#include <elf.h>
#include <err.h>
#include <poll.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/eventfd.h>
#include <linux/const.h>
#include <linux/kvm.h>

#include "uhyve.h"
#include "uhyve-syscalls.h"
#include "uhyve-net.h"
#include "proxy.h"

// define this macro to create checkpoints with KVM's dirty log
//#define USE_DIRTY_LOG

#define MAX_FNAME	256
#define MAX_MSR_ENTRIES	25

#define GUEST_OFFSET		0x0
#define CPUID_FUNC_PERFMON	0x0A
#define GUEST_PAGE_SIZE		0x200000   /* 2 MB pages in guest */

#define KVM_32BIT_MAX_MEM_SIZE	(1ULL << 32)
#define KVM_32BIT_GAP_SIZE	(768 << 20)
#define KVM_32BIT_GAP_START	(KVM_32BIT_MAX_MEM_SIZE - KVM_32BIT_GAP_SIZE)


// Networkports
#define UHYVE_PORT_NETINFO		0x505
#define UHYVE_PORT_NETWRITE		0x506
#define UHYVE_PORT_NETREAD		0x507
#define UHYVE_PORT_NETSTAT		0x508

#define UHYVE_IRQ	11

static bool restart = false;
static bool verbose = false;
static bool full_checkpoint = false;
static uint32_t ncores = 1;
static uint8_t* guest_mem = NULL;
static uint8_t* klog = NULL;
static size_t guest_size = 0x20000000ULL;
static uint64_t elf_entry;
static pthread_t* vcpu_threads = NULL;
static pthread_t net_thread;
static int* vcpu_fds = NULL;
static uint32_t no_checkpoint = 0;
static pthread_mutex_t kvm_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_barrier_t barrier;
int kvm = -1, vmfd = -1, netfd = -1, efd = -1;
uint8_t* mboot = NULL;
__thread struct kvm_run *run = NULL;
__thread int vcpufd = -1;
__thread uint32_t cpuid = 0;
static sem_t net_sem;

int uhyve_argc = -1;
int uhyve_envc = -1;
char **uhyve_argv = NULL;
extern char **environ;
char **uhyve_envp = NULL;

/* Ports and data structures for uhyve command line arguments and envp
 * forwarding */
#define UHYVE_PORT_CMDSIZE	0x509
#define UHYVE_PORT_CMDVAL	0x510

typedef struct {
	int argc;
	int argsz[MAX_ARGC_ENVC];
	int envc;
	int envsz[MAX_ARGC_ENVC];
} __attribute__ ((packed)) uhyve_cmdsize_t;

typedef struct {
	char **argv;
	char **envp;
} __attribute__ ((packed)) uhyve_cmdval_t;

static uint64_t memparse(const char *ptr)
{
	// local pointer to end of parsed string
	char *endptr;

	// parse number
	uint64_t size = strtoull(ptr, &endptr, 0);

	// parse size extension, intentional fall-through
	switch (*endptr) {
	case 'E':
	case 'e':
		size <<= 10;
	case 'P':
	case 'p':
		size <<= 10;
	case 'T':
	case 't':
		size <<= 10;
	case 'G':
	case 'g':
		size <<= 10;
	case 'M':
	case 'm':
		size <<= 10;
	case 'K':
	case 'k':
		size <<= 10;
		endptr++;
	default:
		break;
	}

	return size;
}

// Just close file descriptor if not already done
static inline void close_fd(int* fd)
{
	if (*fd != -1) {
		close(*fd);
		*fd = -1;
	}
}

static void uhyve_exit(void* arg)
{
	if (pthread_mutex_trylock(&kvm_lock))
	{
		close_fd(&vcpufd);
		return;
	}

	// only the main thread will execute this
	if (vcpu_threads) {
		for(uint32_t i=0; i<ncores; i++) {
			if (pthread_self() == vcpu_threads[i])
				continue;

			pthread_kill(vcpu_threads[i], SIGTERM);
		}

		if (netfd > 0)
			pthread_kill(net_thread, SIGTERM);
	}

	close_fd(&vcpufd);
}

static void dump_log(void)
{
	if (klog && verbose)
	{
		fputs("\nDump kernel log:\n", stderr);
		fputs("================\n", stderr);
		fprintf(stderr, "%s\n", klog);
	}
}

static void uhyve_atexit(void)
{
	uhyve_exit(NULL);

	if (vcpu_threads) {
		for(uint32_t i = 0; i < ncores; i++) {
			if (pthread_self() == vcpu_threads[i])
				continue;
			pthread_join(vcpu_threads[i], NULL);
		}

		free(vcpu_threads);
	}

	if (vcpu_fds)
		free(vcpu_fds);

	dump_log();

	// clean up and close KVM
	close_fd(&vmfd);
	close_fd(&kvm);
}

int load_kernel(uint8_t* mem, char* path)
{
	Elf64_Ehdr hdr;
	Elf64_Phdr *phdr = NULL;
	size_t buflen;
	int fd, ret;
	int first_load = 1;

	fd = open(path, O_RDONLY);
	if (fd == -1)
	{
		perror("Unable to open file");
		return -1;
	}

	ret = pread_in_full(fd, &hdr, sizeof(hdr), 0);
	if (ret < 0)
		goto out;

	//  check if the program is a HermitCore file
	if (hdr.e_ident[EI_MAG0] != ELFMAG0
	    || hdr.e_ident[EI_MAG1] != ELFMAG1
	    || hdr.e_ident[EI_MAG2] != ELFMAG2
	    || hdr.e_ident[EI_MAG3] != ELFMAG3
	    || hdr.e_ident[EI_CLASS] != ELFCLASS64
	    || hdr.e_ident[EI_OSABI] != HERMIT_ELFOSABI
	    || hdr.e_type != ET_EXEC || hdr.e_machine != EM_X86_64) {
		fprintf(stderr, "Inavlide HermitCore file!\n");
		goto out;
	}

	elf_entry = hdr.e_entry;

	buflen = hdr.e_phentsize * hdr.e_phnum;
	phdr = malloc(buflen);
	if (!phdr) {
		fprintf(stderr, "Not enough memory\n");
		goto out;
	}

	ret = pread_in_full(fd, phdr, buflen, hdr.e_phoff);
	if (ret < 0)
		goto out;

	/*
	 * Load all segments with type "LOAD" from the file at offset
	 * p_offset, and copy that into in memory.
	 */
	for (Elf64_Half ph_i = 0; ph_i < hdr.e_phnum; ph_i++)
	{
		uint64_t paddr = phdr[ph_i].p_paddr;
		size_t offset = phdr[ph_i].p_offset;
		size_t filesz = phdr[ph_i].p_filesz;
		size_t memsz = phdr[ph_i].p_memsz;

		if (phdr[ph_i].p_type != PT_LOAD)
			continue;

		//printf("Kernel location 0x%zx, file size 0x%zx, memory size 0x%zx\n", paddr, filesz, memsz);

		ret = pread_in_full(fd, mem+paddr-GUEST_OFFSET, filesz, offset);
		if (ret < 0)
			goto out;
		if (!klog)
			klog = mem+paddr+0x5000-GUEST_OFFSET;
		if (!mboot)
			mboot = mem+paddr-GUEST_OFFSET;

		if (first_load) {
			first_load = 0;

			// initialize kernel
			*((uint64_t*) (mem+paddr-GUEST_OFFSET + 0x08)) = paddr; // physical start address
			*((uint64_t*) (mem+paddr-GUEST_OFFSET + 0x10)) = guest_size;   // physical limit
			*((uint32_t*) (mem+paddr-GUEST_OFFSET + 0x18)) = get_cpufreq();
			*((uint32_t*) (mem+paddr-GUEST_OFFSET + 0x24)) = 1; // number of used cpus
			*((uint32_t*) (mem+paddr-GUEST_OFFSET + 0x30)) = 0; // apicid
			*((uint32_t*) (mem+paddr-GUEST_OFFSET + 0x60)) = 1; // numa nodes
			*((uint32_t*) (mem+paddr-GUEST_OFFSET + 0x94)) = 1; // announce uhyve


			char* str = getenv("HERMIT_IP");
			if (str) {
				uint32_t ip[4];

				sscanf(str, "%u.%u.%u.%u",	ip+0, ip+1, ip+2, ip+3);
				*((uint8_t*) (mem+paddr-GUEST_OFFSET + 0xB0)) = (uint8_t) ip[0];
				*((uint8_t*) (mem+paddr-GUEST_OFFSET + 0xB1)) = (uint8_t) ip[1];
				*((uint8_t*) (mem+paddr-GUEST_OFFSET + 0xB2)) = (uint8_t) ip[2];
				*((uint8_t*) (mem+paddr-GUEST_OFFSET + 0xB3)) = (uint8_t) ip[3];
			}

			str = getenv("HERMIT_GATEWAY");
			if (str) {
				uint32_t ip[4];

				sscanf(str, "%u.%u.%u.%u",	ip+0, ip+1, ip+2, ip+3);
				*((uint8_t*) (mem+paddr-GUEST_OFFSET + 0xB4)) = (uint8_t) ip[0];
				*((uint8_t*) (mem+paddr-GUEST_OFFSET + 0xB5)) = (uint8_t) ip[1];
				*((uint8_t*) (mem+paddr-GUEST_OFFSET + 0xB6)) = (uint8_t) ip[2];
				*((uint8_t*) (mem+paddr-GUEST_OFFSET + 0xB7)) = (uint8_t) ip[3];
			}
			str = getenv("HERMIT_MASK");
			if (str) {
				uint32_t ip[4];

				sscanf(str, "%u.%u.%u.%u",	ip+0, ip+1, ip+2, ip+3);
				*((uint8_t*) (mem+paddr-GUEST_OFFSET + 0xB8)) = (uint8_t) ip[0];
				*((uint8_t*) (mem+paddr-GUEST_OFFSET + 0xB9)) = (uint8_t) ip[1];
				*((uint8_t*) (mem+paddr-GUEST_OFFSET + 0xBA)) = (uint8_t) ip[2];
				*((uint8_t*) (mem+paddr-GUEST_OFFSET + 0xBB)) = (uint8_t) ip[3];
			}

		}
		*((uint64_t*) (mem+paddr-GUEST_OFFSET + 0x38)) += memsz; // total kernel size
	}

out:
	if (phdr)
		free(phdr);

	close(fd);

	return 0;
}

static void* wait_for_packet(void* arg)
{
	int ret;
	struct pollfd fds = {	.fd = netfd,
							.events = POLLIN,
							.revents  = 0};

	while(1)
	{
		fds.revents = 0;

		ret = poll(&fds, 1, -1000);

		if (ret < 0 && errno == EINTR)
			continue;

		if (ret < 0)
			perror("poll()");
		else if (ret) {
			uint64_t event_counter = 1;
			write(efd, &event_counter, sizeof(event_counter));
			sem_wait(&net_sem);
		}
	}

	return NULL;
}

static inline void check_network(void)
{
	// should we start the network thread?
	if ((efd < 0) && (getenv("HERMIT_NETIF"))) {
		struct kvm_irqfd irqfd = {};

		efd = eventfd(0, 0);
		irqfd.fd = efd;
		irqfd.gsi = UHYVE_IRQ;
		kvm_ioctl(vmfd, KVM_IRQFD, &irqfd);

		sem_init(&net_sem, 0, 0);

		if (pthread_create(&net_thread, NULL, wait_for_packet, NULL))
			err(1, "unable to create thread");
	}
}

static int vcpu_loop(void)
{
	int ret;

	if (restart) {
		pthread_barrier_wait(&barrier);
		if (cpuid == 0)
			no_checkpoint++;
	}

	while (1) {
		ret = ioctl(vcpufd, KVM_RUN, NULL);

		if(ret == -1) {
			switch(errno) {
			case EINTR:
				continue;

			case EFAULT: {
				struct kvm_regs regs;
				kvm_ioctl(vcpufd, KVM_GET_REGS, &regs);
#ifdef __x86_64__
				err(1, "KVM: host/guest translation fault: rip=0x%llx", regs.rip);
#else
				err(1, "KVM: host/guest translation fault: elr_el1=0x%llx", regs.elr_el1);
#endif
			}

			default:
				err(1, "KVM: ioctl KVM_RUN in vcpu_loop failed");
				break;
			}
		}

		/* handle requests */
		switch (run->exit_reason) {
		case KVM_EXIT_HLT:
			fprintf(stderr, "Guest has halted the CPU, this is considered as a normal exit.\n");
			return 0;

		case KVM_EXIT_MMIO:
			err(1, "KVM: unhandled KVM_EXIT_MMIO at 0x%llx\n", run->mmio.phys_addr);
			break;

		case KVM_EXIT_IO:
			//printf("port 0x%x\n", run->io.port);
			switch (run->io.port) {
			case UHYVE_PORT_WRITE: {
					unsigned data = *((unsigned*)((size_t)run+run->io.data_offset));
					uhyve_write_t* uhyve_write = (uhyve_write_t*) (guest_mem+data);

					uhyve_write->len = write(uhyve_write->fd, guest_mem+(size_t)uhyve_write->buf, uhyve_write->len);
					break;
				}

			case UHYVE_PORT_READ: {
					unsigned data = *((unsigned*)((size_t)run+run->io.data_offset));
					uhyve_read_t* uhyve_read = (uhyve_read_t*) (guest_mem+data);

					uhyve_read->ret = read(uhyve_read->fd, guest_mem+(size_t)uhyve_read->buf, uhyve_read->len);
					break;
				}

			case UHYVE_PORT_EXIT: {
					unsigned data = *((unsigned*)((size_t)run+run->io.data_offset));

					if (cpuid)
						pthread_exit((int*)(guest_mem+data));
					else
						exit(*(int*)(guest_mem+data));
					break;
				}

			case UHYVE_PORT_OPEN: {
					unsigned data = *((unsigned*)((size_t)run+run->io.data_offset));
					uhyve_open_t* uhyve_open = (uhyve_open_t*) (guest_mem+data);

					uhyve_open->ret = open((const char*)guest_mem+(size_t)uhyve_open->name, uhyve_open->flags, uhyve_open->mode);
					break;
				}

			case UHYVE_PORT_CLOSE: {
					unsigned data = *((unsigned*)((size_t)run+run->io.data_offset));
					uhyve_close_t* uhyve_close = (uhyve_close_t*) (guest_mem+data);

					if (uhyve_close->fd > 2)
						uhyve_close->ret = close(uhyve_close->fd);
					else
						uhyve_close->ret = 0;
					break;
				}

			case UHYVE_PORT_NETINFO: {
					unsigned data = *((unsigned*)((size_t)run+run->io.data_offset));
					uhyve_netinfo_t* uhyve_netinfo = (uhyve_netinfo_t*)(guest_mem+data);
					memcpy(uhyve_netinfo->mac_str, uhyve_get_mac(), 18);
					// guest configure the ethernet device => start network thread
					check_network();
					break;
				}

			case UHYVE_PORT_NETWRITE: {
					unsigned data = *((unsigned*)((size_t)run+run->io.data_offset));
					uhyve_netwrite_t* uhyve_netwrite = (uhyve_netwrite_t*)(guest_mem + data);
					uhyve_netwrite->ret = 0;
					ret = write(netfd, guest_mem + (size_t)uhyve_netwrite->data, uhyve_netwrite->len);
					if (ret >= 0) {
						uhyve_netwrite->ret = 0;
						uhyve_netwrite->len = ret;
					} else {
						uhyve_netwrite->ret = -1;
					}
					break;
				}

			case UHYVE_PORT_NETREAD: {
					unsigned data = *((unsigned*)((size_t)run+run->io.data_offset));
					uhyve_netread_t* uhyve_netread = (uhyve_netread_t*)(guest_mem + data);
					ret = read(netfd, guest_mem + (size_t)uhyve_netread->data, uhyve_netread->len);
					if (ret > 0) {
						uhyve_netread->len = ret;
						uhyve_netread->ret = 0;
					} else {
						uhyve_netread->ret = -1;
						sem_post(&net_sem);
					}
					break;
				}

			case UHYVE_PORT_NETSTAT: {
					unsigned status = *((unsigned*)((size_t)run+run->io.data_offset));
					uhyve_netstat_t* uhyve_netstat = (uhyve_netstat_t*)(guest_mem + status);
					char* str = getenv("HERMIT_NETIF");
					if (str)
						uhyve_netstat->status = 1;
					else
						uhyve_netstat->status = 0;
					break;
				}

			case UHYVE_PORT_LSEEK: {
					unsigned data = *((unsigned*)((size_t)run+run->io.data_offset));
					uhyve_lseek_t* uhyve_lseek = (uhyve_lseek_t*) (guest_mem+data);

					uhyve_lseek->offset = lseek(uhyve_lseek->fd, uhyve_lseek->offset, uhyve_lseek->whence);
					break;
				}

			case UHYVE_PORT_CMDSIZE: {
					int i;
					unsigned data = *((unsigned*)((size_t)run+run->io.data_offset));
					uhyve_cmdsize_t *val = (uhyve_cmdsize_t *) (guest_mem+data);

					val->argc = uhyve_argc;
					for(i=0; i<uhyve_argc; i++)
						val->argsz[i] = strlen(uhyve_argv[i]) + 1;

					val->envc = uhyve_envc;
					for(i=0; i<uhyve_envc; i++)
						val->envsz[i] = strlen(uhyve_envp[i]) + 1;

					break;
				}

			case UHYVE_PORT_CMDVAL: {
					int i;
					char **argv_ptr, **env_ptr;
					unsigned data = *((unsigned*)((size_t)run+run->io.data_offset));
					uhyve_cmdval_t *val = (uhyve_cmdval_t *) (guest_mem+data);

					/* argv */
					argv_ptr = (char **)(guest_mem + (size_t)val->argv);
					for(i=0; i<uhyve_argc; i++)
						strcpy(guest_mem + (size_t)argv_ptr[i], uhyve_argv[i]);

					/* env */
					env_ptr = (char **)(guest_mem + (size_t)val->envp);
					for(i=0; i<uhyve_envc; i++)
						strcpy(guest_mem + (size_t)env_ptr[i], uhyve_envp[i]);

					break;
				}

			default:
				err(1, "KVM: unhandled KVM_EXIT_IO at port 0x%x, direction %d\n", run->io.port, run->io.direction);
				break;
			}
			break;

		case KVM_EXIT_FAIL_ENTRY:
			err(1, "KVM: entry failure: hw_entry_failure_reason=0x%llx\n",
				run->fail_entry.hardware_entry_failure_reason);
			break;

		case KVM_EXIT_INTERNAL_ERROR:
			err(1, "KVM: internal error exit: suberror = 0x%x\n", run->internal.suberror);
			break;

		case KVM_EXIT_SHUTDOWN:
			fprintf(stderr, "KVM: receive shutdown command\n");

		case KVM_EXIT_DEBUG:
			print_registers();
			dump_log();
			exit(EXIT_FAILURE);

		default:
			fprintf(stderr, "KVM: unhandled exit: exit_reason = 0x%x\n", run->exit_reason);
			exit(EXIT_FAILURE);
		}
	}

	close(vcpufd);
	vcpufd = -1;

	return 0;
}

static int vcpu_init(void)
{
#ifdef __x86_64__
	struct kvm_regs regs = {
		.rip = elf_entry,	// entry point to HermitCore
		.rflags = 0x2,		// POR value required by x86 architecture
	};
#else
	struct kvm_regs regs = {
		.sp_el1 = 0x205,
        	.elr_el1 = elf_entry, 	// entry point to HermitCore
	};
#endif

	vcpu_fds[cpuid] = vcpufd = kvm_ioctl(vmfd, KVM_CREATE_VCPU, cpuid);

	/* Map the shared kvm_run structure and following data. */
	size_t mmap_size = (size_t) kvm_ioctl(kvm, KVM_GET_VCPU_MMAP_SIZE, NULL);

	if (mmap_size < sizeof(*run))
		err(1, "KVM: invalid VCPU_MMAP_SIZE: %zd", mmap_size);

	run = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, vcpufd, 0);
	if (run == MAP_FAILED)
		err(1, "KVM: VCPU mmap failed");

#ifdef __x86_64__
	run->apic_base = APIC_DEFAULT_BASE;
	setup_cpuid(kvm, vcpufd);
#endif

	if (restart) {
		restore_cpu_state();
	} else {
		init_cpu_state(elf_entry);
	}

	return 0;
}

static void sigusr_handler(int signum)
{
	pthread_barrier_wait(&barrier);

	save_cpu_state();

	pthread_barrier_wait(&barrier);
}

static void* uhyve_thread(void* arg)
{
	size_t ret;
	struct sigaction sa;

	pthread_cleanup_push(uhyve_exit, NULL);

	cpuid = (size_t) arg;

	/* Install timer_handler as the signal handler for SIGVTALRM. */
	memset(&sa, 0x00, sizeof(sa));
	sa.sa_handler = &sigusr_handler;
	sigaction(SIGRTMIN, &sa, NULL);

	// create new cpu
	vcpu_init();

	// run cpu loop until thread gets killed
	ret = vcpu_loop();

	pthread_cleanup_pop(1);

	return (void*) ret;
}

void sigterm_handler(int signum)
{
	pthread_exit(0);
}

int uhyve_init(char *path)
{
	char* v = getenv("HERMIT_VERBOSE");
	if (v && (strcmp(v, "0") != 0))
		verbose = true;

	signal(SIGTERM, sigterm_handler);

	// register routine to close the VM
	atexit(uhyve_atexit);

	FILE* f = fopen("checkpoint/chk_config.txt", "r");
	if (f != NULL) {
		int tmp = 0;
		restart = true;

		fscanf(f, "number of cores: %u\n", &ncores);
		fscanf(f, "memory size: 0x%zx\n", &guest_size);
		fscanf(f, "checkpoint number: %u\n", &no_checkpoint);
		fscanf(f, "entry point: 0x%zx", &elf_entry);
		fscanf(f, "full checkpoint: %d", &tmp);
		full_checkpoint = tmp ? true : false;

		if (verbose)
			fprintf(stderr, "Restart from checkpoint %u (ncores %d, mem size 0x%zx)\n", no_checkpoint, ncores, guest_size);
		fclose(f);
	} else {
		const char* hermit_memory = getenv("HERMIT_MEM");
		if (hermit_memory)
			guest_size = memparse(hermit_memory);

		const char* hermit_cpus = getenv("HERMIT_CPUS");
		if (hermit_cpus)
			ncores = (uint32_t) atoi(hermit_cpus);

		const char* full_chk = getenv("HERMIT_FULLCHECKPOINT");
		if (full_chk && (strcmp(full_chk, "0") != 0))
			full_checkpoint = true;
	}

	vcpu_threads = (pthread_t*) calloc(ncores, sizeof(pthread_t));
	if (!vcpu_threads)
		err(1, "Not enough memory");

	vcpu_fds = (int*) calloc(ncores, sizeof(int));
	if (!vcpu_fds)
		err(1, "Not enough memory");

	kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC);
	if (kvm < 0)
		err(1, "Could not open: /dev/kvm");

	/* Make sure we have the stable version of the API */
	int kvm_api_version = kvm_ioctl(kvm, KVM_GET_API_VERSION, NULL);
	if (kvm_api_version != 12)
		err(1, "KVM: API version is %d, uhyve requires version 12", kvm_api_version);

	/* Create the virtual machine */
	vmfd = kvm_ioctl(kvm, KVM_CREATE_VM, 0);

	uint64_t identity_base = 0xfffbc000;
	if (ioctl(vmfd, KVM_CHECK_EXTENSION, KVM_CAP_SYNC_MMU) > 0) {
		/* Allows up to 16M BIOSes. */
		identity_base = 0xfeffc000;

		kvm_ioctl(vmfd, KVM_SET_IDENTITY_MAP_ADDR, &identity_base);
	}
	kvm_ioctl(vmfd, KVM_SET_TSS_ADDR, identity_base + 0x1000);

	/*
	 * Allocate page-aligned guest memory.
	 *
	 * TODO: support of huge pages
	 */
	if (guest_size < KVM_32BIT_GAP_START) {
		guest_mem = mmap(NULL, guest_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (guest_mem == MAP_FAILED)
			err(1, "mmap failed");
	} else {
		guest_size += KVM_32BIT_GAP_SIZE;
		guest_mem = mmap(NULL, guest_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (guest_mem == MAP_FAILED)
			err(1, "mmap failed");

		/*
		 * We mprotect the gap PROT_NONE so that if we accidently write to it, we will know.
		 */
		mprotect(guest_mem + KVM_32BIT_GAP_START, KVM_32BIT_GAP_SIZE, PROT_NONE);
	}

	const char* merge = getenv("HERMIT_MERGEABLE");
	if (merge && (strcmp(merge, "0") != 0)) {
		/*
		 * The KSM feature is intended for applications that generate
		 * many instances of the same data (e.g., virtualization systems
		 * such as KVM). It can consume a lot of processing power!
		 */
		madvise(guest_mem, guest_size, MADV_MERGEABLE);
		if (verbose)
			fprintf(stderr, "VM uses KSN feature \"mergeable\" to reduce the memory footprint.\n");
	}

	struct kvm_userspace_memory_region kvm_region = {
		.slot = 0,
		.guest_phys_addr = GUEST_OFFSET,
		.memory_size = guest_size,
		.userspace_addr = (uint64_t) guest_mem,
#ifdef USE_DIRTY_LOG
		.flags = KVM_MEM_LOG_DIRTY_PAGES,
#else
		.flags = 0,
#endif
	};

	if (guest_size <= KVM_32BIT_GAP_START - GUEST_OFFSET) {
		kvm_ioctl(vmfd, KVM_SET_USER_MEMORY_REGION, &kvm_region);
	} else {
		kvm_region.memory_size = KVM_32BIT_GAP_START - GUEST_OFFSET;
		kvm_ioctl(vmfd, KVM_SET_USER_MEMORY_REGION, &kvm_region);

		kvm_region.slot = 1;
		kvm_region.guest_phys_addr = KVM_32BIT_GAP_START+KVM_32BIT_GAP_SIZE;
		kvm_region.memory_size = guest_size - KVM_32BIT_GAP_SIZE - KVM_32BIT_GAP_START + GUEST_OFFSET;
		kvm_ioctl(vmfd, KVM_SET_USER_MEMORY_REGION, &kvm_region);
	}

	init_irq_chip();
	if (restart) {
		if (load_checkpoint(guest_mem, path) != 0)
			exit(EXIT_FAILURE);
	} else {
		if (load_kernel(guest_mem, path) != 0)
			exit(EXIT_FAILURE);
	}

	pthread_barrier_init(&barrier, NULL, ncores);
	cpuid = 0;

	// create first CPU, it will be the boot processor by default
	int ret = vcpu_init();

	const char* netif_str = getenv("HERMIT_NETIF");
	if (netif_str)
	{
		// TODO: strncmp for different network interfaces
		// for example tun/tap device or uhyvetap device
		netfd = uhyve_net_init(netif_str);
		if (netfd < 0)
			err(1, "unable to initialized network");
	}

	return ret;
}

int uhyve_loop(int argc, char **argv)
{
	const char* hermit_check = getenv("HERMIT_CHECKPOINT");
	int ts = 0, i = 0;

	/* argv[0] is 'proxy', do not count it */
	uhyve_argc = argc-1;
	uhyve_argv = &argv[1];
	uhyve_envp = environ;
	while(uhyve_envp[i] != NULL)
		i++;
	uhyve_envc = i;

	if (uhyve_argc > MAX_ARGC_ENVC) {
		fprintf(stderr, "uhyve downsiize envc from %d to %d\n", uhyve_argc, MAX_ARGC_ENVC);
		uhyve_argc = MAX_ARGC_ENVC;
	}

	if (uhyve_envc > MAX_ARGC_ENVC-1) {
		fprintf(stderr, "uhyve downsiize envc from %d to %d\n", uhyve_envc, MAX_ARGC_ENVC-1);
		uhyve_envc = MAX_ARGC_ENVC-1;
	}

	if(uhyve_argc > MAX_ARGC_ENVC || uhyve_envc > MAX_ARGC_ENVC) {
		fprintf(stderr, "uhyve cannot forward more than %d command line "
			"arguments or environment variables, please consider increasing "
				"the MAX_ARGC_ENVP cmake argument\n", MAX_ARGC_ENVC);
		return -1;
	}

	if (hermit_check)
		ts = atoi(hermit_check);

	*((uint32_t*) (mboot+0x24)) = ncores;

	// First CPU is special because it will boot the system. Other CPUs will
	// be booted linearily after the first one.
	vcpu_threads[0] = pthread_self();

	// start threads to create VCPUs
	for(size_t i = 1; i < ncores; i++)
		pthread_create(&vcpu_threads[i], NULL, uhyve_thread, (void*) i);

	if (ts > 0)
	{
		struct sigaction sa;
		struct itimerval timer;

		/* Install timer_handler as the signal handler for SIGVTALRM. */
		memset(&sa, 0x00, sizeof(sa));
		sa.sa_handler = &timer_handler;
		sigaction(SIGALRM, &sa, NULL);

		/* Configure the timer to expire after "ts" sec... */
		timer.it_value.tv_sec = ts;
		timer.it_value.tv_usec = 0;
		/* ... and every "ts" sec after that. */
		timer.it_interval.tv_sec = ts;
		timer.it_interval.tv_usec = 0;
		/* Start a virtual timer. It counts down whenever this process is executing. */
		setitimer(ITIMER_REAL, &timer, NULL);
	}

	// Run first CPU
	return vcpu_loop();
}
