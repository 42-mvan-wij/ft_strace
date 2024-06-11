#define _GNU_SOURCE

#include <errno.h>
#include <string.h>
#include <stdbool.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
// #include <linux/signal.h>
#include <sys/ptrace.h>

#include <signal.h>
#include <sys/syscall.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/reg.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/uio.h>
#include <elf.h>
#include <sys/procfs.h>

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "syscallent.h"

void print_syscall_call(pid_t pid) {
	struct iovec iov;
	struct user_regs_struct r;
	iov.iov_base = &r;
	iov.iov_len = sizeof(r);
	ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov);

	_print_syscall_entry(r, pid);
}

void print_syscall_result(pid_t pid) {
	struct iovec iov;
	union {
		struct user_regs_struct x86_64;
		struct i386_user_regs_struct i386;
	} r;
	iov.iov_base = &r;
	iov.iov_len = sizeof(r);
	ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov);
	if (iov.iov_len == sizeof(r.i386)) {
		assert(((void)"TODO:", 0));
	}

	_print_syscall_return(r.x86_64, pid);
}

void handle_syscall(pid_t pid) {
	print_syscall_call(pid); // NOTE:

	ptrace(PTRACE_SYSCALL, pid, NULL, NULL);

	int wait_status2;
	waitpid(pid, &wait_status2, 0);
	if (WIFEXITED(wait_status2)) {
		exit(EXIT_SUCCESS);
	}
	if (WSTOPSIG(wait_status2) == (SIGTRAP|0x80)) {
	}
	else {
		printf("2. Unexpected stop signal: %i\n", WSTOPSIG(wait_status2));
		return;
	}

	print_syscall_result(pid);
}

char const *get_signal_name(int signum) {
	switch (signum) {
		case SIGABRT:   return "SIGABRT";
		case SIGALRM:   return "SIGALRM";
		case SIGBUS:    return "SIGBUS";
		case SIGCHLD:   return "SIGCHLD";
		// case SIGCLD:    return "SIGCLD";
		case SIGCONT:   return "SIGCONT";
		// case SIGEMT:    return "SIGEMT";
		case SIGFPE:    return "SIGFPE";
		case SIGHUP:    return "SIGHUP";
		case SIGILL:    return "SIGILL";
		// case SIGINFO:   return "SIGINFO";
		case SIGINT:    return "SIGINT";
		// case SIGIO:     return "SIGIO";
		// case SIGIOT:    return "SIGIOT";
		case SIGKILL:   return "SIGKILL";
		// case SIGLOST:   return "SIGLOST";
		case SIGPIPE:   return "SIGPIPE";
		case SIGPOLL:   return "SIGPOLL";
		case SIGPROF:   return "SIGPROF";
		case SIGPWR:    return "SIGPWR";
		case SIGQUIT:   return "SIGQUIT";
		case SIGSEGV:   return "SIGSEGV";
		case SIGSTKFLT: return "SIGSTKFLT";
		case SIGSTOP:   return "SIGSTOP";
		case SIGTSTP:   return "SIGTSTP";
		case SIGSYS:    return "SIGSYS";
		case SIGTERM:   return "SIGTERM";
		case SIGTRAP:   return "SIGTRAP";
		case SIGTTIN:   return "SIGTTIN";
		case SIGTTOU:   return "SIGTTOU";
		// case SIGUNUSED: return "SIGUNUSED";
		case SIGURG:    return "SIGURG";
		case SIGUSR1:   return "SIGUSR1";
		case SIGUSR2:   return "SIGUSR2";
		case SIGVTALRM: return "SIGVTALRM";
		case SIGXCPU:   return "SIGXCPU";
		case SIGXFSZ:   return "SIGXFSZ";
		case SIGWINCH:  return "SIGWINCH";
	}
	return "UNKNOWN_SIGNAL";
}

char const *get_signal_code_name(int signum, int si_code) {
	switch (si_code) {
		case SI_USER:    return "SI_USER";
		case SI_KERNEL:  return "SI_KERNEL";
		case SI_QUEUE:   return "SI_QUEUE";
		case SI_TIMER:   return "SI_TIMER";
		case SI_MESGQ:   return "SI_MESGQ";
		case SI_ASYNCIO: return "SI_ASYNCIO";
		case SI_SIGIO:   return "SI_SIGIO";
		case SI_TKILL:   return "SI_TKILL";
	}
	switch (signum) {
		case SIGILL:
			switch (si_code) {
				case ILL_ILLOPC: return "ILL_ILLOPC";
				case ILL_ILLOPN: return "ILL_ILLOPN";
				case ILL_ILLADR: return "ILL_ILLADR";
				case ILL_ILLTRP: return "ILL_ILLTRP";
				case ILL_PRVOPC: return "ILL_PRVOPC";
				case ILL_PRVREG: return "ILL_PRVREG";
				case ILL_COPROC: return "ILL_COPROC";
				case ILL_BADSTK: return "ILL_BADSTK";
			}
			break;
		case SIGFPE:
			switch (si_code) {
				case FPE_INTDIV: return "FPE_INTDIV";
				case FPE_INTOVF: return "FPE_INTOVF";
				case FPE_FLTDIV: return "FPE_FLTDIV";
				case FPE_FLTOVF: return "FPE_FLTOVF";
				case FPE_FLTUND: return "FPE_FLTUND";
				case FPE_FLTRES: return "FPE_FLTRES";
				case FPE_FLTINV: return "FPE_FLTINV";
				case FPE_FLTSUB: return "FPE_FLTSUB";
			}
			break;
		case SIGSEGV:
			switch (si_code) {
				case SEGV_MAPERR: return "SEGV_MAPERR";
				case SEGV_ACCERR: return "SEGV_ACCERR";
				case SEGV_BNDERR: return "SEGV_BNDERR";
				case SEGV_PKUERR: return "SEGV_PKUERR";
			}
			break;
		case SIGBUS:
			switch (si_code) {
				case BUS_ADRALN:    return "BUS_ADRALN";
				case BUS_ADRERR:    return "BUS_ADRERR";
				case BUS_OBJERR:    return "BUS_OBJERR";
				case BUS_MCEERR_AR: return "BUS_MCEERR_AR";
				case BUS_MCEERR_AO: return "BUS_MCEERR_AO";
			}
			break;
		case SIGTRAP:
			switch (si_code) {
				case TRAP_BRKPT:  return "TRAP_BRKPT";
				case TRAP_TRACE:  return "TRAP_TRACE";
				case TRAP_BRANCH: return "TRAP_BRANCH";
				case TRAP_HWBKPT: return "TRAP_HWBKPT";
			}
			break;
		case SIGCHLD:
			switch (si_code) {
				case CLD_EXITED:    return "CLD_EXITED";
				case CLD_KILLED:    return "CLD_KILLED";
				case CLD_DUMPED:    return "CLD_DUMPED";
				case CLD_TRAPPED:   return "CLD_TRAPPED";
				case CLD_STOPPED:   return "CLD_STOPPED";
				case CLD_CONTINUED: return "CLD_CONTINUED";
			}
			break;
		case SIGPOLL:
			switch (si_code) {
				case POLL_IN:  return "POLL_IN";
				case POLL_OUT: return "POLL_OUT";
				case POLL_MSG: return "POLL_MSG";
				case POLL_ERR: return "POLL_ERR";
				case POLL_PRI: return "POLL_PRI";
				case POLL_HUP: return "POLL_HUP";
			}
			break;
		// case SIGSYS:
		// 	switch (si_code) {
		// 		case SYS_SECCOMP: return "SYS_SECCOMP";
		// 	}
		// 	break;
	}
	return "UNKNOWN_SIGNAL_CODE";
}

void print_siginfo(siginfo_t *si) {
	int signum = si->si_signo;
	int si_code = si->si_code;

	char const *signal_name = get_signal_name(signum);

	printf("--- %s {si_signo=%s, si_code=%s", signal_name, signal_name, get_signal_code_name(signum, si_code));
	if (si_code == SI_USER) {
		printf(", si_pid=%i, si_uid=%i", si->si_pid, si->si_uid);
	}
	if (si_code == SI_QUEUE) {
		printf(", si_pid=%i, si_uid=%i, si_int=%i, si_ptr=%p", si->si_pid, si->si_uid, si->si_int, si->si_ptr);
	}
	if (si_code == SI_TIMER) {
		printf(", si_overrun=%i, si_timerid=%i, si_int=%i, si_ptr=%p", si->si_overrun, si->si_timerid, si->si_int, si->si_ptr);
	}
// * Signals sent for message queue notification (see the description of SIGEV_SIG‐
//   NAL  in  mq_notify(3)) fill in si_int/si_ptr, with the sigev_value supplied to
//   mq_notify(3); si_pid, with the process ID of the message sender;  and  si_uid,
//   with the real user ID of the message sender.
	if (signum == SIGILL || signum == SIGFPE || signum == SIGSEGV || signum == SIGBUS || signum == SIGTRAP) {
		printf(", si_addr=%p", si->si_addr);
		// printf(", si_trapno=%p", siginfo->si_trapno);
	}
	if (signum == SIGBUS) {
		if (si_code == BUS_MCEERR_AO || si_code == BUS_MCEERR_AR) {
			printf(", si_addr_lsb=%i", si->si_addr_lsb);
// When SIGTRAP is delivered in response to a ptrace(2) event (PTRACE_EVENT_foo),
// si_addr is not populated, but si_pid and si_uid are populated with the respec‐
// tive  process ID and user ID responsible for delivering the trap.  In the case
// of seccomp(2), the tracee will be shown as delivering the event.  BUS_MCEERR_*
// and si_addr_lsb are Linux-specific extensions.
		}
	}
	if (signum == SIGSEGV) {
		if (si_code == SEGV_BNDERR) {
			printf(", si_lower=%p, si_upper=%p", si->si_lower, si->si_upper);
		}
		if (si_code == SEGV_PKUERR) {
			printf(", si_pkey=%i", si->si_pkey);
		}
	}
	if (signum == SIGPOLL) {
		printf(", si_band=%li, si_fd=%i", si->si_band, si->si_fd);
	}
	if (signum == SIGSYS) {
// * SIGSYS,  generated  (since  Linux  3.5)  when  a  seccomp  filter returns SEC‐
//   COMP_RET_TRAP, fills in si_call_addr, si_syscall, si_arch, si_errno, and other
//   fields as described in seccomp(2).
	}
	printf("} ---\n");
}

pid_t start_tracee(char **args, char **envp) {
	// TODO: check return values
	pid_t pid = fork();
	if (pid < 0) {
		// TODO: error
	}
	if (pid == 0) {
		raise(SIGSTOP);
		execve(args[0], args, envp);
		exit(EXIT_FAILURE);
	}
	return pid;
}

typedef struct {
	bool started;
	enum {
		WAIT_FOR_RETURN,
		WAIT_FOR_ENTRY,
	} syscall_state;
} tracing_state_t;

void handle_x86_64_syscall(pid_t pid, tracing_state_t *state, struct user_regs_struct *regs) {
	if (regs->orig_rax == SYS_execve) {
		state->started = true;
	}
	if (!state->started) {
		return;
	}

	if (state->syscall_state == WAIT_FOR_ENTRY && -regs->rax == ENOSYS) {
		// fprintf(stderr, "\nRequesting entry %lli - %lli\n\n", regs->orig_rax, regs->rax);
		struct syscall_ent entry = syscall_ent[regs->orig_rax];

		size_t args[] = {
			regs->rdi,
			regs->rsi,
			regs->rdx,
			regs->r10,
			regs->r8,
			regs->r9
		};
		printf("%s(", entry.name);
		entry.bound_fn.fn(args, pid, entry.bound_fn.bound_arg);
		printf(")");
		state->syscall_state = WAIT_FOR_RETURN;
	}
	else if (state->syscall_state == WAIT_FOR_RETURN) {
		if ((long long)regs->rax < 0) {
			printf(" = -1 %s (%s)\n", get_errno_name(-regs->rax), strerror(-regs->rax));
		}
		else {
			printf(" = %lli\n", regs->rax);
		}
		state->syscall_state = WAIT_FOR_ENTRY;
	}
}

void handle_syscall2(pid_t pid, tracing_state_t *state) {
	struct user_regs_struct x86_64;
	struct iovec iov = {
		.iov_base = &x86_64,
		.iov_len = sizeof(x86_64)
	};

	ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov);
	handle_x86_64_syscall(pid, state, &x86_64);
}

void trace(pid_t pid) {
	siginfo_t si;
	tracing_state_t state = {
		.started = false,
		.syscall_state = WAIT_FOR_ENTRY,
	};
	int signal = 0;
	int status = 0;

	while (true) {
		ptrace(PTRACE_SYSCALL, pid, NULL, signal);
		waitpid(pid, &status, 0);
		// printf(".");
		// fflush(NULL);
		// usleep(100000);
		if (WIFEXITED(status)) {
			break;
		}

		ptrace(PTRACE_GETSIGINFO, pid, NULL, &si);
		// if (si.si_signo != (SIGTRAP | 0x80)) {
		if (WSTOPSIG(status) != (SIGTRAP | 0x80)) {
			signal = si.si_signo;
			if (state.started) {
				print_siginfo(&si);
			}
		}
		else {
			signal = 0;
		}
		handle_syscall2(pid, &state);
	}
	if (state.started && state.syscall_state == WAIT_FOR_RETURN) {
		printf(" = ?\n");
	}
}

int main(int argc, char **argv, char **envp) {
	// TODO: check all ptrace return values
	// TODO: check all return values
	if (argc < 2) {
		// TODO: print_help();
		return EXIT_FAILURE;
	}
	pid_t pid = start_tracee(&argv[1], envp);
	ptrace(PTRACE_SEIZE, pid, NULL, PTRACE_O_TRACESYSGOOD);
	trace(pid);
	return EXIT_SUCCESS;
}

int main_old(int argc, char **argv, char **envp) {
	if (argc < 2) {
		// print_help();
		return EXIT_FAILURE;
	}
	char **command = &argv[1];

	pid_t child = fork();
	if (child == 0) {
		raise(SIGSTOP);
		execve(*command, command, envp);
		exit(EXIT_FAILURE);
	}
	else {
		int deliver_signal = 0;
		printf("tracee pid: %u\n", child);
		int pt = ptrace(PTRACE_SEIZE, child, NULL, PTRACE_O_TRACESYSGOOD);
		int exited = 0;
		while (1) {
			ptrace(PTRACE_SYSCALL, child, NULL, deliver_signal);
			int wait_status;
			waitpid(child, &wait_status, 0);
			if (WIFEXITED(wait_status)) {
				exited = 1;
				break;
			}

			if (WSTOPSIG(wait_status) == (SIGTRAP|0x80)) {
				struct iovec iov;
				struct user_regs_struct r;
				iov.iov_base = &r;
				iov.iov_len = sizeof(r);
				ptrace(PTRACE_GETREGSET, child, NT_PRSTATUS, &iov);
				if (r.orig_rax == SYS_execve) {
					handle_syscall(child);
					break;
				}
			}
		}
		if (!exited) {
			while (1) {
				pt = ptrace(PTRACE_SYSCALL, child, NULL, deliver_signal);
				// printf("| PTRACE_SYSCALL: %u\n", pt);

				// NOTE: https://stackoverflow.com/questions/44959801/cant-make-ptrace-seizedptrace-request-work
				// man ptrace
				// man strace

				int wait_status;
				waitpid(child, &wait_status, 0);
				if (WIFEXITED(wait_status)) {
					break;
				}

				if (WSTOPSIG(wait_status) == (SIGTRAP|0x80)) {
					handle_syscall(child);
				}
				else {
					// printf("1. Unexpected stop signal: %i\n", WSTOPSIG(wait_status));
					siginfo_t siginfo;
					ptrace(PTRACE_GETSIGINFO, child, NULL, &siginfo);
					print_siginfo(&siginfo);
				}

				// printf("wait: %i\n"
				// 		"\tWIFEXITED:    %s\n"
				// 		"\tWEXITSTATUS:  %i\n"
				// 		"\tWIFSIGNALED:  %s\n"
				// 		"\tWTERMSIG:     %i\n"
				// 		"\tWCOREDUMP:    %s\n"
				// 		"\tWIFSTOPPED:   %s\n"
				// 		"\tWSTOPSIG:     %i\n"
				// 		"\tWIFCONTINUED: %s\n",
				// 			wait_status,
				// 			WIFEXITED(wait_status) ? "true" : "false",
				// 			WEXITSTATUS(wait_status),
				// 			WIFSIGNALED(wait_status) ? "true" : "false",
				// 			WTERMSIG(wait_status),
				// 			WCOREDUMP(wait_status) ? "true" : "false",
				// 			WIFSTOPPED(wait_status) ? "true" : "false",
				// 			WSTOPSIG(wait_status),
				// 			WIFCONTINUED(wait_status) ? "true" : "false");
			}
		}
	}
	return EXIT_SUCCESS;
}

// NOTE:
// Since Linux 3.4, PTRACE_SEIZE  can  be  used  instead  of  PTRACE_ATTACH.
// PTRACE_SEIZE  does not stop the attached process.  If you need to stop it
// after attach (or at any other time) without sending it any  signals,  use
// PTRACE_INTERRUPT command.
