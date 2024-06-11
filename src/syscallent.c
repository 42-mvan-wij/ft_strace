#define _GNU_SOURCE
// ^ This is needed to get access to process_vm_readv

#include <fcntl.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <sys/uio.h>
#include <string.h>

#include "syscallent.h"

void print_char(unsigned char c) {
	switch (c) {
		case '\t':
			printf("\\t");
			break;
		case '\n':
			printf("\\n");
			break;
		case '\v':
			printf("\\v");
			break;
		case '\f':
			printf("\\f");
			break;
		case '\r':
			printf("\\r");
			break;
		case '\\':
			printf("\\\\");
			break;
		case '"':
			printf("\\\""); // NOTE: the real strace does not print a backslash
			break;
		default:
			if ((c >= '\0' && c <= '\10') || (c >= '\16' && c <= '\37') || c >= '\177') {
				printf("\\%o", c);
			}
			else {
				printf("%c", c);
			}
			break;
	}
}

void print_str_n(const char *str, size_t n, pid_t pid) {
	char s[32];
	struct iovec local;
	struct iovec remote;

	local.iov_base = s;
	local.iov_len = n < sizeof(s) ? n : sizeof(s);
	remote.iov_base = (void *)str;
	remote.iov_len = n;

	ssize_t nread = process_vm_readv(pid, &local, 1, &remote, 1, 0);
	if (nread != (ssize_t)local.iov_len) {
		printf("\n\nERROR: read: %zi, expected: %zu\n\n", nread, sizeof(s));
		return;
	}
	printf("\"");
	for (size_t i = 0; i < local.iov_len; ++i) {
		print_char(s[i]);
	}
	printf("\"");
	if (sizeof(s) < n) {
		printf("...");
	}
}

void print_str(const char *str, pid_t pid) {
	// print_str_n(str, 11, pid);
	// return;
	char s[32];
	struct iovec local;
	struct iovec remote;

	local.iov_base = s;
	local.iov_len = sizeof(s);
	remote.iov_base = (void *)str;
	remote.iov_len = sizeof(s);

	printf("\"");

	ssize_t nread = process_vm_readv(pid, &local, 1, &remote, 1, 0);
	if (nread != sizeof(s)) {
		printf("\n\nERROR: read: %zi, expected: %zu\n\n", nread, sizeof(s));
		return;
	}
	for (size_t i = 0; i < sizeof(s); ++i) {
		if (s[i] == '\0') {
			printf("\"");
			return;
		}
		print_char(s[i]);
	}

	printf("\"...");
}

void print_arg(size_t arg, enum arg_type arg_type, pid_t pid) {
	switch (arg_type) {
		case UNUSED:
			break;
		case STRING:
			print_str((void*)arg, pid);
			break;
		case USIZE:
			printf("%zu", arg);
			break;
		case SSIZE:
			printf("%zi", arg);
			break;
		case UINT:
			printf("%d", (int)arg);
			break;
		case SINT:
			printf("%u", (int)arg);
			break;
		case PTR:
			printf("%p", (void*)arg);
			break;
	}
}

char const * get_errno_name(long long errno_val) {
	switch (errno_val) {
		case EPERM:           return "EPERM";
		case ENOENT:          return "ENOENT";
		case ESRCH:           return "ESRCH";
		case EINTR:           return "EINTR";
		case EIO:             return "EIO";
		case ENXIO:           return "ENXIO";
		case E2BIG:           return "E2BIG";
		case ENOEXEC:         return "ENOEXEC";
		case EBADF:           return "EBADF";
		case ECHILD:          return "ECHILD";
		case EAGAIN:          return "EAGAIN";
		case ENOMEM:          return "ENOMEM";
		case EACCES:          return "EACCES";
		case EFAULT:          return "EFAULT";
		case ENOTBLK:         return "ENOTBLK";
		case EBUSY:           return "EBUSY";
		case EEXIST:          return "EEXIST";
		case EXDEV:           return "EXDEV";
		case ENODEV:          return "ENODEV";
		case ENOTDIR:         return "ENOTDIR";
		case EISDIR:          return "EISDIR";
		case EINVAL:          return "EINVAL";
		case ENFILE:          return "ENFILE";
		case EMFILE:          return "EMFILE";
		case ENOTTY:          return "ENOTTY";
		case ETXTBSY:         return "ETXTBSY";
		case EFBIG:           return "EFBIG";
		case ENOSPC:          return "ENOSPC";
		case ESPIPE:          return "ESPIPE";
		case EROFS:           return "EROFS";
		case EMLINK:          return "EMLINK";
		case EPIPE:           return "EPIPE";
		case EDOM:            return "EDOM";
		case ERANGE:          return "ERANGE";
		case EDEADLK:         return "EDEADLK";
		case ENAMETOOLONG:    return "ENAMETOOLONG";
		case ENOLCK:          return "ENOLCK";
		case ENOSYS:          return "ENOSYS";
		case ENOTEMPTY:       return "ENOTEMPTY";
		case ELOOP:           return "ELOOP";
		// case EWOULDBLOCK:     return "EWOULDBLOCK";
		case ENOMSG:          return "ENOMSG";
		case EIDRM:           return "EIDRM";
		case ECHRNG:          return "ECHRNG";
		case EL2NSYNC:        return "EL2NSYNC";
		case EL3HLT:          return "EL3HLT";
		case EL3RST:          return "EL3RST";
		case ELNRNG:          return "ELNRNG";
		case EUNATCH:         return "EUNATCH";
		case ENOCSI:          return "ENOCSI";
		case EL2HLT:          return "EL2HLT";
		case EBADE:           return "EBADE";
		case EBADR:           return "EBADR";
		case EXFULL:          return "EXFULL";
		case ENOANO:          return "ENOANO";
		case EBADRQC:         return "EBADRQC";
		case EBADSLT:         return "EBADSLT";
		// case EDEADLOCK:       return "EDEADLOCK";
		case EBFONT:          return "EBFONT";
		case ENOSTR:          return "ENOSTR";
		case ENODATA:         return "ENODATA";
		case ETIME:           return "ETIME";
		case ENOSR:           return "ENOSR";
		case ENONET:          return "ENONET";
		case ENOPKG:          return "ENOPKG";
		case EREMOTE:         return "EREMOTE";
		case ENOLINK:         return "ENOLINK";
		case EADV:            return "EADV";
		case ESRMNT:          return "ESRMNT";
		case ECOMM:           return "ECOMM";
		case EPROTO:          return "EPROTO";
		case EMULTIHOP:       return "EMULTIHOP";
		case EDOTDOT:         return "EDOTDOT";
		case EBADMSG:         return "EBADMSG";
		case EOVERFLOW:       return "EOVERFLOW";
		case ENOTUNIQ:        return "ENOTUNIQ";
		case EBADFD:          return "EBADFD";
		case EREMCHG:         return "EREMCHG";
		case ELIBACC:         return "ELIBACC";
		case ELIBBAD:         return "ELIBBAD";
		case ELIBSCN:         return "ELIBSCN";
		case ELIBMAX:         return "ELIBMAX";
		case ELIBEXEC:        return "ELIBEXEC";
		case EILSEQ:          return "EILSEQ";
		case ERESTART:        return "ERESTART";
		case ESTRPIPE:        return "ESTRPIPE";
		case EUSERS:          return "EUSERS";
		case ENOTSOCK:        return "ENOTSOCK";
		case EDESTADDRREQ:    return "EDESTADDRREQ";
		case EMSGSIZE:        return "EMSGSIZE";
		case EPROTOTYPE:      return "EPROTOTYPE";
		case ENOPROTOOPT:     return "ENOPROTOOPT";
		case EPROTONOSUPPORT: return "EPROTONOSUPPORT";
		case ESOCKTNOSUPPORT: return "ESOCKTNOSUPPORT";
		case EOPNOTSUPP:      return "EOPNOTSUPP";
		case EPFNOSUPPORT:    return "EPFNOSUPPORT";
		case EAFNOSUPPORT:    return "EAFNOSUPPORT";
		case EADDRINUSE:      return "EADDRINUSE";
		case EADDRNOTAVAIL:   return "EADDRNOTAVAIL";
		case ENETDOWN:        return "ENETDOWN";
		case ENETUNREACH:     return "ENETUNREACH";
		case ENETRESET:       return "ENETRESET";
		case ECONNABORTED:    return "ECONNABORTED";
		case ECONNRESET:      return "ECONNRESET";
		case ENOBUFS:         return "ENOBUFS";
		case EISCONN:         return "EISCONN";
		case ENOTCONN:        return "ENOTCONN";
		case ESHUTDOWN:       return "ESHUTDOWN";
		case ETOOMANYREFS:    return "ETOOMANYREFS";
		case ETIMEDOUT:       return "ETIMEDOUT";
		case ECONNREFUSED:    return "ECONNREFUSED";
		case EHOSTDOWN:       return "EHOSTDOWN";
		case EHOSTUNREACH:    return "EHOSTUNREACH";
		case EALREADY:        return "EALREADY";
		case EINPROGRESS:     return "EINPROGRESS";
		case ESTALE:          return "ESTALE";
		case EUCLEAN:         return "EUCLEAN";
		case ENOTNAM:         return "ENOTNAM";
		case ENAVAIL:         return "ENAVAIL";
		case EISNAM:          return "EISNAM";
		case EREMOTEIO:       return "EREMOTEIO";
		case EDQUOT:          return "EDQUOT";
		case ENOMEDIUM:       return "ENOMEDIUM";
		case EMEDIUMTYPE:     return "EMEDIUMTYPE";
		case ECANCELED:       return "ECANCELED";
		case ENOKEY:          return "ENOKEY";
		case EKEYEXPIRED:     return "EKEYEXPIRED";
		case EKEYREVOKED:     return "EKEYREVOKED";
		case EKEYREJECTED:    return "EKEYREJECTED";
		case EOWNERDEAD:      return "EOWNERDEAD";
		case ENOTRECOVERABLE: return "ENOTRECOVERABLE";
		case ERFKILL:         return "ERFKILL";
		case EHWPOISON:       return "EHWPOISON";
		// case ENOTSUP:         return "ENOTSUP";

		case ERESTARTSYS:           return "ERESTARTSYS";
		case ERESTARTNOINTR:        return "ERESTARTNOINTR";
		case ERESTARTNOHAND:        return "ERESTARTNOHAND";
		case ENOIOCTLCMD:           return "ENOIOCTLCMD";
		case ERESTART_RESTARTBLOCK: return "ERESTART_RESTARTBLOCK";
		case EPROBE_DEFER:          return "EPROBE_DEFER";
		case EOPENSTALE:            return "EOPENSTALE";
		case ENOPARAM:              return "ENOPARAM";
	}
	return "*UNKOWN*";
}

void _print_syscall_entry(struct user_regs_struct regs, pid_t pid) {
	struct syscall_ent entry = syscall_ent[regs.orig_rax];
	size_t args[] = {
		regs.rdi,
		regs.rsi,
		regs.rdx,
		regs.r10,
		regs.r8,
		regs.r9
	};
	printf("%s(", entry.name);
	entry.bound_fn.fn(args, pid, entry.bound_fn.bound_arg);
	printf(")");
}

void _print_syscall_return(struct user_regs_struct regs, pid_t pid) {
	(void)pid;
	// struct syscall_ent entry = syscall_ent[regs.orig_rax];
	if ((long long int)regs.rax < 0) {
		printf(" = -1 %s (%s)\n", get_errno_name(-regs.rax), strerror(-regs.rax));
	}
	else {
		printf(" = %lli\n", regs.rax);
	}
}

void print_syscall(struct user_regs_struct regs, pid_t pid) {
	struct syscall_ent entry = syscall_ent[regs.orig_rax];
	size_t args[] = {
		regs.rdi,
		regs.rsi,
		regs.rdx,
		regs.r10,
		regs.r8,
		regs.r9
	};

	printf("%s(", entry.name);
	entry.bound_fn.fn(args, pid, entry.bound_fn.bound_arg);
	printf(") = %lli", regs.rax);
	if ((long long int)regs.rax < 0) {
		printf(" NAME (%s)", strerror(-regs.rax));
	}
	printf("\n");
}

#define BASIC(...) ((struct bound_fn){ &basic_print_fn, (enum arg_type[MAX_ARGS]){__VA_ARGS__} })
#define CUSTOM(custom_print_fn) ((struct bound_fn){ &custom_print_fn_caller, (void*)(custom_print_fn) })
#define CUSTOM_WITH_DATA(custom_print_fn, data) ((struct bound_fn){ &(custom_print_fn), (void*)(data) })

void basic_print_fn(size_t args[MAX_ARGS], pid_t pid, void *bound_arg) {
	enum arg_type *arg_types = bound_arg;
	if (arg_types != NULL && arg_types[0] != UNUSED) {
		print_arg(args[0], arg_types[0], pid);
		for (size_t i = 1; i < MAX_ARGS && arg_types[i] != UNUSED; ++i) {
			printf(", ");
			print_arg(args[i], arg_types[i], pid);
		}
	}
}

void custom_print_fn_caller(size_t args[MAX_ARGS], pid_t pid, void *bound_arg) {
	void (*fn)(size_t args[MAX_ARGS], pid_t pid) = bound_arg;
	fn(args, pid);
}

void print_read(size_t args[MAX_ARGS], pid_t pid) {
	print_arg(args[0], UINT, pid);
	printf(", ");
	print_str_n((void*)args[1], args[2], pid);
	printf(", ");
	print_arg(args[2], USIZE, pid);
}

void print_write(size_t args[MAX_ARGS], pid_t pid) {
	print_arg(args[0], UINT, pid);
	printf(", ");
	print_str_n((void*)args[1], args[2], pid);
	printf(", ");
	print_arg(args[2], USIZE, pid);
}

#define DECODE_FLAG_DEFS() int print_pipe = 0
#define HAS_FLAG(flags, f) (((flags) & f) == f)
#define DECODE_FLAG(flags, f) do { if (f != 0 && HAS_FLAG(flags, f)) { if (print_pipe != 0) {printf("|");} printf(#f); print_pipe = 1; } } while(0)
#define DECODE_FLAG_EXACT(flags, f) do { if ((flags) == f) { if (print_pipe != 0) {printf("|");} printf(#f); print_pipe = 1; } } while(0)
#define DECODE_FLAG_ELSE(e) do { if (print_pipe == 0) { print_pipe; } } while(0)
#define DECODE_HAD_MATCH() print_pipe

void print_open_flags(int flags) {
	DECODE_FLAG_DEFS();

	DECODE_FLAG_EXACT(flags & O_ACCMODE, O_RDONLY);
	DECODE_FLAG_EXACT(flags & O_ACCMODE, O_WRONLY);
	DECODE_FLAG_EXACT(flags & O_ACCMODE, O_RDWR);

	DECODE_FLAG(flags, O_APPEND);
	DECODE_FLAG(flags, O_ASYNC);
	DECODE_FLAG(flags, O_CLOEXEC);
	DECODE_FLAG(flags, O_CREAT);
	DECODE_FLAG(flags, O_DIRECT);
	DECODE_FLAG(flags, O_DIRECTORY);
	DECODE_FLAG(flags, O_DSYNC);
	DECODE_FLAG(flags, O_EXCL);
	DECODE_FLAG(flags, O_LARGEFILE);
	DECODE_FLAG(flags, O_NOATIME);
	DECODE_FLAG(flags, O_NOCTTY);
	DECODE_FLAG(flags, O_NOFOLLOW);
	DECODE_FLAG(flags, O_NONBLOCK); // A.K.A. O_NDELAY
	DECODE_FLAG(flags, O_PATH);
	DECODE_FLAG(flags, O_SYNC);
	DECODE_FLAG(flags, O_TMPFILE);
	DECODE_FLAG(flags, O_TRUNC);

	DECODE_FLAG_ELSE(printf("0"));
}

void print_open(size_t args[MAX_ARGS], pid_t pid) {
	print_arg(args[0], STRING, pid);
	printf(", ");
	print_open_flags(args[1]);
	if (HAS_FLAG(args[1], O_CREAT)) {
		printf(", ");
		printf("%03o", (unsigned)args[2]);
	}
}

void print_openat(size_t args[MAX_ARGS], pid_t pid) {
	if ((int)args[0] == AT_FDCWD) {
		printf("AT_FDCWD");
	}
	else {
		print_arg(args[0], SINT, pid);
	}
	printf(", ");
	print_arg(args[1], STRING, pid);
	printf(", ");
	print_open_flags(args[2]);
	if (HAS_FLAG(args[2], O_CREAT)) {
		printf(", ");
		printf("%03o", (unsigned)args[3]);
	}
}

void print_stat_struct(size_t stat_buf, pid_t pid) {
	struct stat statbuf;
	struct iovec local;
	struct iovec remote;

	local.iov_base = &statbuf;
	local.iov_len = sizeof(statbuf);
	remote.iov_base = (void *)stat_buf;
	remote.iov_len = sizeof(statbuf);

	ssize_t nread = process_vm_readv(pid, &local, 1, &remote, 1, 0);
	if (nread != (ssize_t)local.iov_len) {
		printf("ERROR\n");
		return;
	}
	printf("{");
	printf("st_mode=%#03o", statbuf.st_mode);
	printf(",");
	printf("st_rdev=%lX", statbuf.st_rdev); // TODO:
	printf(",");
	printf("...");
	printf("}");
}

void print_stat(size_t args[MAX_ARGS], pid_t pid) {
	print_arg(args[0], STRING, pid);
	print_stat_struct(args[1], pid);
}

const struct syscall_ent syscall_ent[] = {
[  0] = { CUSTOM(&print_read),                              "read"                    },
[  1] = { CUSTOM(&print_write),                             "write"                   },
[  2] = { BASIC(STRING, USIZE, USIZE                     ), "open"                    },
[  3] = { BASIC( USIZE                                   ), "close"                   },
[  4] = { BASIC(STRING, USIZE                            ), "stat"                    },
[  5] = { BASIC( USIZE, USIZE                            ), "fstat"                   },
[  6] = { BASIC( USIZE, USIZE                            ), "lstat"                   },
[  7] = { BASIC( USIZE, USIZE, USIZE                     ), "poll"                    },
[  8] = { BASIC( USIZE, USIZE, USIZE                     ), "lseek"                   },
[  9] = { BASIC( USIZE, USIZE, USIZE, USIZE, USIZE, USIZE), "mmap"                    },
[ 10] = { BASIC( USIZE, USIZE, USIZE                     ), "mprotect"                },
[ 11] = { BASIC( USIZE, USIZE                            ), "munmap"                  },
[ 12] = { BASIC( USIZE                                   ), "brk"                     },
[ 13] = { BASIC( USIZE, USIZE, USIZE, USIZE              ), "rt_sigaction"            },
[ 14] = { BASIC( USIZE, USIZE, USIZE, USIZE              ), "rt_sigprocmask"          },
[ 15] = { BASIC(                                         ), "rt_sigreturn"            },
[ 16] = { BASIC( USIZE, USIZE, USIZE                     ), "ioctl"                   },
[ 17] = { BASIC( USIZE, USIZE, USIZE, USIZE              ), "pread64"                 },
[ 18] = { BASIC( USIZE, USIZE, USIZE, USIZE              ), "pwrite64"                },
[ 19] = { BASIC( USIZE, USIZE, USIZE                     ), "readv"                   },
[ 20] = { BASIC( USIZE, USIZE, USIZE                     ), "writev"                  },
[ 21] = { BASIC( USIZE, USIZE                            ), "access"                  },
[ 22] = { BASIC( USIZE                                   ), "pipe"                    },
[ 23] = { BASIC( USIZE, USIZE, USIZE, USIZE, USIZE       ), "select"                  },
[ 24] = { BASIC(                                         ), "sched_yield"             },
[ 25] = { BASIC( USIZE, USIZE, USIZE, USIZE, USIZE       ), "mremap"                  },
[ 26] = { BASIC( USIZE, USIZE, USIZE                     ), "msync"                   },
[ 27] = { BASIC( USIZE, USIZE, USIZE                     ), "mincore"                 },
[ 28] = { BASIC( USIZE, USIZE, USIZE                     ), "madvise"                 },
[ 29] = { BASIC( USIZE, USIZE, USIZE                     ), "shmget"                  },
[ 30] = { BASIC( USIZE, USIZE, USIZE                     ), "shmat"                   },
[ 31] = { BASIC( USIZE, USIZE, USIZE                     ), "shmctl"                  },
[ 32] = { BASIC( USIZE                                   ), "dup"                     },
[ 33] = { BASIC( USIZE, USIZE                            ), "dup2"                    },
[ 34] = { BASIC(                                         ), "pause"                   },
[ 35] = { BASIC( USIZE, USIZE                            ), "nanosleep"               },
[ 36] = { BASIC( USIZE, USIZE                            ), "getitimer"               },
[ 37] = { BASIC( USIZE                                   ), "alarm"                   },
[ 38] = { BASIC( USIZE, USIZE, USIZE                     ), "setitimer"               },
[ 39] = { BASIC(                                         ), "getpid"                  },
[ 40] = { BASIC( USIZE, USIZE, USIZE, USIZE              ), "sendfile"                },
[ 41] = { BASIC( USIZE, USIZE, USIZE                     ), "socket"                  },
[ 42] = { BASIC( USIZE, USIZE, USIZE                     ), "connect"                 },
[ 43] = { BASIC( USIZE, USIZE, USIZE                     ), "accept"                  },
[ 44] = { BASIC( USIZE, USIZE, USIZE, USIZE, USIZE, USIZE), "sendto"                  },
[ 45] = { BASIC( USIZE, USIZE, USIZE, USIZE, USIZE, USIZE), "recvfrom"                },
[ 46] = { BASIC( USIZE, USIZE, USIZE                     ), "sendmsg"                 },
[ 47] = { BASIC( USIZE, USIZE, USIZE                     ), "recvmsg"                 },
[ 48] = { BASIC( USIZE, USIZE                            ), "shutdown"                },
[ 49] = { BASIC( USIZE, USIZE, USIZE                     ), "bind"                    },
[ 50] = { BASIC( USIZE, USIZE                            ), "listen"                  },
[ 51] = { BASIC( USIZE, USIZE, USIZE                     ), "getsockname"             },
[ 52] = { BASIC( USIZE, USIZE, USIZE                     ), "getpeername"             },
[ 53] = { BASIC( USIZE, USIZE, USIZE, USIZE              ), "socketpair"              },
[ 54] = { BASIC( USIZE, USIZE, USIZE, USIZE, USIZE       ), "setsockopt"              },
[ 55] = { BASIC( USIZE, USIZE, USIZE, USIZE, USIZE       ), "getsockopt"              },
[ 56] = { BASIC( USIZE, USIZE, USIZE, USIZE, USIZE       ), "clone"                   },
[ 57] = { BASIC(                                         ), "fork"                    },
[ 58] = { BASIC(                                         ), "vfork"                   },
[ 59] = { BASIC(STRING, USIZE,   PTR                     ), "execve"                  },
[ 60] = { BASIC( USIZE                                   ), "exit"                    },
[ 61] = { BASIC( USIZE, USIZE, USIZE, USIZE              ), "wait4"                   },
[ 62] = { BASIC( USIZE, USIZE                            ), "kill"                    },
[ 63] = { BASIC( USIZE                                   ), "uname"                   },
[ 64] = { BASIC( USIZE, USIZE, USIZE                     ), "semget"                  },
[ 65] = { BASIC( USIZE, USIZE, USIZE                     ), "semop"                   },
[ 66] = { BASIC( USIZE, USIZE, USIZE, USIZE              ), "semctl"                  },
[ 67] = { BASIC( USIZE                                   ), "shmdt"                   },
[ 68] = { BASIC( USIZE, USIZE                            ), "msgget"                  },
[ 69] = { BASIC( USIZE, USIZE, USIZE, USIZE              ), "msgsnd"                  },
[ 70] = { BASIC( USIZE, USIZE, USIZE, USIZE, USIZE       ), "msgrcv"                  },
[ 71] = { BASIC( USIZE, USIZE, USIZE                     ), "msgctl"                  },
[ 72] = { BASIC( USIZE, USIZE, USIZE                     ), "fcntl"                   },
[ 73] = { BASIC( USIZE, USIZE                            ), "flock"                   },
[ 74] = { BASIC( USIZE                                   ), "fsync"                   },
[ 75] = { BASIC( USIZE                                   ), "fdatasync"               },
[ 76] = { BASIC( USIZE, USIZE                            ), "truncate"                },
[ 77] = { BASIC( USIZE, USIZE                            ), "ftruncate"               },
[ 78] = { BASIC( USIZE, USIZE, USIZE                     ), "getdents"                },
[ 79] = { BASIC( USIZE, USIZE                            ), "getcwd"                  },
[ 80] = { BASIC( USIZE                                   ), "chdir"                   },
[ 81] = { BASIC( USIZE                                   ), "fchdir"                  },
[ 82] = { BASIC( USIZE, USIZE                            ), "rename"                  },
[ 83] = { BASIC( USIZE, USIZE                            ), "mkdir"                   },
[ 84] = { BASIC( USIZE                                   ), "rmdir"                   },
[ 85] = { BASIC( USIZE, USIZE                            ), "creat"                   },
[ 86] = { BASIC( USIZE, USIZE                            ), "link"                    },
[ 87] = { BASIC( USIZE                                   ), "unlink"                  },
[ 88] = { BASIC( USIZE, USIZE                            ), "symlink"                 },
[ 89] = { BASIC( USIZE, USIZE, USIZE                     ), "readlink"                },
[ 90] = { BASIC( USIZE, USIZE                            ), "chmod"                   },
[ 91] = { BASIC( USIZE, USIZE                            ), "fchmod"                  },
[ 92] = { BASIC( USIZE, USIZE, USIZE                     ), "chown"                   },
[ 93] = { BASIC( USIZE, USIZE, USIZE                     ), "fchown"                  },
[ 94] = { BASIC( USIZE, USIZE, USIZE                     ), "lchown"                  },
[ 95] = { BASIC( USIZE                                   ), "umask"                   },
[ 96] = { BASIC( USIZE, USIZE                            ), "gettimeofday"            },
[ 97] = { BASIC( USIZE, USIZE                            ), "getrlimit"               },
[ 98] = { BASIC( USIZE, USIZE                            ), "getrusage"               },
[ 99] = { BASIC( USIZE                                   ), "sysinfo"                 },
[100] = { BASIC( USIZE                                   ), "times"                   },
[101] = { BASIC( USIZE, USIZE, USIZE, USIZE              ), "ptrace"                  },
[102] = { BASIC(                                         ), "getuid"                  },
[103] = { BASIC( USIZE, USIZE, USIZE                     ), "syslog"                  },
[104] = { BASIC(                                         ), "getgid"                  },
[105] = { BASIC( USIZE                                   ), "setuid"                  },
[106] = { BASIC( USIZE                                   ), "setgid"                  },
[107] = { BASIC(                                         ), "geteuid"                 },
[108] = { BASIC(                                         ), "getegid"                 },
[109] = { BASIC( USIZE, USIZE                            ), "setpgid"                 },
[110] = { BASIC(                                         ), "getppid"                 },
[111] = { BASIC(                                         ), "getpgrp"                 },
[112] = { BASIC(                                         ), "setsid"                  },
[113] = { BASIC( USIZE, USIZE                            ), "setreuid"                },
[114] = { BASIC( USIZE, USIZE                            ), "setregid"                },
[115] = { BASIC( USIZE, USIZE                            ), "getgroups"               },
[116] = { BASIC( USIZE, USIZE                            ), "setgroups"               },
[117] = { BASIC( USIZE, USIZE, USIZE                     ), "setresuid"               },
[118] = { BASIC( USIZE, USIZE, USIZE                     ), "getresuid"               },
[119] = { BASIC( USIZE, USIZE, USIZE                     ), "setresgid"               },
[120] = { BASIC( USIZE, USIZE, USIZE                     ), "getresgid"               },
[121] = { BASIC( USIZE                                   ), "getpgid"                 },
[122] = { BASIC( USIZE                                   ), "setfsuid"                },
[123] = { BASIC( USIZE                                   ), "setfsgid"                },
[124] = { BASIC( USIZE                                   ), "getsid"                  },
[125] = { BASIC( USIZE, USIZE                            ), "capget"                  },
[126] = { BASIC( USIZE, USIZE                            ), "capset"                  },
[127] = { BASIC( USIZE, USIZE                            ), "rt_sigpending"           },
[128] = { BASIC( USIZE, USIZE, USIZE, USIZE              ), "rt_sigtimedwait"         },
[129] = { BASIC( USIZE, USIZE, USIZE                     ), "rt_sigqueueinfo"         },
[130] = { BASIC( USIZE, USIZE                            ), "rt_sigsuspend"           },
[131] = { BASIC( USIZE, USIZE                            ), "sigaltstack"             },
[132] = { BASIC( USIZE, USIZE                            ), "utime"                   },
[133] = { BASIC( USIZE, USIZE, USIZE                     ), "mknod"                   },
[134] = { BASIC( USIZE                                   ), "uselib"                  },
[135] = { BASIC( USIZE                                   ), "personality"             },
[136] = { BASIC( USIZE, USIZE                            ), "ustat"                   },
[137] = { BASIC( USIZE, USIZE                            ), "statfs"                  },
[138] = { BASIC( USIZE, USIZE                            ), "fstatfs"                 },
[139] = { BASIC( USIZE, USIZE, USIZE                     ), "sysfs"                   },
[140] = { BASIC( USIZE, USIZE                            ), "getpriority"             },
[141] = { BASIC( USIZE, USIZE, USIZE                     ), "setpriority"             },
[142] = { BASIC( USIZE, USIZE                            ), "sched_setparam"          },
[143] = { BASIC( USIZE, USIZE                            ), "sched_getparam"          },
[144] = { BASIC( USIZE, USIZE, USIZE                     ), "sched_setscheduler"      },
[145] = { BASIC( USIZE                                   ), "sched_getscheduler"      },
[146] = { BASIC( USIZE                                   ), "sched_get_priority_max"  },
[147] = { BASIC( USIZE                                   ), "sched_get_priority_min"  },
[148] = { BASIC( USIZE, USIZE                            ), "sched_rr_get_interval"   },
[149] = { BASIC( USIZE, USIZE                            ), "mlock"                   },
[150] = { BASIC( USIZE, USIZE                            ), "munlock"                 },
[151] = { BASIC( USIZE                                   ), "mlockall"                },
[152] = { BASIC(                                         ), "munlockall"              },
[153] = { BASIC(                                         ), "vhangup"                 },
[154] = { BASIC( USIZE, USIZE, USIZE                     ), "modify_ldt"              },
[155] = { BASIC( USIZE, USIZE                            ), "pivot_root"              },
[156] = { BASIC( USIZE                                   ), "_sysctl"                 },
[157] = { BASIC( USIZE, USIZE, USIZE, USIZE, USIZE       ), "prctl"                   },
[158] = { BASIC( USIZE, USIZE                            ), "arch_prctl"              },
[159] = { BASIC( USIZE                                   ), "adjtimex"                },
[160] = { BASIC( USIZE, USIZE                            ), "setrlimit"               },
[161] = { BASIC( USIZE                                   ), "chroot"                  },
[162] = { BASIC(                                         ), "sync"                    },
[163] = { BASIC( USIZE                                   ), "acct"                    },
[164] = { BASIC( USIZE, USIZE                            ), "settimeofday"            },
[165] = { BASIC( USIZE, USIZE, USIZE, USIZE, USIZE       ), "mount"                   },
[166] = { BASIC( USIZE, USIZE                            ), "umount2"                 },
[167] = { BASIC( USIZE, USIZE                            ), "swapon"                  },
[168] = { BASIC( USIZE                                   ), "swapoff"                 },
[169] = { BASIC( USIZE, USIZE, USIZE, USIZE              ), "reboot"                  },
[170] = { BASIC( USIZE, USIZE                            ), "sethostname"             },
[171] = { BASIC( USIZE, USIZE                            ), "setdomainname"           },
[172] = { BASIC( USIZE                                   ), "iopl"                    },
[173] = { BASIC( USIZE, USIZE, USIZE                     ), "ioperm"                  },
[174] = { BASIC( USIZE, USIZE                            ), "create_module"           },
[175] = { BASIC( USIZE, USIZE, USIZE                     ), "init_module"             },
[176] = { BASIC( USIZE, USIZE                            ), "delete_module"           },
[177] = { BASIC( USIZE                                   ), "get_kernel_syms"         },
[178] = { BASIC( USIZE, USIZE, USIZE, USIZE, USIZE       ), "query_module"            },
[179] = { BASIC( USIZE, USIZE, USIZE, USIZE              ), "quotactl"                },
[180] = { BASIC( USIZE, USIZE, USIZE                     ), "nfsservctl"              },
[181] = { BASIC( USIZE, USIZE, USIZE, USIZE, USIZE       ), "getpmsg"                 },
[182] = { BASIC( USIZE, USIZE, USIZE, USIZE, USIZE       ), "putpmsg"                 },
[183] = { BASIC( USIZE, USIZE, USIZE, USIZE, USIZE       ), "afs_syscall"             },
[184] = { BASIC( USIZE, USIZE, USIZE                     ), "tuxcall"                 },
[185] = { BASIC( USIZE, USIZE, USIZE                     ), "security"                },
[186] = { BASIC(                                         ), "gettid"                  },
[187] = { BASIC( USIZE, USIZE, USIZE                     ), "readahead"               },
[188] = { BASIC( USIZE, USIZE, USIZE, USIZE, USIZE       ), "setxattr"                },
[189] = { BASIC( USIZE, USIZE, USIZE, USIZE, USIZE       ), "lsetxattr"               },
[190] = { BASIC( USIZE, USIZE, USIZE, USIZE, USIZE       ), "fsetxattr"               },
[191] = { BASIC( USIZE, USIZE, USIZE, USIZE              ), "getxattr"                },
[192] = { BASIC( USIZE, USIZE, USIZE, USIZE              ), "lgetxattr"               },
[193] = { BASIC( USIZE, USIZE, USIZE, USIZE              ), "fgetxattr"               },
[194] = { BASIC( USIZE, USIZE, USIZE                     ), "listxattr"               },
[195] = { BASIC( USIZE, USIZE, USIZE                     ), "llistxattr"              },
[196] = { BASIC( USIZE, USIZE, USIZE                     ), "flistxattr"              },
[197] = { BASIC( USIZE, USIZE                            ), "removexattr"             },
[198] = { BASIC( USIZE, USIZE                            ), "lremovexattr"            },
[199] = { BASIC( USIZE, USIZE                            ), "fremovexattr"            },
[200] = { BASIC( USIZE, USIZE                            ), "tkill"                   },
[201] = { BASIC( USIZE                                   ), "time"                    },
[202] = { BASIC( USIZE, USIZE, USIZE, USIZE, USIZE, USIZE), "futex"                   },
[203] = { BASIC( USIZE, USIZE, USIZE                     ), "sched_setaffinity"       },
[204] = { BASIC( USIZE, USIZE, USIZE                     ), "sched_getaffinity"       },
[205] = { BASIC( USIZE                                   ), "set_thread_area"         },
[206] = { BASIC( USIZE, USIZE                            ), "io_setup"                },
[207] = { BASIC( USIZE                                   ), "io_destroy"              },
[208] = { BASIC( USIZE, USIZE, USIZE, USIZE, USIZE       ), "io_getevents"            },
[209] = { BASIC( USIZE, USIZE, USIZE                     ), "io_submit"               },
[210] = { BASIC( USIZE, USIZE, USIZE                     ), "io_cancel"               },
[211] = { BASIC( USIZE                                   ), "get_thread_area"         },
[212] = { BASIC( USIZE, USIZE, USIZE                     ), "lookup_dcookie"          },
[213] = { BASIC( USIZE                                   ), "epoll_create"            },
[214] = { BASIC( USIZE, USIZE, USIZE, USIZE              ), "epoll_ctl_old"           },
[215] = { BASIC( USIZE, USIZE, USIZE, USIZE              ), "epoll_wait_old"          },
[216] = { BASIC( USIZE, USIZE, USIZE, USIZE, USIZE       ), "remap_file_pages"        },
[217] = { BASIC( USIZE, USIZE, USIZE                     ), "getdents64"              },
[218] = { BASIC(   PTR                                   ), "set_tid_address"         },
[219] = { BASIC(                                         ), "restart_syscall"         },
[220] = { BASIC( USIZE, USIZE, USIZE, USIZE              ), "semtimedop"              },
[221] = { BASIC( USIZE, USIZE, USIZE, USIZE              ), "fadvise64"               },
[222] = { BASIC( USIZE, USIZE, USIZE                     ), "timer_create"            },
[223] = { BASIC( USIZE, USIZE, USIZE, USIZE              ), "timer_settime"           },
[224] = { BASIC( USIZE, USIZE                            ), "timer_gettime"           },
[225] = { BASIC( USIZE                                   ), "timer_getoverrun"        },
[226] = { BASIC( USIZE                                   ), "timer_delete"            },
[227] = { BASIC( USIZE, USIZE                            ), "clock_settime"           },
[228] = { BASIC( USIZE, USIZE                            ), "clock_gettime"           },
[229] = { BASIC( USIZE, USIZE                            ), "clock_getres"            },
[230] = { BASIC( USIZE, USIZE, USIZE, USIZE              ), "clock_nanosleep"         },
[231] = { BASIC( USIZE                                   ), "exit_group"              },
[232] = { BASIC( USIZE, USIZE, USIZE, USIZE              ), "epoll_wait"              },
[233] = { BASIC( USIZE, USIZE, USIZE, USIZE              ), "epoll_ctl"               },
[234] = { BASIC( USIZE, USIZE, USIZE                     ), "tgkill"                  },
[235] = { BASIC( USIZE, USIZE                            ), "utimes"                  },
[236] = { BASIC( USIZE, USIZE, USIZE, USIZE, USIZE       ), "vserver"                 },
[237] = { BASIC( USIZE, USIZE, USIZE, USIZE, USIZE, USIZE), "mbind"                   },
[238] = { BASIC( USIZE, USIZE, USIZE                     ), "set_mempolicy"           },
[239] = { BASIC( USIZE, USIZE, USIZE, USIZE, USIZE       ), "get_mempolicy"           },
[240] = { BASIC( USIZE, USIZE, USIZE, USIZE              ), "mq_open"                 },
[241] = { BASIC( USIZE                                   ), "mq_unlink"               },
[242] = { BASIC( USIZE, USIZE, USIZE, USIZE, USIZE       ), "mq_timedsend"            },
[243] = { BASIC( USIZE, USIZE, USIZE, USIZE, USIZE       ), "mq_timedreceive"         },
[244] = { BASIC( USIZE, USIZE                            ), "mq_notify"               },
[245] = { BASIC( USIZE, USIZE, USIZE                     ), "mq_getsetattr"           },
[246] = { BASIC( USIZE, USIZE, USIZE, USIZE              ), "kexec_load"              },
[247] = { BASIC( USIZE, USIZE, USIZE, USIZE, USIZE       ), "waitid"                  },
[248] = { BASIC( USIZE, USIZE, USIZE, USIZE, USIZE       ), "add_key"                 },
[249] = { BASIC( USIZE, USIZE, USIZE, USIZE              ), "request_key"             },
[250] = { BASIC( USIZE, USIZE, USIZE, USIZE, USIZE       ), "keyctl"                  },
[251] = { BASIC( USIZE, USIZE, USIZE                     ), "ioprio_set"              },
[252] = { BASIC( USIZE, USIZE                            ), "ioprio_get"              },
[253] = { BASIC(                                         ), "inotify_init"            },
[254] = { BASIC( USIZE, USIZE, USIZE                     ), "inotify_add_watch"       },
[255] = { BASIC( USIZE, USIZE                            ), "inotify_rm_watch"        },
[256] = { BASIC( USIZE, USIZE, USIZE, USIZE              ), "migrate_pages"           },
[257] = { CUSTOM(&print_openat),                            "openat"                  },
[258] = { BASIC( USIZE, USIZE, USIZE                     ), "mkdirat"                 },
[259] = { BASIC( USIZE, USIZE, USIZE, USIZE              ), "mknodat"                 },
[260] = { BASIC( USIZE, USIZE, USIZE, USIZE, USIZE       ), "fchownat"                },
[261] = { BASIC( USIZE, USIZE, USIZE                     ), "futimesat"               },
[262] = { BASIC( USIZE, USIZE, USIZE, USIZE              ), "newfstatat"              },
[263] = { BASIC( USIZE, USIZE, USIZE                     ), "unlinkat"                },
[264] = { BASIC( USIZE, USIZE, USIZE, USIZE              ), "renameat"                },
[265] = { BASIC( USIZE, USIZE, USIZE, USIZE, USIZE       ), "linkat"                  },
[266] = { BASIC( USIZE, USIZE, USIZE                     ), "symlinkat"               },
[267] = { BASIC( USIZE, USIZE, USIZE, USIZE              ), "readlinkat"              },
[268] = { BASIC( USIZE, USIZE, USIZE                     ), "fchmodat"                },
[269] = { BASIC( USIZE, USIZE, USIZE                     ), "faccessat"               },
[270] = { BASIC( USIZE, USIZE, USIZE, USIZE, USIZE, USIZE), "pselect6"                },
[271] = { BASIC( USIZE, USIZE, USIZE, USIZE, USIZE       ), "ppoll"                   },
[272] = { BASIC( USIZE                                   ), "unshare"                 },
[273] = { BASIC(   PTR, USIZE                            ), "set_robust_list"         },
[274] = { BASIC( USIZE, USIZE, USIZE                     ), "get_robust_list"         },
[275] = { BASIC( USIZE, USIZE, USIZE, USIZE, USIZE, USIZE), "splice"                  },
[276] = { BASIC( USIZE, USIZE, USIZE, USIZE              ), "tee"                     },
[277] = { BASIC( USIZE, USIZE, USIZE, USIZE              ), "sync_file_range"         },
[278] = { BASIC( USIZE, USIZE, USIZE, USIZE              ), "vmsplice"                },
[279] = { BASIC( USIZE, USIZE, USIZE, USIZE, USIZE, USIZE), "move_pages"              },
[280] = { BASIC( USIZE, USIZE, USIZE, USIZE              ), "utimensat"               },
[281] = { BASIC( USIZE, USIZE, USIZE, USIZE, USIZE, USIZE), "epoll_pwait"             },
[282] = { BASIC( USIZE, USIZE, USIZE                     ), "signalfd"                },
[283] = { BASIC( USIZE, USIZE                            ), "timerfd_create"          },
[284] = { BASIC( USIZE                                   ), "eventfd"                 },
[285] = { BASIC( USIZE, USIZE, USIZE, USIZE              ), "fallocate"               },
[286] = { BASIC( USIZE, USIZE, USIZE, USIZE              ), "timerfd_settime"         },
[287] = { BASIC( USIZE, USIZE                            ), "timerfd_gettime"         },
[288] = { BASIC( USIZE, USIZE, USIZE, USIZE              ), "accept4"                 },
[289] = { BASIC( USIZE, USIZE, USIZE, USIZE              ), "signalfd4"               },
[290] = { BASIC( USIZE, USIZE                            ), "eventfd2"                },
[291] = { BASIC( USIZE                                   ), "epoll_create1"           },
[292] = { BASIC( USIZE, USIZE, USIZE                     ), "dup3"                    },
[293] = { BASIC( USIZE, USIZE                            ), "pipe2"                   },
[294] = { BASIC( USIZE                                   ), "inotify_init1"           },
[295] = { BASIC( USIZE, USIZE, USIZE, USIZE              ), "preadv"                  },
[296] = { BASIC( USIZE, USIZE, USIZE, USIZE              ), "pwritev"                 },
[297] = { BASIC( USIZE, USIZE, USIZE, USIZE              ), "rt_tgsigqueueinfo"       },
[298] = { BASIC( USIZE, USIZE, USIZE, USIZE, USIZE       ), "perf_event_open"         },
[299] = { BASIC( USIZE, USIZE, USIZE, USIZE, USIZE       ), "recvmmsg"                },
[300] = { BASIC( USIZE, USIZE                            ), "fanotify_init"           },
[301] = { BASIC( USIZE, USIZE, USIZE, USIZE, USIZE       ), "fanotify_mark"           },
[302] = { BASIC( USIZE, USIZE, USIZE, USIZE              ), "prlimit64"               },
[303] = { BASIC( USIZE, USIZE, USIZE, USIZE, USIZE       ), "name_to_handle_at"       },
[304] = { BASIC( USIZE, USIZE, USIZE                     ), "open_by_handle_at"       },
[305] = { BASIC( USIZE, USIZE                            ), "clock_adjtime"           },
[306] = { BASIC( USIZE                                   ), "syncfs"                  },
[307] = { BASIC( USIZE, USIZE, USIZE, USIZE              ), "sendmmsg"                },
[308] = { BASIC( USIZE, USIZE                            ), "setns"                   },
[309] = { BASIC( USIZE, USIZE, USIZE                     ), "getcpu"                  },
[310] = { BASIC( USIZE, USIZE, USIZE, USIZE, USIZE, USIZE), "process_vm_readv"        },
[311] = { BASIC( USIZE, USIZE, USIZE, USIZE, USIZE, USIZE), "process_vm_writev"       },
[312] = { BASIC( USIZE, USIZE, USIZE, USIZE, USIZE       ), "kcmp"                    },
[313] = { BASIC( USIZE, USIZE, USIZE                     ), "finit_module"            },
[314] = { BASIC( USIZE, USIZE, USIZE                     ), "sched_setattr"           },
[315] = { BASIC( USIZE, USIZE, USIZE, USIZE              ), "sched_getattr"           },
[316] = { BASIC( USIZE, USIZE, USIZE, USIZE, USIZE       ), "renameat2"               },
[317] = { BASIC( USIZE, USIZE, USIZE                     ), "seccomp"                 },
[318] = { BASIC( USIZE, USIZE, USIZE                     ), "getrandom"               },
[319] = { BASIC( USIZE, USIZE                            ), "memfd_create"            },
[320] = { BASIC( USIZE, USIZE, USIZE, USIZE, USIZE       ), "kexec_file_load"         },
[321] = { BASIC( USIZE, USIZE, USIZE                     ), "bpf"                     },
[322] = { BASIC( USIZE, USIZE, USIZE, USIZE, USIZE       ), "execveat"                },
[323] = { BASIC( USIZE                                   ), "userfaultfd"             },
[324] = { BASIC( USIZE, USIZE, USIZE                     ), "membarrier"              },
[325] = { BASIC( USIZE, USIZE, USIZE                     ), "mlock2"                  },
[326] = { BASIC( USIZE, USIZE, USIZE, USIZE, USIZE, USIZE), "copy_file_range"         },
[327] = { BASIC( USIZE, USIZE, USIZE, USIZE, USIZE, USIZE), "preadv2"                 },
[328] = { BASIC( USIZE, USIZE, USIZE, USIZE, USIZE, USIZE), "pwritev2"                },
[329] = { BASIC( USIZE, USIZE, USIZE, USIZE              ), "pkey_mprotect"           },
[330] = { BASIC( USIZE, USIZE                            ), "pkey_alloc"              },
[331] = { BASIC( USIZE                                   ), "pkey_free"               },
[332] = { BASIC( USIZE, USIZE, USIZE, USIZE, USIZE       ), "statx"                   },
[333] = { BASIC( USIZE, USIZE, USIZE, USIZE, USIZE, USIZE), "io_pgetevents"           },
[334] = { BASIC( USIZE, USIZE, USIZE, USIZE              ), "rseq"                    },
[424] = { BASIC(                                         ), "pidfd_send_signal"       },
[425] = { BASIC(                                         ), "io_uring_setup"          },
[426] = { BASIC(                                         ), "io_uring_enter"          },
[427] = { BASIC(                                         ), "io_uring_register"       },
[428] = { BASIC(                                         ), "open_tree"               },
[429] = { BASIC(                                         ), "move_mount"              },
[430] = { BASIC(                                         ), "fsopen"                  },
[431] = { BASIC(                                         ), "fsconfig"                },
[432] = { BASIC(                                         ), "fsmount"                 },
[433] = { BASIC(                                         ), "fspick"                  },
[434] = { BASIC(                                         ), "pidfd_open"              },
[435] = { BASIC(                                         ), "clone3"                  },
[436] = { BASIC(                                         ), "close_range"             },
[437] = { BASIC(                                         ), "openat2"                 },
[438] = { BASIC(                                         ), "pidfd_getfd"             },
[439] = { BASIC(                                         ), "faccessat2"              },
[440] = { BASIC(                                         ), "process_madvise"         },
[441] = { BASIC(                                         ), "epoll_pwait2"            },
[442] = { BASIC(                                         ), "mount_setattr"           },
[443] = { BASIC(                                         ), "quotactl_fd"             },
[444] = { BASIC(                                         ), "landlock_create_ruleset" },
[445] = { BASIC(                                         ), "landlock_add_rule"       },
[446] = { BASIC(                                         ), "landlock_restrict_self"  },
[447] = { BASIC(                                         ), "memfd_secret"            },
[448] = { BASIC(                                         ), "process_mrelease"        },
[449] = { BASIC(                                         ), "futex_waitv"             },
[450] = { BASIC(                                         ), "set_mempolicy_home_node" },
[451] = { BASIC(                                         ), "cachestat"               },
[452] = { BASIC(                                         ), "fchmodat2"               },
[453] = { BASIC(                                         ), "map_shadow_stack"        },
[454] = { BASIC(                                         ), "futex_wake"              },
[455] = { BASIC(                                         ), "futex_wait"              },
[456] = { BASIC(                                         ), "futex_requeue"           },
};
