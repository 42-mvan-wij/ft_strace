#pragma once
#ifndef SYSCALLENT_H
#define SYSCALLENT_H

#include <sys/user.h>
#include <stddef.h>
#include <sys/types.h>

#include <errno.h>

/*
 * These should never be seen by user programs.  To return one of ERESTART*
 * codes, signal_pending() MUST be set.  Note that ptrace can observe these
 * at syscall exit tracing, but they will never be left for the debugged user
 * process to see.
 */
#define ERESTARTSYS	512
#define ERESTARTNOINTR	513
#define ERESTARTNOHAND	514	/* restart if no handler.. */
#define ENOIOCTLCMD	515	/* No ioctl command */
#define ERESTART_RESTARTBLOCK 516 /* restart by calling sys_restart_syscall */
#define EPROBE_DEFER	517	/* Driver requests probe retry */
#define EOPENSTALE	518	/* open found a stale dentry */
#define ENOPARAM	519	/* Parameter not supported */

char const *get_errno_name(long long errno_val);
void _print_syscall_entry(struct user_regs_struct regs, pid_t pid);
void _print_syscall_return(struct user_regs_struct regs, pid_t pid);
void print_syscall(struct user_regs_struct regs, pid_t pid);

#define MAX_ARGS 6

enum arg_type {
	UNUSED = 0,
	STRING,
	USIZE,
	SSIZE,
	UINT,
	SINT,
	PTR,
};

struct i386_user_regs_struct
{
	long int ebx;
	long int ecx;
	long int edx;
	long int esi;
	long int edi;
	long int ebp;
	long int eax;
	long int xds;
	long int xes;
	long int xfs;
	long int xgs;
	long int orig_eax;
	long int eip;
	long int xcs;
	long int eflags;
	long int esp;
	long int xss;
};

struct bound_fn {
	void (*fn)(size_t args[MAX_ARGS], pid_t pid, void *bound_arg);
	void *bound_arg;
};

struct syscall_ent {
	const struct bound_fn bound_fn;
	const char *const name;
};
extern const struct syscall_ent syscall_ent[];
#endif
