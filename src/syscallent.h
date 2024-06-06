#pragma once
#ifndef SYSCALLENT_H
#define SYSCALLENT_H

#include <sys/user.h>
#include <stddef.h>
#include <sys/types.h>

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
