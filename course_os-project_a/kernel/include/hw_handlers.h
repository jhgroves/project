#ifndef __HW_HANDLERS_H__
#define __HW_HANDLERS_H__

/*
 *
 *  Hardware Handler Interface for course_os
 *
 * 
 *  A bit of background:
 *  - The ARM architecture has 7 modes of operation:
 * 	+ USR - user mode
 *	+ FIQ - processing "fast" interrupts
 *	+ IRQ - processing "normal" interrupts
 *	+ SVC - proctected mode for OS
 *	+ UND - processing an undefined instruction exception
 *	+ SYS - also protecteed mode for OS --if anyone wants to clarify, feel free--
 *	These modes can be entered or exited by modifying the CPSR (status register)
 *
 *  exceptions (e.g. software interrupts, system calls, etc.), Interrupts (IRQ, FIQ)
 *  trigger the core to switch to an appropriate mode and the pc to jump to a 
 *  preset address (somewhere in the vector table) for a branch instruction to the 
 *  proper handler. 
 *
 *  When this happens the state of the machine must be preserved. The HW handler interface
 *  centralizes the 'top half' exception/interrupt handling code and takes care of the dirty low-level
 *  work so that the software handling interfaces for interrupts, system calls, and exceptions
 *  can be written more clearly elsewhere.
 *
 *  tl;dr - write your handlers as a separate module and call them from one
 *  of the prototypes below.
 *
 */
#include <stdint.h>
#include "kthread.h"

#define BRANCH_INSTRUCTION	0xe59ff018	// ldr pc, pc+offset
#define RET_FROM_SWI(x) asm volatile("mov r0, %0 \n\t sub     sp, fp, #28 \n\t ldm     sp!, {r4, r1, r2, r3, r7, fp, ip, pc}^":: "r"(x) :)
// System Call Types
#define SYSCALL_CREATE 0  
#define SYSCALL_SWITCH 1
#define SYSCALL_DELETE 2
#define SYSCALL_OPEN 3
#define SYSCALL_READ 4
#define SYSCALL_WRITE 5
#define SYSCALL_CLOSE 6
#define SYSCALL_SET_PERM 7
#define SYSCALL_MEM_MAP 8
#define SYSCALL_SEEK 9
#define SYSCALL_MKDIR 10
#define SYSCALL_COPY 11   
#define SYSCALL_LS 12  
#define SYSCALL_MALLOC 13
#define SYSCALL_ALIGNED_ALLOC 14
#define SYSCALL_FREE 15
#define SYSCALL_PRINTF 16
#define SYSCALL_DUMMY 99
#define SYSCALL_CREATE_THREAD 17
#define SYSCALL_THREAD_REMOVE 18
#define SYSCALL_THREAD_CHECK 19
#define SYSCALL_THREAD_SELF 20
#define SYSCALL_THREAD_TID 21
#define SYSCALL_THREAD_JOIN 22
void init_vector_table(void); 

// vector table handlers, should be loaded at 0x00 in this order!
extern void _Reset();
void reset_handler(void);
void __attribute__((interrupt("UNDEF"))) undef_instruction_handler(void);	// 0x04
long __attribute__((interrupt("SWI"))) software_interrupt_handler(void);	// 0x08
void __attribute__((interrupt("ABORT"))) prefetch_abort_handler(void);	// 0x0c
void __attribute__((interrupt("ABORT"))) data_abort_handler(void);		// 0x10
void reserved_handler(void);		// 0x14
void __attribute__((interrupt("IRQ"))) irq_handler(void);			// 0x18
void __attribute__((interrupt("FIQ"))) fiq_handler(void);			// 0x1c


#endif
