/*
 * kthread.h
 *
 *  Created on: Apr 23, 2015
 *      Author: mwkurian
 */

#ifndef KERNEL_INCLUDE_KTHREAD_H_
#define KERNEL_INCLUDE_KTHREAD_H_
#include "process.h"
#include "vm.h"

typedef void (*kthread_callback_handler)();
typedef struct kthread_handle
{
	//ID data
	char* name; /* for debugging purposes */
	uint32_t TID;
	uint32_t starting_address;
	uint32_t process_number; // is this a mapping to actual executable image? or does it describe total number of processes?
	uint32_t user_id;
	uint32_t group_id;
	uint32_t parent_id;
	uint32_t (*function)();
	uint32_t has_executed;
	struct vas* stored_vas;
	uint32_t start;
	uint32_t len;
	//CPU state data
	PROCESS_STATE current_state;

	/*
	 * r0-r3 are the argument and scratch registers; r0-r1 are also the result registers
	 * r4-r8 are callee-save registers
	 * r9 might be a callee-save register or not (on some variants of AAPCS it is a special register)
	 * r10-r11 are callee-save registers
	 * r12-r15 are special registers
	 * 37 REGISTERS IN TOTAL: 31 GPRs, 6 SRs
	 */

	// WE ARE GOING TO TRY TO IMPLEMENT SETJMP/LONGJMP INSTEAD OF MANUALLY DEALING WITH THESE VALUES
	// uint32_t PC;
	// uint32_t SP;
	// uint32_t CPSR; //current prog status register
	// uint32_t SPSR; //saved prog status register when execption occurs
	//unbanked register
	uint32_t R0;
	uint32_t R1;
	uint32_t R2;
	uint32_t R3;
	uint32_t R4;
	uint32_t R5;
	uint32_t R6;
	uint32_t R7;

	//banked registers
	uint32_t R8;
	uint32_t R9;
	uint32_t R10;
	uint32_t R11;
	uint32_t R12;
	uint32_t R13; //corresponds to the SP; do we need both?
	uint32_t R14;
	uint32_t R15; //corresponds to the PC; do we need both?
	pcb * parentProcess;
    uint32_t parent_pid;
    int niceness;
    int state;
    kthread_callback_handler cb_handler;

} kthread_handle;
void init_thread_stack(kthread_handle *thread);
void setup_thread_vas(kthread_handle* pcb_p);
long kthread_create(kthread_callback_handler *cb_handler, long func, long args);
void load_kthread_process_state(kthread_handle *thread);
void save_kthread_process_state(kthread_handle *thread);
int kthread_remove();
long get_tid(long cb_handler);
long get_self();
#endif /* KERNEL_INCLUDE_KTHREAD_H_ */
