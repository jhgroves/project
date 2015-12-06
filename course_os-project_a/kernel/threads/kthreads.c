/*
 * kthreads.c
 *
 *  Created on: Apr 23, 2015
 *      Author: mwkurian
 */

#include "kthread.h"
#include <global_defs.h>
#include "scheduler.h"
#include "data_structures/hash_map.h"

uint32_t GLOBAL_TID = 1;
uint32_t kthread_start(kthread_handle * kthread)
{
	sched_task * task = sched_create_task_from_kthread(kthread,0);
	sched_add_task(task);
	os_printf("Current TID %d\n", kthread->TID);
	return 0;
}
int kthread_remove()
{
	os_printf("\nExiting\n");
	sched_task * task = sched_get_active_task();
	task->state = 3;
    while(1){}
    return 0;
}
void setup_thread_vas(kthread_handle* pcb_p)
{

	//		assert(1==15);
	for (int i = 0; i < 20; i++)
	{
		uint32_t *v = (uint32_t*) (pcb_p->start + (i * BLOCK_SIZE));
		int x = vm_allocate_page(pcb_p->stored_vas, (void*) v, VM_PERM_USER_RW);
		assert(x == 0);
		vm_map_shared_memory(KERNEL_VAS, (void*) v, pcb_p->stored_vas,
				(void*) v, VM_PERM_USER_RW);
	}

	uint32_t *copyIn = (uint32_t *) pcb_p->start;
	int counter = 0;
	uint32_t * v = (uint32_t*) pcb_p->start;
	//*v = *copyIn;
	while (counter < pcb_p->len)
	{
		*v = *copyIn;
		copyIn += 1;
		v += 1;
		counter += 4;
	}

	for (int i = 0; i < 20; i++)
	{
		uint32_t *v = (uint32_t *) (pcb_p->start + (i * BLOCK_SIZE));
		vm_free_mapping(KERNEL_VAS, (void*) v);

	}
}
void init_thread_stack(kthread_handle * pcb_p)
{
	int retval = 0;
	for (int i = 0; i < (STACK_SIZE / BLOCK_SIZE); i++)
	{
		retval = vm_allocate_page(pcb_p->stored_vas,
				(void*) (STACK_BASE + (i * BLOCK_SIZE)), VM_PERM_USER_RW);
		if (retval)
		{
			os_printf("vm_allocate_page error code: %d\n", retval);
			break;
		}
		else
		{
			os_printf(
					"A page have been allocated for thread stack at vptr: 0x%x\n",
					(STACK_BASE + (i * BLOCK_SIZE)));
		}
		vm_map_shared_memory(KERNEL_VAS,
				(void*) (STACK_BASE + (i * BLOCK_SIZE)), pcb_p->stored_vas,
				(void*) (STACK_BASE + (i * BLOCK_SIZE)), VM_PERM_USER_RW);

	}

	// Stick a NULL at STACK_TOP-sizeof(int*)
	uint32_t *stack_top = (uint32_t*) STACK_TOP;
	stack_top[-1] = 0;
	stack_top[-2] = 0;
	stack_top[-3] = 0;
	stack_top[-4] = 0;
	stack_top[-5] = STACK_BASE;
	stack_top[-6] = 1;

	os_strcpy((char*) STACK_BASE, pcb_p->name);

	// We need to set sp (r13) to stack_top - 12
	pcb_p->R13 = STACK_TOP - 4 * 6;
	//print_process_state(pcb_p->PID);

	for (int i = 0; i < (STACK_SIZE / BLOCK_SIZE); i++)
	{
		vm_free_mapping(KERNEL_VAS, (void*) (STACK_BASE + (i * BLOCK_SIZE)));

	}
}
void save_kthread_process_state(kthread_handle* thread_t)
{
	//assert(thread_t && get_address_of_PCB(pcb_p->PID) > 0 && "Invalid PID in load_process_state");

	asm("MOV %0, r0":"=r"(thread_t->R0)::);
	asm("MOV %0, r1":"=r"(thread_t->R1)::);
	asm("MOV %0, r2":"=r"(thread_t->R2)::);
	asm("MOV %0, r3":"=r"(thread_t->R3)::);
	asm("MOV %0, r4":"=r"(thread_t->R4)::);
	asm("MOV %0, r5":"=r"(thread_t->R5)::);
	asm("MOV %0, r6":"=r"(thread_t->R6)::);
	asm("MOV %0, r7":"=r"(thread_t->R7)::);
	asm("MOV %0, r8":"=r"(thread_t->R8)::);
	asm("MOV %0, r9":"=r"(thread_t->R9)::);
	asm("MOV %0, r10":"=r"(thread_t->R10)::);
	asm("MOV %0, r11":"=r"(thread_t->R11)::);
	asm("MOV %0, r12":"=r"(thread_t->R12)::);
	asm("MOV %0, r13":"=r"(thread_t->R13)::);
	asm("MOV %0, r14":"=r"(thread_t->R14)::);
	asm("MOV %0, r15":"=r"(thread_t->R15)::);
}

/*
 Loads registers using values in pcb
 @param Process ID
 @param PID
 @return Returns 0 if successful

 */
void load_kthread_process_state(kthread_handle* thread_t)
{
    //vm_use_kernel_vas();
	os_printf("This is the value stored in R0 as of executing the thread %d\n", thread_t->R0);
	asm("MOV r0, %0"::"r"(thread_t->R0):);
	asm("MOV r1, %0"::"r"(thread_t->R1):);
	asm("MOV r2, %0"::"r"(thread_t->R2):);
	asm("MOV r3, %0"::"r"(thread_t->R3):);
	asm("MOV r4, %0"::"r"(thread_t->R4):);
	asm("MOV r5, %0"::"r"(thread_t->R5):);
	asm("MOV r6, %0"::"r"(thread_t->R6):);
	asm("MOV r7, %0"::"r"(thread_t->R7):);
	asm("MOV r8, %0"::"r"(thread_t->R8):);
	asm("MOV r9, %0"::"r"(thread_t->R9):);
	asm("MOV r10, %0"::"r"(thread_t->R10):);
	//asm("MOV r11, %0"::"r"(11):);
	asm("MOV r12, %0"::"r"(thread_t->R12):);
	asm("MOV r13, %0"::"r"(thread_t->R13):);
	asm("MOV r14, %0"::"r"(thread_t->R14):);
//assert(1==11);*/
	asm("MOV r15, %0"::"r"(thread_t->R15):);

	__builtin_unreachable();
}
long kthread_create(kthread_callback_handler *cb_handler, long func, long args)
{
	os_printf("CURRENTLY IN THREAD CREATE\n");
    vm_use_kernel_vas();
	kthread_handle * kthread = kmalloc(sizeof(kthread_handle));
	init_thread_stack(kthread);
	kthread->cb_handler = *cb_handler;
	sched_task * task = sched_get_active_task();
	if(task->type == 1)
		kthread->parentProcess = (pcb*)task->task;
	kthread->TID = ++GLOBAL_TID;
	kthread->R0 = args;
	kthread->R15 = func;
	kthread->R14 = (uint32_t)&kthread_remove;
	kthread_start(kthread);
	return 0;
}
long get_tid(long cb_handler)
{
	long tid = (get_kthread_from_map((long)cb_handler));
	return tid;
}
long get_self()
{
	sched_task * task = sched_get_active_task();
	if(task->type == 1)
		return (long)NULL;
	return (long)((kthread_handle*) task->task)->cb_handler;
}

