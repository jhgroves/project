#include <thread.h>
#include <assert.h>
#include <stdio.h>

void* f(void* arg)
{
   return NULL;
}

void main(void)
{
   int rc = thread_create(NULL, f, (void*) 1);

   assert(rc == ERR_INVALID_ARGUMENTS);

   printf("passed\n");
   while(1){};
}
