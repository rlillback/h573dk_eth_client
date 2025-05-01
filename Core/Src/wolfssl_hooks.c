#include "wolfssl_hooks.h"
#include <stdio.h>
#include <stdlib.h>
#include "main.h"

static void* malloc_wrapper(size_t sz, void* heap, int type)
{
    void* p = malloc(sz);
    if (!p) {
		printf("XMALLOC failed! type=%d, size=%lu\r\n", type, (unsigned long)sz);
		Error_Handler();
	}
#if defined(__PRINT_ALLOCATIONS__)
    else {
    	printf("XMALLOC(type=%d, size=%lu) = %p\r\n", type, (unsigned long)sz, p);
    }
#endif
    return p;
}

static void free_wrapper(void* p, void* heap, int type)
{
#if defined(__PRINT_ALLOCATIONS__)
    printf("XFREE(type=%d, ptr=%p)\r\n", type, p);
#endif
    free(p);
}

static void* realloc_wrapper(void* p, size_t n, void* heap, int type)
{
    void* np = realloc(p, n);
#if defined(__PRINT_ALLOCATIONS__)
    printf("XREALLOC(type=%d, new_size=%lu) = %p\n", type, (unsigned long)n, np);
#endif
    return np;
}

void setup_allocators() {
    wolfSSL_SetAllocators((wolfSSL_Malloc_cb)malloc_wrapper,
    		              (wolfSSL_Free_cb)free_wrapper,
						  (wolfSSL_Realloc_cb)realloc_wrapper);
}

int verify_cb(int preverify, WOLFSSL_X509_STORE_CTX* store) {
	printf("Entered verify_cb function...\r\n");
    return preverify;
} /* verify_cb */

#if defined(__PRINT_WOLF_SSL_DEBUG__)
void wolfssl_debug_cb(const int level, const char *const msg) {
	if (level <= WOLFSSL_DEBUG_LEVEL) {
		printf("[wolfSSL][%d] %s\r\n", level, msg);
	}
}
#endif
