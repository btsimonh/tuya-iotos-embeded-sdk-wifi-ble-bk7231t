#include "include.h"
#include "arm_arch.h"
#include <string.h>

#include "sys_rtos.h"
#include "uart_pub.h"

#define os_printf                      bk_printf

#undef __WRAP_DEBUG

INT32 os_memcmp(const void *s1, const void *s2, UINT32 n)
{
    return memcmp(s1, s2, (unsigned int)n);
}

void *os_memmove(void *out, const void *in, UINT32 n)
{
    return memmove(out, in, n);
}

void *os_memcpy(void *out, const void *in, UINT32 n)
{
    return memcpy(out, in, n);
}

void *os_memset(void *b, int c, UINT32 len)
{
    return (void *)memset(b, c, (unsigned int)len);
}

void *os_realloc(void *ptr, size_t size)
{
	#ifdef FIX_REALLOC_ISSUE
    return pvPortRealloc(ptr, size);
	#else
	void *tmp;

    if(platform_is_in_interrupt_context())
    {
        os_printf("realloc_risk\r\n");
    }

	tmp = (void *)pvPortMalloc(size);
	if(tmp)
	{
        // NOTE:::  This could copy from bad memory?
        // it's copying too much...
		os_memcpy(tmp, ptr, size);
		vPortFree(ptr);
	}

	return tmp;
	#endif
}

int os_memcmp_const(const void *a, const void *b, size_t len)
{
    return memcmp(a, b, len);
}

// becuse libraries contain os_malloc, we must provide them...
#if OSMALLOC_STATISTICAL
#undef os_malloc
#undef os_free
#undef os_zalloc
#endif



void *os_malloc(size_t size)
{
    if(platform_is_in_interrupt_context())
    {
        os_printf("malloc_risk\r\n");
    }
#if OSMALLOC_STATISTICAL
    return (void *)pvPortMalloc_cm(__FILE__, __LINE__, size, 0);
#else
    return (void *)pvPortMalloc(size);
#endif
}

void * os_zalloc(size_t size)
{
#if OSMALLOC_STATISTICAL
    return (void *)pvPortMalloc_cm(__FILE__, __LINE__, size, 1);
#else
	void *n = (void *)pvPortMalloc(size);
    
    if(platform_is_in_interrupt_context())
    {
        os_printf("zalloc_risk\r\n");
    }
    
	if (n)
		os_memset(n, 0, size);
	return n;
#endif
}

void os_free(void *ptr)
{
    if(platform_is_in_interrupt_context())
    {
        os_printf("free_risk\r\n");
    }
    
    if(ptr)
    {        
#if OSMALLOC_STATISTICAL
        vPortFree_cm(__FILE__, __LINE__, ptr);
#else
        vPortFree(ptr);
#endif
    }
}

#ifdef NOTHERE
void *__wrap_malloc(size_t size)
{    
#ifdef __WRAP_DEBUG
	os_printf("__wrap_malloc\r\n");
#endif    
    if(platform_is_in_interrupt_context())
    {
        os_printf("malloc_risk\r\n");
    }
#if OSMALLOC_STATISTICAL
    return (void *)pvPortMalloc_cm(__FILE__, __LINE__, size, 0);
#else
    return (void *)pvPortMalloc(size);
#endif
}
#endif

void *__wrap_malloc(size_t size )
{    
#ifdef __WRAP_DEBUG
    register uint32_t result; 
    __asm volatile ("MOV %0, LR\n" : "=r" (result) ); 
#endif
    if(platform_is_in_interrupt_context())
    {
        os_printf("malloc_risk\r\n");
    }
#if OSMALLOC_STATISTICAL
    void* t = (void *)pvPortMalloc_cm(__FILE__, __LINE__, size, 0);
#else
    void* t = (void *)pvPortMalloc(size);
#endif

#ifdef __WRAP_DEBUG
    if (t){
	    os_printf("__wrap_malloc caller:0x%08X - %u @ %u\r\n", result, size, t);
    } else {
    	os_printf("__wrap_malloc #####FAIL##### caller:0x%08X - %u @ %u\r\n", result, size, t);
    }
#endif

    return t;
}

void *__wrap_os_malloc(size_t size )
{    
#ifdef __WRAP_DEBUG
    register uint32_t result; 
    __asm volatile ("MOV %0, LR\n" : "=r" (result) ); 
#endif
#if OSMALLOC_STATISTICAL
    void* t = (void *)pvPortMalloc_cm(__FILE__, __LINE__, size, 0);
#else
    void* t = (void *)pvPortMalloc(size);
#endif
#ifdef __WRAP_DEBUG
    if (t){
	    os_printf("__wrap_os_malloc caller:0x%08X - %u @ %u\r\n", result, size, t);
    } else {
    	os_printf("__wrap_os_malloc #####FAIL##### caller:0x%08X - %u @ %u\r\n", result, size, t);
    }
#endif

    return t;
}


void * __wrap__malloc_r (void *p, size_t size)
{
#ifdef __WRAP_DEBUG
	os_printf("__wrap__malloc_r\r\n");
#endif    
	return pvPortMalloc(size);
}


void * __wrap_zalloc(size_t size)
{
#ifdef __WRAP_DEBUG
	os_printf("__wrap_zalloc\r\n");
#endif    
	return os_zalloc(size);
}



// from heap_4.c
typedef struct A_BLOCK_LINK
{
	struct A_BLOCK_LINK *pxNextFreeBlock;	/*<< The next free block in the list. */
	size_t xBlockSize;						/*<< The size of the free block. */
} BlockLink_t;

static const size_t xHeapStructSize	= ( sizeof( BlockLink_t ) + ( ( size_t ) ( portBYTE_ALIGNMENT - 1 ) ) ) & ~( ( size_t ) portBYTE_ALIGNMENT_MASK );
static size_t xBlockAllocatedBit = (1<<31);
/* Define the linked list structure.  This is used to link free blocks in order
of their memory address. */

void __wrap_free(void *ptr)
{
#ifdef __WRAP_DEBUG
	uint8_t *puc;
	BlockLink_t *pxLink;
	int presize, datasize;
    int allocated;

    register uint32_t result; 
    __asm volatile ("MOV %0, LR\n" : "=r" (result) ); 
    if (ptr == NULL){
    	os_printf("__wrap_free of NULL from 0x%08X @ %u\r\n", result, ptr);
        return;
    }
    puc = ( uint8_t * ) ptr;

    puc -= xHeapStructSize;
	pxLink = ( void * ) puc;
	presize = (pxLink->xBlockSize & ~xBlockAllocatedBit);
	datasize = presize - xHeapStructSize;
	allocated = pxLink->xBlockSize & xBlockAllocatedBit;
    if (!allocated){
        os_printf("__wrap_free DOUBLEFREE from 0x%08X %d @ %u\r\n", result, datasize, ptr);
    } else {
        os_printf("__wrap_free from 0x%08X %d @ %u\r\n", result, datasize, ptr);
    }
#endif    
    if(platform_is_in_interrupt_context())
    {
        os_printf("free_risk\r\n");
    }
    
    if(ptr)
    {        
#if OSMALLOC_STATISTICAL
        vPortFree_cm(__FILE__, __LINE__, ptr);
#else
        vPortFree(ptr);
#endif
    }
}

void __wrap_os_free(void *ptr)
{
#ifdef __WRAP_DEBUG
	uint8_t *puc;
	BlockLink_t *pxLink;
	int presize, datasize;
    int allocated;

    register uint32_t result; 
    __asm volatile ("MOV %0, LR\n" : "=r" (result) ); 
    if (ptr == NULL){
    	os_printf("__wrap_os_free of NULL from 0x%08X @ %u\r\n", result, ptr);
        return;
    }
    puc = ( uint8_t * ) ptr;

    puc -= xHeapStructSize;
	pxLink = ( void * ) puc;
	presize = (pxLink->xBlockSize & ~xBlockAllocatedBit);
	datasize = presize - xHeapStructSize;
	allocated = pxLink->xBlockSize & xBlockAllocatedBit;
    if (!allocated){
        os_printf("__wrap_os_free DOUBLEFREE from 0x%08X %d @ %u\r\n", result, datasize, ptr);
    } else {
        os_printf("__wrap_os_free from 0x%08X %d @ %u\r\n", result, datasize, ptr);
    }
#endif    
    if(platform_is_in_interrupt_context())
    {
        os_printf("free_risk\r\n");
    }
    
    if(ptr)
    {        
#if OSMALLOC_STATISTICAL
        vPortFree_cm(__FILE__, __LINE__, ptr);
#else
        vPortFree(ptr);
#endif
    } else {
#ifdef __WRAP_DEBUG
        os_printf("__wrap_os_free of NULL from 0x%08X\r\n", result);
#endif
    }
}

void * __wrap_calloc (size_t a, size_t b)
{
	void *pvReturn;

#ifdef __WRAP_DEBUG
	os_printf("__wrap_calloc\r\n");
#endif    
    pvReturn = pvPortMalloc( a*b );
    if (pvReturn)
    {
        os_memset(pvReturn, 0, a*b);
    }

    return pvReturn;
}

void * __wrap_realloc (void* pv, size_t size)
{
#ifdef __WRAP_DEBUG
	os_printf("__wrap_realloc\r\n");
#endif    
	return pvPortRealloc(pv, size);
}

void __wrap__free_r (void *p, void *x)
{
#ifdef __WRAP_DEBUG
	os_printf("__wrap__free_r\r\n");
#endif    
    __wrap_free(x);
}

void* __wrap__realloc_r (void *p, void* x, size_t sz)
{
#ifdef __WRAP_DEBUG
    os_printf("__wrap__realloc_r\r\n");
#endif    
    return __wrap_realloc (x, sz);
}


// EOF
