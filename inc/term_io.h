/*
 * term_io.h
 */


#ifndef _TERM_IO_H_
#define _TERM_IO_H_
        
#ifdef __PREFIX__
    #define perror(errstr) \
		perror(__PREFIX__ errstr) 
    #define printf(fmt, ...) \
		printf(__PREFIX__ fmt, ## __VA_ARGS__)
#endif /* __PREFIX__ */

#if __DEBUG__
		#define DPRINTF(fmt, ...) \
			printf(fmt, ## __VA_ARGS__)
#else
		#define DPRINTF(fmt, ...) 
#endif

#define CALLED(func) DPRINTF("function %s called\n", func)

#endif /* _TERM_IO_H_ */

/* vim: set expandtab ts=8 sw=4 tw=80: */
