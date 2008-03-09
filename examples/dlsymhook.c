/**
 * \file examples/dlsymhook.c
 * \brief elfhacks example: wrapping dlopen() and dlsym()
 * \author Pyry Haulos <pyry.haulos@gmail.com>
 * \date 2007-2008
 * For conditions of distribution and use, see copyright notice in elfhacks.h
 */

#include <stdio.h>
#include <stdlib.h>
#include <elfhacks.h>

/**
 * \brief real dlopen()
 */
void *(*__dlopen)(const char *, int) = NULL;
/**
 * \brief real dlsym()
 */
void *(*__dlsym)(void *, const char *) = NULL;

/**
 * \brief retvieves real dlsym() and dlopen() using elfhacks
 */
void get_real_functions()
{
	eh_obj_t libdl;
	
	if (eh_find_obj(&libdl, "*libdl.so*")) {
		fprintf(stderr, "can't get libdl.so\n");
		exit(1);
	}

	if (eh_find_sym(&libdl, "dlopen", (void **) &__dlopen)) {
		fprintf(stderr, "can't get dlopen()\n");
		exit(1);
	}

	if (eh_find_sym(&libdl, "dlsym", (void **) &__dlsym)) {
		fprintf(stderr, "can't get dlsym()\n");
		exit(1);
	}

	eh_destroy_obj(&libdl);
}

/**
 * \brief dlopen() wrapper, just passes calls to real dlopen()
 *        and writes information to standard output
 */
void *dlopen(const char *filename, int flag)
{
	if (__dlopen == NULL)
		get_real_functions();
	
	void *result = __dlopen(filename, flag);
	
	printf("dlopen(%s, ", filename);
	const char *fmt = "%s";
#define FLAG(test) if (flag & test) { printf(fmt, #test); fmt = "|%s"; }
	FLAG(RTLD_LAZY)
	FLAG(RTLD_NOW)
	FLAG(RTLD_GLOBAL)
	FLAG(RTLD_LOCAL)
	FLAG(RTLD_NODELETE)
	FLAG(RTLD_NOLOAD)
	FLAG(RTLD_DEEPBIND)
	printf(") = %p\n", result);
	
	return result;
}

/**
 * \brief dlsym() wrapper, passes calls to real dlsym() and
 *        writes information to standard output
 */
void *dlsym(void *handle, const char *symbol)
{
	if (__dlsym == NULL)
		get_real_functions();
	
	void *result = __dlsym(handle, symbol);
	printf("dlsym(%p, %s) = %p\n", handle, symbol, result);
	
	return result;
}
