/**
 * \file examples/ldinfo.c
 * \brief elfhacks example: iterating objects and symbols
 * \author Pyry Haulos <pyry.haulos@gmail.com>
 * \date 2007-2008
 * For conditions of distribution and use, see copyright notice in elfhacks.h
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <elfhacks.h>

/**
 * \brief argument struct for iterate functions
 */
struct ldinfo_args {
	unsigned int objects;
	unsigned int symbols;
	unsigned int rel;
	unsigned int rela;
};

/**
 * \brief eh_iterate_sym callback
 */
int iterate_sym_callback(eh_sym_t *sym, void *arg)
{
	struct ldinfo_args *ld = arg;

	printf("     [sym:%04d] %s = %p\n", ld->symbols++, sym->name, (void *) sym->sym->st_value);

	return 0;
}

/**
 * \brief eh_iterate_rel callback
 */
int iterate_rel_callback(eh_rel_t *rel, void *arg)
{
	struct ldinfo_args *ld = arg;

	if (rel->rel)
		printf("     [rel:%04d] %s = %p\n", ld->rel++, rel->sym->name,
		       *((void **) (rel->rel->r_offset + rel->obj->addr)));
	else if (rel->rela)
		printf("     [rela:%04d] %s = %p\n", ld->rela++, rel->sym->name,
		       *((void **) (rel->rela->r_offset + rel->obj->addr)));

	return 0;
}

/**
 * \brief eh_iterate_obj callback
 */
int iterate_obj_callback(eh_obj_t *obj, void *arg)
{
	struct ldinfo_args *ld = arg;
	int ret;

	printf("[%02d] %s\n", ld->objects++, obj->name);

	/*
	not supported currently...
	ld->symbols = 0;
	if ((ret = eh_iterate_sym(obj, iterate_sym_callback, ld))) {
		fprintf(stderr, "eh_iterate_sym failed: %s (%d)\n", strerror(ret), ret);
		return ret;
	}
	*/

	ld->rel = ld->rela = 0;
	if ((ret = eh_iterate_rel(obj, iterate_rel_callback, ld))) {
		fprintf(stderr, "eh_iterate_rel failed: %s (%d)\n", strerror(ret), ret);
		return ret;
	}

	return 0;
}

/**
 * \brief constructor, called when library is initialized
 */
__attribute__ ((constructor)) void ldinfo()
{
	struct ldinfo_args ld;
	int ret;

	ld.objects = 0;
	if ((ret = eh_iterate_obj(iterate_obj_callback, &ld)))
		fprintf(stderr, "eh_iterate_obj failed: %s (%d)\n", strerror(ret), ret);
}
