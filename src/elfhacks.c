/**
 * \file src/elfhacks.c
 * \brief various ELF run-time hacks
 * \author Pyry Haulos <pyry.haulos@gmail.com>
 * \date 2007
 */

/* elfhacks.c -- various ELF run-time hacks
 * Copyright (C) 2007 Pyry Haulos
 * For conditions of distribution and use, see copyright notice in elfhacks.h
 */

#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <elf.h>
#include <link.h>
#include <fnmatch.h>
#include "elfhacks.h"

/**
 *  \addtogroup elfhacks
 *  \{
 */

#ifdef __x86_64__
# define __elf64
#endif
#ifdef __i386__
# define __elf32
#endif

#ifdef __elf64
# define ELFW_R_SYM ELF64_R_SYM
# define ElfW_Sword Elf64_Sxword
#else
# ifdef __elf32
#  define ELFW_R_SYM ELF32_R_SYM
#  define ElfW_Sword Elf32_Sword
# else
#  error neither __elf32 nor __elf64 is defined
# endif
#endif

int eh_phdr_callback(struct dl_phdr_info *info, size_t size, void *argptr);
int eh_load_obj(eh_obj_t *obj);
int eh_find_next_dyn(eh_obj_t *obj, ElfW_Sword tag, int i, ElfW(Dyn) **next);

int eh_set_rela_plt(eh_obj_t *obj, int p, const char *sym, void *val);
int eh_set_rel_plt(eh_obj_t *obj, int p, const char *sym, void *val);

int eh_phdr_callback(struct dl_phdr_info *info, size_t size, void *argptr)
{
	eh_obj_t *find = (eh_obj_t *) argptr;

	if (find->name == NULL) {
		if (strcmp(info->dlpi_name, ""))
			return 0;
	} else if (fnmatch(find->name, info->dlpi_name, 0))
		return 0;

	if (find->name == NULL) /* TODO readlink? */
		find->name = "/proc/self/exe";
	else
		find->name = info->dlpi_name;
	find->addr = info->dlpi_addr;

	/* segment headers */
	find->phdr = info->dlpi_phdr;
	find->phnum = info->dlpi_phnum;

	return 0;
}

int eh_init_obj(eh_obj_t *obj, const char *soname)
{
	/* This function uses glibc-specific dl_iterate_phdr().
	   Another way could be parsing /proc/self/exe or using
	   pmap() on Solaris or *BSD */
	int p;

	obj->phdr = NULL;
	obj->name = soname;
	dl_iterate_phdr(eh_phdr_callback, obj);

	if (!obj->phdr)
		return EAGAIN;

	/*
	 ELF spec says in section header documentation, that:
	 "An object file may have only one dynamic section."

	 Let's assume it means that object has only one PT_DYNAMIC
	 as well.
	*/
	obj->dynamic = NULL;
	for (p = 0; p < obj->phnum; p++) {
		if (obj->phdr[p].p_type == PT_DYNAMIC) {
			if (obj->dynamic)
				return ENOTSUP;

			obj->dynamic = (ElfW(Dyn) *) (obj->phdr[p].p_vaddr + obj->addr);
		}
	}

	if (!obj->dynamic)
		return ENOTSUP;

	/*
	 ELF spec says that program is allowed to have more than one
	 .strtab but does not describe how string table indexes translate
	 to multiple string tables.

	 And spec says that only one SHT_HASH is allowed, does it mean that
	 obj has only one DT_HASH?

	 About .symtab it does not mention anything about if multiple
	 symbol tables are allowed or not.

	 Maybe st_shndx is the key here?
	*/
	obj->strtab = NULL;
	obj->hash_table = NULL;
	obj->symtab = NULL;
	p = 0;
	while (obj->dynamic[p].d_tag != DT_NULL) {
		if (obj->dynamic[p].d_tag == DT_STRTAB) {
			if (obj->strtab)
				return ENOTSUP;

			obj->strtab = (const char *) obj->dynamic[p].d_un.d_ptr;
		} else if (obj->dynamic[p].d_tag == DT_HASH) {
			if (obj->hash_table)
				return ENOTSUP;

			obj->hash_table = (ElfW(Word) *) obj->dynamic[p].d_un.d_ptr;
		} else if (obj->dynamic[p].d_tag == DT_SYMTAB) {
			if (obj->symtab)
				return ENOTSUP;

			obj->symtab = (ElfW(Sym) *) obj->dynamic[p].d_un.d_ptr;
		}
		p++;
	}

	if ((!obj->strtab) | (!obj->hash_table) | (!obj->symtab))
		return ENOTSUP;

	return 0;
}

int eh_find_sym(eh_obj_t *obj, const char *sym, void **to)
{
	/*
	 http://docsrv.sco.com/SDK_cprog/_Dynamic_Linker.html#objfiles_Fb
	 states that "The number of symbol table entries should equal nchain".

	 'nchain' is the second item in DT_HASH.
	*/
	ElfW_Sword symnum = obj->hash_table[1];
	int i;

	for (i = 0; i < symnum; i++) {
		if (!obj->symtab[i].st_name)
			continue;

		if (!strcmp(&obj->strtab[obj->symtab[i].st_name], sym)) {
			*to = (void *) (obj->symtab[i].st_value + obj->addr);
			return 0;
		}
	}

	return EAGAIN;
}

int eh_set_sym(eh_obj_t *obj, const char *sym, void *to)
{
	ElfW_Sword symnum = obj->hash_table[1];
	int i;

	for (i = 0; i < symnum; i++) {
		if (!obj->symtab[i].st_name)
			continue;

		if (!strcmp(&obj->strtab[obj->symtab[i].st_name], sym))
			*((void **) (obj->symtab[i].st_value + obj->addr)) = to;
	}

	return 0;
}

int eh_find_next_dyn(eh_obj_t *obj, ElfW_Sword tag, int i, ElfW(Dyn) **next)
{
	/* first from i + 1 to end, then from start to i - 1 */
	int p;
	*next = NULL;

	p = i + 1;
	while (obj->dynamic[p].d_tag != DT_NULL) {
		if (obj->dynamic[p].d_tag == tag) {
			*next = &obj->dynamic[p];
			return 0;
		}
		p++;
	}

	p = 0;
	while ((obj->dynamic[i].d_tag != DT_NULL) && (p < i)) {
		if (obj->dynamic[p].d_tag == tag) {
			*next = &obj->dynamic[p];
			return 0;
		}
		p++;
	}

	return EAGAIN;
}

int eh_set_rela_plt(eh_obj_t *obj, int p, const char *sym, void *val)
{
	ElfW(Rela) *rela = (ElfW(Rela) *) obj->dynamic[p].d_un.d_ptr;
	ElfW(Dyn) *relasize;
	int i;

	/* DT_PLTRELSZ contains PLT relocs size in bytes */
	if (eh_find_next_dyn(obj, DT_PLTRELSZ, p, &relasize))
		return EINVAL; /* b0rken elf :/ */

	for (i = 0; i < relasize->d_un.d_val / sizeof(ElfW(Rela)); i++) {
		if (!obj->symtab[ELFW_R_SYM(rela[i].r_info)].st_name)
			continue;

		if (!strcmp(&obj->strtab[obj->symtab[ELFW_R_SYM(rela[i].r_info)].st_name], sym))
			*((void **) (rela[i].r_offset + obj->addr)) = val;
	}

	return 0;
}

int eh_set_rel_plt(eh_obj_t *obj, int p, const char *sym, void *val)
{
	ElfW(Rel) *rel = (ElfW(Rel) *) obj->dynamic[p].d_un.d_ptr;
	ElfW(Dyn) *relsize;
	int i;

	if (eh_find_next_dyn(obj, DT_PLTRELSZ, p, &relsize))
		return EINVAL; /* b0rken elf :/ */

	for (i = 0; i < relsize->d_un.d_val / sizeof(ElfW(Rela)); i++) {
		if (!obj->symtab[ELFW_R_SYM(rel[i].r_info)].st_name)
			continue;

		if (!strcmp(&obj->strtab[obj->symtab[ELFW_R_SYM(rel[i].r_info)].st_name], sym))
			*((void **) (rel[i].r_offset + obj->addr)) = val;
	}

	return 0;
}

int eh_set_rel(eh_obj_t *obj, const char *sym, void *val)
{
	/*
	 Elf spec states that object is allowed to have multiple
	 .rel.plt and .rela.plt tables, so we will support 'em - here.
	*/
	ElfW(Dyn) *pltrel;
	int ret, p = 0;

	while (obj->dynamic[p].d_tag != DT_NULL) {
		/* DT_JMPREL contains .rel.plt or .rela.plt */
		if (obj->dynamic[p].d_tag == DT_JMPREL) {
			/* DT_PLTREL tells if it is Rela or Rel */
			eh_find_next_dyn(obj, DT_PLTREL, p, &pltrel);

			if (pltrel->d_un.d_val == DT_RELA) {
				if ((ret = eh_set_rela_plt(obj, p, sym, val)))
					return ret;
			} else if (pltrel->d_un.d_val == DT_REL) {
				if ((ret = eh_set_rel_plt(obj, p, sym, val)))
					return ret;
			} else
				return EINVAL;
		}
		p++;
	}

	return 0;
}

int eh_destroy_obj(eh_obj_t *obj)
{
	obj->phdr = NULL;

	return 0;
}

/**  \} */
