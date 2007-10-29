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

struct eh_iterate_callback_args {
	eh_iterate_obj_callback_func callback;
	void *arg;
};

int eh_check_addr(eh_obj_t *obj, void *addr);
int eh_find_callback(struct dl_phdr_info *info, size_t size, void *argptr);
int eh_find_next_dyn(eh_obj_t *obj, ElfW_Sword tag, int i, ElfW(Dyn) **next);
int eh_init_obj(eh_obj_t *obj);

int eh_set_rela_plt(eh_obj_t *obj, int p, const char *sym, void *val);
int eh_set_rel_plt(eh_obj_t *obj, int p, const char *sym, void *val);

int eh_iterate_rela_plt(eh_obj_t *obj, int p, eh_iterate_rel_callback_func callback, void *arg);
int eh_iterate_rel_plt(eh_obj_t *obj, int p, eh_iterate_rel_callback_func callback, void *arg);

int eh_find_callback(struct dl_phdr_info *info, size_t size, void *argptr)
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

int eh_iterate_callback(struct dl_phdr_info *info, size_t size, void *argptr)
{
	struct eh_iterate_callback_args *args = argptr;
	eh_obj_t obj;
	int ret = 0;

	/* eh_init_obj needs phdr and phnum */
	obj.phdr = info->dlpi_phdr;
	obj.phnum = info->dlpi_phnum;
	obj.addr = info->dlpi_addr;
	obj.name = info->dlpi_name;

	if ((ret = eh_init_obj(&obj))) {
		if (ret == ENOTSUP) /* just skip */
			return 0;
		return ret;
	}

	if ((ret = args->callback(&obj, args->arg)))
		return ret;

	if ((ret = eh_destroy_obj(&obj)))
		return ret;

	return 0;
}

int eh_iterate_obj(eh_iterate_obj_callback_func callback, void *arg)
{
	int ret;
	struct eh_iterate_callback_args args;

	args.callback = callback;
	args.arg = arg;

	if ((ret = dl_iterate_phdr(eh_iterate_callback, &args)))
		return ret;

	return 0;
}

int eh_find_obj(eh_obj_t *obj, const char *soname)
{
	/* This function uses glibc-specific dl_iterate_phdr().
	   Another way could be parsing /proc/self/exe or using
	   pmap() on Solaris or *BSD */
	obj->phdr = NULL;
	obj->name = soname;
	dl_iterate_phdr(eh_find_callback, obj);

	if (!obj->phdr)
		return EAGAIN;

	return eh_init_obj(obj);
}

int eh_check_addr(eh_obj_t *obj, void *addr)
{
	/*
	 Check that given address is inside program's
	 memory maps. PT_LOAD program headers tell us
	 where program has been loaded into.
	*/
	int p;
	for (p = 0; p < obj->phnum; p++) {
		if (obj->phdr[p].p_type == PT_LOAD) {
			if (((ElfW(Addr)) addr < obj->phdr[p].p_memsz + obj->phdr[p].p_vaddr + obj->addr) &&
			    ((ElfW(Addr)) addr >= obj->phdr[p].p_vaddr + obj->addr))
				return 0;
		}
	}

	printf("addr %p not valid\n", addr);
	return EINVAL;
}

int eh_init_obj(eh_obj_t *obj)
{
	/*
	 ELF spec says in section header documentation, that:
	 "An object file may have only one dynamic section."

	 Let's assume it means that object has only one PT_DYNAMIC
	 as well.
	*/
	int p;
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

	/* This is here to catch b0rken headers (vdso) */
	if ((eh_check_addr(obj, (void *) obj->strtab)) |
	    (eh_check_addr(obj, (void *) obj->hash_table)) |
	    (eh_check_addr(obj, (void *) obj->symtab)))
		return ENOTSUP;

	/*
	 http://docsrv.sco.com/SDK_cprog/_Dynamic_Linker.html#objfiles_Fb
	 states that "The number of symbol table entries should equal nchain".

	 'nchain' is the second item in DT_HASH.
	*/
	obj->symnum = obj->hash_table[1];

	return 0;
}

int eh_find_sym(eh_obj_t *obj, const char *sym, void **to)
{
	int i;

	for (i = 0; i < obj->symnum; i++) {
		if (!obj->symtab[i].st_name)
			continue;

		if (!strcmp(&obj->strtab[obj->symtab[i].st_name], sym)) {
			*to = (void *) (obj->symtab[i].st_value + obj->addr);
			return 0;
		}
	}

	return EAGAIN;
}

int eh_iterate_sym(eh_obj_t *obj, eh_iterate_sym_callback_func callback, void *arg)
{
	eh_sym_t sym;
	int ret, i;

	sym.obj = obj;
	for (i = 0; i < obj->symnum; i++) {
		sym.sym = &obj->symtab[i];
		if (sym.sym->st_name)
			sym.name = &obj->strtab[sym.sym->st_name];
		else
			sym.name = NULL;

		if ((ret = callback(&sym, arg)))
			return ret;
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

int eh_iterate_rela_plt(eh_obj_t *obj, int p, eh_iterate_rel_callback_func callback, void *arg)
{
	ElfW(Rela) *rela = (ElfW(Rela) *) obj->dynamic[p].d_un.d_ptr;
	ElfW(Dyn) *relasize;
	eh_rel_t rel;
	eh_sym_t sym;
	int i, ret;

	rel.sym = &sym;
	rel.rel = NULL;
	rel.obj = obj;

	if (eh_find_next_dyn(obj, DT_PLTRELSZ, p, &relasize))
		return EINVAL;

	for (i = 0; i < relasize->d_un.d_val / sizeof(ElfW(Rela)); i++) {
		rel.rela = &rela[i];
		sym.sym = &obj->symtab[ELFW_R_SYM(rel.rela->r_info)];
		if (sym.sym->st_name)
			sym.name = &obj->strtab[sym.sym->st_name];
		else
			sym.name = NULL;

		if ((ret = callback(&rel, arg)))
			return ret;
	}

	return 0;
}

int eh_iterate_rel_plt(eh_obj_t *obj, int p, eh_iterate_rel_callback_func callback, void *arg)
{
	ElfW(Rel) *relp = (ElfW(Rel) *) obj->dynamic[p].d_un.d_ptr;
	ElfW(Dyn) *relsize;
	eh_rel_t rel;
	eh_sym_t sym;
	int i, ret;

	rel.sym = &sym;
	rel.rela = NULL;
	rel.obj = obj;

	if (eh_find_next_dyn(obj, DT_PLTRELSZ, p, &relsize))
		return EINVAL;

	for (i = 0; i < relsize->d_un.d_val / sizeof(ElfW(Rel)); i++) {
		rel.rel = &relp[i];
		sym.sym = &obj->symtab[ELFW_R_SYM(rel.rel->r_info)];
		if (sym.sym->st_name)
			sym.name = &obj->strtab[sym.sym->st_name];
		else
			sym.name = NULL;

		if ((ret = callback(&rel, arg)))
			return ret;
	}

	return 0;
}

int eh_iterate_rel(eh_obj_t *obj, eh_iterate_rel_callback_func callback, void *arg)
{
	ElfW(Dyn) *pltrel;
	int ret, p = 0;

	while (obj->dynamic[p].d_tag != DT_NULL) {
		if (obj->dynamic[p].d_tag == DT_JMPREL) {
			eh_find_next_dyn(obj, DT_PLTREL, p, &pltrel);

			if (pltrel->d_un.d_val == DT_RELA) {
				if ((ret = eh_iterate_rela_plt(obj, p, callback, arg)))
					return ret;
			} else if (pltrel->d_un.d_val == DT_REL) {
				if ((ret = eh_iterate_rel_plt(obj, p, callback, arg)))
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
