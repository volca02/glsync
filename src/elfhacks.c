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
#else
# ifdef __elf32
#  define ELFW_R_SYM ELF32_R_SYM
# else
#  error neither __elf32 nor __elf64 is defined
# endif
#endif

int eh_phdr_callback(struct dl_phdr_info *info, size_t size, void *argptr);
int eh_load_obj(eh_obj_t *obj);
int eh_find_shdr(eh_obj_t *obj, const char *name, ElfW(Shdr) **shdrptr);

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

int eh_find_obj(const char *search, eh_obj_t **objptr)
{
	/* This function uses glibc-specific dl_iterate_phdr().
	   Another way could be parsing /proc/self/exe or using
	   pmap() on Solaris or *BSD */
	eh_obj_t *obj;
	int ret;
	ElfW(Shdr) *shdr;
	*objptr = NULL;
	
	if ((obj = (eh_obj_t *) malloc(sizeof(eh_obj_t))) == NULL)
		return ENOMEM;

	obj->name = search;
	dl_iterate_phdr(eh_phdr_callback, obj);
	
	if (!obj->phdr)
		return EAGAIN;
	
	if ((ret = eh_load_obj(obj)))
		return ret;
	
	if ((ret = eh_find_shdr(obj, ".dynstr", &shdr)))
		return ret;
	obj->symtab = (char *) (shdr->sh_addr + obj->addr);
	
	if ((ret = eh_find_shdr(obj, ".dynsym", &shdr)))
		return ret;
	obj->dynsym = (ElfW(Sym) *) (shdr->sh_addr + obj->addr);
	obj->symnum = shdr->sh_size / sizeof(ElfW(Sym));
	
	*objptr = obj;
	return 0;
}

int eh_load_obj(eh_obj_t *obj)
{
	/* Everything except section headers are present in memory
	   and accessible using PT_DYNAMIC segment. Unfortunately
	   shnum is critical to find_sym(), so reading some data
	   from file is unavoidable */
	FILE *bin_h;
	
	if ((bin_h = fopen(obj->name, "r")) == NULL)
		return errno;
	
	/* ELF header */
	obj->ehdr = (ElfW(Ehdr) *) malloc(sizeof(ElfW(Ehdr)));
	fseek(bin_h, 0, SEEK_SET);
	fread(obj->ehdr, 1, sizeof(ElfW(Ehdr)), bin_h);
	
	/* section headers */
	obj->shnum = obj->ehdr->e_shnum;
	obj->shdr = (ElfW(Shdr) *) malloc(sizeof(ElfW(Shdr)) * obj->shnum);
	fseek(bin_h, obj->ehdr->e_shoff, SEEK_SET);
	fread(obj->shdr, 1, sizeof(ElfW(Shdr)) * obj->shnum, bin_h);
	
	/* section header name table */
	obj->shstr = (char *) malloc(obj->shdr[obj->ehdr->e_shstrndx].sh_size);
	fseek(bin_h, obj->shdr[obj->ehdr->e_shstrndx].sh_offset, SEEK_SET);
	fread(obj->shstr, 1, obj->shdr[obj->ehdr->e_shstrndx].sh_size, bin_h);
	
	fclose(bin_h);
	return 0;
}

int eh_find_shdr(eh_obj_t *obj, const char *name, ElfW(Shdr) **shdrptr)
{
	int i;
	for (i = 0; i < obj->shnum; i++) {
		if (!strcmp(name, &obj->shstr[obj->shdr[i].sh_name])) {
			*shdrptr = &obj->shdr[i];
			return 0;
		}
	}
	
	return EAGAIN;
}

int eh_find_sym(eh_obj_t *obj, const char *sym, void **to)
{
	/* just loop thru .symtab and return possible match */
	int i;
	for (i = 0; i < obj->symnum; i++) {
		if (!obj->dynsym[i].st_name)
			continue;
		
		if (!strcmp(sym, &obj->symtab[obj->dynsym[i].st_name])) {
			*to = (void *) (obj->dynsym[i].st_value + obj->addr);
			return 0;
		}
	}
	
	return EAGAIN;
}

int eh_set_rel(eh_obj_t *obj, const char *sym, void *val)
{
	/* relocations can be in .rel.plt or .rela.plt */
	ElfW(Shdr) *shdr;
	ElfW(Rel) *rel;
	ElfW(Rela) *rela;
	int i;
	
	if (!eh_find_shdr(obj, ".rel.plt", &shdr)) {
		rel = (ElfW(Rel) *) (shdr->sh_addr + obj->addr);
		
		for (i = 0; i < shdr->sh_size / sizeof(ElfW(Rel)); i++) {
			if (!strcmp(&obj->symtab[obj->dynsym[ELFW_R_SYM(rel[i].r_info)].st_name], sym))
				*((void **) (rel[i].r_offset + obj->addr)) = val;
		}
	}
	
	if (!eh_find_shdr(obj, ".rela.plt", &shdr)) {
		rela = (ElfW(Rela) *) (shdr->sh_addr + obj->addr);
		
		for (i = 0; i < shdr->sh_size / sizeof(ElfW(Rela)); i++) {

			if (!strcmp(&obj->symtab[obj->dynsym[ELFW_R_SYM(rela[i].r_info)].st_name], sym))
				*((void **) (rela[i].r_offset + obj->addr)) = val;
		}
	
	}
	
	return 0;
}

int eh_free_obj(eh_obj_t *obj)
{
	free(obj->ehdr);
	free(obj->shdr);
	free(obj->shstr);
	free(obj);
	
	return 0;
}

/**  \} */
