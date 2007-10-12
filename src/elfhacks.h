/**
 * \file src/elfhacks.h
 * \brief elfhacks application interface
 * \author Pyry Haulos <pyry.haulos@gmail.com>
 * \date 2007
 */

/* elfhacks.h -- Various ELF run-time hacks
  version 0.1.1, October 9th, 2007

  Copyright (C) 2007 Pyry Haulos

  This software is provided 'as-is', without any express or implied
  warranty.  In no event will the authors be held liable for any damages
  arising from the use of this software.

  Permission is granted to anyone to use this software for any purpose,
  including commercial applications, and to alter it and redistribute it
  freely, subject to the following restrictions:

  1. The origin of this software must not be misrepresented; you must not
     claim that you wrote the original software. If you use this software
     in a product, an acknowledgment in the product documentation would be
     appreciated but is not required.
  2. Altered source versions must be plainly marked as such, and must not be
     misrepresented as being the original software.
  3. This notice may not be removed or altered from any source distribution.

  Pyry Haulos <pyry.haulos@gmail.com>
*/

#include <elf.h>
#include <link.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 *  \defgroup elfhacks elfhacks
 *  Elfhacks is a collection of functions that aim for retvieving
 *  or modifying progam's dynamic linking information at run-time.
 *  \{
 */

/**
 * \brief elfhacks program object
 */
typedef struct {
	/** file name */
	const char *name;
	/** base address in memory */
	ElfW(Addr) addr;
	/** ELF header */
	ElfW(Ehdr) *ehdr;
	/** program headers */
	const ElfW(Phdr) *phdr;
	/** number of program headers */
	ElfW(Half) phnum;
	/** section headers */
	ElfW(Shdr) *shdr;
	/** number of section headers */
	ElfW(Half) shnum;
	/** section name string table */
	char *shstr;
	/** .dynsym */
	ElfW(Sym) *dynsym;
	/** number of .dynsym entries */
	ElfW(Half) symnum;
	/** .symtab */
	char *symtab;
} eh_obj_t;

/**
 * \brief Finds object in memory and creates eh_obj_t for it.
 *
 * Matching is done using fnmatch() so wildcards and other standard
 * filename metacharacters and expressions work.
 *
 * If search is NULL, this function returns the main program object.
 * \param search object's soname (see /proc/pid/maps) or NULL for main
 * \param objptr returned pointer
 * \return 0 on success otherwise a positive error code
*/
extern int eh_find_obj(const char *search, eh_obj_t **objptr);

/**
 * \brief Finds symbol in object's .dynsym and retrvieves its value.
 * \param obj elfhacks program object
 * \param sym symbol to find
 * \param to returned value
 * \return 0 on success otherwise a positive error code
*/
extern int eh_find_sym(eh_obj_t *obj, const char *sym, void **to);

/**
 * \brief Iterates through object's .rel.plt and .rela.plt and sets every
 *        occurrence of some symbol to the specified value.
 * \param obj elfhacks program object
 * \param sym symbol to replace
 * \param val new value
 * \return 0 on success otherwise a positive error code
*/
extern int eh_set_rel(eh_obj_t *obj, const char *sym, void *val);

/**
 * \brief Frees eh_obj_t created using eh_find_obj().
 * \param obj elfhacks program object
 * \return 0 on success otherwise a positive error code
*/
extern int eh_free_obj(eh_obj_t *obj);

/** \} */

#ifdef __cplusplus
}
#endif
