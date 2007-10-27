/**
 * \file src/elfhacks.h
 * \brief elfhacks application interface
 * \author Pyry Haulos <pyry.haulos@gmail.com>
 * \date 2007
 */

/* elfhacks.h -- Various ELF run-time hacks
  version 0.2.0, October 27th, 2007

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
	/** program headers */
	const ElfW(Phdr) *phdr;
	/** number of program headers */
	ElfW(Half) phnum;
	/** .dynamic */
	ElfW(Dyn) *dynamic;
	/** .symtab */
	ElfW(Sym) *symtab;
	/** .strtab */
	const char *strtab;
	/** symbol hash table */
	ElfW(Word) *hash_table;
} eh_obj_t;

/**
 * \brief Initializes eh_obj_t for given soname
 *
 * Matching is done using fnmatch() so wildcards and other standard
 * filename metacharacters and expressions work.
 *
 * If soname is NULL, this function returns the main program object.
 * \param soname object's soname (see /proc/pid/maps) or NULL for main
 * \param objptr returned pointer
 * \return 0 on success otherwise a positive error code
*/
extern int eh_init_obj(eh_obj_t *obj, const char *soname);

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
 * \brief Destroy eh_obj_t object.
 * \param obj elfhacks program object
 * \return 0 on success otherwise a positive error code
*/
extern int eh_destroy_obj(eh_obj_t *obj);

/** \} */

#ifdef __cplusplus
}
#endif
