/**
 * \file examples/sync.c
 * \brief makes glxswapbuffers sync on fence object
 * \author Pyry Haulos <pyry.haulos@gmail.com>
 * \author Filip Volejnik <f.volejnik@centrum.cz>
 * \date 2007-2013
 * For conditions of distribution and use, see copyright notice in elfhacks.h
 */

/*
 Compile with:
 gcc -fPIC -shared -o sync.so sync.c -lelfhacks -Wall -O2

 And use:
 LD_PRELOAD=/sync.so [some opengl app]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <GL/glx.h>
#include <sys/time.h>
#include <elfhacks.h>

typedef void (*GLXextFuncPtr)(void);

/**
 * \brief sync private data struct
 */
struct sync_data_s {
	/** pointer to real dlsym() */
	void *(*dlsym)(void*, const char*);

	/** pointer to real dlvsym() */
	void *(*dlvsym)(void*, const char*, const char*);

	/** pointer to real glXGetProcAddressARB() */
	GLXextFuncPtr (*glXGetProcAddressARB)(const GLubyte*);

	/** pointer to real glXSwapBuffers() */
	void (*glXSwapBuffers)(Display*, GLXDrawable);
};

/** pointer to sync data structure */
static struct sync_data_s *sync_data = NULL;

/**
 * \brief initializes sync_data
 */
void init_sync_data()
{
	sync_data = malloc(sizeof(struct sync_data_s));
	memset(sync_data, 0, sizeof(struct sync_data_s));

	/* get dlsym() and dlvsym() using elfhacks */
	eh_obj_t libdl;

	if (eh_find_obj(&libdl, "*libdl.so*")) {
		fprintf(stderr, "can't get libdl.so\n");
		exit(1);
	}

	if (eh_find_sym(&libdl, "dlsym", (void **) &sync_data->dlsym)) {
		fprintf(stderr, "can't get dlsym()\n");
		exit(1);
	}

	if (eh_find_sym(&libdl, "dlvsym", (void **) &sync_data->dlvsym)) {
		fprintf(stderr, "can't get dlvsym()\n");
		exit(1);
	}

	eh_destroy_obj(&libdl);

	/* get glXSwapBuffers() using our pointer to dlsym() */
	void *libGL_handle = dlopen("libGL.so.1", RTLD_LAZY);
	if (libGL_handle == NULL) {
		fprintf(stderr, "can't open libGL.so.1\n");
		exit(1);
	}

	sync_data->glXGetProcAddressARB = (GLXextFuncPtr (*)(const GLubyte*)) sync_data->dlsym(libGL_handle, "glXGetProcAddressARB");
	if (sync_data->glXGetProcAddressARB == NULL) {
		fprintf(stderr, "can't get glXGetProcAddressARB()\n");
		exit(1);
	}

	sync_data->glXSwapBuffers = (void (*)(Display*, GLXDrawable)) sync_data->dlsym(libGL_handle, "glXSwapBuffers");
	if (sync_data->glXSwapBuffers == NULL) {
		fprintf(stderr, "can't get glXSwapBuffers()\n");
		exit(1);
	}
}

void handleGLError(const char *call) {
    GLenum err = glGetError();
    if (err == GL_NO_ERROR)
        return;

    fprintf(stderr, "GL error on %s: %d\n", call, err);
}

/**
 * \brief wrapped glXSwapBuffers that enforces sync with fence object.
 */
void sync_glXSwapBuffers(Display* dpy, GLXDrawable drawable)
{
	if (sync_data == NULL)
		init_sync_data();

        static int first = 1;

        if (first) {
            fprintf(stderr, "GLXFLUSH swap buf\n");
            first = 0;
        }

        static GLsync prev_sync = 0;
        GLsync sync = glFenceSync(GL_SYNC_GPU_COMMANDS_COMPLETE, 0);
        handleGLError("glFenceSync");
        sync_data->glXSwapBuffers(dpy, drawable);
        handleGLError("glXSwapBuffers");

        if (prev_sync) {
            glClientWaitSync(prev_sync, GL_SYNC_FLUSH_COMMANDS_BIT, GL_TIMEOUT_IGNORED);
            handleGLError("glWaitSync");
            glDeleteSync(prev_sync);
            handleGLError("glDeleteSync");
        }

        prev_sync = sync;
}

/**
 * \brief glXGetProcAddressARB() hook
 */
GLXextFuncPtr sync_glXGetProcAddressARB(const GLubyte *proc_name)
{
	if (sync_data == NULL)
		init_sync_data();

	if (!strcmp((char*) proc_name, "glXSwapBuffers"))
		return (GLXextFuncPtr) &sync_glXSwapBuffers;
	else if (!strcmp((char*) proc_name, "glXGetProcAddressARB"))
		return (GLXextFuncPtr) &sync_glXGetProcAddressARB;
	else
		return sync_data->glXGetProcAddressARB(proc_name);
}

/**
 * \brief glXSwapBuffers() entry point
 */
void glXSwapBuffers(Display *dpy, GLXDrawable drawable)
{
	sync_glXSwapBuffers(dpy, drawable);
}

/**
 * \brief glXGetProcAddressARB() entry point
 */
GLXextFuncPtr glXGetProcAddressARB(const GLubyte *proc_name)
{
	return sync_glXGetProcAddressARB(proc_name);
}

/**
 * \brief dlsym() wrapper
 */
void *dlsym(void *handle, const char *symbol)
{
	if (sync_data == NULL)
		init_sync_data();

	if (!strcmp(symbol, "glXSwapBuffers"))
		return (void*) &sync_glXSwapBuffers;
	else if (!strcmp(symbol, "glXGetProcAddressARB"))
		return (void*) &sync_glXGetProcAddressARB;
	else
		return sync_data->dlsym(handle, symbol);
}

/**
 * \brief dlvsym() wrapper
 */
void *dlvsym(void *handle, const char *symbol, const char *version)
{
	if (sync_data == NULL)
		init_sync_data();

	if (!strcmp(symbol, "glXSwapBuffers"))
		return (void*) &sync_glXSwapBuffers;
	else
		return sync_data->dlvsym(handle, symbol, version);
}
