/**
 * \file examples/fps.c
 * \brief simple fps logger
 * \author Pyry Haulos <pyry.haulos@gmail.com>
 * \date 2007-2008
 * For conditions of distribution and use, see copyright notice in elfhacks.h
 */

/*
 Compile with:
 gcc -fPIC -shared -o fps.so fps.c -lelfhacks -Wall -O2

 And use:
 FPS_LOG_FILE=fps.txt LD_PRELOAD=fps.so [some opengl app]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <GL/glx.h>
#include <sys/time.h>
#include <elfhacks.h>

#define FPS_SAMPLE_USEC 1000000
#define FPS_FORMAT "%.2f\n"

typedef void (*GLXextFuncPtr)(void);

/**
 * \brief fps private data struct
 */
struct fps_data_s {
	/** pointer to real dlsym() */
	void *(*dlsym)(void*, const char*);

	/** pointer to real dlvsym() */
	void *(*dlvsym)(void*, const char*, const char*);

	/** pointer to real glXGetProcAddressARB() */
	GLXextFuncPtr (*glXGetProcAddressARB)(const GLubyte*);

	/** pointer to real glXSwapBuffers() */
	void (*glXSwapBuffers)(Display*, GLXDrawable);

	/** last time fps was calculated */
	struct timeval last_time;

	/** number of frames */
	unsigned long frames;

	/** target stream */
	FILE *stream;
};

/** pointer to fps data structure */
static struct fps_data_s *fps_data = NULL;

/**
 * \brief initializes fps_data
 */
void init_fps_data()
{
	fps_data = malloc(sizeof(struct fps_data_s));
	memset(fps_data, 0, sizeof(struct fps_data_s));

	/* get dlsym() and dlvsym() using elfhacks */
	eh_obj_t libdl;

	if (eh_find_obj(&libdl, "*libdl.so*")) {
		fprintf(stderr, "can't get libdl.so\n");
		exit(1);
	}

	if (eh_find_sym(&libdl, "dlsym", (void **) &fps_data->dlsym)) {
		fprintf(stderr, "can't get dlsym()\n");
		exit(1);
	}

	if (eh_find_sym(&libdl, "dlvsym", (void **) &fps_data->dlvsym)) {
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

	fps_data->glXGetProcAddressARB = (GLXextFuncPtr (*)(const GLubyte*)) fps_data->dlsym(libGL_handle, "glXGetProcAddressARB");
	if (fps_data->glXGetProcAddressARB == NULL) {
		fprintf(stderr, "can't get glXGetProcAddressARB()\n");
		exit(1);
	}

	fps_data->glXSwapBuffers = (void (*)(Display*, GLXDrawable)) fps_data->dlsym(libGL_handle, "glXSwapBuffers");
	if (fps_data->glXSwapBuffers == NULL) {
		fprintf(stderr, "can't get glXSwapBuffers()\n");
		exit(1);
	}

	/* open target file or stdout if none is specified */
	if (getenv("FPS_LOG_FILE")) {
		fps_data->stream = fopen(getenv("FPS_LOG_FILE"), "w");
		if (fps_data->stream != NULL) {
			fprintf(stderr, "can't open %s\n", getenv("FPS_LOG_FILE"));
			exit(1);
		}
	} else
		fps_data->stream = stdout;

	/* init time and frames */
	gettimeofday(&fps_data->last_time, NULL);
	fps_data->frames = 0;
}

/**
 * \brief fps counter function
 */
void fps_glXSwapBuffers(Display* dpy, GLXDrawable drawable)
{
	if (fps_data == NULL)
		init_fps_data();

	/* pass call to real glXSwapBuffers */
	fps_data->glXSwapBuffers(dpy, drawable);

	fps_data->frames++;

	/* calculate time difference in nanoseconds */
	struct timeval tv;
	gettimeofday(&tv, NULL);

	tv.tv_sec -= fps_data->last_time.tv_sec;
	tv.tv_usec -= fps_data->last_time.tv_usec;

	if ((tv.tv_sec * 1000000 + tv.tv_usec) >= FPS_SAMPLE_USEC) {
		fprintf(fps_data->stream, FPS_FORMAT, (double) fps_data->frames / ((double) tv.tv_sec + (double) tv.tv_usec / 1000000.0));
		fps_data->frames = 0;
		gettimeofday(&fps_data->last_time, NULL);
	}
}

/**
 * \brief glXGetProcAddressARB() hook
 */
GLXextFuncPtr fps_glXGetProcAddressARB(const GLubyte *proc_name)
{
	if (fps_data == NULL)
		init_fps_data();

	if (!strcmp((char*) proc_name, "glXSwapBuffers"))
		return (GLXextFuncPtr) &fps_glXSwapBuffers;
	else if (!strcmp((char*) proc_name, "glXGetProcAddressARB"))
		return (GLXextFuncPtr) &fps_glXGetProcAddressARB;
	else
		return fps_data->glXGetProcAddressARB(proc_name);
}

/**
 * \brief glXSwapBuffers() entry point
 */
void glXSwapBuffers(Display *dpy, GLXDrawable drawable)
{
	fps_glXSwapBuffers(dpy, drawable);
}

/**
 * \brief glXGetProcAddressARB() entry point
 */
GLXextFuncPtr glXGetProcAddressARB(const GLubyte *proc_name)
{
	return fps_glXGetProcAddressARB(proc_name);
}

/**
 * \brief dlsym() wrapper
 */
void *dlsym(void *handle, const char *symbol)
{
	if (fps_data == NULL)
		init_fps_data();

	if (!strcmp(symbol, "glXSwapBuffers"))
		return (void*) &fps_glXSwapBuffers;
	else if (!strcmp(symbol, "glXGetProcAddressARB"))
		return (void*) &fps_glXGetProcAddressARB;
	else
		return fps_data->dlsym(handle, symbol);
}

/**
 * \brief dlvsym() wrapper
 */
void *dlvsym(void *handle, const char *symbol, const char *version)
{
	if (fps_data == NULL)
		init_fps_data();

	if (!strcmp(symbol, "glXSwapBuffers"))
		return (void*) &fps_glXSwapBuffers;
	else
		return fps_data->dlvsym(handle, symbol, version);
}
