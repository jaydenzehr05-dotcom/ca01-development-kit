/*
 * CA01 display research — ARMEL EGL pbuffer interposer, version 2.
 * Tested only on self-authored ARM32 probe under QEMU.
 *
 * Important: This emulates the ORIGINAL HMI's observed window callback call
 * signature (+0x1c) with synthetic handles. It does not claim to implement
 * Fujitsu Ten's native-window or sysDisMng driver ABI.
 * Restricted to trusted synthetic 32-byte window pointers.
 */
#define _POSIX_C_SOURCE 200809L
#include <EGL/egl.h>
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef EGLBoolean (*ChooseFn)(EGLDisplay, const EGLint *, EGLConfig *, EGLint, EGLint *);
typedef EGLSurface (*WindowFn)(EGLDisplay, EGLConfig, EGLNativeWindowType, const EGLint *);
typedef EGLSurface (*PbufferFn)(EGLDisplay, EGLConfig, const EGLint *);
typedef EGLBoolean (*DestroyFn)(EGLDisplay, EGLSurface);
enum { CA01_BUFFER_COUNT = 3, CA01_MAX_WINDOWS = 8 };
typedef struct {
    const void *native_window;
    uint32_t next;
    uint32_t count;
    uint32_t *handle_array;
    EGLSurface surface;
} Ca01WindowState;
/* This is test-only state, NOT a production thread-safe native window driver. */
static Ca01WindowState active[CA01_MAX_WINDOWS];

static int enabled(void) {
    const char *v = getenv("CA01_EGL_BRIDGE");
    return v && strcmp(v, "1") == 0;
}
static uint32_t ca01_test_acquire_next(void *window) {
    for (unsigned i=0;i<CA01_MAX_WINDOWS;++i) {
        Ca01WindowState *s=&active[i];
        if (s->native_window == window && s->surface != EGL_NO_SURFACE &&
            s->handle_array && s->count==CA01_BUFFER_COUNT) {
            const uint32_t handle=s->handle_array[s->next % CA01_BUFFER_COUNT];
            s->next++;
            return handle;
        }
    }
    return 0; /* Unknown window is not considered a successful acquisition. */
}
EGLBoolean eglChooseConfig(EGLDisplay d, const EGLint *attrs,
                            EGLConfig *out, EGLint capacity, EGLint *count) {
    ChooseFn original=(ChooseFn)dlsym(RTLD_NEXT,"eglChooseConfig");
    if (!original) {
        fputs("CA01-v2: real eglChooseConfig unavailable\n",stderr);
        return EGL_FALSE;
    }
    if (!enabled() || !attrs)return original(d,attrs,out,capacity,count);
    EGLint rewritten[129];
    int replaced=0;
    for (size_t i=0;i<128;i+=2) {
        if (attrs[i]==EGL_NONE) {
            rewritten[i]=EGL_NONE;
            if (replaced) {
                fputs("CA01-v2: translated EGL_WINDOW_BIT -> EGL_PBUFFER_BIT\n",stderr);
                return original(d,rewritten,out,capacity,count);
            }
            return original(d,attrs,out,capacity,count);
        }
        rewritten[i]=attrs[i];
        rewritten[i+1]=attrs[i+1];
        if (attrs[i]==EGL_SURFACE_TYPE && (attrs[i+1]&EGL_WINDOW_BIT)) {
            rewritten[i+1]=(attrs[i+1]&~EGL_WINDOW_BIT)|EGL_PBUFFER_BIT;
            replaced=1;
        }
    }
    fputs("CA01-v2: unsafe / unterminated EGL attribute list\n",stderr);
    return EGL_FALSE;
}
EGLSurface eglCreateWindowSurface(EGLDisplay d, EGLConfig cfg,
                                   EGLNativeWindowType window, const EGLint *attrs) {
    WindowFn original=(WindowFn)dlsym(RTLD_NEXT,"eglCreateWindowSurface");
    if (!original)return EGL_NO_SURFACE;
    if (!enabled())return original(d,cfg,window,attrs);
    if (!window || (attrs && attrs[0]!=EGL_NONE)) {
        fputs("CA01-v2: unsupported window or attributes\n",stderr);
        return EGL_NO_SURFACE;
    }
    uint32_t w[8];
    memcpy(w,(void *)(uintptr_t)window,sizeof(w));
    const uint32_t width=w[0], height=w[1];
    if (width<16||height<16||width>2048||height>2048||
        w[2]!=width||w[3]!=2||w[4]!=CA01_BUFFER_COUNT||w[5]==0) {
        fputs("CA01-v2: native-window shape rejected\n",stderr);
        return EGL_NO_SURFACE;
    }
    /* Pointer address is guest ARM32 and test-controlled. The original native
       window stores an address to three handles in word5. */
    uint32_t *handles=(uint32_t *)(uintptr_t)w[5];
    uint32_t candidate_handles[CA01_BUFFER_COUNT];
    memcpy(candidate_handles,handles,sizeof(candidate_handles));
    for (int i=0;i<CA01_BUFFER_COUNT;++i) {
        if (!candidate_handles[i]) {
            fputs("CA01-v2: empty buffer handle\n",stderr);
            return EGL_NO_SURFACE;
        }
        for (int j=0;j<i;++j)
            if (candidate_handles[i]==candidate_handles[j]) {
                fputs("CA01-v2: duplicate buffer handle\n",stderr);
                return EGL_NO_SURFACE;
            }
    }
    Ca01WindowState *slot=NULL;
    for (unsigned i=0;i<CA01_MAX_WINDOWS;++i)
        if (active[i].native_window==NULL) {slot=&active[i];break;}
    if (!slot) {
        fputs("CA01-v2: window registry full\n",stderr);
        return EGL_NO_SURFACE;
    }
    PbufferFn create=(PbufferFn)dlsym(RTLD_NEXT,"eglCreatePbufferSurface");
    if (!create)return EGL_NO_SURFACE;
    const EGLint surface_attrs[]={EGL_WIDTH,(EGLint)width,EGL_HEIGHT,(EGLint)height,EGL_NONE};
    EGLSurface surface=create(d,cfg,surface_attrs);
    if (surface==EGL_NO_SURFACE)return EGL_NO_SURFACE;
    *slot=(Ca01WindowState){(void *)(uintptr_t)window,0,CA01_BUFFER_COUNT,handles,surface};
    ((uint32_t *)(uintptr_t)window)[7]=(uint32_t)(uintptr_t)&ca01_test_acquire_next;
    fprintf(stderr,"CA01-v2: %ux%u pbuffer; +0x1c callback installed, synthetic handles\n",
            width,height);
    return surface;
}
EGLBoolean eglDestroySurface(EGLDisplay display,EGLSurface surface) {
    DestroyFn real=(DestroyFn)dlsym(RTLD_NEXT,"eglDestroySurface");
    if (!real)return EGL_FALSE;
    EGLBoolean ok=real(display,surface);
    if (ok && enabled()) {
        for (unsigned i=0;i<CA01_MAX_WINDOWS;++i)
            if (active[i].native_window && active[i].surface==surface)
                memset(&active[i],0,sizeof(active[i]));
    }
    return ok;
}
