/*
 * Experiment only: EGL_WINDOW_BIT and EGL window surface -> Mesa pbuffer.
 * Runs with ARMEL Mesa under QEMU. Does not implement sysDisMng* or rq_*.
 * Explicit opt-in CA01_EGL_BRIDGE=1; never alters original firmware.
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

static int enabled(void) {
    const char *v = getenv("CA01_EGL_BRIDGE");
    return v && strcmp(v, "1") == 0;
}
EGLBoolean eglChooseConfig(EGLDisplay d, const EGLint *attrs,
                            EGLConfig *out, EGLint capacity, EGLint *count) {
    ChooseFn original = (ChooseFn)dlsym(RTLD_NEXT, "eglChooseConfig");
    if (!original) { fputs("CA01: missing real eglChooseConfig\n", stderr); return EGL_FALSE; }
    if (!enabled() || !attrs) return original(d, attrs, out, capacity, count);
    EGLint rewritten[129];
    int replaced = 0;
    for (size_t i = 0; i < 128; i += 2) {
        if (attrs[i] == EGL_NONE) {
            rewritten[i] = EGL_NONE;
            if (replaced) {
                fprintf(stderr, "CA01: eglChooseConfig WINDOW_BIT -> PBUFFER_BIT\n");
                return original(d, rewritten, out, capacity, count);
            }
            return original(d, attrs, out, capacity, count);
        }
        rewritten[i] = attrs[i];
        rewritten[i + 1] = attrs[i + 1];
        if (attrs[i] == EGL_SURFACE_TYPE && (attrs[i + 1] & EGL_WINDOW_BIT)) {
            rewritten[i + 1] = (attrs[i + 1] & ~EGL_WINDOW_BIT) | EGL_PBUFFER_BIT;
            replaced = 1;
        }
    }
    fputs("CA01: EGL attribute list exceeded safe maximum\n", stderr);
    return EGL_FALSE;
}
EGLSurface eglCreateWindowSurface(EGLDisplay d, EGLConfig c,
                                  EGLNativeWindowType window, const EGLint *attrs) {
    WindowFn original = (WindowFn)dlsym(RTLD_NEXT, "eglCreateWindowSurface");
    if (!original) { fputs("CA01: missing real eglCreateWindowSurface\n", stderr); return EGL_NO_SURFACE; }
    if (!enabled()) return original(d, c, window, attrs);
    /* Window from FUN_0002b66c, offsets 0..20 are established statically.
       Only use the window pointer provided by the trusted synthetic test.
       This interception is NOT safe for arbitrary unknown window pointers. */
    if (!window || (attrs && attrs[0] != EGL_NONE)) {
        fputs("CA01: null window or unsupported attributes\n", stderr);
        return EGL_NO_SURFACE;
    }
    uint32_t words[8];
    memcpy(words, (const void *)(uintptr_t)window, sizeof(words));
    uint32_t w = words[0], h = words[1];
    if (w < 16 || w > 2048 || h < 16 || h > 2048 ||
        words[2] != w || words[3] != 2 || words[4] != 3 || words[5] == 0) {
        fprintf(stderr, "CA01: reject window w=%u h=%u count=%u\n",
                w, h, words[4]);
        return EGL_NO_SURFACE;
    }
    PbufferFn create_pbuffer = (PbufferFn)dlsym(RTLD_NEXT, "eglCreatePbufferSurface");
    if (!create_pbuffer) {
        fputs("CA01: missing real eglCreatePbufferSurface\n", stderr);
        return EGL_NO_SURFACE;
    }
    const EGLint pbuffer[] = {EGL_WIDTH, (EGLint)w, EGL_HEIGHT, (EGLint)h, EGL_NONE};
    EGLSurface surface = create_pbuffer(d, c, pbuffer);
    fprintf(stderr, "CA01: native window %ux%u count=3 => offscreen pbuffer %s\n",
            w, h, surface == EGL_NO_SURFACE ? "FAILED" : "OK");
    return surface;
}
