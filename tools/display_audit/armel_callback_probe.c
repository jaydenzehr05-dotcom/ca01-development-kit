/*
 * Standalone ARMEL EGL/GLES1 pbuffer experiment for Toyota CA01 research.
 * Synthetic frames only; never loads or executes any recovered Toyota code.
 * This is NOT a vendor display API or ABI replacement.
 */
#define _POSIX_C_SOURCE 200809L
#include <EGL/egl.h>
#include <EGL/eglext.h>
#include <GLES/gl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#ifndef EGL_PLATFORM_SURFACELESS_MESA
#define EGL_PLATFORM_SURFACELESS_MESA 0x31DD
#endif
#ifndef CA01_TEST_WIDTH
#define CA01_TEST_WIDTH 800
#endif
#ifndef CA01_TEST_HEIGHT
#define CA01_TEST_HEIGHT 480
#endif
enum { WIDTH = CA01_TEST_WIDTH, HEIGHT = CA01_TEST_HEIGHT, FRAME_COUNT = 3 };
static void report_egl_failure(const char *step) {
    fprintf(stderr, "FAIL %s EGL error=0x%04x\n", step, (unsigned)eglGetError());
}
static void report_gl_failure(const char *step) {
    fprintf(stderr, "FAIL %s GL error=0x%04x\n", step, (unsigned)glGetError());
}
static uint64_t hash_pixels(const unsigned char *p, size_t len) {
    uint64_t h = UINT64_C(14695981039346656037);
    for (size_t i = 0; i < len; ++i) {
        h ^= p[i];
        h *= UINT64_C(1099511628211);
    }
    return h;
}
static int write_ppm(const char *filename, const uint8_t *rgba) {
    FILE *out = fopen(filename, "wb");
    if (!out) { perror(filename); return -1; }
    if (fprintf(out, "P6\n%d %d\n255\n", WIDTH, HEIGHT) < 0) {
        fclose(out); return -1;
    }
    /* OpenGL ES glReadPixels is bottom-first; PPM stores top-first. */
    for (int y = HEIGHT - 1; y >= 0; --y) {
        for (int x = 0; x < WIDTH; ++x) {
            const uint8_t *p = rgba + ((size_t)y * WIDTH + (size_t)x) * 4u;
            if (fwrite(p, 1, 3, out) != 3) { fclose(out); return -1; }
        }
    }
    return fclose(out) == 0 ? 0 : -1;
}
int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s OUTPUT_PREFIX\n", argv[0]); return 2;
    }
    const int window_mode = getenv("CA01_PROBE_NATIVE_WINDOW") &&
                            strcmp(getenv("CA01_PROBE_NATIVE_WINDOW"), "1") == 0;
    uint32_t handles[3] = {0xca010001u, 0xca010002u, 0xca010003u};
    uint32_t native_window[8] = {
        WIDTH, HEIGHT, WIDTH, 2u, 3u, (uint32_t)(uintptr_t)handles, 0u, 0u
    };
    if (getenv("CA01_PROBE_INVALID_WINDOW")) native_window[4] = 2u;
    printf("surface_mode=%s\n", window_mode ? "Toyota-style synthetic window" : "pbuffer");
    const char *client_exts = eglQueryString(EGL_NO_DISPLAY, EGL_EXTENSIONS);
    printf("client_exts=%s\n", client_exts ? client_exts : "(unavailable)");
    PFNEGLGETPLATFORMDISPLAYEXTPROC get_platform =
        (PFNEGLGETPLATFORMDISPLAYEXTPROC)eglGetProcAddress("eglGetPlatformDisplayEXT");
    EGLDisplay display = EGL_NO_DISPLAY;
    if (get_platform && client_exts && strstr(client_exts, "EGL_MESA_platform_surfaceless"))
        display = get_platform(EGL_PLATFORM_SURFACELESS_MESA, EGL_DEFAULT_DISPLAY, NULL);
    if (display == EGL_NO_DISPLAY) display = eglGetDisplay(EGL_DEFAULT_DISPLAY);
    if (display == EGL_NO_DISPLAY) { report_egl_failure("eglGetDisplay"); return 10; }
    EGLint major = 0, minor = 0;
    if (eglInitialize(display, &major, &minor) != EGL_TRUE) {
        report_egl_failure("eglInitialize"); return 11;
    }
    int result = 0;
    EGLContext ctx = EGL_NO_CONTEXT;
    EGLSurface surface = EGL_NO_SURFACE;
    uint8_t *frames[FRAME_COUNT] = {NULL, NULL, NULL};
    uint64_t hashes[FRAME_COUNT] = {0, 0, 0};
    printf("egl=%d.%d vendor=%s\n", (int)major, (int)minor, eglQueryString(display, EGL_VENDOR));
    if (eglBindAPI(EGL_OPENGL_ES_API) != EGL_TRUE) {
        report_egl_failure("eglBindAPI"); result = 12; goto cleanup;
    }
    const EGLint cfg[] = {
        EGL_SURFACE_TYPE, window_mode ? EGL_WINDOW_BIT : EGL_PBUFFER_BIT,
        EGL_RENDERABLE_TYPE, EGL_OPENGL_ES_BIT,
        EGL_RED_SIZE, 8, EGL_GREEN_SIZE, 8,
        EGL_BLUE_SIZE, 8, EGL_ALPHA_SIZE, 8,
        EGL_DEPTH_SIZE, 16,
        EGL_NONE
    };
    EGLConfig config = 0; EGLint found = 0;
    if (eglChooseConfig(display, cfg, &config, 1, &found) != EGL_TRUE || found < 1) {
        report_egl_failure("eglChooseConfig"); result = 13; goto cleanup;
    }
    EGLint surface_types = 0, renderable = 0;
    eglGetConfigAttrib(display, config, EGL_SURFACE_TYPE, &surface_types);
    eglGetConfigAttrib(display, config, EGL_RENDERABLE_TYPE, &renderable);
    printf("config_surface_types=0x%x config_renderable=0x%x\n",
           (unsigned)surface_types, (unsigned)renderable);
    const EGLint context_attrs[] = { EGL_CONTEXT_CLIENT_VERSION, 1, EGL_NONE };
    ctx = eglCreateContext(display, config, EGL_NO_CONTEXT, context_attrs);
    if (ctx == EGL_NO_CONTEXT) {
        report_egl_failure("eglCreateContext"); result = 14; goto cleanup;
    }
    const EGLint pbuffer_attrs[] = {EGL_WIDTH, WIDTH, EGL_HEIGHT, HEIGHT, EGL_NONE};
    surface = window_mode ?
        eglCreateWindowSurface(display, config, (EGLNativeWindowType)native_window, NULL) :
        eglCreatePbufferSurface(display, config, pbuffer_attrs);
    if (surface == EGL_NO_SURFACE) {
        report_egl_failure(window_mode ? "eglCreateWindowSurface" : "eglCreatePbufferSurface");
        result = 15; goto cleanup;
    }
    if (window_mode && native_window[7] == 0) {
        fputs("FAIL no callback installed at window +0x1c\n",stderr);
        result = 23; goto cleanup;
    }
    if (eglMakeCurrent(display, surface, surface, ctx) != EGL_TRUE) {
        report_egl_failure("eglMakeCurrent"); result = 16; goto cleanup;
    }
    printf("gl_vendor=%s\ngl_renderer=%s\ngl_version=%s\n",
           (const char *)glGetString(GL_VENDOR),
           (const char *)glGetString(GL_RENDERER),
           (const char *)glGetString(GL_VERSION));
    printf("glBlendFuncSeparateOES_proc=%s\n",
           eglGetProcAddress("glBlendFuncSeparateOES") ? "present" : "missing");
    const GLfloat vertices[6] = {-0.75f, -0.65f, 0.75f, -0.65f, 0.0f, 0.8f};
    const GLfloat colors[12] = {1.f,0.f,0.f,1.f, 0.f,1.f,0.f,1.f, 0.f,0.f,1.f,1.f};
    const size_t frame_bytes = (size_t)WIDTH * HEIGHT * 4u;
    glViewport(0, 0, WIDTH, HEIGHT);
    glMatrixMode(GL_PROJECTION); glLoadIdentity();
    glMatrixMode(GL_MODELVIEW); glLoadIdentity();
    glDisable(GL_DEPTH_TEST);
    glEnableClientState(GL_VERTEX_ARRAY);
    glEnableClientState(GL_COLOR_ARRAY);
    glVertexPointer(2, GL_FLOAT, 0, vertices);
    glColorPointer(4, GL_FLOAT, 0, colors);
    glPixelStorei(GL_PACK_ALIGNMENT, 1);
    for (int frame = 0; frame < FRAME_COUNT; ++frame) {
        frames[frame] = (uint8_t *)malloc(frame_bytes);
        if (!frames[frame]) { result = 17; goto cleanup; }
        glClearColor(0.10f + frame * 0.28f, 0.12f, 0.36f, 1.f);
        glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);
        glDrawArrays(GL_TRIANGLES, 0, 3);
        glFinish();
        if (glGetError() != GL_NO_ERROR) {
            report_gl_failure("glDrawArrays"); result = 18; goto cleanup;
        }
        glReadPixels(0, 0, WIDTH, HEIGHT, GL_RGBA, GL_UNSIGNED_BYTE, frames[frame]);
        GLenum gl_error = glGetError();
        if (gl_error != GL_NO_ERROR) {
            fprintf(stderr, "FAIL glReadPixels GL error=0x%04x\n", (unsigned)gl_error);
            result = 19; goto cleanup;
        }
        if (eglSwapBuffers(display, surface) != EGL_TRUE) {
            report_egl_failure("eglSwapBuffers"); result = 22; goto cleanup;
        }
        if (window_mode) {
            typedef uint32_t (*AcquireFn)(void *);
            AcquireFn acquire = (AcquireFn)(uintptr_t)native_window[7];
            const uint32_t acquired = acquire(native_window);
            if (acquired != handles[frame]) {
                fprintf(stderr,"FAIL callback: frame=%d got=0x%08x expected=0x%08x\n",
                        frame,acquired,handles[frame]);
                result = 24; goto cleanup;
            }
            printf("callback_frame=%d handle=0x%08x\n",frame,acquired);
        }
        char name[1024];
        int name_len = snprintf(name, sizeof(name), "%s-%02d.ppm", argv[1], frame);
        if (name_len < 0 || (size_t)name_len >= sizeof(name) ||
            write_ppm(name, frames[frame]) != 0) {
            fprintf(stderr, "FAIL write_ppm frame=%d\n", frame);
            result = 20; goto cleanup;
        }
        hashes[frame] = hash_pixels(frames[frame], frame_bytes);
        printf("frame=%d size=%zu fnv64=%016" PRIx64 " bottomLeft=%02x%02x%02x\n",
               frame, frame_bytes, hashes[frame],
               frames[frame][0], frames[frame][1], frames[frame][2]);
    }
    if (window_mode) {
        typedef uint32_t (*AcquireFn)(void *);
        AcquireFn acquire=(AcquireFn)(uintptr_t)native_window[7];
        uint32_t next=acquire(native_window);
        if (next != handles[0]) {
            fprintf(stderr,"FAIL callback does not wrap to first handle: 0x%08x\n",next);
            result=25; goto cleanup;
        }
        printf("callback_wrap_handle=0x%08x\n",next);
    }
    if (hashes[0] == hashes[1] || hashes[1] == hashes[2] || hashes[0] == hashes[2]) {
        fprintf(stderr, "FAIL triple-buffer frames are identical\n");
        result = 21;
    }
cleanup:
    if (ctx != EGL_NO_CONTEXT && surface != EGL_NO_SURFACE)
        eglMakeCurrent(display, EGL_NO_SURFACE, EGL_NO_SURFACE, EGL_NO_CONTEXT);
    if (surface != EGL_NO_SURFACE) eglDestroySurface(display, surface);
    if (ctx != EGL_NO_CONTEXT) eglDestroyContext(display, ctx);
    for (int i = 0; i < FRAME_COUNT; ++i) free(frames[i]);
    eglTerminate(display);
    if (result == 0) printf("PASS armel-egl-gles1-%s-3frames (synthetic only)\n",
                            window_mode ? "window-bridge" : "pbuffer");
    return result;
}
