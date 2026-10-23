/* Diagnostic only: real ARM EGL/GLES1 rendering, NOT a Toyota GUI. */
#include <EGL/egl.h>
#include <EGL/eglext.h>
#include <GLES/gl.h>
#include <stdio.h>
#include <stdlib.h>

static int fail(const char *what) {
    fprintf(stderr, "%s failed: EGL error 0x%x\n", what, eglGetError());
    return 1;
}
int main(void) {
    const EGLint cfg[] = { EGL_SURFACE_TYPE, EGL_PBUFFER_BIT,
        EGL_RENDERABLE_TYPE, EGL_OPENGL_ES_BIT,
        EGL_RED_SIZE, 8, EGL_GREEN_SIZE, 8, EGL_BLUE_SIZE, 8, EGL_NONE };
    const EGLint pb[] = { EGL_WIDTH, 800, EGL_HEIGHT, 480, EGL_NONE };
    const EGLint ctx[] = { EGL_CONTEXT_CLIENT_VERSION, 1, EGL_NONE };
    EGLint major, minor, count;
    EGLConfig config;
    PFNEGLGETPLATFORMDISPLAYEXTPROC platform =
        (PFNEGLGETPLATFORMDISPLAYEXTPROC)eglGetProcAddress("eglGetPlatformDisplayEXT");
    EGLDisplay d = platform ? platform(EGL_PLATFORM_SURFACELESS_MESA, EGL_DEFAULT_DISPLAY, NULL)
                            : eglGetDisplay(EGL_DEFAULT_DISPLAY);
    if (d == EGL_NO_DISPLAY || !eglInitialize(d, &major, &minor)) return fail("eglInitialize");
    if (!eglBindAPI(EGL_OPENGL_ES_API)) return fail("eglBindAPI");
    if (!eglChooseConfig(d, cfg, &config, 1, &count) || count < 1) return fail("eglChooseConfig");
    EGLSurface surface = eglCreatePbufferSurface(d, config, pb);
    if (surface == EGL_NO_SURFACE) return fail("eglCreatePbufferSurface");
    EGLContext context = eglCreateContext(d, config, EGL_NO_CONTEXT, ctx);
    if (context == EGL_NO_CONTEXT) return fail("eglCreateContext");
    if (!eglMakeCurrent(d, surface, surface, context)) return fail("eglMakeCurrent");
    printf("EGL_VERSION=%d.%d\nEGL_VENDOR=%s\nGL_RENDERER=%s\nGL_VERSION=%s\n",
        major, minor, eglQueryString(d, EGL_VENDOR), glGetString(GL_RENDERER), glGetString(GL_VERSION));
    glViewport(0, 0, 800, 480);
    glEnable(GL_SCISSOR_TEST);
    glScissor(0, 0, 400, 240); glClearColor(1, 0, 0, 1); glClear(GL_COLOR_BUFFER_BIT);
    glScissor(400, 0, 400, 240); glClearColor(0, 1, 0, 1); glClear(GL_COLOR_BUFFER_BIT);
    glScissor(0, 240, 400, 240); glClearColor(0, 0, 1, 1); glClear(GL_COLOR_BUFFER_BIT);
    glScissor(400, 240, 400, 240); glClearColor(1, 1, 1, 1); glClear(GL_COLOR_BUFFER_BIT);
    glDisable(GL_SCISSOR_TEST); glFinish();
    unsigned char *pixels = malloc(800 * 480 * 4);
    if (!pixels) return 2;
    glReadPixels(0, 0, 800, 480, GL_RGBA, GL_UNSIGNED_BYTE, pixels);
    if (glGetError() != GL_NO_ERROR) { free(pixels); return 3; }
    FILE *f = fopen("/tmp/out/arm-software-render.ppm", "wb");
    if (!f) { perror("output"); free(pixels); return 4; }
    fprintf(f, "P6\n800 480\n255\n");
    for (int y = 479; y >= 0; --y)
        for (int x = 0; x < 800; ++x)
            if (fwrite(pixels + 4 * (y * 800 + x), 1, 3, f) != 3) return 5;
    if (fclose(f)) return 6;
    free(pixels);
    eglMakeCurrent(d, EGL_NO_SURFACE, EGL_NO_SURFACE, EGL_NO_CONTEXT);
    eglDestroyContext(d, context); eglDestroySurface(d, surface); eglTerminate(d);
    puts("ARM_SOFTWARE_RENDER_800x480_OK");
    return 0;
}
