#include "ca01_gui_egl_bridge.h"
#include <EGL/eglext.h>
#include <GLES/gl.h>
#include <stdlib.h>
#include <string.h>

Ca01Result ca01_egl_bridge_init(Ca01EglBridge *b, const Ca01NativeWindow32 *window) {
    if (!b || !window || b->ready) return CA01_ERR_ARG;
    const uint32_t width=window->words[0], height=window->words[1];
    /* Only the layout/values measured from the recovered HMI are accepted.
       This is NOT the native EGL window ABI; a pbuffer is used instead. */
    if (window->words[2]!=width || window->words[3]!=2 ||
        window->words[4]!=CA01_BUFFER_COUNT || window->words[5]==0)
        return CA01_ERR_ARG;
    if (!width || !height || width > CA01_MODEL_MAX_DIMENSION ||
        height > CA01_MODEL_MAX_DIMENSION) return CA01_ERR_RANGE;
    memset(b, 0, sizeof(*b));
    b->display = EGL_NO_DISPLAY;
    b->surface = EGL_NO_SURFACE;
    b->context = EGL_NO_CONTEXT;
    b->width = width;
    b->height = height;
    PFNEGLGETPLATFORMDISPLAYEXTPROC get_platform =
        (PFNEGLGETPLATFORMDISPLAYEXTPROC)eglGetProcAddress("eglGetPlatformDisplayEXT");
    b->display = get_platform
        ? get_platform(EGL_PLATFORM_SURFACELESS_MESA, EGL_DEFAULT_DISPLAY, NULL)
        : eglGetDisplay(EGL_DEFAULT_DISPLAY);
    EGLint major=0,minor=0,count=0;
    if (b->display == EGL_NO_DISPLAY || eglInitialize(b->display, &major, &minor) != EGL_TRUE)
        goto error;
    if (eglBindAPI(EGL_OPENGL_ES_API)!=EGL_TRUE) goto error;
    const EGLint config_attribs[] = {
        EGL_SURFACE_TYPE, EGL_PBUFFER_BIT,
        EGL_RENDERABLE_TYPE, EGL_OPENGL_ES_BIT,
        EGL_RED_SIZE, 8, EGL_GREEN_SIZE, 8, EGL_BLUE_SIZE, 8, EGL_ALPHA_SIZE, 8,
        EGL_DEPTH_SIZE, 16, EGL_NONE
    };
    if (eglChooseConfig(b->display,config_attribs,&b->config,1,&count)!=EGL_TRUE || count<1)
        goto error;
    const EGLint pbuffer[] = {EGL_WIDTH,(EGLint)width,EGL_HEIGHT,(EGLint)height,EGL_NONE};
    b->surface = eglCreatePbufferSurface(b->display,b->config,pbuffer);
    if (b->surface==EGL_NO_SURFACE) goto error;
    const EGLint context[] = {EGL_CONTEXT_CLIENT_VERSION,1,EGL_NONE};
    b->context = eglCreateContext(b->display,b->config,EGL_NO_CONTEXT,context);
    if (b->context==EGL_NO_CONTEXT) goto error;
    if (eglMakeCurrent(b->display,b->surface,b->surface,b->context)!=EGL_TRUE)
        goto error;
    if (!glGetString(GL_RENDERER)) goto error;
    b->ready=1;
    return CA01_OK;
error:
    b->last_egl_error = eglGetError();
    /* cleanup must not overwrite the error reported above */
    if (b->display != EGL_NO_DISPLAY) {
        eglMakeCurrent(b->display,EGL_NO_SURFACE,EGL_NO_SURFACE,EGL_NO_CONTEXT);
        if (b->context != EGL_NO_CONTEXT) eglDestroyContext(b->display,b->context);
        if (b->surface != EGL_NO_SURFACE) eglDestroySurface(b->display,b->surface);
        eglTerminate(b->display);
    }
    b->display = EGL_NO_DISPLAY;
    b->surface = EGL_NO_SURFACE;
    b->context = EGL_NO_CONTEXT;
    return CA01_ERR_STATE;
}

void ca01_egl_bridge_destroy(Ca01EglBridge *b) {
    if (!b) return;
    if (b->display != EGL_NO_DISPLAY) {
        eglMakeCurrent(b->display,EGL_NO_SURFACE,EGL_NO_SURFACE,EGL_NO_CONTEXT);
        if (b->context != EGL_NO_CONTEXT) eglDestroyContext(b->display,b->context);
        if (b->surface != EGL_NO_SURFACE) eglDestroySurface(b->display,b->surface);
        eglTerminate(b->display);
    }
    memset(b,0,sizeof(*b));
    b->display=EGL_NO_DISPLAY;
    b->surface=EGL_NO_SURFACE;
    b->context=EGL_NO_CONTEXT;
}

static void clear_rect(int x,int y,int w,int h,GLfloat r,GLfloat g,GLfloat b) {
    glScissor(x,y,w,h);
    glClearColor(r,g,b,1.0f);
    glClear(GL_COLOR_BUFFER_BIT);
}
Ca01Result ca01_egl_bridge_draw_diagnostic(Ca01EglBridge *b, int frame) {
    if (!b || !b->ready) return CA01_ERR_STATE;
    if (frame<0 || frame>2) return CA01_ERR_RANGE;
    if (eglMakeCurrent(b->display,b->surface,b->surface,b->context)!=EGL_TRUE)
        return CA01_ERR_STATE;
    glViewport(0,0,(GLsizei)b->width,(GLsizei)b->height);
    glEnable(GL_SCISSOR_TEST);
    if (frame==0) {
        const int half_w=(int)b->width/2,half_h=(int)b->height/2;
        clear_rect(0,0,half_w,half_h,1,0,0); /* bottom-left red */
        clear_rect(half_w,0,(int)b->width-half_w,half_h,0,1,0);
        clear_rect(0,half_h,half_w,(int)b->height-half_h,0,0,1);
        clear_rect(half_w,half_h,(int)b->width-half_w,(int)b->height-half_h,1,1,1);
    } else if (frame==1) {
        clear_rect(0,0,(int)b->width,(int)b->height,1,1,0);
    } else {
        clear_rect(0,0,(int)b->width,(int)b->height,1,0,1);
    }
    glDisable(GL_SCISSOR_TEST);
    glFinish();
    return glGetError()==GL_NO_ERROR ? CA01_OK : CA01_ERR_STATE;
}

Ca01Result ca01_egl_bridge_capture(Ca01EglBridge *b,Ca01Display *d,
                                    uint32_t target_handle) {
    if (!b || !b->ready || !d || !d->ready) return CA01_ERR_STATE;
    if (d->width != b->width || d->height != b->height) return CA01_ERR_RANGE;
    uint8_t *pixels=(uint8_t *)malloc(d->bytes_per_buffer);
    if (!pixels) return CA01_ERR_ALLOC;
    glPixelStorei(GL_PACK_ALIGNMENT,4);
    glReadPixels(0,0,(GLsizei)b->width,(GLsizei)b->height,
                 GL_RGBA,GL_UNSIGNED_BYTE,pixels);
    GLenum error=glGetError();
    Ca01Result status= error==GL_NO_ERROR ?
      ca01_display_copy_bottom_up_rgba(d,target_handle,pixels,d->bytes_per_buffer) :
      CA01_ERR_STATE;
    free(pixels);
    return status;
}

const char *ca01_egl_bridge_vendor(Ca01EglBridge *b) {
    return (b && b->ready)?eglQueryString(b->display,EGL_VENDOR):NULL;
}
const char *ca01_egl_bridge_renderer(Ca01EglBridge *b) {
    return (b && b->ready)?(const char *)glGetString(GL_RENDERER):NULL;
}
