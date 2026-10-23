/* Mesa/EGL PBuffer renderer for synthetic CA01 display contract tests.
 * This is not a vendor native-window driver and does not load Toyota applications.
 */
#ifndef CA01_GUI_EGL_BRIDGE_H
#define CA01_GUI_EGL_BRIDGE_H
#include "ca01_gui_compat.h"
#include <EGL/egl.h>

typedef struct {
    EGLDisplay display;
    EGLConfig config;
    EGLSurface surface;
    EGLContext context;
    uint32_t width, height;
    EGLint last_egl_error;
    int ready;
} Ca01EglBridge;

Ca01Result ca01_egl_bridge_init(Ca01EglBridge *b, const Ca01NativeWindow32 *window);
void ca01_egl_bridge_destroy(Ca01EglBridge *b);
Ca01Result ca01_egl_bridge_draw_diagnostic(Ca01EglBridge *b, int frame);
Ca01Result ca01_egl_bridge_capture(Ca01EglBridge *b, Ca01Display *d,
                                    uint32_t target_handle);
const char *ca01_egl_bridge_vendor(Ca01EglBridge *b);
const char *ca01_egl_bridge_renderer(Ca01EglBridge *b);
#endif
