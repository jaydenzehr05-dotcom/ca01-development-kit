/* CA01 HMI emulation research model. NOT the proprietary Fujitsu Ten ABI.
 * Based on Ghidra findings; does not export vendor function names.
 * This GUI fixture neither changes nor launches vendor applications.
 * Separate research tools execute explicitly bounded Unicorn slices.
 */
#ifndef CA01_GUI_COMPAT_H
#define CA01_GUI_COMPAT_H
#include <stddef.h>
#include <stdint.h>

#include "ca01_hmi_ipc.h"
enum { CA01_BUFFER_COUNT = 3, CA01_MODEL_MAX_DIMENSION = 2048 };

typedef struct {
    /* The original 32-byte HMI window object uses 8 ARM32 words.
     * The 6th word is a guest *address* of an array of display handles,
     * not an actual pointer in this process.
     */
    uint32_t words[8];
} Ca01NativeWindow32;

/* Measured caller-visible descriptor. Tokens/handles are model values;
 * no physical-address semantics are claimed for the original +4 word. */
typedef struct {
    uint32_t bytes, memory_token, reserved, handle;
} Ca01DisplayMemory32;
_Static_assert(sizeof(Ca01DisplayMemory32)==16, "Display descriptor is 16 bytes");
_Static_assert(offsetof(Ca01DisplayMemory32,memory_token)==4, "VRAM token at +4");
_Static_assert(offsetof(Ca01DisplayMemory32,handle)==12, "Buffer handle at +12");

typedef struct {
    uint32_t width, height;
    size_t bytes_per_buffer;
    uint8_t *buffers[CA01_BUFFER_COUNT];
    uint32_t handle[CA01_BUFFER_COUNT];
    uint32_t current_front;
    uint32_t swaps;
    uint32_t pending_token;
    uint8_t alpha;
    int plane_enabled, ready;
} Ca01Display;

/* CPU-side display-buffer reference model (RGBA8, top-down). */
Ca01Result ca01_display_init(Ca01Display *d, uint32_t width, uint32_t height);
void ca01_display_destroy(Ca01Display *d);
Ca01Result ca01_display_build_window(Ca01Display *d, uint32_t guest_array_addr,
                                     Ca01NativeWindow32 *out);
Ca01Result ca01_display_set_plane(Ca01Display *d, int enabled, unsigned alpha);
Ca01Result ca01_display_get_back(Ca01Display *d, uint32_t *out_handle);
Ca01Result ca01_display_pixels(Ca01Display *d, uint32_t handle, uint8_t **pixels, size_t *bytes);
Ca01Result ca01_display_copy_bottom_up_rgba(Ca01Display *d, uint32_t handle,
                                             const uint8_t *src, size_t src_bytes);
Ca01Result ca01_display_present(Ca01Display *d, uint32_t handle);
Ca01Result ca01_display_front(Ca01Display *d, const uint8_t **pixels, size_t *bytes);

/* Shared validation for the explicit EGL bridge and original-shaped interposer. */
Ca01Result ca01_native_window_shape(const Ca01NativeWindow32 *window);
Ca01Result ca01_native_window_validate(const Ca01NativeWindow32 *window,
                                      const uint32_t handles[CA01_BUFFER_COUNT]);
Ca01Result ca01_display_export_descriptor(const Ca01Display *d,unsigned index,
                                           Ca01DisplayMemory32 *out);
Ca01Result ca01_display_handle_for_token(const Ca01Display *d,uint32_t token,uint32_t *out);
Ca01Result ca01_display_begin_vram(Ca01Display *d,uint32_t token);
Ca01Result ca01_display_wait_vram(Ca01Display *d,uint32_t token);
#endif
