#include "ca01_gui_compat.h"
#include <limits.h>
#include <stdlib.h>
#include <string.h>

_Static_assert(sizeof(Ca01NativeWindow32) == 32, "ARM window model must contain 32 bytes");

static int find_buffer(const Ca01Display *d, uint32_t handle) {
    unsigned i;
    for (i = 0; i < CA01_BUFFER_COUNT; ++i)
        if (d->handle[i] == handle) return (int)i;
    return -1;
}

Ca01Result ca01_display_init(Ca01Display *d, uint32_t width, uint32_t height) {
    unsigned i;
    if (!d) return CA01_ERR_ARG;
    if (d->ready) return CA01_ERR_STATE;
    if (!width || !height || width > CA01_MODEL_MAX_DIMENSION ||
        height > CA01_MODEL_MAX_DIMENSION) return CA01_ERR_RANGE;
    /* This is a deliberately bounded synthetic framebuffer allocation. */
    size_t bytes = (size_t)width * (size_t)height * 4U;
    if (bytes / 4U / width != height) return CA01_ERR_RANGE;
    memset(d, 0, sizeof(*d));
    d->width = width;
    d->height = height;
    d->bytes_per_buffer = bytes;
    d->current_front = UINT32_MAX;
    for (i = 0; i < CA01_BUFFER_COUNT; ++i) {
        d->buffers[i] = (uint8_t *)calloc(1, bytes);
        if (!d->buffers[i]) {
            ca01_display_destroy(d);
            return CA01_ERR_ALLOC;
        }
        /* These are *model handles*, not original physical addresses. */
        d->handle[i] = 0xca010001U + i;
    }
    d->ready = 1;
    d->plane_enabled = 1;
    d->alpha = 255;
    return CA01_OK;
}

void ca01_display_destroy(Ca01Display *d) {
    unsigned i;
    if (!d) return;
    for (i=0; i<CA01_BUFFER_COUNT; ++i) {
        free(d->buffers[i]);
        d->buffers[i] = NULL;
    }
    memset(d, 0, sizeof(*d));
}

Ca01Result ca01_display_build_window(Ca01Display *d, uint32_t guest_array_addr,
                                     Ca01NativeWindow32 *out) {
    if (!d || !out || !d->ready || !guest_array_addr || (guest_array_addr & 3U)) return CA01_ERR_ARG;
    memset(out, 0, sizeof(*out));
    out->words[0] = d->width;
    out->words[1] = d->height;
    out->words[2] = d->width;
    out->words[3] = 2;  /* observed native-window field, semantics unknown */
    out->words[4] = CA01_BUFFER_COUNT;
    out->words[5] = guest_array_addr; /* expected guest address of handles */
    /* Remaining two words remain zero. Actual vendor callback still unknown. */
    return CA01_OK;
}

Ca01Result ca01_display_set_plane(Ca01Display *d, int enabled, unsigned alpha) {
    if (!d || !d->ready) return CA01_ERR_STATE;
    if ((enabled != 0 && enabled != 1) || alpha > 255) return CA01_ERR_RANGE;
    d->plane_enabled = enabled;
    d->alpha = (uint8_t)alpha;
    return CA01_OK;
}

Ca01Result ca01_display_get_back(Ca01Display *d, uint32_t *out_handle) {
    if (!d || !d->ready || !out_handle) return CA01_ERR_ARG;
    unsigned idx = d->current_front == UINT32_MAX ? 0 :
                   (d->current_front + 1) % CA01_BUFFER_COUNT;
    *out_handle = d->handle[idx];
    return CA01_OK;
}

Ca01Result ca01_display_pixels(Ca01Display *d, uint32_t handle, uint8_t **pixels, size_t *bytes) {
    if (!d || !d->ready || !pixels || !bytes) return CA01_ERR_ARG;
    int idx = find_buffer(d, handle);
    if (idx < 0) return CA01_ERR_NOT_FOUND;
    *pixels = d->buffers[idx];
    *bytes = d->bytes_per_buffer;
    return CA01_OK;
}

Ca01Result ca01_display_copy_bottom_up_rgba(Ca01Display *d, uint32_t handle,
                                             const uint8_t *src, size_t src_bytes) {
    if (!d || !d->ready || !src) return CA01_ERR_ARG;
    if (src_bytes != d->bytes_per_buffer) return CA01_ERR_RANGE;
    int idx = find_buffer(d, handle);
    if (idx < 0) return CA01_ERR_NOT_FOUND;
    const size_t row_bytes = (size_t)d->width * 4U;
    unsigned y;
    for (y=0; y<d->height; ++y) {
        memcpy(d->buffers[idx] + row_bytes * y,
               src + row_bytes * (d->height - 1U - y), row_bytes);
    }
    return CA01_OK;
}

Ca01Result ca01_display_present(Ca01Display *d, uint32_t handle) {
    if (!d || !d->ready) return CA01_ERR_STATE;
    if (!d->plane_enabled) return CA01_ERR_STATE;
    int idx = find_buffer(d, handle);
    if (idx < 0) return CA01_ERR_NOT_FOUND;
    if ((uint32_t)idx == d->current_front) return CA01_ERR_STATE;
    d->current_front = (uint32_t)idx;
    d->swaps += 1;
    return CA01_OK;
}

Ca01Result ca01_display_front(Ca01Display *d, const uint8_t **pixels, size_t *bytes) {
    if (!d || !d->ready || !pixels || !bytes) return CA01_ERR_ARG;
    if (d->current_front == UINT32_MAX) return CA01_ERR_STATE;
    *pixels = d->buffers[d->current_front];
    *bytes = d->bytes_per_buffer;
    return CA01_OK;
}

Ca01Result ca01_native_window_shape(const Ca01NativeWindow32 *w) {
    if (!w || !w->words[0] || !w->words[1] ||
        w->words[0]>CA01_MODEL_MAX_DIMENSION || w->words[1]>CA01_MODEL_MAX_DIMENSION ||
        w->words[2]!=w->words[0] || w->words[3]!=2 ||
        w->words[4]!=CA01_BUFFER_COUNT || !w->words[5] || (w->words[5]&3))
        return CA01_ERR_ARG;
    return CA01_OK;
}
Ca01Result ca01_native_window_validate(const Ca01NativeWindow32 *w,const uint32_t handles[3]) {
    if (ca01_native_window_shape(w)!=CA01_OK || !handles) return CA01_ERR_ARG;
    for(unsigned i=0;i<CA01_BUFFER_COUNT;i++) {
        if(!handles[i])return CA01_ERR_ARG;
        for(unsigned j=0;j<i;j++)if(handles[j]==handles[i])return CA01_ERR_ARG;
    }
    return CA01_OK;
}
Ca01Result ca01_display_export_descriptor(const Ca01Display *d,unsigned index,Ca01DisplayMemory32 *out) {
    if(!d || !d->ready)return CA01_ERR_STATE;
    if(!out)return CA01_ERR_ARG;
    if(index>=CA01_BUFFER_COUNT)return CA01_ERR_RANGE;
    if(!d->buffers[index] || !d->handle[index])return CA01_ERR_STATE;
    *out=(Ca01DisplayMemory32){(uint32_t)d->bytes_per_buffer,0xcb010001U+index,0,d->handle[index]};
    return CA01_OK;
}
Ca01Result ca01_display_handle_for_token(const Ca01Display *d,uint32_t token,uint32_t *out) {
    if(!d || !d->ready)return CA01_ERR_STATE;
    if(!out)return CA01_ERR_ARG;
    for(unsigned i=0;i<CA01_BUFFER_COUNT;i++) {
        Ca01DisplayMemory32 m;
        if(ca01_display_export_descriptor(d,i,&m)==CA01_OK && m.memory_token==token) {
            *out=m.handle;return CA01_OK;
        }
    }
    return CA01_ERR_NOT_FOUND;
}
Ca01Result ca01_display_begin_vram(Ca01Display *d,uint32_t token) {
    uint32_t handle;
    if(!d || !d->ready || d->pending_token)return CA01_ERR_STATE;
    Ca01Result result=ca01_display_handle_for_token(d,token,&handle);
    if(result!=CA01_OK)return result;
    if(d->current_front!=UINT32_MAX && d->handle[d->current_front]==handle)return CA01_ERR_STATE;
    d->pending_token=token;return CA01_OK;
}
Ca01Result ca01_display_wait_vram(Ca01Display *d,uint32_t token) {
    uint32_t handle;
    if(!d || !d->ready || !token || d->pending_token!=token)return CA01_ERR_STATE;
    Ca01Result result=ca01_display_handle_for_token(d,token,&handle);
    if(result!=CA01_OK)return result;
    result=ca01_display_present(d,handle);
    if(result==CA01_OK)d->pending_token=0;
    return result;
}
