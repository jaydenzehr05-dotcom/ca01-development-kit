/* An ARM ELF diagnostic that exercises modelled CA01 display/IPC contracts.
 * It is NOT PROC_HMI and must never be presented as original Toyota GUI output.
 */
#include "ca01_gui_compat.h"
#include "ca01_gui_egl_bridge.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define REQUIRE(condition,what) do { if (!(condition)) { fprintf(stderr,"FAIL %s\n",what); goto fail; } } while (0)

static int pixel_is(const Ca01Display *d,const uint8_t *p,int x,int y,
                    unsigned r,unsigned g,unsigned b) {
    const uint8_t *q=p+4*((size_t)y*d->width+(size_t)x);
    return q[0]==r && q[1]==g && q[2]==b && q[3]==255;
}
static int save_ppm(const char *path,const Ca01Display *d,const uint8_t *rgba) {
    FILE *f=fopen(path,"wb");
    if (!f) {perror(path);return 1;}
    if (fprintf(f,"P6\n%u %u\n255\n",d->width,d->height)<0) {
        fclose(f);return 1;
    }
    for (size_t i=0;i<(size_t)d->width*d->height;++i) {
        if (fwrite(rgba+4*i,1,3,f)!=3) {fclose(f);return 1;}
    }
    return fclose(f)==0?0:1;
}
int main(int argc,char **argv) {
    Ca01Display d={0};
    Ca01EglBridge egl={0};
    Ca01Queue queue={0};
    Ca01NativeWindow32 window;
    uint32_t handle[3]={0};
    Ca01Message m;
    Ca01Dispatch event;
    const uint8_t *p=NULL;
    uint8_t *earlier_pixels=NULL;
    size_t bytes=0;
    int ret=1;
    if (argc!=2) {fprintf(stderr,"usage: ca01_adapter_demo /output/diagnostic.ppm\n");return 2;}
    REQUIRE(ca01_display_init(&d,800,480)==CA01_OK,"display init");
    REQUIRE(ca01_display_build_window(&d,0x31000000U,&window)==CA01_OK,"window descriptor");
    REQUIRE(window.words[0]==800 && window.words[1]==480 &&
            window.words[3]==2 && window.words[4]==3 &&
            window.words[5]==0x31000000U,"original-shape descriptor fields");
    REQUIRE(ca01_queue_init(&queue,CA01_QUEUE_ID_HMI)==CA01_OK,"queue init");
    /* Bad native-window descriptors must never reach EGL. */
    window.words[4]=2;
    REQUIRE(ca01_egl_bridge_init(&egl,&window)==CA01_ERR_ARG,"reject invalid buffer count");
    window.words[4]=CA01_BUFFER_COUNT;
    REQUIRE(ca01_egl_bridge_init(&egl,&window)==CA01_OK,"EGL window-to-pbuffer bridge");
    printf("EGL_VENDOR=%s\n",ca01_egl_bridge_vendor(&egl));
    printf("GL_RENDERER=%s\n",ca01_egl_bridge_renderer(&egl));
    for (int frame=0;frame<3;frame++) {
        REQUIRE(ca01_display_get_back(&d,&handle[frame])==CA01_OK,"buffer acquire");
        REQUIRE(ca01_egl_bridge_draw_diagnostic(&egl,frame)==CA01_OK,"GLES1 draw");
        REQUIRE(ca01_egl_bridge_capture(&egl,&d,handle[frame])==CA01_OK,"pixel copy");
        REQUIRE(ca01_display_present(&d,handle[frame])==CA01_OK,"present buffer");
        REQUIRE(ca01_display_front(&d,&p,&bytes)==CA01_OK,"front RGBA");
        REQUIRE(bytes==(size_t)800*480*4,"RGBA expected size");
        if(frame==0) {
            REQUIRE(pixel_is(&d,p,200,120,0,0,255),"upper-left blue");
            REQUIRE(pixel_is(&d,p,600,120,255,255,255),"upper-right white");
            REQUIRE(pixel_is(&d,p,200,360,255,0,0),"lower-left red");
            REQUIRE(pixel_is(&d,p,600,360,0,255,0),"lower-right green");
            REQUIRE(save_ppm(argv[1],&d,p)==0,"save diagnostic frame");
        } else if (frame==1) {
            REQUIRE(pixel_is(&d,p,200,120,255,255,0),"frame1 yellow");
        } else {
            REQUIRE(pixel_is(&d,p,200,120,255,0,255),"frame2 magenta");
        }
    }
    REQUIRE(handle[0]!=handle[1] && handle[1]!=handle[2] &&
            handle[2]!=handle[0],"distinct triple buffer handles");
    REQUIRE(d.swaps==3,"three presentation events");
    REQUIRE(ca01_display_pixels(&d,handle[0],&earlier_pixels,&bytes)==CA01_OK,"old backbuffer");
    p=earlier_pixels;
    REQUIRE(pixel_is(&d,p,200,120,0,0,255),"old displayed buffer not overwritten");
    REQUIRE(ca01_queue_send(&queue,CA01_QUEUE_ID_HMI,(Ca01Message){0,1,2,0})==CA01_OK,"send type0");
    REQUIRE(ca01_queue_send(&queue,CA01_QUEUE_ID_HMI,(Ca01Message){CA01_EVENT_ALT,3,4,0})==CA01_OK,"send type41002");
    REQUIRE(ca01_queue_send(&queue,CA01_QUEUE_ID_HMI,(Ca01Message){0xdeaddead,5,6,0})==CA01_OK,"send unknown");
    REQUIRE(ca01_queue_receive(&queue,CA01_QUEUE_ID_HMI,&m)==CA01_OK && m.code==0,"receive type0");
    REQUIRE(ca01_queue_dispatch(&queue,&m,&event)==CA01_OK && event==CA01_DISPATCH_ZERO,"dispatch type0");
    REQUIRE(ca01_queue_receive(&queue,CA01_QUEUE_ID_HMI,&m)==CA01_OK && m.code==CA01_EVENT_ALT,"receive type41002");
    REQUIRE(ca01_queue_dispatch(&queue,&m,&event)==CA01_OK && event==CA01_DISPATCH_41002,"dispatch type41002");
    REQUIRE(ca01_queue_receive(&queue,CA01_QUEUE_ID_HMI,&m)==CA01_OK,"receive unknown");
    REQUIRE(ca01_queue_dispatch(&queue,&m,&event)==CA01_OK && event==CA01_DISPATCH_OTHER,"dispatch unknown");
    REQUIRE(queue.type_zero_count==1 && queue.type_41002_count==1 &&
            queue.other_count==1,"queue counters");
    printf("CA01_SYNTHETIC_ADAPTER_OK frames=%u buffer_count=%u queue=0x%x zero=%u alt=%u other=%u\n",
           d.swaps,window.words[4],queue.queue_id,queue.type_zero_count,
           queue.type_41002_count,queue.other_count);
    ret=0;
fail:
    ca01_egl_bridge_destroy(&egl);
    ca01_queue_destroy(&queue);
    ca01_display_destroy(&d);
    return ret;
}
