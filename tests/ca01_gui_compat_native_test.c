#include "ca01_gui_compat.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
static int allocation_budget=-1;
void *__real_calloc(size_t,size_t);
void *__wrap_calloc(size_t n,size_t size) {
    if(allocation_budget==0)return NULL;
    if(allocation_budget>0)--allocation_budget;
    return __real_calloc(n,size);
}

#define CHECK(x) do { if (!(x)) { fprintf(stderr,"CHECK failed at %s:%d: %s\n",__FILE__,__LINE__,#x); return 1; } } while (0)

static int test_display(void) {
    Ca01Display d={0};
    Ca01NativeWindow32 win;
    uint32_t h=0, h2=0;
    uint8_t *p=NULL;
    const uint8_t *front=NULL;
    size_t bytes=0;
    uint8_t src[4*2*4]={0};
    CHECK(ca01_display_init(NULL,4,2)==CA01_ERR_ARG);
    CHECK(ca01_display_init(&d,0,2)==CA01_ERR_RANGE);
    CHECK(ca01_display_init(&d,4,0)==CA01_ERR_RANGE);
    CHECK(ca01_display_init(&d,CA01_MODEL_MAX_DIMENSION+1,2)==CA01_ERR_RANGE);
    CHECK(ca01_display_init(&d,4,2)==CA01_OK);
    CHECK(ca01_display_init(&d,4,2)==CA01_ERR_STATE);
    CHECK(d.ready && d.bytes_per_buffer==32 && d.width==4 && d.height==2);
    CHECK(ca01_display_build_window(&d,0,&win)==CA01_ERR_ARG);
    CHECK(ca01_display_build_window(&d,0x31000001,&win)==CA01_ERR_ARG);
    CHECK(ca01_display_build_window(&d,0x31000000,&win)==CA01_OK);
    CHECK(sizeof(win)==32);
    CHECK(win.words[0]==4 && win.words[1]==2 && win.words[2]==4);
    CHECK(win.words[3]==2 && win.words[4]==3 && win.words[5]==0x31000000);
    CHECK(win.words[6]==0 && win.words[7]==0);
    CHECK(ca01_display_front(&d,&front,&bytes)==CA01_ERR_STATE);
    CHECK(ca01_display_get_back(&d,&h)==CA01_OK && h==0xca010001);
    CHECK(ca01_display_pixels(&d,0x12345678,&p,&bytes)==CA01_ERR_NOT_FOUND);
    CHECK(ca01_display_pixels(&d,h,&p,&bytes)==CA01_OK);
    CHECK(bytes==32 && p!=NULL);
    /* OpenGL's pixel origin is bottom left. The model stores top-down RGBA. */
    for (int i=0;i<4;i++) {
        src[i*4+0]=255; src[i*4+3]=255;
        src[16+i*4+2]=255; src[16+i*4+3]=255;
    }
    CHECK(ca01_display_copy_bottom_up_rgba(&d,h,src,31)==CA01_ERR_RANGE);
    CHECK(ca01_display_copy_bottom_up_rgba(&d,0xBAD,src,32)==CA01_ERR_NOT_FOUND);
    CHECK(ca01_display_copy_bottom_up_rgba(&d,h,src,32)==CA01_OK);
    CHECK(p[0]==0 && p[1]==0 && p[2]==255 && p[3]==255);
    CHECK(p[16]==255 && p[17]==0 && p[18]==0 && p[19]==255);
    CHECK(ca01_display_set_plane(&d,1,256)==CA01_ERR_RANGE);
    CHECK(ca01_display_set_plane(&d,2,255)==CA01_ERR_RANGE);
    CHECK(ca01_display_set_plane(&d,0,127)==CA01_OK);
    CHECK(ca01_display_present(&d,h)==CA01_ERR_STATE);
    CHECK(ca01_display_set_plane(&d,1,255)==CA01_OK);
    CHECK(ca01_display_present(&d,h)==CA01_OK);
    CHECK(ca01_display_present(&d,h)==CA01_ERR_STATE);
    CHECK(ca01_display_front(&d,&front,&bytes)==CA01_OK && front==p && bytes==32);
    CHECK(ca01_display_get_back(&d,&h2)==CA01_OK);
    CHECK(h2!=h && h2==0xca010002);
    CHECK(ca01_display_present(&d,h2)==CA01_OK);
    CHECK(ca01_display_get_back(&d,&h2)==CA01_OK && h2==0xca010003);
    CHECK(ca01_display_present(&d,h2)==CA01_OK);
    CHECK(ca01_display_get_back(&d,&h2)==CA01_OK && h2==h);
    CHECK(d.swaps==3);
    ca01_display_destroy(&d);
    CHECK(!d.ready && d.buffers[0]==NULL);
    ca01_display_destroy(&d);
    return 0;
}
static int test_queue(void) {
    CHECK(sizeof(Ca01Message)==16);
    CHECK(CA01_QUEUE_CAPACITY==64);
    CHECK(offsetof(Ca01Message,code)==0 && offsetof(Ca01Message,subcommand)==4);
    CHECK(offsetof(Ca01Message,event)==8 && offsetof(Ca01Message,payload)==12);
    Ca01Queue q={0};
    Ca01Message m;
    Ca01Dispatch event;
    CHECK(ca01_queue_init(&q,0)==CA01_ERR_ARG);
    CHECK(ca01_queue_init(&q,CA01_QUEUE_ID_HMI)==CA01_OK);
    CHECK(ca01_queue_receive(&q,CA01_QUEUE_ID_HMI,&m)==CA01_ERR_EMPTY);
    for(int i=0;i<CA01_QUEUE_CAPACITY;i++) {
        Ca01Message entry={(uint32_t)i,(uint32_t)(i+100),0,0};
        CHECK(ca01_queue_send(&q,CA01_QUEUE_ID_HMI,entry)==CA01_OK);
    }
    CHECK(ca01_queue_send(&q,CA01_QUEUE_ID_HMI,(Ca01Message){0,0,0,0})==CA01_ERR_FULL);
    CHECK(ca01_queue_receive(&q,0,&m)==CA01_ERR_ARG);
    CHECK(ca01_queue_receive(&q,CA01_QUEUE_ID_HMI,&m)==CA01_OK);
    CHECK(m.code==0 && m.subcommand==100);
    CHECK(ca01_queue_send(&q,CA01_QUEUE_ID_HMI,(Ca01Message){CA01_EVENT_ALT,567,0,0})==CA01_OK);
    for(int i=1;i<CA01_QUEUE_CAPACITY;i++) {
        CHECK(ca01_queue_receive(&q,CA01_QUEUE_ID_HMI,&m)==CA01_OK);
        CHECK(m.code==(uint32_t)i && m.subcommand==(uint32_t)(i+100));
    }
    CHECK(ca01_queue_receive(&q,CA01_QUEUE_ID_HMI,&m)==CA01_OK);
    CHECK(m.code==CA01_EVENT_ALT && m.subcommand==567);
    CHECK(ca01_queue_receive(&q,CA01_QUEUE_ID_HMI,&m)==CA01_ERR_EMPTY);
    CHECK(ca01_queue_dispatch(&q,&(Ca01Message){0,0,0,0},&event)==CA01_OK);
    CHECK(event==CA01_DISPATCH_ZERO && q.type_zero_count==1);
    CHECK(ca01_queue_dispatch(&q,&m,&event)==CA01_OK);
    CHECK(event==CA01_DISPATCH_41002 && q.type_41002_count==1);
    CHECK(ca01_queue_dispatch(&q,&(Ca01Message){0xdeadbeef,0,0,0},&event)==CA01_OK);
    CHECK(event==CA01_DISPATCH_OTHER && q.other_count==1);
    CHECK(ca01_queue_dispatch(&q,NULL,&event)==CA01_ERR_ARG);
    m=(Ca01Message){0x41002,7,10,0xfedcba98};
    CHECK(ca01_queue_send_t(&q,&m,0)==0);
    m=(Ca01Message){0,0,0,0};
    CHECK(ca01_queue_receive_p(&q,&m)==-1);
    CHECK(m.code==0x41002 && m.subcommand==7 && m.event==10 && m.payload==0xfedcba98);
    CHECK(ca01_queue_receive_p(&q,&m)==-2);
    CHECK(m.payload==0xfedcba98);
    CHECK(ca01_queue_receive_t(&q,&m,1)==-1);
    CHECK(m.code==0x41002 && m.subcommand==7 && m.event==10 && m.payload==0xfedcba98);
    ca01_queue_destroy(&q);
    return 0;
}
static int test_allocation_failures(void) {
    for(int failure=0;failure<3;failure++) {
        Ca01Display d={0};allocation_budget=failure;
        CHECK(ca01_display_init(&d,800,480)==CA01_ERR_ALLOC);
        CHECK(!d.ready && !d.buffers[0] && !d.buffers[1] && !d.buffers[2]);
        ca01_display_destroy(&d);
    }
    allocation_budget=-1;return 0;
}
static int test_descriptor_service(void) {
    Ca01Display d={0}; Ca01DisplayMemory32 descriptor;
    Ca01NativeWindow32 window; uint32_t handle=0;
    CHECK(sizeof(descriptor)==16 && offsetof(Ca01DisplayMemory32,handle)==12);
    CHECK(ca01_display_init(&d,800,480)==CA01_OK);
    CHECK(ca01_display_build_window(&d,0x31000000,&window)==CA01_OK);
    CHECK(ca01_native_window_validate(&window,d.handle)==CA01_OK);
    for(unsigned i=0;i<3;i++) {
        CHECK(ca01_display_export_descriptor(&d,i,&descriptor)==CA01_OK);
        CHECK(descriptor.bytes==1536000 && descriptor.reserved==0);
        CHECK(descriptor.memory_token!=0 && descriptor.memory_token!=descriptor.handle);
        CHECK(descriptor.handle==d.handle[i]);
        CHECK(ca01_display_handle_for_token(&d,descriptor.memory_token,&handle)==CA01_OK);
        CHECK(handle==descriptor.handle);
        CHECK(ca01_display_begin_vram(&d,descriptor.memory_token)==CA01_OK);
        CHECK(ca01_display_begin_vram(&d,descriptor.memory_token)==CA01_ERR_STATE);
        CHECK(ca01_display_wait_vram(&d,0)==CA01_ERR_STATE);
        CHECK(ca01_display_wait_vram(&d,descriptor.memory_token)==CA01_OK);
        CHECK(d.current_front==i);
    }
    CHECK(ca01_display_handle_for_token(&d,0xdeadbeef,&handle)==CA01_ERR_NOT_FOUND);
    CHECK(ca01_display_begin_vram(&d,0xdeadbeef)==CA01_ERR_NOT_FOUND);
    CHECK(ca01_display_export_descriptor(&d,3,&descriptor)==CA01_ERR_RANGE);
    uint32_t bad[3]={d.handle[0],d.handle[0],d.handle[2]};
    CHECK(ca01_native_window_validate(&window,bad)==CA01_ERR_ARG);
    bad[1]=0;CHECK(ca01_native_window_validate(&window,bad)==CA01_ERR_ARG);
    window.words[4]=2;CHECK(ca01_native_window_validate(&window,d.handle)==CA01_ERR_ARG);
    ca01_display_destroy(&d);
    CHECK(ca01_display_export_descriptor(&d,0,&descriptor)==CA01_ERR_STATE);
    return 0;
}
int main(void) {
    if (test_display()!=0 || test_queue()!=0 || test_descriptor_service()!=0 || test_allocation_failures()!=0) return 1;
    puts("CA01_GUI_MODEL_TEST_OK");
    return 0;
}
