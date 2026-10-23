/* Bounded original HMI graphics slice, not an application launcher.
 * Linked at 0x10000000 so the original HMI address range remains vacant.
 * The Python entrypoint SHA-checks the baseline before staging. This program
 * runs ONLY in the offline ARMEL sandbox. Private import/profile bindings do
 * not alter the source ELF. Unknown services terminate, never return success.
 */
#define _GNU_SOURCE
#include "ca01_gui_compat.h"
#include <EGL/egl.h>
#include <GLES/gl.h>
#include <dlfcn.h>
#include <elf.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static Ca01Display display;
static Ca01Queue queue;
static unsigned allocations, frees, draw_calls, clear_calls, updates;
static unsigned width, height=480;
static int graphics_ready, allocation_failure, invalid_callback;
static uint8_t allocated[3];
static const char *stage="loader";
static uint32_t *native_window;
static void fail(const char *reason) {
    fprintf(stderr,"SLICE_ERROR stage=%s reason=%s\n",stage,reason);
    fflush(NULL);exit(90);
}
#define REQUIRE(x,msg) do { if(!(x))fail(msg); } while(0)
static void event(const char *name) { printf("EVENT %s\n",name);fflush(stdout); }
static void unknown_import(void) {
    fprintf(stderr,"UNKNOWN_IMPORT stage=%s original_return=%p\n",stage,__builtin_return_address(0));
    fail("unimplemented original import");
}
static void patch_branch(uint32_t address,void *target) {
    uint32_t *p=(void *)(uintptr_t)address;
    p[0]=0xe59fc000; /* ldr ip,[pc,#0] */
    p[1]=0xe12fff1c; /* bx ip, preserves soft-float arguments and LR */
    p[2]=(uint32_t)(uintptr_t)target;
    __builtin___clear_cache((char *)p,(char *)(p+3));
}
static uint32_t profile(void) {
    /* Explicit vehicle-profile fixture, same measured records as Unicorn. */
    return width==800 ? 0x295fe8 : 0x296108;
}
static int init_service(void *descriptors) {
    REQUIRE((uintptr_t)descriptors==0x1a24bb8,"unexpected display-init descriptor address");
    event("modeled_sysDisMngInit descriptors=0x1a24bb8");return 0;
}
static int allocate_service(uint32_t bytes,Ca01DisplayMemory32 *out) {
    unsigned index=allocations++;
    REQUIRE(index<3 && (uintptr_t)out==0x1a24bb8+16*index,"unexpected allocation descriptor");
    REQUIRE(bytes==display.bytes_per_buffer,"unexpected display allocation size");
    if(allocation_failure && index==1) { event("injected_allocation_failure");return -1; }
    REQUIRE(ca01_display_export_descriptor(&display,index,out)==CA01_OK,"cannot export descriptor");
    allocated[index]=1;
    printf("BUFFER %u handle=%" PRIu32 " token=%" PRIu32 " bytes=%" PRIu32 "\n",index,out->handle,out->memory_token,out->bytes);
    return 0;
}
static int free_service(Ca01DisplayMemory32 *out) {
    uintptr_t address=(uintptr_t)out;
    REQUIRE(address>=0x1a24bb8 && address<0x1a24bb8+48 && (address-0x1a24bb8)%16==0,"invalid free descriptor");
    unsigned index=(address-0x1a24bb8)/16;
    REQUIRE(allocated[index] && !display.pending_token,"invalid/double/pending descriptor free");
    allocated[index]=0;memset(out,0,sizeof(*out));++frees;return 0;
}
static int end_service(void) { event("modeled_sysDisMngEnd");return 0; }
/* Wrappers log original call sites and forward to actual ARMEL GLES. */
static void original_clear_color(GLfloat r,GLfloat g,GLfloat b,GLfloat a) {
    printf("ORIGINAL_GL glClearColor return=%p rgba=%.8f,%.8f,%.8f,%.8f\n",__builtin_return_address(0),r,g,b,a);
    glClearColor(r,g,b,a);
}
static void original_clear(GLbitfield mask) {
    REQUIRE(graphics_ready,"clear before graphics readiness");++clear_calls;
    printf("ORIGINAL_GL glClear return=%p mask=%u\n",__builtin_return_address(0),mask);glClear(mask);
}
static void original_vertices(GLint size,GLenum type,GLsizei stride,const void *pointer) {
    REQUIRE(size==2 && type==GL_SHORT && stride==0,"unexpected original vertex ABI");
    const int16_t *p=pointer;
    printf("ORIGINAL_VERTICES %d,%d %d,%d %d,%d %d,%d\n",p[0],p[1],p[2],p[3],p[4],p[5],p[6],p[7]);
    glVertexPointer(size,type,stride,pointer);
}
static void original_draw(GLenum mode,GLint first,GLsizei count) {
    REQUIRE(graphics_ready,"draw before graphics readiness");
    REQUIRE(mode==GL_TRIANGLE_STRIP && first==0 && count==4,"unexpected original draw geometry");
    ++draw_calls;
    printf("ORIGINAL_GL glDrawArrays return=%p mode=%u first=%d count=%d\n",__builtin_return_address(0),mode,first,count);
    glDrawArrays(mode,first,count);
}
static int update_service(uint32_t plane,uint32_t kind,const uint16_t *size,const uint16_t *origin,
                          const uint16_t *destination,const uint16_t *extent,uint32_t token) {
    REQUIRE(graphics_ready,"VRAM update before readiness");
    REQUIRE(plane==0 && kind==0 && size[0]==width && size[1]==height &&
       !origin[0] && !origin[1] && !destination[0] && !destination[1] &&
       extent[0]==width && extent[1]==height,"unexpected VRAM rectangle ABI");
    uint32_t handle;uint8_t *pixels;size_t bytes;
    REQUIRE(ca01_display_begin_vram(&display,token)==CA01_OK,"invalid/busy VRAM token");
    REQUIRE(ca01_display_handle_for_token(&display,token,&handle)==CA01_OK,"unmapped VRAM token");
    REQUIRE(ca01_display_pixels(&display,handle,&pixels,&bytes)==CA01_OK,"unmapped buffer handle");
    uint8_t *scratch=malloc(bytes);REQUIRE(scratch,"pixel allocation failed");
    glReadPixels(0,0,width,height,GL_RGBA,GL_UNSIGNED_BYTE,scratch);
    REQUIRE(glGetError()==GL_NO_ERROR,"Mesa pixel readback failed");
    REQUIRE(ca01_display_copy_bottom_up_rgba(&display,handle,scratch,bytes)==CA01_OK,"pixel copy failed");
    free(scratch);++updates;
    printf("VRAM_UPDATE token=%" PRIu32 " handle=%" PRIu32 "\n",token,handle);return 0;
}
static int wait_service(uint32_t plane,uint32_t token) {
    REQUIRE(plane==0 && ca01_display_wait_vram(&display,token)==CA01_OK,"invalid VRAM wait");
    return 0;
}
static int plane_switch(uint32_t value) { REQUIRE(value==0,"unexpected plane-switch argument");event("modeled_plane_switch argument=0 hardware_semantics_unknown");return 0; }
static int plane_alpha(uint32_t plane,uint32_t alpha,uint32_t mode) {
    REQUIRE(!plane && alpha==255 && mode==1,"unexpected plane alpha");display.alpha=(uint8_t)alpha;event("modeled_plane_alpha arguments=0,255,1");return 0;
}
static int plane_trans(uint32_t plane,uint32_t mode,uint32_t color) {
    REQUIRE(!plane && !mode && color==0xff00ff,"unexpected plane transparency");event("modeled_plane_trans arguments=0,0,0x00ff00ff");return 0;
}
static uint32_t bad_callback(void *window) { (void)window;return 0xdeadcafe; }
static void *resolve(const char *name) {
    struct { const char *name;void *function; } model[]={
        {"sysDisMngInit",init_service},{"sysDisMngMemAlloc",allocate_service},
        {"sysDisMngMemFree",free_service},{"sysDisMngEnd",end_service},
        {"sysDisMngPlnUpdateVram",update_service},{"sysDisMngPlnWaitDispVram",wait_service},
        {"sysDisMngPlnDispSw",plane_switch},{"sysDisMngPlnAlpha",plane_alpha},{"sysDisMngPlnTrans",plane_trans},
        {"glClearColor",original_clear_color},{"glClear",original_clear},
        {"glVertexPointer",original_vertices},{"glDrawArrays",original_draw}};
    for(unsigned i=0;i<sizeof(model)/sizeof(model[0]);i++)if(!strcmp(name,model[i].name))return model[i].function;
    if((!strncmp(name,"gl",2) && name[2]>='A' && name[2]<='Z') ||
       (!strncmp(name,"egl",3) && name[3]>='A' && name[3]<='Z') ||
       !strcmp(name,"malloc") || !strcmp(name,"free")) {
        void *fn=dlsym(RTLD_DEFAULT,name);if(fn)return fn;
    }
    return unknown_import;
}
static int within(size_t offset,size_t length,size_t total) { return offset<=total && length<=total-offset; }
static void load_original(const char *file) {
    FILE *f=fopen(file,"rb");REQUIRE(f,"cannot open staged input");
    REQUIRE(!fseek(f,0,SEEK_END),"input seek failed");
    long length=ftell(f);REQUIRE(length==6152368,"unexpected input size");rewind(f);
    uint8_t *data=malloc(length);REQUIRE(data,"loader allocation failed");
    REQUIRE(fread(data,1,length,f)==(size_t)length,"short firmware read");fclose(f);
    uint64_t fnv=UINT64_C(14695981039346656037);
    for(long i=0;i<length;i++)fnv=(fnv^data[i])*UINT64_C(1099511628211);
    /* Secondary consistency check, not a replacement for launcher's SHA-256. */
    REQUIRE(fnv==UINT64_C(0x1d62c63e596b2a4e),"baseline bytes changed after SHA verification");
    Elf32_Ehdr *e=(void *)data;
    REQUIRE(!memcmp(e->e_ident,ELFMAG,SELFMAG) && e->e_machine==EM_ARM && e->e_type==ET_EXEC &&
        e->e_ident[EI_CLASS]==ELFCLASS32 && e->e_ident[EI_DATA]==ELFDATA2LSB &&
        e->e_phentsize==sizeof(Elf32_Phdr) && e->e_shentsize==sizeof(Elf32_Shdr) &&
        e->e_phnum<=32 && within(e->e_phoff,e->e_phnum*sizeof(Elf32_Phdr),length) &&
        within(e->e_shoff,e->e_shnum*sizeof(Elf32_Shdr),length),"unsupported ELF layout");
    Elf32_Phdr *ph=(void *)(data+e->e_phoff);
    for(unsigned i=0;i<e->e_phnum;i++)if(ph[i].p_type==PT_LOAD) {
        Elf32_Phdr *p=&ph[i];
        REQUIRE(p->p_vaddr>=0x8000 && p->p_vaddr+p->p_memsz<0x4000000 && p->p_filesz<=p->p_memsz &&
            within(p->p_offset,p->p_filesz,length),"invalid original load bounds");
        uintptr_t low=p->p_vaddr&~4095U,end=(p->p_vaddr+p->p_memsz+4095)&~4095U;
        void *mapped=mmap((void *)low,end-low,PROT_READ|PROT_WRITE|PROT_EXEC,
             MAP_ANONYMOUS|MAP_PRIVATE|MAP_FIXED_NOREPLACE,-1,0);
        REQUIRE(mapped==(void *)low,"original slice address collision");
        memcpy((void *)(uintptr_t)p->p_vaddr,data+p->p_offset,p->p_filesz);
    }
    Elf32_Shdr *sh=(void *)(data+e->e_shoff);
    for(unsigned i=0;i<e->e_shnum;i++) {
        REQUIRE(sh[i].sh_type==SHT_NOBITS || within(sh[i].sh_offset,sh[i].sh_size,length),"invalid section bounds");
        if(sh[i].sh_type!=SHT_DYNSYM)continue;
        REQUIRE(sh[i].sh_link<e->e_shnum && sh[i].sh_entsize==sizeof(Elf32_Sym),"invalid symbol table");
        Elf32_Shdr *strings=&sh[sh[i].sh_link];
        Elf32_Sym *syms=(void *)(data+sh[i].sh_offset);
        for(unsigned j=0;j<sh[i].sh_size/sizeof(*syms);j++) {
            Elf32_Sym *s=&syms[j];if(s->st_shndx!=SHN_UNDEF)continue;
            REQUIRE(s->st_name<strings->sh_size && memchr(data+strings->sh_offset+s->st_name,0,strings->sh_size-s->st_name),"unterminated symbol");
            const char *name=(void *)(data+strings->sh_offset+s->st_name);
            void *target=resolve(name);
            if(s->st_value) {
                REQUIRE(s->st_value>=0xc000 && s->st_value+12<=0xd900,"unexpected PLT address");
                patch_branch(s->st_value,target);
            }
        }
    }
    for(unsigned i=0;i<e->e_shnum;i++)if(sh[i].sh_type==SHT_REL) {
        REQUIRE(sh[i].sh_link<e->e_shnum && sh[i].sh_entsize==sizeof(Elf32_Rel),"invalid relocations");
        Elf32_Shdr *symbols=&sh[sh[i].sh_link];
        REQUIRE(symbols->sh_type==SHT_DYNSYM && symbols->sh_link<e->e_shnum,"unsupported relocation symbols");
        Elf32_Shdr *strings=&sh[symbols->sh_link];
        Elf32_Sym *syms=(void *)(data+symbols->sh_offset);
        Elf32_Rel *rels=(void *)(data+sh[i].sh_offset);
        for(unsigned j=0;j<sh[i].sh_size/sizeof(*rels);j++) {
            unsigned type=ELF32_R_TYPE(rels[j].r_info),index=ELF32_R_SYM(rels[j].r_info);
            REQUIRE(index<symbols->sh_size/sizeof(*syms),"invalid relocation symbol index");
            if(type!=R_ARM_JUMP_SLOT && type!=R_ARM_GLOB_DAT)continue;
            REQUIRE(rels[j].r_offset>=0x5dd324 && rels[j].r_offset<0x5e2000,"unexpected GOT slot");
            Elf32_Sym *s=&syms[index];
            REQUIRE(s->st_name<strings->sh_size,"invalid relocation name");
            uint32_t target=s->st_shndx==SHN_UNDEF ? (uint32_t)(uintptr_t)resolve((char *)data+strings->sh_offset+s->st_name) : s->st_value;
            *(uint32_t *)(uintptr_t)rels[j].r_offset=target;
        }
    }
    patch_branch(0x2a548,profile); /* explicitly substituted vehicle selector */
    for(unsigned i=0;i<e->e_phnum;i++)if(ph[i].p_type==PT_LOAD && (ph[i].p_flags&PF_X)) {
        uintptr_t low=ph[i].p_vaddr&~4095U,end=(ph[i].p_vaddr+ph[i].p_memsz+4095)&~4095U;
        REQUIRE(!mprotect((void *)low,end-low,PROT_READ|PROT_EXEC),"cannot seal original code");
    }
    const uint32_t entries[]={0x2bb08,0x2b66c,0x1e092c,0x1c4654,0x1e0640,0x2b9fc,0x1602c};
    for(unsigned i=0;i<sizeof(entries)/sizeof(entries[0]);i++) {
        REQUIRE(!memcmp((void *)(uintptr_t)entries[i],data+entries[i]-0x8000,32),"original function entry changed during binding");
        printf("UNCHANGED_ORIGINAL_ENTRY 0x%x bytes=32\n",entries[i]);
    }
    free(data);
}
static void capture(unsigned frame) {
    char path[80];snprintf(path,sizeof(path),"/tmp/output/frame-%u.ppm",frame);
    const uint8_t *pixels;size_t bytes;
    REQUIRE(ca01_display_front(&display,&pixels,&bytes)==CA01_OK,"no presented frame");
    FILE *f=fopen(path,"wb");REQUIRE(f,"capture open failed");
    REQUIRE(fprintf(f,"P6\n%u %u\n255\n",width,height)>0,"capture header failed");
    for(size_t i=0;i<bytes;i+=4)REQUIRE(fwrite(pixels+i,1,3,f)==3,"capture pixel write failed");
    REQUIRE(!fclose(f),"capture close failed");
}
int main(int argc,char **argv) {
    REQUIRE(argc==4,"usage: HMI WIDTH MODE");
    width=!strcmp(argv[2],"800") ? 800 : !strcmp(argv[2],"480") ? 480 : 0;
    REQUIRE(width,"unsupported recovered profile");
    REQUIRE(!strcmp(argv[3],"normal") || !strcmp(argv[3],"alloc-fail") || !strcmp(argv[3],"invalid-callback"),"unknown test mode");
    allocation_failure=!strcmp(argv[3],"alloc-fail");invalid_callback=!strcmp(argv[3],"invalid-callback");
    alarm(20);setvbuf(stdout,NULL,_IOLBF,0);load_original(argv[1]);
    REQUIRE(ca01_display_init(&display,width,height)==CA01_OK,"display model allocation failed");
    REQUIRE(ca01_queue_init(&queue,CA01_QUEUE_ID_HMI)==CA01_OK,"queue creation failed");
    stage="original_graphics_initialization";event("ORIGINAL_ENTRY 0x2bb08");
    uint32_t result=((uint32_t(*)(void))(uintptr_t)0x2bb08)();
    printf("ORIGINAL_INIT result=%u\n",result);
    native_window=*(void **)(uintptr_t)0x925f38;
    REQUIRE(result==1 && native_window && native_window[7] && allocations==3 &&
       ca01_native_window_validate((Ca01NativeWindow32 *)native_window,display.handle)==CA01_OK &&
       allocated[0] && allocated[1] && allocated[2],"original graphics initialization not ready");
    graphics_ready=1;event("GRAPHICS_READY bounded_slice_only");
    printf("MESA %s\n",glGetString(GL_RENDERER));
    if(invalid_callback)native_window[7]=(uint32_t)(uintptr_t)bad_callback;
    /* Explicit fixture state: projection/current color/vertex enable, not a scene. */
    glViewport(0,0,width,height);glMatrixMode(GL_PROJECTION);glLoadIdentity();
    glOrthof(-(float)width/2,(float)width/2,-(float)height/2,(float)height/2,-1,1);
    glMatrixMode(GL_MODELVIEW);glLoadIdentity();glEnableClientState(GL_VERTEX_ARRAY);
    uint32_t renderer_words[256]={0};uint8_t *renderer=(void *)renderer_words;int16_t vertices[8]={0};
    renderer[0x264]=renderer[0x265]=renderer[0x266]=1;
    *(uint32_t *)(renderer+0x2c)=1;*(uint32_t *)(renderer+0x30)=1;
    for(unsigned frame=0;frame<3;frame++) {
        stage="original_heartbeat";
        Ca01Message message={0,0,10,0},received={0};
        REQUIRE(graphics_ready && ca01_queue_send_t(&queue,&message,0)==0,"queue/send readiness failure");
        REQUIRE(ca01_queue_receive_t(&queue,&received,500)==0,"queue receive failed");
        REQUIRE(((uint32_t(*)(Ca01Message *))(uintptr_t)0x2b170)(&received)==1 &&
          *(uint8_t *)(uintptr_t)0x26c98a2==1,"original heartbeat did not set draw pending");
        stage="original_clear_and_rectangle";event("ORIGINAL_ENTRY 0x1e092c");
        ((void(*)(void *,uint32_t,uint32_t))(uintptr_t)0x1e092c)(renderer,2,0xff442211);
        unsigned rw=width/2+frame*2,rh=height/3+frame*2;
        event("ORIGINAL_ENTRY 0x1c4654");
        ((void(*)(void *,int,int))(uintptr_t)0x1c4654)(vertices,rw,rh);
        event("ORIGINAL_ENTRY 0x1e0640");
        ((void(*)(void *,void *,int,int))(uintptr_t)0x1e0640)(renderer,vertices,5,4);
        REQUIRE(glGetError()==GL_NO_ERROR,"original drawing reached a Mesa error");glFinish();
        stage="original_frame_submission";
        REQUIRE(((uint32_t(*)(void))(uintptr_t)0x2b9fc)()==1,"original EGL/frame checker failed");
        REQUIRE(updates==frame+1 && display.swaps==frame+1,"callback handle did not map to a presented VRAM frame");
        capture(frame);*(uint8_t *)(uintptr_t)0x26c98a2=0;
        printf("FRAME %u rectangle=%ux%u handle=%" PRIu32 "\n",frame,rw,rh,display.handle[display.current_front]);
    }
    stage="cleanup";
    EGLDisplay egl_display=*(EGLDisplay *)(uintptr_t)0x26c98c4;
    EGLSurface surface=*(EGLSurface *)(uintptr_t)0x26c98c0;
    EGLContext context=*(EGLContext *)(uintptr_t)0x26c98b0;
    REQUIRE(eglMakeCurrent(egl_display,EGL_NO_SURFACE,EGL_NO_SURFACE,EGL_NO_CONTEXT),"context detach failed");
    REQUIRE(eglDestroySurface(egl_display,surface),"surface destroy failed");
    REQUIRE(((uint32_t(*)(void *))(uintptr_t)native_window[7])(native_window)==0,"callback registry retained destroyed surface");
    REQUIRE(eglDestroyContext(egl_display,context) && eglTerminate(egl_display),"EGL cleanup failed");
    free(native_window);((void(*)(void))(uintptr_t)0x1602c)();
    REQUIRE(frees==3,"display descriptors were not released");
    ca01_queue_destroy(&queue);ca01_display_destroy(&display);
    printf("SLICE_COMPLETE draws=%u clears=%u frames=%u freed=%u\n",draw_calls,clear_calls,updates,frees);
    return 0;
}
