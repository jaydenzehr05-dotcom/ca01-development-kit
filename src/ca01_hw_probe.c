/* CA01 read-only hardware interface probe (ARM Linux EABI, 32-bit).
 * No libc, no rootfs writes, no device writes, no flash access.
 * Run ONLY on a test environment or authorized diagnostic shell.
 * It does not install firmware, autorun from USB, or bypass boot security.
 * Linux input events are passively observed through separate read-only fds.
 */
/* On physical hardware, some status registers may have read side effects.
 * Leave vendor ASIC register reads OFF until handlers are independently
 * reviewed for the exact installed board configuration.
 */
#ifndef CA01_ENABLE_ASIC_READS
#define CA01_ENABLE_ASIC_READS 0
#endif
typedef unsigned int u32;
typedef unsigned short u16;
typedef signed int s32;
struct input_event_32 { s32 sec; s32 usec; u16 type; u16 code; s32 value; };
struct pollfd { int fd; short events; short revents; };
_Static_assert(sizeof(struct input_event_32) == 16, "ARM input_event ABI");
_Static_assert(sizeof(struct pollfd) == 8, "ARM poll ABI");
enum { SYS_EXIT=1, SYS_READ=3, SYS_WRITE=4, SYS_OPEN=5, SYS_CLOSE=6,
       SYS_IOCTL=54, SYS_POLL=168, O_RDONLY=0, O_NONBLOCK=2048,
       POLLIN=1, FBIOGET_VSCREENINFO=0x4600, EV_KEY=1 };
static long call3(long number,long a,long b,long c) {
    register long r0 __asm__("r0")=a;
    register long r1 __asm__("r1")=b;
    register long r2 __asm__("r2")=c;
    register long r7 __asm__("r7")=number;
    __asm__ volatile("svc 0":"+r"(r0):"r"(r1),"r"(r2),"r"(r7):"memory","cc");
    return r0;
}
static void write_all(const char *s,unsigned len) {
    while(len) {
        long n=call3(SYS_WRITE,1,(long)s,len);
        if(n==-4)continue; /* EINTR */
        if(n<=0)call3(SYS_EXIT,2,0,0);
        s+=n;len-=(unsigned)n;
    }
}
static void puts_(const char *s) {
    unsigned len=0;while(s[len])len++;write_all(s,len);
}
static void number(u32 n) {
    char digits[10];unsigned i=0;
    do{digits[i++]=(char)('0'+n%10);n/=10;}while(n);
    while(i)write_all(&digits[--i],1);
}
static void show_file(const char *path) {
    char buf[256];unsigned total=0;
    puts_("\n[FILE] ");puts_(path);puts_("\n");
    long fd=call3(SYS_OPEN,(long)path,O_RDONLY,0);
    if(fd<0){puts_("unavailable (errno ");number((u32)-fd);puts_(")\n");return;}
    while(total<1024) {
        unsigned request=1024-total;
        if(request>sizeof(buf))request=sizeof(buf);
        long n=call3(SYS_READ,fd,(long)buf,request);
        if(n==-4)continue;
        if(n<0){puts_("read error\n");break;}
        if(n==0)break;
        write_all(buf,(unsigned)n);
        total+=(unsigned)n;
    }
    if(total==1024)puts_("\n[TRUNCATED 1024 BYTES]\n");
    call3(SYS_CLOSE,fd,0,0);
}
static void framebuffer(const char *path) {
    volatile u32 fields[64];unsigned j;
    for(j=0;j<64;j++)fields[j]=0;
    puts_("\n[FRAMEBUFFER] ");puts_(path);puts_("\n");
    long fd=call3(SYS_OPEN,(long)path,O_RDONLY,0);
    if(fd<0){puts_("unavailable\n");return;}
    long status=call3(SYS_IOCTL,fd,FBIOGET_VSCREENINFO,(long)fields);
    if(status<0){puts_("query failed\n");}
    else {puts_("width=");number(fields[0]);puts_(" height=");number(fields[1]);
          puts_(" bpp=");number(fields[6]);puts_("\n");}
    call3(SYS_CLOSE,fd,0,0);
}
static const char *key_name(u16 key) {
    switch(key) {
       case 115:return "VOLUMEUP";
       case 114:return "VOLUMEDOWN";
       case 402:return "CHANNELUP";
       case 403:return "CHANNELDOWN";
       case 200:return "OFFHOOK";
       case 201:return "ONHOOK";
       case 164:return "PLAYPAUSE";
       case 116:return "POWER";
       case 139:return "MENU";
       case 158:return "BACK";
       default:return "OTHER";
    }
}
static void listen_input(void) {
    /* Each opened event device is independent; never write to input devices. */
    static const char *paths[]={"/dev/input/event0","/dev/input/event1",
      "/dev/input/event2","/dev/input/event3","/dev/input/event4",
      "/dev/input/event5","/dev/input/event6","/dev/input/event7"};
    struct pollfd pfd[8];u32 i,count=0,opened=0;
    for(i=0;i<8;i++){
        long fd=call3(SYS_OPEN,(long)paths[i],O_RDONLY|O_NONBLOCK,0);
        pfd[i].fd=(int)fd;pfd[i].events=POLLIN;pfd[i].revents=0;
        if(fd>=0)opened++;
    }
    puts_("\n[INPUT] event devices opened=");number(opened);puts_("\n");
    if(opened) {
        /* Bounded, passive 2-second sample for manual button test. */
        long ret=call3(SYS_POLL,(long)pfd,8,2000);
        if(ret>0){
            for(i=0;i<8 && count<24;i++){
                if(pfd[i].fd<0 || !(pfd[i].revents&POLLIN))continue;
                while(count<24){
                    struct input_event_32 ev;
                    long got=call3(SYS_READ,pfd[i].fd,(long)&ev,sizeof(ev));
                    if(got==-4)continue;
                    if(got!=sizeof(ev))break;
                    if(ev.type!=EV_KEY)continue;
                    puts_("event");number(i);puts_(" key=");
                    number(ev.code);puts_(" ");puts_(key_name(ev.code));
                    puts_(" value=");number((u32)ev.value);puts_("\n");
                    count++;
                }
            }
        }
        if(ret<0){puts_("poll failed\n");}
    }
    for(i=0;i<8;i++)if(pfd[i].fd>=0)call3(SYS_CLOSE,pfd[i].fd,0,0);
    puts_("[INPUT] complete; events captured=");number(count);puts_("\n");
}
__attribute__((noreturn)) void _start(void) {
    puts_("CA01 hardware probe v0.2 READ ONLY (not a firmware installer)\n");
    show_file("/proc/version");
    show_file("/proc/cmdline");
    show_file("/proc/partitions");
    show_file("/proc/bus/input/devices");
    show_file("/proc/asound/cards");
    show_file("/proc/fb");
#if CA01_ENABLE_ASIC_READS
    show_file("/proc/asic/gpio");
    show_file("/proc/asic/adc");
    show_file("/proc/asic/intc_m");
    show_file("/proc/asic/intc_l");
    show_file("/proc/asic/psel");
#else
    puts_("\n[ASIC] volatile register reads DISABLED by default\n");
#endif
    framebuffer("/dev/fb0");
    framebuffer("/dev/graphics/fb0");
    listen_input();
    puts_("\nCA01 hardware probe finished safely.\n");
    call3(SYS_EXIT,0,0,0);
    for(;;){}
}
