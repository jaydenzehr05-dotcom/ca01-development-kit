/*
 * Offline-only CA01 read-only filesystem exporter.
 *
 * Never a KWI firmware/update package; requires an independently verified,
 * authorized execution channel on hardware. Refuses writes unless --copy.
 * In production refuses destinations on same device as source root.
 * Walks ALL path components through anchored openat(O_NOFOLLOW|O_DIRECTORY).
 *
 * ARM CA01_LEGACY_ARM build uses old Linux ARM EABI syscalls directly:
 * no glibc, dynamic loader, newer libc minimum, network, shell, mounts,
 * chmod/chown, or writes to original source. All ARM syscall IDs are from
 * the EABI table and available by Linux 2.6.35.7.
 *
 * Offline test build may define CA01_OFFLINE_TEST to enable copying between
 * synthetic dirs on the same test device. Never set that for radio build.
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#if defined(CA01_LEGACY_ARM)
#if !defined(__arm__) || !defined(__ARM_EABI__)
#error "Legacy build requires 32-bit ARM Linux EABI"
#endif
#include <asm/unistd.h>
#include <asm/fcntl.h>
#include <asm/stat.h>
typedef struct stat64 KernelStat;
#define SYS_OPENAT __NR_openat
#define SYS_MKDIRAT __NR_mkdirat
#define SYS_FSTAT __NR_fstat64
#define SYS_GETDENTS __NR_getdents64
#define SYS_UNLINKAT __NR_unlinkat
#define SYS_FSYNC __NR_fsync
#define SYS_READ __NR_read
#define SYS_WRITE __NR_write
#define SYS_CLOSE __NR_close
#define SYS_EXIT __NR_exit
static long sc4(long n,long a,long b,long c,long d) {
    register long r0 __asm__("r0")=a,r1 __asm__("r1")=b;
    register long r2 __asm__("r2")=c,r3 __asm__("r3")=d;
    register long r7 __asm__("r7")=n;
    __asm__ volatile("svc 0":"+r"(r0):"r"(r1),"r"(r2),"r"(r3),"r"(r7):"cc","memory");
    return r0;
}
#else
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/syscall.h>
#include <sys/stat.h>
typedef struct stat KernelStat;
#define SYS_OPENAT SYS_openat
#define SYS_MKDIRAT SYS_mkdirat
#define SYS_FSTAT SYS_fstat
#define SYS_GETDENTS SYS_getdents64
#define SYS_UNLINKAT SYS_unlinkat
#define SYS_FSYNC SYS_fsync
#define SYS_READ SYS_read
#define SYS_WRITE SYS_write
#define SYS_CLOSE SYS_close
#define SYS_EXIT SYS_exit
static long sc4(long n,long a,long b,long c,long d) {
    long value=syscall(n,a,b,c,d);
    return value<0 ? -(long)errno : value;
}
#endif
#define AT_ROOT (-100L)
#define L_O_DIR (O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC)
#define L_O_FILE (O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC)
#define L_O_NEW (O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC)
#define L_S_IFMT 0170000
#define L_S_IFREG 0100000
#define L_S_IFDIR 0040000
#define L_DT_DIR 4
#define L_DT_REG 8
#define L_DT_LNK 10
#define L_EINTR 4
#define L_EEXIST 17
#define MAX_DEPTH 20
#define MAX_FILES 16384
#define MAX_FILE_BYTES (128UL*1024UL*1024UL)
#define MAX_BYTES (512UL*1024UL*1024UL)
#define DENT_BUFSIZE 2048
#define IO_BUFSIZE 16384
#define MAX_NAME 255
static int sourcefd=-1,destfd=-1;
static uint64_t source_dev,dest_dev;
static unsigned files=0,missing=0,skipped=0,failures=0;
static uint64_t total_bytes=0;
static bool do_copy=false;
static char io_buf[IO_BUFSIZE];
static const char *selected[]={
 "opt/ftl/gui/MC","opt/ftl/gui/font","opt/ftl/gui/allwords",
 "opt/ftl/lib","opt/ftl/apl","etc/ipasz.conf","opt/ftl/ipasz.conf"
};
#define ARR_SIZE(x) (sizeof(x)/sizeof(x[0]))
static long os_open(long base,const char *name,long flags,long mode){
    return sc4(SYS_OPENAT,base,(long)name,flags,mode);
}
static long os_close(long fd){return sc4(SYS_CLOSE,fd,0,0,0);}
static long os_stat(long fd,KernelStat *s){return sc4(SYS_FSTAT,fd,(long)s,0,0);}
static long os_mkdir(long fd,const char *name,long mode){return sc4(SYS_MKDIRAT,fd,(long)name,mode,0);}
static long os_unlink(long fd,const char *name){return sc4(SYS_UNLINKAT,fd,(long)name,0,0);}
static long os_read(long fd,void *ptr,long count){return sc4(SYS_READ,fd,(long)ptr,count,0);}
static long os_write(long fd,const void *ptr,long count){return sc4(SYS_WRITE,fd,(long)ptr,count,0);}
static long os_fsync(long fd){return sc4(SYS_FSYNC,fd,0,0,0);}
static long os_getdents(long fd,void *ptr,long count){return sc4(SYS_GETDENTS,fd,(long)ptr,count,0);}
static unsigned c_len(const char *s){unsigned n=0;while(s[n])n++;return n;}
static bool c_eq(const char *a,const char *b){
    while(*a && *b){if(*a!=*b)return false;a++;b++;}
    return *a==*b;
}
#ifndef CA01_OFFLINE_TEST
static bool c_starts(const char *value,const char *prefix){
    while(*prefix){if(*value++!=*prefix++)return false;}
    return true;
}
#endif
static void say_to(long fd,const char *s){
    unsigned n=c_len(s),off=0;
    while(off<n){
        long result=os_write(fd,s+off,n-off);
        if(result==-L_EINTR)continue;
        if(result<=0)return;
        off+=(unsigned)result;
    }
}
static void say(const char *s){say_to(1,s);}
static void warn(const char *s){say_to(2,s);}
static void dec(uint64_t n){
    char buf[24];unsigned i=0;
    do{buf[i++]=(char)('0'+(n%10));n/=10;}while(n && i<sizeof(buf));
    while(i){char c=buf[--i];os_write(1,&c,1);}
}
static bool dot_name(const char *s){return c_eq(s,".")||c_eq(s,"..");}
static bool is_regular(const KernelStat *s){return (s->st_mode&L_S_IFMT)==L_S_IFREG;}
static bool is_dir(const KernelStat *s){return (s->st_mode&L_S_IFMT)==L_S_IFDIR;}
static bool same_inode(const KernelStat *a,const KernelStat *b){
    return a->st_dev==b->st_dev && a->st_ino==b->st_ino;
}
/* Every directory component opened relative to an already approved fd.
 * Handles root-only "/" and absolute paths without resolving symlinks.
 */
static int abs_dir(const char *s){
    if(!s || s[0]!='/' || c_len(s)>4000)return -1;
    long current=os_open(AT_ROOT,"/",L_O_DIR,0);
    if(current<0)return -1;
    while(*s){
        while(*s=='/')s++;
        if(!*s)break;
        char part[MAX_NAME+1];unsigned n=0;
        while(*s && *s!='/'){
            if(n==MAX_NAME){os_close(current);return -1;}
            part[n++]=*s++;
        }
        part[n]=0;
        if(!n || dot_name(part)){os_close(current);return -1;}
        long child=os_open(current,part,L_O_DIR,0);
        os_close(current);
        if(child<0)return -1;
        current=child;
    }
    return (int)current;
}
/* Refuse copies into input asset subtrees; file-descriptor ancestry works
 * across bind/mount paths without trusting string prefixes or realpath().
 */
static bool descends_from(int childfd,int ancestorfd){
    KernelStat ancestor,child,parent;
    if(os_stat(ancestorfd,&ancestor)<0)return true;
    int cursor=(int)os_open(childfd,".",L_O_DIR,0);
    if(cursor<0)return true;
    for(unsigned i=0;i<1024;i++){
        if(os_stat(cursor,&child)<0){os_close(cursor);return true;}
        if(same_inode(&ancestor,&child)){os_close(cursor);return true;}
        long next=os_open(cursor,"..",L_O_DIR,0);
        if(next<0){os_close(cursor);return true;}
        if(os_stat(next,&parent)<0){os_close(next);os_close(cursor);return true;}
        bool at_root=same_inode(&child,&parent);
        os_close(cursor);
        cursor=(int)next;
        if(at_root){os_close(cursor);return false;}
    }
    os_close(cursor);
    return true;/* Fail closed if a path walk is pathological. */
}
/* Resolve existing input directory, or make output parents. No symlinks at
 * any intermediate component, and no mount crossing in output subtrees.
 */
static int relative_dir(int base,const char *rel,bool make,bool *absent){
    long current=os_open(base,".",L_O_DIR,0);
    if(current<0)return -1;
    const char *p=rel;
    while(*p){
        while(*p=='/')p++;
        if(!*p)break;
        char part[MAX_NAME+1];unsigned n=0;
        while(*p && *p!='/'){
            if(n==MAX_NAME){os_close(current);return -1;}
            part[n++]=*p++;
        }
        part[n]=0;
        if(!n||dot_name(part)){os_close(current);return -1;}
        long child=os_open(current,part,L_O_DIR,0);
        if(child<0 && make){
            long made=os_mkdir(current,part,0700);
            if(made<0 && made!=-L_EEXIST){
                os_close(current);return -1;
            }
            child=os_open(current,part,L_O_DIR,0);
        }
        os_close(current);
        if(child<0){if(absent)*absent=true;return -1;}
        KernelStat status;
        if(os_stat(child,&status)<0 || !is_dir(&status) ||
            (make && (uint64_t)status.st_dev!=dest_dev)){
            os_close(child);return -1;
        }
        current=child;
    }
    return (int)current;
}
static int path_parent(int root,const char *rel,bool make,char name[MAX_NAME+1],bool *absent){
    unsigned len=c_len(rel);
    if(!len || len>4000)return -1;
    int last=-1;
    for(unsigned i=0;i<len;i++)if(rel[i]=='/')last=(int)i;
    const char *base=rel+last+1;
    if(c_len(base)>MAX_NAME || !*base || dot_name(base))return -1;
    unsigned i=0;while(base[i]){name[i]=base[i];i++;}name[i]=0;
    if(last<0)return (int)os_open(root,".",L_O_DIR,0);
    char parent[4096];
    for(i=0;i<(unsigned)last;i++)parent[i]=rel[i];
    parent[last]=0;
    return relative_dir(root,parent,make,absent);
}
/* Untrusted directory entry type is never used as security authority.
 * Open by fd, then inspect fstat on the opened object.
 */
static void copy_file(int srcdir,int dstdir,const char *name,bool skip_symlink){
    if(skip_symlink){skipped++;return;}
    long src=os_open(srcdir,name,L_O_FILE,0);
    if(src<0){skipped++;return;}
    KernelStat meta;
    if(os_stat(src,&meta)<0||!is_regular(&meta)||meta.st_size<0){
        skipped++;os_close(src);return;
    }
    if((uint64_t)meta.st_size>MAX_FILE_BYTES||files>=MAX_FILES ||
        (uint64_t)meta.st_size>MAX_BYTES-total_bytes){
        warn("Refusing file or total export size limit\n");failures++;os_close(src);return;
    }
    if(!do_copy){
        files++;total_bytes+=(uint64_t)meta.st_size;os_close(src);return;
    }
    long out=os_open(dstdir,name,L_O_NEW,0600);
    if(out<0){warn("Refusing output file overwrite\n");failures++;os_close(src);return;}
    KernelStat target;
    bool ok=os_stat(out,&target)>=0 && is_regular(&target) &&
            (uint64_t)target.st_dev==dest_dev;
    uint64_t sz=0;
    while(ok){
        long n=os_read(src,io_buf,sizeof(io_buf));
        if(n==-L_EINTR)continue;
        if(n<0){ok=false;break;}
        if(n==0)break;
        if(sz+(uint64_t)n>MAX_FILE_BYTES||sz+(uint64_t)n>MAX_BYTES-total_bytes){
            ok=false;break;
        }
        long off=0;
        while(off<n){
            long w=os_write(out,io_buf+off,n-off);
            if(w==-L_EINTR)continue;
            if(w<=0){ok=false;break;}
            off+=w;
        }
        if(!ok)break;
        sz+=(uint64_t)n;
    }
    if(ok && os_fsync(out)<0)ok=false;
    if(os_close(out)<0)ok=false;
    os_close(src);
    if(!ok){
        os_unlink(dstdir,name);
        warn("File copy failed or exceeded quota\n");failures++;return;
    }
    files++;total_bytes+=sz;
}
static void walk(int src,int dst,unsigned depth){
    if(depth>=MAX_DEPTH){failures++;warn("Directory depth bound exceeded\n");return;}
    unsigned char dent[DENT_BUFSIZE];
    for(;;){
        long count=os_getdents(src,dent,sizeof(dent));
        if(count==-L_EINTR)continue;
        if(count<0){warn("Cannot enumerate input directory\n");failures++;return;}
        if(count==0)break;
        unsigned pos=0;
        while(pos<(unsigned)count){
            if((unsigned)count-pos<20){failures++;return;}
            unsigned reclen=(unsigned)dent[pos+16]|((unsigned)dent[pos+17]<<8);
            if(reclen<20||pos+reclen>(unsigned)count){failures++;return;}
            char *name=(char*)(dent+pos+19);
            unsigned max=reclen-19,len=0;
            while(len<max && name[len])len++;
            if(len==max||len>MAX_NAME){failures++;return;}
            unsigned type=dent[pos+18];
            pos+=reclen;
            if(!*name||dot_name(name))continue;
            if(type==L_DT_LNK){skipped++;continue;}
            if(type==L_DT_DIR||type==0){
                long child=os_open(src,name,L_O_DIR,0);
                if(child>=0){
                    KernelStat meta;
                    if(os_stat(child,&meta)<0||!is_dir(&meta)){
                        os_close(child);failures++;continue;
                    }
                    /* A nested bind mount may alias the destination even
                     * after the selected root passed preflight. Check the
                     * opened inode before making any corresponding output.
                     */
                    if(descends_from(destfd,(int)child)||
                       descends_from((int)child,destfd)){
                        warn("Destination overlaps selected source directory\n");
                        failures++;os_close(child);continue;
                    }
                    int out=-1;
                    if(do_copy){
                        long made=os_mkdir(dst,name,0700);
                        if(made<0 && made!=-L_EEXIST){
                            failures++;os_close(child);continue;
                        }
                        out=(int)os_open(dst,name,L_O_DIR,0);
                        KernelStat target;
                        if(out<0||os_stat(out,&target)<0||!is_dir(&target)||
                            (uint64_t)target.st_dev!=dest_dev){
                            if(out>=0)os_close(out);
                            failures++;os_close(child);continue;
                        }
                    }
                    walk((int)child,out,depth+1);
                    if(out>=0)os_close(out);
                    os_close(child);
                    continue;
                }
                if(type==L_DT_DIR){failures++;continue;}
            }
            if(type==L_DT_REG||type==0)copy_file(src,dst,name,false);
            else skipped++;
        }
    }
}
static bool output_empty(int fd){
    unsigned char buf[DENT_BUFSIZE];
    for(;;){
        long n=os_getdents(fd,buf,sizeof(buf));
        if(n==-L_EINTR)continue;
        if(n<0)return false;
        if(!n)return true;
        unsigned pos=0;
        while(pos<(unsigned)n){
            if((unsigned)n-pos<20)return false;
            unsigned len=buf[pos+16]|((unsigned)buf[pos+17]<<8);
            if(len<20||pos+len>(unsigned)n)return false;
            const char *name=(const char*)(buf+pos+19);
            if(!dot_name(name))return false;
            pos+=len;
        }
    }
}
/* Validate all selected subtrees before creating a single output file.
 * This prevents an overlapped destination from being partly populated when
 * only a later-selected source subtree points into it.
 */
static bool preflight_selection(void){
    for(unsigned i=0;i<5;i++){
        bool absent=false;
        int input=relative_dir(sourcefd,selected[i],false,&absent);
        if(input<0){
            if(absent)continue;
            warn("Input ancestry could not be validated\n");
            return false;
        }
        bool overlap=descends_from(destfd,input);
        os_close(input);
        if(overlap){
            warn("Destination overlaps selected source directory\n");
            return false;
        }
    }
    return true;
}
static void selected_copy(const char *name,bool directory){
    char last[MAX_NAME+1];bool absent=false;
    int parent=path_parent(sourcefd,name,false,last,&absent);
    if(parent<0){
        if(absent){missing++;return;}
        failures++;return;
    }
    if(!directory){
        int dst=-1;
        if(do_copy)dst=path_parent(destfd,name,true,last,0);
        if(!do_copy||dst>=0)copy_file(parent,dst,last,false);
        else failures++;
        if(dst>=0)os_close(dst);
        os_close(parent);
        return;
    }
    long indir=os_open(parent,last,L_O_DIR,0);
    os_close(parent);
    if(indir<0){missing++;return;}
    KernelStat meta;
    if(os_stat(indir,&meta)<0||!is_dir(&meta)){failures++;os_close(indir);return;}
    if(descends_from(destfd,(int)indir)){
        failures++;warn("Destination overlaps selected source directory\n");
        os_close(indir);return;
    }
    bool dummy=false;
    int dst=-1;
    if(do_copy)dst=relative_dir(destfd,name,true,&dummy);
    if(!do_copy||dst>=0)walk((int)indir,dst,0);
    else failures++;
    if(dst>=0)os_close(dst);
    os_close(indir);
}
static int exporter(int argc,char **argv){
    const char *source=0,*destination=0;
    bool test_allow_same=false;
    for(int i=1;i<argc;i++){
        if(c_eq(argv[i],"--source-root") && i+1<argc)source=argv[++i];
        else if(c_eq(argv[i],"--destination")&&i+1<argc)destination=argv[++i];
        else if(c_eq(argv[i],"--copy"))do_copy=true;
#ifdef CA01_OFFLINE_TEST
        else if(c_eq(argv[i],"--test-allow-same-device"))test_allow_same=true;
#endif
        else{warn("Usage: --source-root ABSOLUTE --destination ABSOLUTE [--copy]\n");return 2;}
    }
#ifndef CA01_OFFLINE_TEST
    (void)test_allow_same;
#endif
    if(!source||!destination){warn("Absolute source and destination required\n");return 2;}
    sourcefd=abs_dir(source);
    destfd=abs_dir(destination);
    if(sourcefd<0||destfd<0){warn("Rejected path or symlinked parent directory\n");return 2;}
    KernelStat a,b;
    if(os_stat(sourcefd,&a)<0||os_stat(destfd,&b)<0||!is_dir(&a)||!is_dir(&b)){
        warn("Invalid source/destination directory\n");return 2;
    }
    source_dev=(uint64_t)a.st_dev;dest_dev=(uint64_t)b.st_dev;
    if(same_inode(&a,&b)){warn("Source and destination identical\n");return 2;}
    if(do_copy){
        if(source_dev==dest_dev && !test_allow_same){
            warn("Refusing destination on source filesystem; require mounted external volume\n");
            return 2;
        }
#ifndef CA01_OFFLINE_TEST
        /* A copy can only target a newly created directory on the existing
         * independently mounted /mnt/usb1 filesystem. A path merely named
         * usb1 on an unmounted eMMC root filesystem is never sufficient. */
        if(!c_starts(destination,"/mnt/usb1/") || !destination[10]){
            warn("Refusing output outside /mnt/usb1/\n");return 2;
        }
        int usb=abs_dir("/mnt/usb1"),mount_parent=abs_dir("/mnt");
        KernelStat usb_stat,parent_stat;
        bool valid_mount=usb>=0 && mount_parent>=0 &&
            os_stat(usb,&usb_stat)>=0 && os_stat(mount_parent,&parent_stat)>=0 &&
            usb_stat.st_dev!=parent_stat.st_dev && (uint64_t)usb_stat.st_dev==dest_dev;
        if(usb>=0)os_close(usb);
        if(mount_parent>=0)os_close(mount_parent);
        if(!valid_mount){warn("Refusing unverified USB mount\n");return 2;}
#endif
        if(!output_empty(destfd)){warn("Refusing nonempty output directory\n");return 2;}
    }
    if(!preflight_selection())return 2;
    say("CA01 exporter mode=");say(do_copy?"COPY\n":"DRY-RUN\n");
    for(unsigned i=0;i<ARR_SIZE(selected);i++)selected_copy(selected[i],i<5);
    say("Summary entries=");dec(files);
    say(" bytes=");dec(total_bytes);
    say(" absent=");dec(missing);
    say(" skipped=");dec(skipped);
    say(" errors=");dec(failures);say("\n");
    os_close(destfd);os_close(sourcefd);
    return failures?1:0;
}
#ifdef CA01_LEGACY_ARM
__attribute__((noreturn)) static void os_exit(int status){
    sc4(SYS_EXIT,status,0,0,0);
    for(;;){}
}
void entry_from_stack(uintptr_t *sp) __attribute__((noreturn));
void entry_from_stack(uintptr_t *sp){
    int argc=(int)sp[0];
    char **argv=(char **)(sp+1);
    os_exit(exporter(argc,argv));
}
__attribute__((naked,noreturn)) void _start(void){
    __asm__ volatile("mov r0, sp\nbl entry_from_stack\n");
}
#else
int main(int argc,char **argv){return exporter(argc,argv);}
#endif
