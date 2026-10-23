/*
 * CA01 read-only filesystem copier proof-of-concept, NOT firmware update.
 * Purpose: preserve selected GUI and library paths to a pre-mounted output.
 * No installation, service changes, USB gadget, Bluetooth or internal writes.
 * Defaults to DRY RUN. Needs explicit --copy to write output.
 * Only for operation on hardware for which the user has permission.
 * Test against synthetic directories before any real-unit use.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dirent.h>
#include <sys/types.h>
#include <stdbool.h>

#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif
static size_t done_files=0, failed_files=0, skipped=0, copied_bytes=0;
static bool do_copy=false;
static const char *source_root, *dest_root;
static const char *allow_paths[]={
  "opt/ftl/gui/MC","opt/ftl/gui/font","opt/ftl/gui/allwords",
  "opt/ftl/lib","opt/ftl/apl","etc/ipasz.conf",
  "opt/ftl/ipasz.conf"
};
#define COUNT_OF(x) (sizeof(x)/sizeof(x[0]))
static bool join(char out[PATH_MAX],const char *a,const char *b){
    int n=snprintf(out,PATH_MAX,"%s/%s",a,b);
    return n>=0 && n<PATH_MAX;
}
static bool ensure_directory(const char *p){
    struct stat st;
    if (lstat(p,&st)==0){
        if (!S_ISDIR(st.st_mode)) {fprintf(stderr,"Not a directory: %s\n",p);return false;}
        return true;
    }
    if(errno!=ENOENT)return false;
    if(mkdir(p,0700)<0 && errno!=EEXIST){
        perror("mkdir");return false;
    }
    return true;
}
static bool ensure_parent(const char *full){
    char tmp[PATH_MAX];
    int n=snprintf(tmp,sizeof(tmp),"%s",full);
    if(n<=0||n>=PATH_MAX)return false;
    for(char *q=tmp+1;*q;q++){
        if(*q=='/'){
            *q=0;
            if(!ensure_directory(tmp))return false;
            *q='/';
        }
    }
    return true;
}
static bool copy_regular(const char *src,const char *dst){
    int in=open(src,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    if(in<0){perror("open source");failed_files++;return false;}
    int out=open(dst,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW,0600);
    if(out<0){
        fprintf(stderr,"Refusing overwrite: %s (%s)\n",dst,strerror(errno));
        close(in);failed_files++;return false;
    }
    char buf[32768];bool ok=true;
    while(1){
        ssize_t n=read(in,buf,sizeof(buf));
        if(n==0)break;
        if(n<0){if(errno==EINTR)continue;ok=false;break;}
        ssize_t done=0;
        while(done<n){
            ssize_t w=write(out,buf+done,(size_t)(n-done));
            if(w<0 && errno==EINTR)continue;
            if(w<=0){ok=false;break;}
            done+=w;
            copied_bytes+=(size_t)w;
        }
        if(!ok)break;
    }
    if(fsync(out)<0)ok=false;
    if(close(out)<0)ok=false;
    close(in);
    if(!ok){fprintf(stderr,"Copy failed: %s\n",src);unlink(dst);failed_files++;return false;}
    done_files++;
    return true;
}
static void visit(const char *relative,unsigned depth){
    if(depth>26){fprintf(stderr,"Depth cap %s\n",relative);skipped++;return;}
    char src[PATH_MAX],dst[PATH_MAX];
    if(!join(src,source_root,relative)||!join(dst,dest_root,relative)){
        fprintf(stderr,"Overlong path: %s\n",relative);skipped++;return;
    }
    struct stat st;
    if(lstat(src,&st)<0){
        if(errno!=ENOENT){fprintf(stderr,"Cannot stat %s: %s\n",src,strerror(errno));failed_files++;}
        else fprintf(stderr,"Not present: %s\n",src);
        return;
    }
    if(S_ISLNK(st.st_mode)){printf("SKIP symlink %s\n",relative);skipped++;return;}
    if(S_ISREG(st.st_mode)){
        if(do_copy){
            if(!ensure_parent(dst)){failed_files++;return;}
            copy_regular(src,dst);
        }
        else {done_files++;copied_bytes+=(size_t)st.st_size;printf("PLAN %s (%lld bytes)\n",relative,(long long)st.st_size);}
        return;
    }
    if(!S_ISDIR(st.st_mode)){printf("SKIP non-file %s\n",relative);skipped++;return;}
    if(do_copy&&(!ensure_parent(dst)||!ensure_directory(dst))){failed_files++;return;}
    DIR *dir=opendir(src);
    if(!dir){failed_files++;perror("opendir");return;}
    struct dirent *it;
    while((it=readdir(dir))){
        if(strcmp(it->d_name,".")==0||strcmp(it->d_name,"..")==0)continue;
        char rel[PATH_MAX];
        if(join(rel,relative,it->d_name))visit(rel,depth+1);
        else skipped++;
    }
    closedir(dir);
}
static bool prefix_of(const char *dir,const char *path){
    size_t n=strlen(dir);return strncmp(dir,path,n)==0 && (path[n]=='/' || path[n]==0);
}
int main(int argc,char **argv){
    for(int i=1;i<argc;i++){
        if(!strcmp(argv[i],"--source-root")&&i+1<argc)source_root=argv[++i];
        else if(!strcmp(argv[i],"--destination")&&i+1<argc)dest_root=argv[++i];
        else if(!strcmp(argv[i],"--copy"))do_copy=true;
        else{fprintf(stderr,"Usage: %s --source-root DIR --destination EXISTING_DIR [--copy]\n",argv[0]);return 2;}
    }
    if(!source_root||!dest_root){fprintf(stderr,"Specify paths. Dry-run is default.\n");return 2;}
    char root[PATH_MAX],dest[PATH_MAX];
    if(!realpath(source_root,root)||!realpath(dest_root,dest)){
        perror("Realpath - source and destination must exist");return 2;
    }
    if(!strcmp(root,dest)){fprintf(stderr,"Source and destination are identical\n");return 2;}
    if(do_copy){
        DIR *dir=opendir(dest);
        if(!dir){perror("Destination");return 2;}
        struct dirent *ent;bool nonempty=false;
        while((ent=readdir(dir))){
            if(strcmp(ent->d_name,".")&&strcmp(ent->d_name,"..")){nonempty=true;break;}
        }
        closedir(dir);
        if(nonempty){fprintf(stderr,"Refusing nonempty output directory\n");return 2;}
    }
    /* Refuse destination inside selected source subdirectories. */
    for(size_t i=0;i<COUNT_OF(allow_paths);i++){
        char selected[PATH_MAX],actual[PATH_MAX];
        if(!join(selected,root,allow_paths[i]))continue;
        if(realpath(selected,actual) && prefix_of(actual,dest)){
            fprintf(stderr,"Destination inside selected input tree\n");return 2;
        }
    }
    source_root=root;dest_root=dest;
    printf("CA01 exporter PoC mode=%s source=%s destination=%s\n",
           do_copy?"COPY":"DRY-RUN",source_root,dest_root);
    for(size_t i=0;i<COUNT_OF(allow_paths);i++)visit(allow_paths[i],0);
    printf("Summary entries=%zu bytes=%zu skipped=%zu errors=%zu\n",
           done_files,copied_bytes,skipped,failed_files);
    return failed_files?1:0;
}
