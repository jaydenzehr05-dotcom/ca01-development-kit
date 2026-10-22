/* Read-only ARM Linux EABI probe. No libc, network, graphics writes or GPIO.
 * Standalone user-space ELF: it requires an existing executable launch path.
 * It is NOT a KWI update and will not autorun from a USB drive.
 */
typedef unsigned int u32;

static long call3(long number, long a, long b, long c) {
    register long r0 __asm__("r0") = a;
    register long r1 __asm__("r1") = b;
    register long r2 __asm__("r2") = c;
    register long r7 __asm__("r7") = number;
    __asm__ volatile ("svc 0" : "+r"(r0) : "r"(r1), "r"(r2), "r"(r7) : "memory", "cc");
    return r0;
}

static void write_all(const char *s, unsigned n) {
    while (n) {
        long result = call3(4, 1, (long)s, n);
        if (result == -4) continue; /* EINTR */
        if (result <= 0) call3(1, 1, 0, 0);
        s += result;
        n -= (unsigned)result;
    }
}

static void print(const char *s) {
    unsigned n = 0;
    while (s[n]) ++n;
    write_all(s, n);
}

static void number(u32 n) {
    char digits[10];
    unsigned count = 0;
    do { digits[count++] = (char)('0' + n % 10); n /= 10; } while (n);
    while (count) write_all(&digits[--count], 1);
}

static void show_file(const char *path) {
    char buffer[512];
    unsigned total = 0;
    long fd;
    print("\n--- "); print(path); print(" ---\n");
    fd = call3(5, (long)path, 0, 0); /* O_RDONLY */
    if (fd < 0) { print("unavailable, errno="); number((u32)-fd); print("\n"); return; }
    while (total < 16384) {
        unsigned remaining = 16384 - total;
        long count = call3(3, fd, (long)buffer,
                          remaining < sizeof(buffer) ? remaining : sizeof(buffer));
        if (count == -4) continue;
        if (count < 0) { print("read failed\n"); break; }
        if (count == 0) break;
        write_all(buffer, (unsigned)count);
        total += (unsigned)count;
    }
    if (total == 16384) print("\n[output limited to 16 KiB]\n");
    call3(6, fd, 0, 0);
}

static void show_framebuffer(const char *path) {
    /* 256-byte buffer exceeds the 160-byte fb_var_screeninfo in supplied 2.6.35.7.
     * The first seven 32-bit fields are sufficient for dimensions and depth. */
    volatile u32 info[64]; /* Keep initialization scalar; require no NEON state. */
    unsigned i;
    long fd, result;
    for (i = 0; i < 64; ++i) info[i] = 0;
    print("\n--- "); print(path); print(" (query only) ---\n");
    fd = call3(5, (long)path, 0, 0);
    if (fd < 0) { print("unavailable, errno="); number((u32)-fd); print("\n"); return; }
    result = call3(54, fd, 0x4600, (long)info); /* FBIOGET_VSCREENINFO */
    if (result < 0) { print("query failed, errno="); number((u32)-result); print("\n"); }
    else {
        print("visible="); number(info[0]); print("x"); number(info[1]);
        print(" virtual="); number(info[2]); print("x"); number(info[3]);
        print(" bits_per_pixel="); number(info[6]); print("\n");
    }
    call3(6, fd, 0, 0);
}

__attribute__((noreturn)) void _start(void) {
    print("CA01 research probe v0.1 - read-only metadata\n");
    show_file("/proc/version");
    show_file("/proc/cpuinfo");
    show_file("/proc/meminfo");
    show_file("/proc/fb");
    show_file("/proc/bus/input/devices");
    show_file("/proc/mounts");
    show_framebuffer("/dev/fb0");
    show_framebuffer("/dev/graphics/fb0");
    print("\nProbe complete.\n");
    call3(1, 0, 0, 0);
    for (;;) { }
}
