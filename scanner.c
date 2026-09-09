/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 scanner contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * scanner.c - single-file offline defensive scanner + sandbox (educational)
 * Version 0.2.0
 *
 * Build (MinGW):  gcc scanner.c -o scanner.exe -Wall -Wextra -O2
 * Build (MSVC):   cl scanner.c
 * Build (Linux):  gcc scanner.c -o scanner -Wall -Wextra -O2 -lm
 *
 * Usage:
 *   scanner scan <folder> [--json]   offline scan (EICAR + heuristics)
 *   scanner sandbox <exe> [args...]  limited execution (Job Object / rlimit)
 *   scanner hash <file>              print FNV-1a + SHA-256 of a file
 *   scanner sigtest                  in-memory self test (no disk write)
 *   scanner --version
 *
 * Fully offline. No network, no VirusTotal, no third-party libs.
 * Defensive/educational only. Not a commercial AV. No evasion content.
 * Verdicts: HIT (strong sig only) / SUSPICIOUS (needs review) / INFO / CLEAN.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <math.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>
#include <limits.h>
#endif

/* Defensive-only lab logging: report virtualization context to logs. */
#if defined(_MSC_VER)
#include <intrin.h>
#elif defined(__GNUC__) || defined(__clang__)
#include <cpuid.h>
#endif

#define SCANNER_VERSION "0.2.0"
#define MAX_SCAN_SIZE   (64ULL*1024ULL*1024ULL)
#define CHUNK_SIZE      65536
#define MAX_DEPTH       32
#define ENT_THRESHOLD   7.2
#define ENT_MIN_LEN     512

/* ---------------- CPUID lab context (log only, no branching) ---------------- */
static int cpuid_hypervisor_bit_logonly(void) {
#if defined(_MSC_VER)
    int regs[4] = {0,0,0,0};
    __cpuid(regs, 1);
    {
        int present = (int)(((unsigned)regs[2] >> 31) & 1u);
        printf("[lab-context] CPUID.01H:ECX[31] hypervisor-present-bit=%d\n", present);
        return present;
    }
#elif defined(__GNUC__) || defined(__clang__)
    unsigned int eax=0, ebx=0, ecx=0, edx=0;
    if (!__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
        printf("[lab-context] CPUID.01H unavailable\n");
        return -1;
    }
    {
        int present = (int)((ecx >> 31) & 1u);
        printf("[lab-context] CPUID.01H:ECX[31] hypervisor-present-bit=%d\n", present);
        return present;
    }
#else
    printf("[lab-context] CPUID unavailable on this compiler\n");
    return -1;
#endif
}

static void cpuid_hypervisor_vendor_logonly(void) {
#if defined(_MSC_VER)
    int regs[4] = {0,0,0,0};
    char vendor[13];
    __cpuid(regs, 0x40000000);
    memcpy(vendor+0, &regs[1], 4);
    memcpy(vendor+4, &regs[2], 4);
    memcpy(vendor+8, &regs[3], 4);
    vendor[12] = '\0';
    printf("[lab-context] CPUID.40000000H: EAX=%08X vendor=\"%.12s\" (log only)\n",
           (unsigned)regs[0], vendor);
#elif defined(__GNUC__) || defined(__clang__)
    unsigned int eax=0, ebx=0, ecx=0, edx=0;
    char vendor[13];
    if (!__get_cpuid(0x40000000u, &eax, &ebx, &ecx, &edx)) {
        printf("[lab-context] CPUID.40000000H unavailable\n");
        return;
    }
    memcpy(vendor+0, &ebx, 4);
    memcpy(vendor+4, &ecx, 4);
    memcpy(vendor+8, &edx, 4);
    vendor[12] = '\0';
    printf("[lab-context] CPUID.40000000H: EAX=%08X vendor=\"%.12s\" (log only)\n",
           eax, vendor);
#else
    printf("[lab-context] CPUID vendor leaf unavailable on this compiler\n");
#endif
}

static void log_lab_vm_context(void) {
    (void)cpuid_hypervisor_bit_logonly();
    cpuid_hypervisor_vendor_logonly();
}

/* ---------------- globals ---------------- */
static int g_json = 0;
static long g_files = 0, g_hits = 0, g_susp = 0, g_info = 0, g_err = 0;
static unsigned long long g_bytes = 0;

/* ---------------- EICAR ---------------- */
static const char EICAR_STR[] =
    "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
static const char EICAR_TOKEN[] = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE";

/* ---------------- FNV-1a ---------------- */
static uint64_t fnv1a_buf(const unsigned char *d, size_t n) {
    uint64_t h = 14695981039346656037ULL;
    size_t i;
    for (i = 0; i < n; i++) { h ^= d[i]; h *= 1099511628211ULL; }
    return h;
}

/* ---------------- SHA-256 (compact, public-domain style) ---------------- */
typedef struct { uint32_t h[8]; uint64_t len; unsigned char buf[64]; size_t buflen; } sha256_ctx;

static uint32_t rotr32(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

static void sha256_init(sha256_ctx *c) {
    c->h[0]=0x6a09e667u; c->h[1]=0xbb67ae85u; c->h[2]=0x3c6ef372u; c->h[3]=0xa54ff53au;
    c->h[4]=0x510e527fu; c->h[5]=0x9b05688cu; c->h[6]=0x1f83d9abu; c->h[7]=0x5be0cd19u;
    c->len = 0; c->buflen = 0;
}

static void sha256_block(sha256_ctx *c, const unsigned char *p) {
    static const uint32_t K[64] = {
        0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
        0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
        0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
        0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
        0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
        0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
        0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
        0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u };
    uint32_t w[64], a,b,cc,d,e,f,g,hh,t1,t2;
    int i;
    for (i = 0; i < 16; i++)
        w[i] = ((uint32_t)p[i*4]<<24)|((uint32_t)p[i*4+1]<<16)|((uint32_t)p[i*4+2]<<8)|(uint32_t)p[i*4+3];
    for (i = 16; i < 64; i++) {
        uint32_t s0 = rotr32(w[i-15],7)^rotr32(w[i-15],18)^(w[i-15]>>3);
        uint32_t s1 = rotr32(w[i-2],17)^rotr32(w[i-2],19)^(w[i-2]>>10);
        w[i] = w[i-16]+s0+w[i-7]+s1;
    }
    a=c->h[0]; b=c->h[1]; cc=c->h[2]; d=c->h[3];
    e=c->h[4]; f=c->h[5]; g=c->h[6]; hh=c->h[7];
    for (i = 0; i < 64; i++) {
        uint32_t S1 = rotr32(e,6)^rotr32(e,11)^rotr32(e,25);
        uint32_t ch = (e&f)^((~e)&g);
        t1 = hh+S1+ch+K[i]+w[i];
        {
            uint32_t S0 = rotr32(a,2)^rotr32(a,13)^rotr32(a,22);
            uint32_t mj = (a&b)^(a&cc)^(b&cc);
            t2 = S0+mj;
        }
        hh=g; g=f; f=e; e=d+t1; d=cc; cc=b; b=a; a=t1+t2;
    }
    c->h[0]+=a; c->h[1]+=b; c->h[2]+=cc; c->h[3]+=d;
    c->h[4]+=e; c->h[5]+=f; c->h[6]+=g; c->h[7]+=hh;
}

static void sha256_update(sha256_ctx *c, const unsigned char *d, size_t n) {
    size_t i;
    c->len += (uint64_t)n;
    for (i = 0; i < n; i++) {
        c->buf[c->buflen++] = d[i];
        if (c->buflen == 64) { sha256_block(c, c->buf); c->buflen = 0; }
    }
}

static void sha256_final(sha256_ctx *c, unsigned char out[32]) {
    uint64_t bitlen = c->len * 8ULL;
    int i;
    c->buf[c->buflen++] = 0x80;
    if (c->buflen > 56) {
        while (c->buflen < 64) c->buf[c->buflen++] = 0;
        sha256_block(c, c->buf); c->buflen = 0;
    }
    while (c->buflen < 56) c->buf[c->buflen++] = 0;
    for (i = 7; i >= 0; i--) c->buf[c->buflen++] = (unsigned char)(bitlen >> (i*8));
    sha256_block(c, c->buf);
    for (i = 0; i < 8; i++) {
        out[i*4+0]=(unsigned char)(c->h[i]>>24); out[i*4+1]=(unsigned char)(c->h[i]>>16);
        out[i*4+2]=(unsigned char)(c->h[i]>>8);  out[i*4+3]=(unsigned char)(c->h[i]);
    }
}

static void sha256_hex(const unsigned char h[32], char out[65]) {
    static const char *xd = "0123456789abcdef";
    int i;
    for (i = 0; i < 32; i++) { out[i*2]=xd[h[i]>>4]; out[i*2+1]=xd[h[i]&15]; }
    out[64]='\0';
}

/* ---------------- byte helpers ---------------- */
static const unsigned char *memfind(const unsigned char *h, size_t hlen,
                                    const unsigned char *n, size_t nlen) {
    size_t i;
    if (nlen == 0 || nlen > hlen) return NULL;
    for (i = 0; i + nlen <= hlen; i++)
        if (memcmp(h+i, n, nlen) == 0) return h+i;
    return NULL;
}

static char ascii_low(char c) { return (c>='A'&&c<='Z') ? (char)(c+32) : c; }

static const unsigned char *memfind_ci(const unsigned char *h, size_t hlen, const char *needle) {
    size_t nlen = strlen(needle), i, j;
    if (nlen == 0 || nlen > hlen) return NULL;
    for (i = 0; i + nlen <= hlen; i++) {
        for (j = 0; j < nlen; j++)
            if (ascii_low((char)h[i+j]) != ascii_low(needle[j])) break;
        if (j == nlen) return h+i;
    }
    return NULL;
}

static const char *base_name(const char *p) {
    const char *b1 = strrchr(p, '/'), *b2 = strrchr(p, '\\'), *b = p;
    if (b1 && b1+1 > b) b = b1+1;
    if (b2 && b2+1 > b) b = b2+1;
    return b;
}

static void get_ext_lower(const char *path, char *out, size_t cap) {
    const char *b = base_name(path), *dot = strrchr(b, '.');
    size_t i;
    if (!dot || cap == 0) { if (cap) out[0]='\0'; return; }
    for (i = 0; i+1 < cap && dot[i]; i++) out[i] = ascii_low(dot[i]);
    out[i] = '\0';
}

static int ext_is(const char *ext, const char *list) {
    /* list like "|.exe|.dll|.bat|" */
    char needle[32];
    snprintf(needle, sizeof(needle), "|%s|", ext);
    return strstr(list, needle) != NULL;
}

static int is_risky_ext(const char *ext) {
    return ext_is(ext, "|.exe|.dll|.bat|.cmd|.ps1|.vbs|.js|.scr|.msi|.hta|.lnk|.jar|");
}
static int is_script_ext(const char *ext) {
    return ext_is(ext, "|.ps1|.bat|.cmd|.js|.vbs|.hta|");
}

/* allowlisted benign metadata files -> force CLEAN */
static int is_allowlisted(const char *path) {
    const char *b = base_name(path);
    char lower[64];
    size_t i;
    static const char *allow[] = {"desktop.ini","thumbs.db",".ds_store",NULL};
    for (i = 0; i+1 < sizeof(lower) && b[i]; i++) lower[i] = ascii_low(b[i]);
    lower[i] = '\0';
    for (i = 0; allow[i]; i++) if (strcmp(lower, allow[i]) == 0) return 1;
    return 0;
}

/* double extension: doc-like middle + risky final, e.g. invoice.pdf.exe */
static int has_double_ext(const char *path) {
    const char *b = base_name(path);
    const char *first = strchr(b, '.'), *last = strrchr(b, '.');
    char mid[24], fin[24];
    size_t i, n;
    const char *second;
    if (!first || !last || first == last) return 0;
    second = strchr(first+1, '.');
    if (!second) return 0;
    n = (size_t)(last - (first+1));
    if (n == 0 || n > 10) return 0;
    for (i = 0; i < n && i+1 < sizeof(mid); i++) mid[i] = ascii_low(first[1+i]);
    mid[i] = '\0';
    for (i = 0; i+1 < sizeof(fin) && last[i]; i++) fin[i] = ascii_low(last[i]);
    fin[i] = '\0';
    {
        int mid_doc = ext_is(mid, "|pdf|doc|docx|xls|xlsx|ppt|pptx|txt|jpg|png|zip|csv|one|");
        return mid_doc && is_risky_ext(fin);
    }
}

/* skip pseudo filesystems (nix absolute paths) */
static int is_skipped_path(const char *p) {
    static const char *skip[] = {"/proc", "/sys", "/dev", NULL};
    int i;
    for (i = 0; skip[i]; i++) {
        size_t n = strlen(skip[i]);
        if (strncmp(p, skip[i], n) == 0 && (p[n]=='\0' || p[n]=='/')) return 1;
    }
    return 0;
}

/* ---------------- entropy ---------------- */
static double shannon_entropy(const unsigned char *b, size_t n) {
    size_t cnt[256] = {0}, i;
    double h = 0.0, inv_log2;
    if (!b || n == 0) return 0.0;
    for (i = 0; i < n; i++) cnt[b[i]]++;
    inv_log2 = 1.0 / log(2.0);
    for (i = 0; i < 256; i++) {
        if (!cnt[i]) continue;
        {
            double p = (double)cnt[i] / (double)n;
            h -= p * log(p) * inv_log2;
        }
    }
    return h;
}

/* ---------------- PE anomaly check (detection only) ---------------- */
static uint16_t rd16le(const unsigned char *p) { return (uint16_t)(p[0]|(p[1]<<8)); }
static uint32_t rd32le(const unsigned char *p) {
    return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);
}
static uint64_t rd64le(const unsigned char *p) {
    uint64_t v = 0; int i;
    for (i = 7; i >= 0; i--) v = (v<<8) | p[i];
    return v;
}
static int add_o32(uint32_t a, uint32_t b) { return (0xFFFFFFFFu - a) < b; }

/* returns 0 ok, else anomaly code */
static int pe_check(const unsigned char *b, size_t len) {
    uint32_t lfanew, sig, entry, imgSize, sectOff;
    uint16_t nsect, szopt, magic;
    uint16_t i;
    if (!b || len < 64) return 1;
    if (b[0]!='M' || b[1]!='Z') return 2;
    lfanew = rd32le(b+0x3C);
    if ((lfanew & 3u) || lfanew < 64 || add_o32(lfanew, 6) || (size_t)lfanew+6 > len) return 3;
    sig = rd32le(b+lfanew);
    if (sig != 0x00004550u) return 4;
    if ((size_t)lfanew+24 > len) return 5;
    nsect = rd16le(b+lfanew+6);
    szopt = rd16le(b+lfanew+20);
    if (nsect == 0 || nsect > 96) return 6;
    if ((size_t)lfanew+24+szopt > len) return 7;
    if (szopt < 28) return 8;
    magic = rd16le(b+lfanew+24);
    if (magic != 0x10Bu && magic != 0x20Bu) return 9;
    entry = rd32le(b+lfanew+24+16);
    imgSize = rd32le(b+lfanew+24+56);
    if (imgSize == 0 || imgSize > 0x20000000u) return 10;
    sectOff = lfanew+24+szopt;
    if (add_o32(sectOff, (uint32_t)nsect*40u) || (size_t)sectOff+(size_t)nsect*40u > len) return 11;
    {
        int found = 0;
        for (i = 0; i < nsect; i++) {
            const unsigned char *s = b+sectOff+(size_t)i*40u;
            uint32_t vsize=rd32le(s+8), vaddr=rd32le(s+12);
            uint32_t rawsz=rd32le(s+16), rawptr=rd32le(s+20);
            uint32_t flags=rd32le(s+36);
            uint32_t vext = vsize > rawsz ? vsize : rawsz;
            if (!vext) vext = 1;
            if (rawsz > 0) {
                if (add_o32(rawptr, rawsz) || (size_t)rawptr+rawsz > len) return 12;
            }
            if (add_o32(vaddr, vext) || vaddr+vext > imgSize) return 13;
            if (entry >= vaddr && entry < vaddr+vext) {
                found = 1;
                if (!(flags & 0x20000000u)) return 14; /* entry in non-executable */
            }
        }
        if (entry == 0 || !found) return 15;
    }
    return 0;
}

/* ---------------- ELF anomaly check (detection only, LE-focused) ---------------- */
static int elf_check(const unsigned char *b, size_t len) {
    int is64;
    uint64_t phoff, shoff;
    uint16_t phentsize, phnum, shentsize, shnum;
    size_t i;
    if (!b || len < 52) return 1;
    if (!(b[0]==0x7F && b[1]=='E' && b[2]=='L' && b[3]=='F')) return 2;
    if (b[4]!=1 && b[4]!=2) return 3;             /* class */
    if (b[5]!=1 && b[5]!=2) return 4;             /* data */
    if (b[6]!=1) return 5;                        /* version */
    if (b[5]==2) return 0;                        /* BE: skip detail, avoid FP */
    is64 = (b[4]==2);
    if (is64) {
        uint64_t need;
        if (len < 64 || rd16le(b+52)!=64) return 6;
        phentsize=rd16le(b+54); phnum=rd16le(b+56);
        shentsize=rd16le(b+58); shnum=rd16le(b+60);
        phoff=rd64le(b+32); shoff=rd64le(b+40);
        if (phnum > 64 || shnum > 1024) return 7;
        if (phentsize && phentsize < 56) return 8;
        if (shentsize && shnum && shentsize < 64) return 9;
        need = (uint64_t)phnum*(phentsize?phentsize:56);
        if (phnum && (phoff+need < phoff || phoff+need > len)) return 10;
        for (i = 0; i < phnum; i++) {
            const unsigned char *p = b+phoff+(uint64_t)i*(phentsize?phentsize:56);
            uint32_t type=rd32le(p), flags=rd32le(p+4);
            uint64_t off=rd64le(p+8), filesz=rd64le(p+32), memsz=rd64le(p+40);
            if (type==1) { /* PT_LOAD */
                if (filesz > memsz) return 11;
                if (off+filesz < off || off+filesz > len) return 12;
                if ((flags&7u)==7u) return 13; /* RWX */
            }
        }
        need = (uint64_t)shnum*(shentsize?shentsize:64);
        if (shnum && (shoff+need < shoff || shoff+need > len)) return 14;
        for (i = 0; i < shnum; i++) {
            const unsigned char *s = b+shoff+(uint64_t)i*(shentsize?shentsize:64);
            uint32_t type=rd32le(s+4);
            uint64_t flags=rd64le(s+8), off=rd64le(s+24), size=rd64le(s+32);
            if (type!=0 && type!=8) {
                if (off+size < off || off+size > len) return 15;
            }
            if ((flags&6ULL)==6ULL) return 16; /* W+X */
        }
    } else {
        uint32_t need32, phoff32, shoff32;
        if (rd16le(b+40)!=52) return 6;
        phentsize=rd16le(b+42); phnum=rd16le(b+44);
        shentsize=rd16le(b+46); shnum=rd16le(b+48);
        phoff32=rd32le(b+28); shoff32=rd32le(b+32);
        phoff=phoff32; shoff=shoff32;
        if (phnum > 64 || shnum > 1024) return 7;
        if (phentsize && phentsize < 32) return 8;
        if (shentsize && shnum && shentsize < 40) return 9;
        need32 = (uint32_t)phnum*(phentsize?phentsize:32);
        if (phnum && (phoff32+need32 < phoff32 || (uint64_t)phoff32+need32 > len)) return 10;
        for (i = 0; i < phnum; i++) {
            const unsigned char *p = b+phoff+(uint64_t)i*(phentsize?phentsize:32);
            uint32_t type=rd32le(p), off=rd32le(p+4), filesz=rd32le(p+16);
            uint32_t memsz=rd32le(p+20), flags=rd32le(p+24);
            if (type==1) {
                if (filesz > memsz) return 11;
                if (off+filesz < off || (uint64_t)off+filesz > len) return 12;
                if ((flags&7u)==7u) return 13;
            }
        }
        need32 = (uint32_t)shnum*(shentsize?shentsize:40);
        if (shnum && (shoff32+need32 < shoff32 || (uint64_t)shoff32+need32 > len)) return 14;
        for (i = 0; i < shnum; i++) {
            const unsigned char *s = b+shoff+(uint64_t)i*(shentsize?shentsize:40);
            uint32_t type=rd32le(s+4), flags=rd32le(s+8);
            uint32_t off=rd32le(s+16), size=rd32le(s+20);
            if (type!=0 && type!=8) {
                if (off+size < off || (uint64_t)off+size > len) return 15;
            }
            if ((flags&6u)==6u) return 16;
        }
    }
    return 0;
}

/* ---------------- string indicators (report only) ---------------- */
typedef struct { const char *s; int strong; int cat; } Ind;
/* cats: 0 persist, 1 cred, 2 download/exec, 3 lolbin, 4 ransom, 5 net-ioc, 6 script-kw */
static const Ind INDS[] = {
    {"CurrentVersion\\Run",1,0},{"RunOnce",0,0},{"shell:startup",1,0},
    {"Register-ScheduledTask",1,0},{"schtasks",1,0},{"__EventFilter",1,0},
    {"ActiveScriptEventConsumer",1,0},{"CreateService",0,0},
    {"mimikatz",1,1},{"sekurlsa",1,1},{"ntds.dit",1,1},{"lsass",0,1},
    {"-EncodedCommand",1,2},{"FromBase64String",1,2},{"Invoke-Expression",1,2},
    {"DownloadString",1,2},{"DownloadFile",0,2},{"IEX(",0,2},
    {"powershell.exe",0,3},{"pwsh.exe",0,3},{"mshta.exe",1,3},{"rundll32.exe",0,3},
    {"regsvr32.exe",0,3},{"certutil.exe",0,3},{"bitsadmin.exe",0,3},
    {"wscript.exe",0,3},{"cscript.exe",0,3},{"msbuild.exe",0,3},{"installutil.exe",0,3},
    {"HOW_TO_DECRYPT",1,4},{"HOW_TO_RECOVER",1,4},{"YOUR_FILES_ARE_ENCRYPTED",1,4},
    {"vssadmin",1,4},{"shadowcopy",1,4},{"wevtutil",0,4},{"recoveryenabled",0,4},
    {"http://",0,5},{"https://",0,5},{".onion",1,5},
    {"AutoOpen",0,6},{"Document_Open",1,6},{"Workbook_Open",1,6},
    {"WScript.Shell",0,6},{"ShellExecute",0,6},{"URLDownloadToFile",1,6},
    {"VirtualAlloc",0,6},{"CreateThread",0,6},{"eval(",0,6},{"fromCharCode",0,6},
    {NULL,0,0}
};

static const char *VM_INFO_STRS[] = {
    "vboxservice","vmtoolsd","qemu-ga","sandboxie","cuckoo",
    "any.run","hybrid-analysis","joebox","SbieDll",NULL
};

/* base64 blob run >= 500 */
static int has_b64_blob(const unsigned char *b, size_t n) {
    size_t run = 0, i;
    for (i = 0; i < n; i++) {
        char c = (char)b[i];
        int ok = (c>='A'&&c<='Z')||(c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='+'||c=='/'||c=='=';
        if (ok) { if (++run >= 500) return 1; }
        else run = 0;
    }
    return 0;
}

static int has_long_line(const unsigned char *b, size_t n) {
    size_t run = 0, i;
    for (i = 0; i < n; i++) {
        if (b[i]=='\n') run = 0;
        else if (++run > 2000) return 1;
    }
    return 0;
}

/* IPv4-like literal present (report only, private ranges downgraded by caller note) */
static int has_ipv4_like(const unsigned char *b, size_t n, char *out, size_t cap) {
    size_t i;
    for (i = 0; i + 7 < n; i++) {
        int a,bb,cc,dd, consumed = 0;
        if (b[i]<'0'||b[i]>'9') continue;
        if (i > 0) {
            char p = (char)b[i-1];
            if ((p>='0'&&p<='9')||p=='.') continue;
        }
        if (sscanf((const char*)b+i, "%d.%d.%d.%d%n", &a,&bb,&cc,&dd,&consumed) == 4) {
            if (a>=0&&a<=255&&bb>=0&&bb<=255&&cc>=0&&cc<=255&&dd>=0&&dd<=255&&consumed>=7) {
                char tail = (consumed < 16 && i+(size_t)consumed < n) ? (char)b[i+consumed] : '\0';
                if ((tail>='0'&&tail<='9')||tail=='.') continue;
                if (out && cap) { snprintf(out, cap, "%d.%d.%d.%d", a,bb,cc,dd); }
                return 1;
            }
        }
    }
    return 0;
}

/* ---------------- verdicts ---------------- */
typedef enum { V_CLEAN=0, V_INFO=1, V_SUSPICIOUS=2, V_HIT=3 } verdict_t;
static const char *verdict_name(verdict_t v) {
    return v==V_HIT?"HIT":v==V_SUSPICIOUS?"SUSPICIOUS":v==V_INFO?"INFO":"CLEAN";
}

typedef struct {
    verdict_t v;
    char reason[256];
    double entropy;
    int packed;
    uint64_t fnv;
    unsigned char sha[32];
} Analysis;

static void analyze_buffer(const char *path, const unsigned char *b, size_t n, Analysis *a) {
    char ext[24];
    int pe_anom = 0, pe_code = 0, elf_anom = 0, elf_code = 0;
    int strong = 0, weak = 0, cats = 0, catmask = 0, i, j;
    int vm_info = 0, dbl = 0, ole = 0, zipm = 0, vba = 0, scr = 0, scrscore = 0;
    char first_strong[64] = "", first_weak[64] = "";
    memset(a, 0, sizeof(*a));
    a->v = V_CLEAN;
    snprintf(a->reason, sizeof(a->reason), "OK");

    get_ext_lower(path, ext, sizeof(ext));
    a->fnv = fnv1a_buf(b, n);
    {
        sha256_ctx cx; sha256_init(&cx);
        sha256_update(&cx, b, n); sha256_final(&cx, a->sha);
    }
    a->entropy = shannon_entropy(b, n);
    a->packed = (n >= ENT_MIN_LEN && a->entropy >= ENT_THRESHOLD);

    /* 1. strong signature: EICAR */
    if (memfind(b, n, (const unsigned char*)EICAR_TOKEN, strlen(EICAR_TOKEN))) {
        a->v = V_HIT; snprintf(a->reason, sizeof(a->reason), "EICAR-TEST");
        return;
    }

    /* 2. PE / ELF anomaly */
    if (n >= 2 && b[0]=='M' && b[1]=='Z') { pe_code = pe_check(b, n); pe_anom = (pe_code != 0); }
    if (n >= 4 && b[0]==0x7F && b[1]=='E' && b[2]=='L' && b[3]=='F') {
        elf_code = elf_check(b, n); elf_anom = (elf_code != 0);
    }

    /* 3. string indicators */
    for (i = 0; INDS[i].s; i++) {
        if (memfind_ci(b, n, INDS[i].s)) {
            if (!(catmask & (1<<INDS[i].cat))) { catmask |= (1<<INDS[i].cat); cats++; }
            if (INDS[i].strong) {
                strong++;
                if (!first_strong[0]) snprintf(first_strong, sizeof(first_strong), "%s", INDS[i].s);
            } else {
                weak++;
                if (!first_weak[0]) snprintf(first_weak, sizeof(first_weak), "%s", INDS[i].s);
            }
        }
    }
    for (j = 0; VM_INFO_STRS[j]; j++)
        if (memfind_ci(b, n, VM_INFO_STRS[j])) { vm_info = 1; break; }

    /* 4. script heuristics */
    scr = is_script_ext(ext);
    if (scr) {
        if (has_b64_blob(b, n)) scrscore += 3;
        if (has_long_line(b, n)) scrscore += 1;
        if (memfind_ci(b, n, "fromCharCode") || memfind_ci(b, n, "Chr(")) scrscore += 2;
        if (memfind_ci(b, n, "ExecuteGlobal") || memfind_ci(b, n, "eval(")) scrscore += 2;
    }

    /* 5. container checks */
    dbl = has_double_ext(path);
    if (n >= 8 && b[0]==0xD0 && b[1]==0xCF && b[2]==0x11 && b[3]==0xE0) ole = 1;
    if (n >= 4 && b[0]=='P' && b[1]=='K' && b[2]==0x03 && b[3]==0x04) zipm = 1;
    if ((ole || zipm) && (memfind_ci(b,n,"AutoOpen")||memfind_ci(b,n,"Document_Open")||
        memfind_ci(b,n,"Workbook_Open")||memfind_ci(b,n,"vbaProject"))) vba = 1;

    /* ---- combine (fail-closed on structure, never on entropy alone) ---- */
    if (pe_anom) {
        a->v = V_SUSPICIOUS;
        snprintf(a->reason, sizeof(a->reason), "PE-ANOMALY:%d%s", pe_code, a->packed?" +PACKED":"");
        return;
    }
    if (elf_anom) {
        a->v = V_SUSPICIOUS;
        snprintf(a->reason, sizeof(a->reason), "ELF-ANOMALY:%d%s", elf_code, a->packed?" +PACKED":"");
        return;
    }
    if (dbl) {
        a->v = V_SUSPICIOUS;
        snprintf(a->reason, sizeof(a->reason), "DOUBLE-EXT%s", a->packed?" +PACKED":"");
        return;
    }
    if (vba) {
        a->v = V_SUSPICIOUS;
        snprintf(a->reason, sizeof(a->reason), "MACRO-SUSPECT");
        return;
    }
    if (strcmp(ext, ".lnk") == 0 &&
        (memfind_ci(b,n,"powershell")||memfind_ci(b,n,"mshta")||memfind_ci(b,n,"rundll32")||
         memfind_ci(b,n,"http"))) {
        a->v = V_SUSPICIOUS;
        snprintf(a->reason, sizeof(a->reason), "LNK-SUSPECT");
        return;
    }
    if (strong > 0 || cats >= 2 || (weak >= 2 && cats >= 1) || scrscore >= 3) {
        a->v = V_SUSPICIOUS;
        if (strong > 0) snprintf(a->reason, sizeof(a->reason), "STR:%s%s", first_strong, a->packed?" +PACKED":"");
        else if (scr && scrscore >= 3) snprintf(a->reason, sizeof(a->reason), "SCRIPT-OBF:%d%s", scrscore, a->packed?" +PACKED":"");
        else snprintf(a->reason, sizeof(a->reason), "STR:%s multi-cat=%d%s", first_weak[0]?first_weak:"multi", cats, a->packed?" +PACKED":"");
        return;
    }
    if (weak == 1 || vm_info || a->packed || (is_risky_ext(ext) && n > 0 && n < 1024)) {
        char ip[32] = "";
        a->v = V_INFO;
        if (weak == 1) snprintf(a->reason, sizeof(a->reason), "INFO-STR:%s", first_weak);
        else if (vm_info) snprintf(a->reason, sizeof(a->reason), "ANTI-ANALYSIS-STRING");
        else if (a->packed) snprintf(a->reason, sizeof(a->reason), "PACKED-NOTE ent=%.2f", a->entropy);
        else snprintf(a->reason, sizeof(a->reason), "SMALL-RISKY-EXT");
        if (has_ipv4_like(b, n, ip, sizeof(ip)) && strcmp(a->reason,"OK")==0)
            snprintf(a->reason, sizeof(a->reason), "EMBEDDED-IP:%s", ip);
        return;
    }
    {
        char ip[32] = "";
        if (has_ipv4_like(b, n, ip, sizeof(ip))) {
            a->v = V_INFO;
            snprintf(a->reason, sizeof(a->reason), "EMBEDDED-IP:%s", ip);
            return;
        }
    }
}

/* ---------------- file IO ---------------- */
static int read_file(const char *path, unsigned char **out, size_t *out_len) {
    FILE *f;
    long sz;
    unsigned char *buf;
    size_t n;
    f = fopen(path, "rb");
    if (!f) return -1;
    fseek(f, 0, SEEK_END);
    sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz < 0 || (unsigned long long)sz > MAX_SCAN_SIZE) { fclose(f); return 1; }
    if (sz == 0) { fclose(f); *out = NULL; *out_len = 0; return 0; }
    buf = (unsigned char*)malloc((size_t)sz);
    if (!buf) { fclose(f); return -1; }
    n = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if ((long)n != sz) { free(buf); return -1; }
    *out = buf; *out_len = n;
    return 0;
}

static void json_escape(const char *s, char *out, size_t cap) {
    size_t o = 0, i;
    for (i = 0; s[i] && o+6 < cap; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c=='"'||c=='\\') { out[o++]='\\'; out[o++]=c; }
        else if (c=='\n') { out[o++]='\\'; out[o++]='n'; }
        else if (c=='\t') { out[o++]='\\'; out[o++]='t'; }
        else if (c < 0x20) { snprintf(out+o, cap-o, "\\u%04x", c); o = strlen(out); }
        else out[o++] = c;
    }
    out[o]='\0';
}

static void print_result(const char *path, size_t size, const Analysis *a) {
    char shahex[65], esc[1024];
    sha256_hex(a->sha, shahex);
    if (g_json) {
        json_escape(path, esc, sizeof(esc));
        printf("{\"path\":\"%s\",\"size\":%lu,\"fnv1a\":\"%016llx\",\"sha256\":\"%s\","
               "\"entropy\":%.2f,\"verdict\":\"%s\",\"reason\":\"%s\"}\n",
               esc, (unsigned long)size, (unsigned long long)a->fnv, shahex,
               a->entropy, verdict_name(a->v), a->reason);
    } else {
        if (a->v == V_HIT)
            printf("[HIT] %s | %s | size=%lu fnv=%016llx sha256=%.16s.. ent=%.2f\n",
                   a->reason, path, (unsigned long)size,
                   (unsigned long long)a->fnv, shahex, a->entropy);
        else if (a->v == V_SUSPICIOUS)
            printf("[SUSPICIOUS] %s | %s | size=%lu fnv=%016llx ent=%.2f\n",
                   a->reason, path, (unsigned long)size,
                   (unsigned long long)a->fnv, a->entropy);
        else if (a->v == V_INFO)
            printf("[INFO] %s | %s | size=%lu\n", a->reason, path, (unsigned long)size);
    }
}

static void scan_one(const char *path) {
    unsigned char *buf = NULL;
    size_t n = 0;
    int rc;
    Analysis a;
    g_files++;
    if (is_allowlisted(path)) return;
    rc = read_file(path, &buf, &n);
    if (rc == 1) {
        g_info++;
        if (!g_json) printf("[INFO] SKIP-LARGE (>64MB): %s\n", path);
        else printf("{\"path\":\"%s\",\"verdict\":\"INFO\",\"reason\":\"SKIP-LARGE\"}\n", path);
        return;
    }
    if (rc != 0) {
        g_err++;
        if (!g_json) printf("[INFO] UNREADABLE: %s\n", path);
        return;
    }
    if (n == 0) {
        g_info++;
        memset(&a, 0, sizeof(a));
        a.v = V_INFO; snprintf(a.reason, sizeof(a.reason), "EMPTY");
        a.fnv = fnv1a_buf(NULL, 0);
        if (!g_json) printf("[INFO] EMPTY: %s\n", path);
        else printf("{\"path\":\"%s\",\"size\":0,\"verdict\":\"INFO\",\"reason\":\"EMPTY\"}\n", path);
        return;
    }
    analyze_buffer(path, buf, n, &a);
    g_bytes += (unsigned long long)n;
    if (a.v == V_HIT) g_hits++;
    else if (a.v == V_SUSPICIOUS) g_susp++;
    else if (a.v == V_INFO) g_info++;
    print_result(path, n, &a);
    free(buf);
}

/* ---------------- traversal ---------------- */
#ifdef _WIN32
static void scan_dir_win(const char *dir, int depth) {
    char pattern[MAX_PATH], full[MAX_PATH];
    WIN32_FIND_DATAA fd;
    HANDLE h;
    if (depth > MAX_DEPTH) return;
    snprintf(pattern, sizeof(pattern), "%s\\*", dir);
    h = FindFirstFileA(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) { g_err++; return; }
    do {
        if (strcmp(fd.cFileName,".")==0 || strcmp(fd.cFileName,"..")==0) continue;
        snprintf(full, sizeof(full), "%s\\%s", dir, fd.cFileName);
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) scan_dir_win(full, depth+1);
        else scan_one(full);
    } while (FindNextFileA(h, &fd));
    FindClose(h);
}
#else
static void scan_dir_nix(const char *dir, int depth) {
    DIR *d;
    struct dirent *e;
    if (depth > MAX_DEPTH || is_skipped_path(dir)) return;
    d = opendir(dir);
    if (!d) { g_err++; return; }
    while ((e = readdir(d)) != NULL) {
        char full[4096];
        struct stat st;
        if (strcmp(e->d_name,".")==0 || strcmp(e->d_name,"..")==0) continue;
        snprintf(full, sizeof(full), "%s/%s", dir, e->d_name);
        if (is_skipped_path(full)) continue;
        if (lstat(full, &st) != 0) { g_err++; continue; }
        if (S_ISLNK(st.st_mode)) { g_info++; continue; } /* never follow symlinks */
        if (S_ISDIR(st.st_mode)) scan_dir_nix(full, depth+1);
        else if (S_ISREG(st.st_mode)) scan_one(full);
    }
    closedir(d);
}
#endif

/* ---------------- sandbox ---------------- */
#ifdef _WIN32
static int sandbox_run(const char *exe, char **args, int nargs) {
    char cmdline[8192];
    size_t off = 0;
    int i;
    HANDLE job;
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION lim;
    JOBOBJECT_BASIC_UI_RESTRICTIONS ui;
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    DWORD wait, code = 0;

    off += snprintf(cmdline+off, sizeof(cmdline)-off, "\"%s\"", exe);
    for (i = 0; i < nargs && off+2 < sizeof(cmdline); i++)
        off += snprintf(cmdline+off, sizeof(cmdline)-off, " %s", args[i]);

    job = CreateJobObjectA(NULL, NULL);
    if (!job) { printf("Job create failed: %lu\n", GetLastError()); return 3; }
    memset(&lim, 0, sizeof(lim));
    lim.BasicLimitInformation.LimitFlags =
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE |
        JOB_OBJECT_LIMIT_ACTIVE_PROCESS |
        JOB_OBJECT_LIMIT_PROCESS_MEMORY |
        JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
    lim.BasicLimitInformation.ActiveProcessLimit = 3;
    lim.ProcessMemoryLimit = 512ULL*1024ULL*1024ULL;
    if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &lim, sizeof(lim)))
        printf("[sandbox] warn: limits not fully applied (%lu)\n", GetLastError());
    memset(&ui, 0, sizeof(ui));
    ui.UIRestrictionsClass = JOB_OBJECT_UILIMIT_DESKTOP | JOB_OBJECT_UILIMIT_EXITWINDOWS |
                             JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS | JOB_OBJECT_UILIMIT_WRITECLIPBOARD;
    SetInformationJobObject(job, JobObjectBasicUIRestrictions, &ui, sizeof(ui));

    memset(&si, 0, sizeof(si)); si.cb = sizeof(si);
    memset(&pi, 0, sizeof(pi));
    printf("[sandbox] run: %s\n[sandbox] limits: 3 procs, 512MB, UI-restricted, 15s timeout\n", cmdline);
    if (!CreateProcessA(NULL, cmdline, NULL, NULL, FALSE,
                        CREATE_SUSPENDED | CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS,
                        NULL, NULL, &si, &pi)) {
        printf("CreateProcess failed: %lu\n", GetLastError());
        CloseHandle(job);
        return 3;
    }
    if (!AssignProcessToJobObject(job, pi.hProcess)) {
        printf("Assign to job failed: %lu -> killing\n", GetLastError());
        TerminateProcess(pi.hProcess, 3);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess); CloseHandle(job);
        return 3;
    }
    ResumeThread(pi.hThread);
    wait = WaitForSingleObject(pi.hProcess, 15000);
    if (wait == WAIT_TIMEOUT) {
        printf("[sandbox] TIMEOUT (15s) -> killing job tree\n");
        TerminateJobObject(job, 99);
        WaitForSingleObject(pi.hProcess, 5000);
        GetExitCodeProcess(pi.hProcess, &code);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess); CloseHandle(job);
        return 4;
    }
    GetExitCodeProcess(pi.hProcess, &code);
    printf("[sandbox] exit=%lu\n", code);
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess); CloseHandle(job);
    return (code == 0) ? 0 : 5;
}
#else
static int sandbox_run(const char *exe, char **args, int nargs) {
    pid_t pid;
    int status = 0, elapsed = 0, i;
    char **cargv;
    struct timespec ts;
    printf("[sandbox] run: %s\n[sandbox] limits: CPU 10s, AS 512MB, NPROC 32, 15s wall, killpg\n", exe);
    pid = fork();
    if (pid < 0) { perror("fork"); return 3; }
    if (pid == 0) {
        struct rlimit rl;
        setpgid(0, 0);
        rl.rlim_cur = rl.rlim_max = 10;  setrlimit(RLIMIT_CPU, &rl);
        rl.rlim_cur = rl.rlim_max = 512UL*1024UL*1024UL; setrlimit(RLIMIT_AS, &rl);
        rl.rlim_cur = rl.rlim_max = 0;   setrlimit(RLIMIT_CORE, &rl);
        rl.rlim_cur = rl.rlim_max = 16UL*1024UL*1024UL; setrlimit(RLIMIT_FSIZE, &rl);
        rl.rlim_cur = rl.rlim_max = 32;  setrlimit(RLIMIT_NPROC, &rl);
        cargv = (char**)malloc(sizeof(char*) * (size_t)(nargs + 3));
        if (!cargv) _exit(3);
        cargv[0] = (char*)exe;
        for (i = 0; i < nargs; i++) cargv[1+i] = args[i];
        cargv[1+nargs] = NULL;
        execv(exe, cargv);
        perror("execv");
        _exit(127);
    }
    setpgid(pid, pid);
    ts.tv_sec = 0; ts.tv_nsec = 100*1000*1000;
    while (elapsed < 15000) {
        pid_t r = waitpid(pid, &status, WNOHANG);
        if (r == pid) {
            if (WIFEXITED(status)) {
                printf("[sandbox] exit=%d\n", WEXITSTATUS(status));
                return (WEXITSTATUS(status) == 0) ? 0 : 5;
            }
            if (WIFSIGNALED(status)) {
                printf("[sandbox] killed by signal %d\n", WTERMSIG(status));
                return 5;
            }
            return 0;
        }
        nanosleep(&ts, NULL);
        elapsed += 100;
    }
    if (waitpid(pid, &status, WNOHANG) == 0) {
        printf("[sandbox] TIMEOUT (15s) -> killpg\n");
        kill(-pid, SIGKILL);
        waitpid(pid, &status, 0);
        return 4;
    }
    return 0;
}
#endif

/* ---------------- hash cmd ---------------- */
static int cmd_hash(const char *path) {
    unsigned char *buf = NULL;
    size_t n = 0;
    uint64_t fnv;
    sha256_ctx cx;
    unsigned char sha[32];
    char hex[65];
    int rc = read_file(path, &buf, &n);
    if (rc == 1) { fprintf(stderr, "too large (>64MB): %s\n", path); return 3; }
    if (rc != 0 || !buf) { fprintf(stderr, "unreadable: %s\n", path); return 3; }
    fnv = fnv1a_buf(buf, n);
    sha256_init(&cx); sha256_update(&cx, buf, n); sha256_final(&cx, sha);
    sha256_hex(sha, hex);
    printf("FNV1A %016llx SHA256 %s SIZE %lu FILE %s\n",
           (unsigned long long)fnv, hex, (unsigned long)n, path);
    free(buf);
    return 0;
}

/* ---------------- sigtest (in-memory, no EICAR file write) ---------------- */
static int cmd_sigtest(void) {
    int ok = 1;
    /* EICAR token match on memory buffer */
    if (!memfind((const unsigned char*)EICAR_STR, strlen(EICAR_STR),
                 (const unsigned char*)EICAR_TOKEN, strlen(EICAR_TOKEN))) ok = 0;
    {
        const char clean[] = "hello world, benign text";
        if (memfind((const unsigned char*)clean, strlen(clean),
                    (const unsigned char*)EICAR_TOKEN, strlen(EICAR_TOKEN))) ok = 0;
    }
    /* SHA-256("abc") known vector */
    {
        sha256_ctx cx; unsigned char out[32]; char hex[65];
        sha256_init(&cx);
        sha256_update(&cx, (const unsigned char*)"abc", 3);
        sha256_final(&cx, out); sha256_hex(out, hex);
        if (strcmp(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") != 0) ok = 0;
    }
    /* entropy sanity: zeros -> ~0, uniform 0..255 -> ~8 */
    {
        unsigned char z[600]; unsigned char u[512];
        size_t i;
        memset(z, 0, sizeof(z));
        for (i = 0; i < sizeof(u); i++) u[i] = (unsigned char)(i % 256);
        if (shannon_entropy(z, sizeof(z)) > 0.01) ok = 0;
        if (shannon_entropy(u, sizeof(u)) < 7.0) ok = 0;
    }
    printf("sigtest: %s (eicar-mem=1 clean=0 sha256-abc=ok entropy=ok)\n", ok ? "PASS" : "FAIL");
    return ok ? 0 : 1;
}

/* ---------------- usage ---------------- */
static void usage(const char *p) {
    printf("scanner %s (offline, educational)\n", SCANNER_VERSION);
    printf("Usage:\n");
    printf("  %s scan <folder> [--json]\n", p);
    printf("  %s sandbox <exe> [args...]\n", p);
    printf("  %s hash <file>\n", p);
    printf("  %s sigtest\n", p);
    printf("  %s --version | --help\n", p);
    printf("Exit: 0 clean | 1 detection | 2 usage | 3 runtime | 4 sandbox-timeout | 5 child-nonzero\n");
}

int main(int argc, char **argv) {
    clock_t t0;
    if (argc >= 2 && (strcmp(argv[1],"--version")==0 || strcmp(argv[1],"-V")==0 ||
                      strcmp(argv[1],"version")==0)) {
        printf("scanner %s\n", SCANNER_VERSION);
        return 0;
    }
    if (argc >= 2 && (strcmp(argv[1],"--help")==0 || strcmp(argv[1],"-h")==0 ||
                      strcmp(argv[1],"help")==0)) {
        usage(argv[0]);
        return 0;
    }
    if (argc < 3 && !(argc == 2 && strcmp(argv[1],"sigtest")==0)) {
        usage(argv[0]);
        return 2;
    }
    if (strcmp(argv[1],"sigtest")==0) return cmd_sigtest();
    if (strcmp(argv[1],"hash")==0) {
        if (argc < 3) { usage(argv[0]); return 2; }
        return cmd_hash(argv[2]);
    }
    if (strcmp(argv[1],"scan")==0) {
        int i;
        for (i = 3; i < argc; i++) if (strcmp(argv[i],"--json")==0) g_json = 1;
        t0 = clock();
        if (!g_json) log_lab_vm_context();
        else { /* keep json stdout pure: lab context to stderr */ }
#ifdef _WIN32
        scan_dir_win(argv[2], 0);
#else
        scan_dir_nix(argv[2], 0);
#endif
        {
            double secs = (double)(clock()-t0)/(double)CLOCKS_PER_SEC;
            if (g_json) {
                printf("{\"summary\":{\"files\":%ld,\"hit\":%ld,\"suspicious\":%ld,"
                       "\"info\":%ld,\"errors\":%ld,\"bytes\":%llu,\"secs\":%.2f},\"result\":\"%s\"}\n",
                       g_files, g_hits, g_susp, g_info, g_err, g_bytes, secs,
                       g_hits?"HIT":g_susp?"SUSPICIOUS":"CLEAN");
            } else {
                printf("\n---\nScanned: %ld files, Hit: %ld, Suspicious: %ld, Info: %ld, Errors: %ld, Bytes: %llu (%.2fs)\n",
                       g_files, g_hits, g_susp, g_info, g_err, g_bytes, secs);
                if (g_hits==0 && g_susp==0) printf("Clean (no HIT/SUSPICIOUS).\n");
            }
        }
        if (g_hits || g_susp) return 1;
        return 0;
    }
    if (strcmp(argv[1],"sandbox")==0) {
        if (argc < 3) { usage(argv[0]); return 2; }
        return sandbox_run(argv[2], argv+3, argc-3);
    }
    usage(argv[0]);
    return 2;
}
