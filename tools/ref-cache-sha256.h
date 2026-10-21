#pragma once
// Minimal dependency-free SHA-256 for native reference-cache keys/checksums.
// No files, paths, transcripts or reference samples leave the host.
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

struct RefSHA256 {
    uint32_t h[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                     0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    uint8_t block[64] = {};
    uint64_t total = 0;
    size_t used = 0;
    static uint32_t rot(uint32_t v, unsigned n) { return (v >> n) | (v << (32-n)); }
    void transform(const uint8_t *p) {
        static const uint32_t k[64] = {
          0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
          0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
          0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
          0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
          0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
          0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
          0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
          0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2 };
        uint32_t w[64];
        for (int i=0;i<16;i++)
            w[i] = (uint32_t(p[4*i])<<24) | (uint32_t(p[4*i+1])<<16) | (uint32_t(p[4*i+2])<<8) | p[4*i+3];
        for (int i=16;i<64;i++) {
            const uint32_t s0=rot(w[i-15],7)^rot(w[i-15],18)^(w[i-15]>>3);
            const uint32_t s1=rot(w[i-2],17)^rot(w[i-2],19)^(w[i-2]>>10);
            w[i]=w[i-16]+s0+w[i-7]+s1;
        }
        uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],v=h[7];
        for (int i=0;i<64;i++) {
            const uint32_t s1=rot(e,6)^rot(e,11)^rot(e,25);
            const uint32_t ch=(e&f)^(~e&g);
            const uint32_t t1=v+s1+ch+k[i]+w[i];
            const uint32_t s0=rot(a,2)^rot(a,13)^rot(a,22);
            const uint32_t maj=(a&b)^(a&c)^(b&c);
            const uint32_t t2=s0+maj;
            v=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
        }
        h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=v;
    }
    void update(const void *data,size_t n) {
        const auto *p=static_cast<const uint8_t*>(data);
        total+=n;
        while (n) {
            size_t take=(n<64-used?n:64-used);
            std::memcpy(block+used,p,take);
            used+=take;p+=take;n-=take;
            if (used==64) {transform(block);used=0;}
        }
    }
    void update(const std::string &s) {update(s.data(),s.size());}
    std::string finish() {
        uint64_t bits=total*8;
        uint8_t one=0x80;update(&one,1);
        uint8_t zero=0;
        while (used!=56) update(&zero,1);
        uint8_t sz[8];
        for (int i=0;i<8;i++) sz[i]=(uint8_t)(bits>>(56-8*i));
        update(sz,8);
        char res[65];
        for(int i=0;i<8;i++) std::snprintf(res+8*i,9,"%08x",h[i]);
        return std::string(res,64);
    }
};
static bool ref_hash_file(const char* path, RefSHA256 &sha) {
    FILE *f=std::fopen(path,"rb");
    if(!f) return false;
    std::array<char,262144> buf{};
    size_t n;
    while((n=std::fread(buf.data(),1,buf.size(),f))!=0) sha.update(buf.data(),n);
    bool ok=std::ferror(f)==0;
    std::fclose(f);return ok;
}
static std::string ref_file_sha256(const char *path) {
    RefSHA256 s;
    if(!ref_hash_file(path,s)) return "";
    return s.finish();
}
