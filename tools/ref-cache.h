#pragma once
// Persistent, content-addressed RVQ cache for omnivoice-tts.
// Cache lives outside public Gradio paths; files retain owner-only permissions.
#include "ref-cache-sha256.h"
#include "rvq-file.h"
#include "omnivoice.h"
#include "audio-postproc.h"
#include <chrono>
#include <cmath>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <limits>
#include <sstream>
#include <string>
#include <vector>
#if !defined(_WIN32)
#include <sys/stat.h>
#endif
namespace refcache {
namespace fs=std::filesystem;
static constexpr const char *version="omnivoice-ref-rvq-v1-preproc1";
static std::string key_for(const char *wav, const char *codec) {
    // Hash full WAV contents, plus codec content fingerprint and size/timestamp.
    // Sampling first+last 64KB of GGUF avoids hashing 250-700MB every request.
    RefSHA256 h;
    h.update(version);
    if (!ref_hash_file(wav,h)) return "";
    std::error_code ec;
    const auto size=fs::file_size(codec,ec);
    if(ec) return "";
    h.update(std::to_string(size));
    auto mtime=fs::last_write_time(codec,ec);
    if(ec) return "";
    h.update(std::to_string(mtime.time_since_epoch().count()));
    FILE *f=std::fopen(codec,"rb");
    if(!f) return "";
    uint8_t sample[65536];
    size_t n=std::fread(sample,1,sizeof(sample),f);
    h.update(sample,n);
    if(size>sizeof(sample)) {
        if(std::fseek(f, static_cast<long>(size-sizeof(sample)), SEEK_SET)!=0) {
            std::fclose(f);return "";
        }
        n=std::fread(sample,1,sizeof(sample),f);
        h.update(sample,n);
    }
    if(std::ferror(f)) {std::fclose(f);return "";}
    std::fclose(f);
    return h.finish();
}
static float raw_rms(const std::vector<float> &pcm) {
    if(pcm.empty()) return -1.0f;
    double sum=0.0;
    for(float x:pcm) sum+=double(x)*x;
    return static_cast<float>(std::sqrt(sum/double(pcm.size())));
}
static bool cache_read(const fs::path &base, const std::string &key, int K,
                       std::vector<int32_t> &codes, int &T,float &rms) {
    const auto rvq=base/(key+".rvq");
    const auto meta=base/(key+".meta");
    std::ifstream fin(meta);
    std::string ver, expected, checksum;
    float parsed_rms=-1.0f;
    int T_saved=0,K_saved=0;
    if(!std::getline(fin,ver) || ver!=version || !std::getline(fin,expected) || expected!=key ||
       !(fin>>K_saved>>T_saved>>parsed_rms>>checksum) || K_saved!=K || T_saved<1 ||
       !std::isfinite(parsed_rms) || parsed_rms<0.f) return false;
    if(ref_file_sha256(rvq.string().c_str())!=checksum) return false;
    std::vector<int32_t> temp;int decoded_T=0;
    if(!rvq_read_file(rvq.string().c_str(),K,11,temp,&decoded_T)||decoded_T!=T_saved)return false;
    codes=std::move(temp);T=decoded_T;rms=parsed_rms;
    return true;
}
static void cache_write(const fs::path &base,const std::string &key,
                        const std::vector<int32_t> &codes,int K,int T,float rms) {
    std::error_code ec;
    fs::create_directories(base,ec);
    if(ec)return;
#if !defined(_WIN32)
    chmod(base.string().c_str(),0700);
#endif
    // Atomic publish: metadata is renamed last. Incomplete entries fail
    // validation and are automatically regenerated.
    const std::string nonce=std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    const fs::path rvq=base/(key+".rvq"),meta=base/(key+".meta");
    const fs::path tmp_rvq=base/(key+"."+nonce+".tmp.rvq");
    const fs::path tmp_meta=base/(key+"."+nonce+".tmp.meta");
    if(!rvq_write_file(tmp_rvq.string().c_str(),codes,11))return;
#if !defined(_WIN32)
    chmod(tmp_rvq.string().c_str(),0600);
#endif
    const auto sha=ref_file_sha256(tmp_rvq.string().c_str());
    if(sha.empty()){fs::remove(tmp_rvq,ec);return;}
    {
        std::ofstream out(tmp_meta);
        if(!out){fs::remove(tmp_rvq,ec);return;}
        out<<version<<'\n'<<key<<'\n'<<K<<' '<<T<<' '
           <<std::setprecision(std::numeric_limits<float>::max_digits10)<<rms<<' '<<sha<<'\n';
    }
#if !defined(_WIN32)
    chmod(tmp_meta.string().c_str(),0600);
#endif
    fs::rename(tmp_rvq,rvq,ec);
    if(ec){fs::remove(tmp_rvq,ec);fs::remove(tmp_meta,ec);return;}
    fs::rename(tmp_meta,meta,ec);
    if(ec)fs::remove(tmp_meta,ec);
}
// Fast path: inspect and validate cache BEFORE decoding/resampling the WAV.
static bool lookup(const char *wav, const char *codec, const char *dir,
                   ov_context *ov,std::vector<int32_t>&codes,int &T,float &rms) {
    if(!wav || !codec || !dir || !ov)return false;
    const std::string key=key_for(wav,codec);
    if(key.empty())return false;
    if(!cache_read(fs::path(dir),key,ov_num_codebooks(ov),codes,T,rms)) return false;
    fprintf(stderr,"[RefCache] HIT key=%s K=%d T=%d (WAV decode + codec encode skipped)\n",
            key.c_str(),ov_num_codebooks(ov),T);
    return true;
}
static bool prepare(const char *wav,const char *codec,const char *dir,ov_context *ov,
                    std::vector<float>& pcm,std::vector<int32_t>& codes,int &T,float &rms) {
    if(!dir || !wav || !codec || !ov) return false;
    const auto key=key_for(wav,codec);
    if(key.empty())return false;
    const fs::path cache_dir(dir);
    const int K=ov_num_codebooks(ov);
    if(cache_read(cache_dir,key,K,codes,T,rms)) {
        pcm.clear();
        fprintf(stderr,"[RefCache] HIT key=%s K=%d T=%d (codec encode skipped)\n",key.c_str(),K,T);
        return true;
    }
    fprintf(stderr,"[RefCache] MISS key=%s (encoding once)\n",key.c_str());
    // Extract reference using the exact same native preprocessing / codec
    // path as the raw-WAV synthesis; no additional C++ process or model load.
    ov_voice_ref extracted={};
    if(ov_extract_voice_ref(ov,pcm.data(),(int)pcm.size(),&extracted)!=OV_STATUS_OK) {
        fprintf(stderr,"[RefCache] failed to encode reference: %s\n",ov_last_error());
        return false;
    }
    codes.assign(extracted.ref_codes,extracted.ref_codes+(size_t)extracted.num_codebooks*(size_t)extracted.ref_T);
    T=extracted.ref_T;
    rms=raw_rms(pcm);
    ov_voice_ref_free(&extracted);
    cache_write(cache_dir,key,codes,K,T,rms);
    pcm.clear();
    fprintf(stderr,"[RefCache] STORED key=%s K=%d T=%d rms=%.7f\n",key.c_str(),K,T,rms);
    return true;
}
}  // namespace refcache
