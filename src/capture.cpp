#include "packet.hpp"
#include <thread>
#include <cstring>
#include <stdexcept>
#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
// The public libpcap ABI used by Npcap; no driver code or SDK is redistributed.
// Checked against Npcap SDK 1.16 Include/pcap/pcap.h (pcap_if, pcap_pkthdr, bpf_program, pcap_stat).
struct pcap; using pcap_t=pcap;
struct pcap_if { pcap_if* next; char* name; char* description; void* addresses; unsigned flags; }; using pcap_if_t=pcap_if;
struct pcap_pkthdr { timeval ts; unsigned caplen; unsigned len; };
struct bpf_program { unsigned bf_len; void* bf_insns; };
// On _WIN32 the SDK header adds ps_capt/ps_sent/ps_netdrop; declaring all six keeps the struct the size Npcap expects.
struct pcap_stat { unsigned ps_recv,ps_drop,ps_ifdrop,ps_capt,ps_sent,ps_netdrop; };
#else
#include <pcap/pcap.h>
#endif
namespace ws {
struct Capture::Impl {
    Store& store; mutable std::mutex mutex; std::thread worker; std::atomic<bool> running{false};
    std::string error,device,filter; uint64_t received=0,dropped=0; bool ready=false;
#ifdef _WIN32
    HMODULE library=nullptr;
#endif
    int (*finddevs)(pcap_if_t**,char*)=nullptr; void (*freedevs)(pcap_if_t*)=nullptr;
    pcap_t* (*openlive)(const char*,int,int,int,char*)=nullptr;
    int (*next)(pcap_t*,pcap_pkthdr**,const unsigned char**)=nullptr;
    int (*compile)(pcap_t*,bpf_program*,const char*,int,unsigned)=nullptr;
    int (*setfilter)(pcap_t*,bpf_program*)=nullptr;void (*freecode)(bpf_program*)=nullptr;
    void (*close)(pcap_t*)=nullptr;int (*datalink)(pcap_t*)=nullptr;
    char* (*geterr)(pcap_t*)=nullptr;int (*stats)(pcap_t*,pcap_stat*)=nullptr;
    int (*setnonblock)(pcap_t*,int,char*)=nullptr;
    explicit Impl(Store& s):store(s) {
#ifdef _WIN32
        wchar_t system[MAX_PATH]; if(!GetSystemDirectoryW(system,MAX_PATH)){error="Windows system directory unavailable";return;}
        std::wstring path=std::wstring(system)+L"\\Npcap\\wpcap.dll";
        library=LoadLibraryExW(path.c_str(),nullptr,LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|LOAD_LIBRARY_SEARCH_SYSTEM32);
        if(!library){error="Npcap is not installed. Install Npcap with loopback support, then restart WireScope.";return;}
// FARPROC -> void(*)() -> real signature: the generic function-pointer hop avoids -Wcast-function-type noise.
#define LOAD(member,name) member=reinterpret_cast<decltype(member)>(reinterpret_cast<void(*)()>(GetProcAddress(library,name))); if(!member){error="Npcap API unavailable: " name;return;}
#else
#define LOAD(member,name) member=&name
#endif
#ifdef _WIN32
        LOAD(finddevs,"pcap_findalldevs");LOAD(freedevs,"pcap_freealldevs");LOAD(openlive,"pcap_open_live");LOAD(next,"pcap_next_ex");LOAD(compile,"pcap_compile");LOAD(setfilter,"pcap_setfilter");LOAD(freecode,"pcap_freecode");LOAD(close,"pcap_close");LOAD(datalink,"pcap_datalink");LOAD(geterr,"pcap_geterr");LOAD(stats,"pcap_stats");LOAD(setnonblock,"pcap_setnonblock");
#else
        LOAD(finddevs,pcap_findalldevs);LOAD(freedevs,pcap_freealldevs);LOAD(openlive,pcap_open_live);LOAD(next,pcap_next_ex);LOAD(compile,pcap_compile);LOAD(setfilter,pcap_setfilter);LOAD(freecode,pcap_freecode);LOAD(close,pcap_close);LOAD(datalink,pcap_datalink);LOAD(geterr,pcap_geterr);LOAD(stats,pcap_stats);LOAD(setnonblock,pcap_setnonblock);
#endif
#undef LOAD
        ready=true;
    }
    ~Impl(){running=false;if(worker.joinable())worker.join();
#ifdef _WIN32
        if(library)FreeLibrary(library);
#endif
    }
};
Capture::Capture(Store& s):impl_(std::make_unique<Impl>(s)){}
Capture::~Capture()=default;
json Capture::interfaces(){auto& i=*impl_;if(!i.ready)return {{"available",false},{"error",i.error},{"interfaces",json::array()}};pcap_if_t* devs=nullptr;char err[256]{};if(i.finddevs(&devs,err)!=0)return {{"available",false},{"error",err},{"interfaces",json::array()}};json result=json::array();for(auto* p=devs;p;p=p->next)result.push_back({{"id",p->name?p->name:""},{"name",p->description?p->description:p->name},{"loopback",bool(p->flags&1)}});i.freedevs(devs);return {{"available",true},{"interfaces",result}};}
void Capture::start(const std::string& device,const std::string& filter){stop();auto& i=*impl_;if(!i.ready)throw std::runtime_error(i.error);if(device.empty()||device.size()>1024||filter.size()>2048)throw std::runtime_error("Select a capture interface");auto available=interfaces();bool found=false;for(auto& d:available["interfaces"])if(d["id"]==device)found=true;if(!found)throw std::runtime_error("Capture interface not found");char err[256]{};pcap_t* handle=i.openlive(device.c_str(),65535,0,100,err);if(!handle)throw std::runtime_error(err);if(!filter.empty()){bpf_program program{};if(i.compile(handle,&program,filter.c_str(),1,0xffffffff)!=0){std::string e=i.geterr(handle);i.close(handle);throw std::runtime_error(e);}int ok=i.setfilter(handle,&program);i.freecode(&program);if(ok!=0){std::string e=i.geterr(handle);i.close(handle);throw std::runtime_error(e);}}if(i.setnonblock(handle,1,err)!=0){i.close(handle);throw std::runtime_error(err);}int link=i.datalink(handle);{std::lock_guard lock(i.mutex);i.error.clear();i.device=device;i.filter=filter;i.received=i.dropped=0;}i.running=true;
    i.worker=std::thread([&i,handle,link,device]{auto last=nowMs();try{while(i.running){pcap_pkthdr* h=nullptr;const unsigned char* bytes=nullptr;int n=i.next(handle,&h,&bytes);if(n==1&&h){i.store.addPacket(decodePacket(std::string(reinterpret_cast<const char*>(bytes),h->caplen),link,int64_t(h->ts.tv_sec)*1000+h->ts.tv_usec/1000,h->len,device));{std::lock_guard lock(i.mutex);++i.received;}}else if(n==0)std::this_thread::sleep_for(std::chrono::milliseconds(4));else if(n<0){if(n==-1){std::lock_guard lock(i.mutex);i.error=i.geterr(handle);}break;}if(nowMs()-last>1000){pcap_stat st{};if(i.stats(handle,&st)==0){std::lock_guard lock(i.mutex);i.dropped=st.ps_drop;}last=nowMs();}}}catch(const std::exception& e){std::lock_guard lock(i.mutex);i.error=e.what();}i.close(handle);i.running=false;});
}
void Capture::stop(){auto& i=*impl_;i.running=false;if(i.worker.joinable())i.worker.join();}
json Capture::status()const{auto& i=*impl_;std::lock_guard lock(i.mutex);return {{"available",i.ready},{"running",i.running.load()},{"device",i.device},{"filter",i.filter},{"received",i.received},{"dropped",i.dropped},{"error",i.error}};}
}
