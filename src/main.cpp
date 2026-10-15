#include "net.hpp"
#include "packet.hpp"
#include "sysproxy.hpp"
#include "httplib.h"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <csignal>
#include <thread>
#ifdef _WIN32
#include <windows.h>
#include <shellapi.h>
#endif
using namespace ws;
namespace {
std::atomic<bool> quit{false},cleaned{false};
void onSignal(int){quit=true;}
#ifdef _WIN32
// Closing the console window, logoff and shutdown end the process soon after this handler returns.
// Hold it (up to ~5 s, the system limit) until main() has stopped the proxy and capture.
BOOL WINAPI onConsole(DWORD type){quit=true;if(type==CTRL_CLOSE_EVENT||type==CTRL_LOGOFF_EVENT||type==CTRL_SHUTDOWN_EVENT)for(int i=0;i<45&&!cleaned;++i)Sleep(100);return TRUE;}
#endif
std::string utf8(const std::filesystem::path& p){auto u=p.u8string();return std::string(u.begin(),u.end());}
std::string readFile(const std::filesystem::path& p){std::ifstream f(p,std::ios::binary);if(!f)throw std::runtime_error("Missing asset: "+utf8(p));return {(std::istreambuf_iterator<char>(f)),{}};}
void output(httplib::Response& r,const json& j){r.set_content(safeJson(j),"application/json; charset=utf-8");}
uint64_t idOf(const httplib::Request& r){return std::stoull(r.matches[1].str());}
}
int main(int argc,char** argv){try{
#ifdef _WIN32
    WSADATA winsock{};if(WSAStartup(MAKEWORD(2,2),&winsock))throw std::runtime_error("Winsock initialization failed");
    SetConsoleOutputCP(CP_UTF8);SetConsoleCtrlHandler(onConsole,TRUE);
#else
    std::signal(SIGPIPE,SIG_IGN);
#endif
    std::signal(SIGINT,onSignal);std::signal(SIGTERM,onSignal);
    int port=17890;bool open=true,demo=false;std::string data="data",web;
#ifdef _WIN32
    wchar_t local[32768];DWORD count=GetEnvironmentVariableW(L"LOCALAPPDATA",local,32768);if(count&&count<32768){auto u=(std::filesystem::path(local)/L"WireScope").u8string();data=std::string(u.begin(),u.end());}
    wchar_t module[32768];count=GetModuleFileNameW(nullptr,module,32768);if(count&&count<32768){auto u=(std::filesystem::path(module).parent_path()/L"web").u8string();web=std::string(u.begin(),u.end());}
#else
    web=(std::filesystem::absolute(argv[0]).parent_path()/"web").string();
#endif
    std::vector<std::string> args(argv,argv+argc);
#ifdef _WIN32
    // argv is in the ANSI code page (CP949 on Korean Windows), so --data C:\Users\<Korean name>\... arrives mangled. Re-read the UTF-16 command line.
    {int n=0;LPWSTR* wide=CommandLineToArgvW(GetCommandLineW(),&n);if(wide){args.clear();for(int i=0;i<n;++i)args.push_back(utf8(std::filesystem::path(wide[i])));LocalFree(wide);}}
#endif
    const int argCount=int(args.size());
    for(int i=1;i<argCount;++i){const std::string& arg=args[i];if(arg=="--port"&&i+1<argCount)port=std::stoi(args[++i]);else if(arg=="--data"&&i+1<argCount)data=args[++i];else if(arg=="--web"&&i+1<argCount)web=args[++i];else if(arg=="--no-open")open=false;else if(arg=="--sample")demo=true;else if(arg=="--help"){std::cout<<"WireScope [--port 17890] [--data DIR] [--web DIR] [--no-open] [--sample]\n";return 0;}else throw std::runtime_error("Unknown argument: "+arg);}
    if(port<1024||port>65535)throw std::runtime_error("UI port must be 1024–65535");
    auto webPath=utf8Path(web);const auto index=readFile(webPath/"index.html"),css=readFile(webPath/"app.css"),script=readFile(webPath/"app.js");
    Store store;Tls tls(data);Proxy proxy(store,tls);Capture capture(store);SystemProxy sysproxy(data);std::mutex controls;
    if(demo)sample(store);const std::string token=randomHex(24),origin="http://127.0.0.1:"+std::to_string(port);
    httplib::Server server;server.new_task_queue=[](){return new httplib::ThreadPool(6);};server.set_payload_max_length(192*1024*1024);server.set_read_timeout(15);server.set_write_timeout(30);
    server.set_pre_routing_handler([&](const httplib::Request& r,httplib::Response& res){
        auto host=r.get_header_value("Host");if(host!="127.0.0.1:"+std::to_string(port)&&host!="localhost:"+std::to_string(port)){res.status=403;output(res,{{"error","Invalid Host"}});return httplib::Server::HandlerResponse::Handled;}
        if(startsWith(r.path,"/api/")&&r.path!="/api/bootstrap"&&r.get_header_value("X-WireScope-Token")!=token){res.status=403;output(res,{{"error","Session token required"}});return httplib::Server::HandlerResponse::Handled;}
        auto from=r.get_header_value("Origin");if(!from.empty()&&from!=origin&&from!="http://localhost:"+std::to_string(port)){res.status=403;output(res,{{"error","Cross-origin request blocked"}});return httplib::Server::HandlerResponse::Handled;}
        return httplib::Server::HandlerResponse::Unhandled;
    });
    server.set_post_routing_handler([](const httplib::Request&,httplib::Response& r){r.set_header("Cache-Control","no-store");r.set_header("X-Content-Type-Options","nosniff");r.set_header("X-Frame-Options","DENY");r.set_header("Content-Security-Policy","default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'");});
    server.set_exception_handler([](const httplib::Request&,httplib::Response& r,std::exception_ptr p){r.status=400;try{std::rethrow_exception(p);}catch(const std::exception& e){output(r,{{"error",e.what()}});}catch(...){output(r,{{"error","Request failed"}});}});
    server.Get("/",[&](const auto&,auto& r){r.set_content(index,"text/html; charset=utf-8");});server.Get("/app.css",[&](const auto&,auto& r){r.set_content(css,"text/css");});server.Get("/app.js",[&](const auto&,auto& r){r.set_content(script,"text/javascript");});
    server.Get("/api/bootstrap",[&](const auto&,auto& r){output(r,{{"token",token},{"version","0.1.0"},{"uiPort",port}});});
    server.Get("/api/state",[&](const auto& req,auto& r){json state;if(req.has_param("revision")&&req.get_param_value("revision")==std::to_string(store.revision()))state={{"unchanged",true},{"revision",store.revision()}};else state=store.snapshot();state["capture"]=capture.status();state["proxy"]=proxy.status();state["systemProxy"]=sysproxy.status();output(r,state);});
    server.Get("/api/interfaces",[&](const auto&,auto& r){output(r,capture.interfaces());});
    server.Get(R"(/api/flows/(\d+))",[&](const auto& req,auto& r){auto f=store.flow(idOf(req));if(f.is_null())r.status=404;output(r,f);});
    server.Get(R"(/api/packets/(\d+))",[&](const auto& req,auto& r){auto p=store.packet(idOf(req));if(p.is_null())r.status=404;output(r,p);});
    server.Get("/api/stream",[&](const auto& req,auto& r){output(r,streamPreview(store.packets(),req.get_param_value("key")));});
    server.Post("/api/capture/start",[&](const auto& req,auto& r){std::lock_guard lock(controls);auto j=json::parse(req.body);capture.start(j.at("device"),j.value("filter","not tcp port "+std::to_string(port)));output(r,capture.status());});
    server.Post("/api/capture/stop",[&](const auto&,auto& r){std::lock_guard lock(controls);capture.stop();output(r,capture.status());});
    server.Post("/api/proxy/start",[&](const auto& req,auto& r){std::lock_guard lock(controls);auto j=json::parse(req.body);int pp=j.value("port",18080);if(pp<1024||pp>65535||pp==port)throw std::runtime_error("Choose a proxy port from 1024–65535, different from the UI port");proxy.start(uint16_t(pp),j.value("mitm",true));output(r,proxy.status());});
    // Apps must stop sending to 127.0.0.1:port before the proxy goes away, so the system proxy is restored first.
    server.Post("/api/proxy/stop",[&](const auto&,auto& r){std::lock_guard lock(controls);if(sysproxy.owned())sysproxy.restore();proxy.stop();output(r,proxy.status());});
    server.Get("/api/sysproxy",[&](const auto&,auto& r){output(r,sysproxy.status());});
    server.Post("/api/sysproxy",[&](const auto& req,auto& r){std::lock_guard lock(controls);if(json::parse(req.body).value("enable",false)){auto st=proxy.status();if(!st["running"].get<bool>())throw std::runtime_error("Start the proxy before pointing the system proxy at it");sysproxy.enable(st["port"].get<uint16_t>());}else sysproxy.restore();output(r,sysproxy.status());});
    auto requireStopped=[&](){if(capture.status()["running"].get<bool>()||proxy.status()["running"].get<bool>())throw std::runtime_error("Stop capture and proxy before replacing the session");};
    server.Post("/api/session",[&](const auto& req,auto& r){store.setSession(json::parse(req.body));output(r,{{"ok",true}});});
    server.Post("/api/session/new",[&](const auto& req,auto& r){std::lock_guard lock(controls);requireStopped();auto j=json::parse(req.body);store.clear(j.value("name","Untitled capture"));output(r,{{"ok",true}});});
    server.Post("/api/sample",[&](const auto&,auto& r){std::lock_guard lock(controls);requireStopped();sample(store);output(r,{{"ok",true}});});
    server.Post(R"(/api/flows/(\d+)/notes)",[&](const auto& req,auto& r){store.note(idOf(req),json::parse(req.body).value("notes",""));output(r,{{"ok",true}});});
    server.Get("/api/session/download",[&](const auto&,auto& r){r.set_header("Content-Disposition","attachment; filename=capture.wscope");r.set_content(safeJson(store.archive()),"application/json");});
    server.Post("/api/session/import",[&](const auto& req,auto& r){std::lock_guard lock(controls);requireStopped();auto j=json::parse(req.body);store.restore(j);output(r,{{"ok",true}});});
    server.Post("/api/pcap/import",[&](const auto& req,auto& r){std::lock_guard lock(controls);requireStopped();auto packets=readCapture(req.body);store.clear("Imported packet capture");for(auto& p:packets)store.addPacket(std::move(p));output(r,{{"packets",packets.size()}});});
    server.Get("/api/pcap/download",[&](const auto&,auto& r){r.set_content(writePcapng(store.packets()),"application/octet-stream");r.set_header("Content-Disposition","attachment; filename=capture.pcapng");});
    server.Post("/api/report",[&](const httplib::Request& req,httplib::Response& r){auto settings=json::parse(req.body);auto archive=store.archive();if(settings.contains("ids")&&!settings["ids"].empty()){std::set<uint64_t> ids=settings["ids"].get<std::set<uint64_t>>();auto& flows=archive["flows"];flows.erase(std::remove_if(flows.begin(),flows.end(),[&](const json& f){return !ids.count(f.at("id").get<uint64_t>());}),flows.end());archive["packets"]=json::array();}auto html=htmlReport(archive,css,script,settings.value("redact",true));r.set_content(html,"text/html; charset=utf-8");r.set_header("Content-Disposition","attachment; filename=wirescope-report.html");});
    server.Get("/api/ca",[&](const auto&,auto& r){std::lock_guard lock(controls);output(r,tls.info());});
    server.Post("/api/ca/create",[&](const auto&,auto& r){std::lock_guard lock(controls);tls.initialize();output(r,tls.info());});
    server.Post("/api/ca/trust",[&](const auto& req,auto& r){std::lock_guard lock(controls);tls.trust(json::parse(req.body).value("install",true));output(r,{{"ok",true}});});
    if(!server.bind_to_port("127.0.0.1",port))throw std::runtime_error("UI port is already in use");
    std::cout<<"WireScope 0.1.0\n"<<origin<<"\nCapture and proxy are stopped. Ctrl+C to exit.\n"<<std::flush;
#ifdef _WIN32
    if(open){std::wstring url(origin.begin(),origin.end());ShellExecuteW(nullptr,L"open",url.c_str(),nullptr,nullptr,SW_SHOWNORMAL);}
#else
    (void)open;
#endif
    std::thread stopper([&]{while(!quit)std::this_thread::sleep_for(std::chrono::milliseconds(100));server.stop();});server.listen_after_bind();quit=true;stopper.join();if(sysproxy.owned())try{sysproxy.restore();}catch(const std::exception& e){std::cerr<<"WireScope: system proxy not restored: "<<e.what()<<"\n";}capture.stop();proxy.stop();cleaned=true;return 0;
}catch(const std::exception& e){std::cerr<<"WireScope: "<<e.what()<<"\n";return 1;}}
