#include "packet.hpp"
#include <algorithm>
#include <cstring>
#include <set>
#include <sstream>
#include <stdexcept>
#include <limits>

namespace ws {
namespace {
uint16_t be16(const std::string& s,size_t p) {return (uint16_t(uint8_t(s[p]))<<8)|uint8_t(s[p+1]);}
uint32_t be32(const std::string& s,size_t p) {return (uint32_t(be16(s,p))<<16)|be16(s,p+2);}
std::string ipv4(const std::string& s,size_t p){return std::to_string(uint8_t(s[p]))+"."+std::to_string(uint8_t(s[p+1]))+"."+std::to_string(uint8_t(s[p+2]))+"."+std::to_string(uint8_t(s[p+3]));}
std::string ipv6(const std::string& s,size_t p){std::ostringstream o; for(int i=0;i<8;++i){if(i)o<<":"; o<<std::hex<<be16(s,p+i*2);}return o.str();}
std::string dnsName(const std::string& s,size_t start,size_t end,size_t& pos){std::string out; size_t p=pos; bool jumped=false; std::set<size_t> seen; for(int loops=0;loops<128;++loops){if(p>=end||!seen.insert(p).second)throw std::runtime_error("DNS name bounds/loop"); unsigned n=uint8_t(s[p++]); if(!n){if(!jumped)pos=p;return out;} if((n&0xc0)==0xc0){if(p>=end)break; size_t off=((n&0x3f)<<8)|uint8_t(s[p++]);if(!jumped)pos=p;jumped=true;p=start+off;continue;}if(n>63||p+n>end||out.size()+n>253)break;if(!out.empty())out+='.';out.append(s,p,n);p+=n;if(!jumped)pos=p;}throw std::runtime_error("Malformed DNS name");}
void le32(std::string& s,uint32_t v){for(int i=0;i<4;++i)s.push_back(char(v>>(i*8)));}
void le16(std::string& s,uint16_t v){s.push_back(char(v));s.push_back(char(v>>8));}
uint32_t u32(const std::string& s,size_t p,bool little){if(p+4>s.size())throw std::runtime_error("Capture truncated");if(!little)return be32(s,p);return uint8_t(s[p])|(uint32_t(uint8_t(s[p+1]))<<8)|(uint32_t(uint8_t(s[p+2]))<<16)|(uint32_t(uint8_t(s[p+3]))<<24);}
uint16_t u16(const std::string& s,size_t p,bool little){if(p+2>s.size())throw std::runtime_error("Capture truncated");return little?uint16_t(uint8_t(s[p])|(uint16_t(uint8_t(s[p+1]))<<8)):be16(s,p);}
void block(std::string& out,uint32_t type,std::string data){while(data.size()%4)data+='\0';le32(out,type);le32(out,uint32_t(data.size()+12));out+=data;le32(out,uint32_t(data.size()+12));}
}
Packet decodePacket(const std::string& raw,int linkType,int64_t time,uint32_t originalLength,const std::string& device){
    Packet p; p.raw=raw;p.linkType=linkType;p.time=time;p.originalLength=originalLength;p.device=device;
    p.info={{"protocol","Other"},{"source",""},{"destination",""},{"summary",""},{"key",""},{"fields",json::array()}};
    auto& j=p.info;size_t off=0,end=raw.size();uint16_t ether=0;
    auto field=[&](std::string name,std::string value,size_t a,size_t n){j["fields"].push_back({{"name",name},{"value",value},{"offset",a},{"length",n}});};
    try{
        if(linkType==1){if(end<14)throw std::runtime_error("Ethernet header truncated");ether=be16(raw,12);off=14;field("Ethernet type",std::to_string(ether),12,2);for(int i=0;i<2&&(ether==0x8100||ether==0x88a8);++i){if(off+4>end)throw std::runtime_error("VLAN header truncated");ether=be16(raw,off+2);off+=4;}}
        else if(linkType==0||linkType==108){if(end<5)throw std::runtime_error("Loopback header truncated");off=4;ether=(uint8_t(raw[off])>>4)==6?0x86dd:0x800;}
        else if(linkType==12||linkType==101||linkType==228||linkType==229){if(!end)throw std::runtime_error("Empty packet");ether=(uint8_t(raw[0])>>4)==6?0x86dd:0x800;}
        else if(linkType==113){if(end<16)throw std::runtime_error("SLL header truncated");ether=be16(raw,14);off=16;}
        else if(linkType==276){if(end<20)throw std::runtime_error("SLL2 header truncated");ether=be16(raw,0);off=20;}
        else{j["summary"]="Link type "+std::to_string(linkType);return p;}
        if(ether==0x806){j["protocol"]="ARP";j["summary"]="Address resolution";return p;}
        uint8_t proto=0;std::string src,dst;bool fragment=false;
        if(ether==0x800){if(off+20>end)throw std::runtime_error("IPv4 header truncated");size_t ihl=(uint8_t(raw[off])&15)*4;uint16_t len=be16(raw,off+2);if(ihl<20||len<ihl||off+ihl>end)throw std::runtime_error("Invalid IPv4 length");end=std::min(end,off+len);proto=uint8_t(raw[off+9]);src=ipv4(raw,off+12);dst=ipv4(raw,off+16);field("IPv4 source",src,off+12,4);field("IPv4 destination",dst,off+16,4);field("IPv4 TTL",std::to_string(uint8_t(raw[off+8])),off+8,1);auto frag=be16(raw,off+6);fragment=(frag&0x3fff)!=0;off+=ihl;}
        else if(ether==0x86dd){if(off+40>end)throw std::runtime_error("IPv6 header truncated");proto=uint8_t(raw[off+6]);src=ipv6(raw,off+8);dst=ipv6(raw,off+24);field("IPv6 source",src,off+8,16);field("IPv6 destination",dst,off+24,16);end=std::min(end,off+40+be16(raw,off+4));off+=40;for(int n=0;n<8&&(proto==0||proto==43||proto==60||proto==44||proto==51);++n){if(off+2>end)throw std::runtime_error("IPv6 extension truncated");uint8_t next=uint8_t(raw[off]);size_t size=proto==44?8:proto==51?(size_t(uint8_t(raw[off+1]))+2)*4:(size_t(uint8_t(raw[off+1]))+1)*8;if(off+size>end)throw std::runtime_error("IPv6 extension length");if(proto==44)fragment=true;off+=size;proto=next;}}
        else{j["summary"]="EtherType "+std::to_string(ether);return p;}
        j["source"]=src;j["destination"]=dst;j["protocol"]=proto==6?"TCP":proto==17?"UDP":proto==1?"ICMP":proto==58?"ICMPv6":"IP";j["key"]=connectionKey(src,dst);
        if(fragment){j["summary"]="IP fragment";j["fragment"]=true;return p;}
        size_t payload=off;
        if(proto==6||proto==17){size_t min=proto==6?20:8;if(off+min>end)throw std::runtime_error("Transport header truncated");uint16_t sp=be16(raw,off),dp=be16(raw,off+2);j["srcPort"]=sp;j["dstPort"]=dp;j["source"]=endpoint(src,sp);j["destination"]=endpoint(dst,dp);j["key"]=connectionKey(j["source"],j["destination"]);field("Source port",std::to_string(sp),off,2);field("Destination port",std::to_string(dp),off+2,2);
            if(proto==6){size_t h=(uint8_t(raw[off+12])>>4)*4;if(h<20||off+h>end)throw std::runtime_error("TCP header length");unsigned flags=uint8_t(raw[off+13]);std::string f;for(auto [mask,name]:std::vector<std::pair<int,std::string>>{{2,"SYN"},{16,"ACK"},{1,"FIN"},{4,"RST"},{8,"PSH"},{32,"URG"}})if(flags&mask){if(!f.empty())f+=' ';f+=name;}j["flags"]=f;j["seq"]=be32(raw,off+4);j["ack"]=be32(raw,off+8);field("TCP sequence",std::to_string(be32(raw,off+4)),off+4,4);field("TCP acknowledgment",std::to_string(be32(raw,off+8)),off+8,4);field("TCP flags",f,off+13,1);j["summary"]=f;payload=off+h;}
            else{uint16_t len=be16(raw,off+4);if(len<8)throw std::runtime_error("UDP length");end=std::min(end,off+len);payload=off+8;j["summary"]="Datagram";}
            j["payloadOffset"]=payload;j["payloadLength"]=end-payload;
            if(proto==17&&(sp==53||dp==53)&&payload+12<=end){j["protocol"]="DNS";uint16_t flags=be16(raw,payload+2);field("DNS transaction",std::to_string(be16(raw,payload)),payload,2);field("DNS flags",std::to_string(flags),payload+2,2);std::string name;size_t q=payload+12;if(be16(raw,payload+4)){name=dnsName(raw,payload,end,q);if(q+4>end)throw std::runtime_error("DNS question truncated");j["dnsName"]=name;field("DNS question",name,payload+12,q-payload-12);field("DNS query type",std::to_string(be16(raw,q)),q,2);}j["summary"]=(flags&0x8000?"Response ":"Query ")+name;}
            if(proto==6&&payload+5<=end&&uint8_t(raw[payload])>=20&&uint8_t(raw[payload])<=23&&uint8_t(raw[payload+1])==3){j["protocol"]="TLS";j["summary"]=uint8_t(raw[payload])==22?"Handshake record":"Encrypted record";field("TLS content type",std::to_string(uint8_t(raw[payload])),payload,1);field("TLS record length",std::to_string(be16(raw,payload+3)),payload+3,2);}
            else if(proto==6&&end>payload){auto prefix=raw.substr(payload,std::min(size_t(12),end-payload));if(prefix.starts_with("HTTP/")||prefix.starts_with("GET ")||prefix.starts_with("POST ")||prefix.starts_with("PUT ")||prefix.starts_with("CONNECT ")){j["protocol"]="HTTP";auto e=raw.find("\r\n",payload);j["summary"]=raw.substr(payload,std::min(size_t(120),(e==std::string::npos?end:e)-payload));}}
        }else if((proto==1||proto==58)&&off+2<=end){field("ICMP type",std::to_string(uint8_t(raw[off])),off,1);field("ICMP code",std::to_string(uint8_t(raw[off+1])),off+1,1);j["summary"]="Type "+std::to_string(uint8_t(raw[off]));}
    }catch(const std::exception& e){j["error"]=e.what();j["summary"]=e.what();}
    return p;
}
std::vector<Packet> readCapture(const std::string& s){
    if(s.size()<12||s.size()>96*1024*1024)throw std::runtime_error("Capture size outside limits");std::vector<Packet> out;size_t retained=0;
    auto add=[&](size_t pos,uint32_t cap,uint32_t len,int link,int64_t ts,std::string device){if(cap>262144||pos+cap>s.size()||cap>len)throw std::runtime_error("Invalid capture record");retained+=cap;if(retained>MEMORY_LIMIT/2||out.size()>=16000)throw std::runtime_error("Capture exceeds 64 MiB / 16000 packet import limit");auto p=decodePacket(s.substr(pos,cap),link,ts,len,device);p.id=out.size()+1;out.push_back(std::move(p));};
    uint32_t magic=u32(s,0,true);
    if(magic!=0x0a0d0d0a){bool le=magic==0xa1b2c3d4||magic==0xa1b23c4d;bool ns=magic==0xa1b23c4d||magic==0x4d3cb2a1;if(!le&&magic!=0xd4c3b2a1&&magic!=0x4d3cb2a1)throw std::runtime_error("Not PCAP or PCAPNG");if(s.size()<24)throw std::runtime_error("PCAP header truncated");int link=int(u32(s,20,le)&0xffff);size_t off=24;while(off<s.size()){if(off+16>s.size())throw std::runtime_error("PCAP record truncated");auto sec=u32(s,off,le), frac=u32(s,off+4,le),cap=u32(s,off+8,le),len=u32(s,off+12,le);add(off+16,cap,len,link,int64_t(sec)*1000+frac/(ns?1000000:1000),"pcap");off+=16+cap;}return out;}
    bool le=true;std::vector<std::pair<int,double>> ifs;size_t off=0;
    while(off<s.size()){if(off+12>s.size())throw std::runtime_error("PCAPNG block truncated");if(u32(s,off,true)==0x0a0d0d0a){if(off+28>s.size())throw std::runtime_error("PCAPNG section truncated");auto bom=u32(s,off+8,true);if(bom!=0x1a2b3c4d&&bom!=0x4d3c2b1a)throw std::runtime_error("Invalid PCAPNG byte order");le=bom==0x1a2b3c4d;ifs.clear();}
        auto type=u32(s,off,le),len=u32(s,off+4,le);if(len<12||len%4||len>s.size()-off||u32(s,off+len-4,le)!=len)throw std::runtime_error("Invalid PCAPNG block");
        if(type==1){if(len<20)throw std::runtime_error("IDB truncated");int link=u16(s,off+8,le);double unit=0.001;size_t op=off+16;while(op+4<=off+len-4){auto code=u16(s,op,le),n=u16(s,op+2,le);op+=4;if(op+n>off+len-4)throw std::runtime_error("IDB option truncated");if(code==0)break;if(code==9&&n==1){uint8_t r=uint8_t(s[op]);unit=1000;for(int i=0;i<(r&127);++i)unit/=r&128?2:10;}op+=(n+3)&~size_t(3);}ifs.push_back({link,unit});}
        else if(type==6){if(len<32)throw std::runtime_error("EPB truncated");auto id=u32(s,off+8,le);if(id>=ifs.size())throw std::runtime_error("Missing PCAPNG interface");uint64_t ts=(uint64_t(u32(s,off+12,le))<<32)|u32(s,off+16,le);auto cap=u32(s,off+20,le),orig=u32(s,off+24,le);if(uint64_t(cap)+32>len)throw std::runtime_error("EPB data truncated");double stamp=double(ts)*ifs[id].second;if(stamp>double(std::numeric_limits<int64_t>::max()))throw std::runtime_error("PCAPNG timestamp overflow");add(off+28,cap,orig,ifs[id].first,int64_t(stamp),"pcapng:"+std::to_string(id));}
        else if(type==3){if(len<16||ifs.empty())throw std::runtime_error("SPB truncated");auto orig=u32(s,off+8,le);add(off+12,std::min(orig,len-16),orig,ifs[0].first,0,"pcapng:0");}
        off+=len;
    }return out;
}
std::string writePcapng(const std::vector<Packet>& packets){std::string out,d;le32(d,0x1a2b3c4d);le16(d,1);le16(d,0);le32(d,0xffffffff);le32(d,0xffffffff);block(out,0x0a0d0d0a,d);std::map<std::pair<int,std::string>,uint32_t> ifs;for(auto& p:packets){auto key=std::make_pair(p.linkType,p.device);if(!ifs.count(key)){uint32_t id=uint32_t(ifs.size());ifs[key]=id;d.clear();le16(d,uint16_t(p.linkType));le16(d,0);le32(d,262144);block(out,1,d);}d.clear();uint64_t us=uint64_t(std::max(int64_t(0),p.time))*1000;le32(d,ifs[key]);le32(d,uint32_t(us>>32));le32(d,uint32_t(us));le32(d,uint32_t(p.raw.size()));le32(d,p.originalLength);d+=p.raw;block(out,6,d);}return out;}
json streamPreview(const std::vector<Packet>& packets,const std::string& key){
    struct Segment{int64_t seq;std::string data;uint64_t id;};struct Direction{bool baseSet=false;uint32_t base=0;std::vector<Segment> segments;};std::map<std::string,Direction> dirs;
    for(auto& p:packets){auto& i=p.info;if(i.value("key","")!=key||!i.contains("seq"))continue;auto& d=dirs[i.value("source","")];uint32_t seq=i.at("seq").get<uint32_t>();if(i.value("flags","").find("SYN")!=std::string::npos)++seq;if(!d.baseSet){d.base=seq;d.baseSet=true;}size_t off=i.value("payloadOffset",size_t(0)),n=i.value("payloadLength",size_t(0));if(n&&off+n<=p.raw.size())d.segments.push_back({int32_t(seq-d.base),p.raw.substr(off,n),p.id});}
    json out=json::array();for(auto& [source,d]:dirs){std::stable_sort(d.segments.begin(),d.segments.end(),[](auto& a,auto& b){return a.seq<b.seq;});json chunks=json::array();int64_t next=0;bool first=true;size_t bytes=0;for(auto& seg:d.segments){if(first){next=seg.seq;first=false;}if(seg.seq>next)chunks.push_back({{"gap",seg.seq-next}});size_t skip=seg.seq<next?size_t(next-seg.seq):0;if(skip>=seg.data.size())continue;size_t n=std::min(seg.data.size()-skip,BODY_LIMIT-bytes);chunks.push_back({{"packet",seg.id},{"offset",seg.seq+int64_t(skip)},{"base64",base64(seg.data.substr(skip,n))}});bytes+=n;next=seg.seq+int64_t(seg.data.size());if(bytes>=BODY_LIMIT)break;}out.push_back({{"source",source},{"chunks",chunks},{"captured",bytes},{"limit",BODY_LIMIT}});}return out;
}
}
