#include "net.hpp"
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <filesystem>
#include <fstream>
#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#include <sddl.h>
#include <aclapi.h>
#endif
namespace ws {
namespace {
void require(bool ok,const char* m){if(!ok)throw std::runtime_error(m);}
// File I/O goes through std::filesystem so Windows profile paths with non-ASCII characters work; OpenSSL only sees memory BIOs.
std::string readFile(const std::filesystem::path& p){std::ifstream f(p,std::ios::binary);if(!f)return {};return {(std::istreambuf_iterator<char>(f)),{}};}
void writeFile(const std::filesystem::path& p,const std::string& data){std::ofstream f(p,std::ios::binary|std::ios::trunc);require(bool(f),"Cannot write file");f.write(data.data(),std::streamsize(data.size()));require(bool(f),"File write failed");}
std::string utf8(const std::filesystem::path& p){auto u=p.u8string();return std::string(u.begin(),u.end());}
template<class F> std::string pem(F write){BIO* b=BIO_new(BIO_s_mem());require(b!=nullptr,"BIO allocation failed");int ok=write(b);char* data=nullptr;long n=BIO_get_mem_data(b,&data);std::string out(data,size_t(n>0?n:0));BIO_free(b);require(ok==1,"PEM encoding failed");return out;}
X509* parseCert(const std::string& text){BIO* b=BIO_new_mem_buf(text.data(),int(text.size()));if(!b)return nullptr;X509* x=PEM_read_bio_X509(b,nullptr,nullptr,nullptr);BIO_free(b);return x;}
EVP_PKEY* parseKey(const std::string& text){BIO* b=BIO_new_mem_buf(text.data(),int(text.size()));if(!b)return nullptr;EVP_PKEY* k=PEM_read_bio_PrivateKey(b,nullptr,nullptr,nullptr);BIO_free(b);return k;}
void extension(X509* cert,X509* issuer,int nid,const std::string& value){X509V3_CTX c;X509V3_set_ctx(&c,issuer,cert,nullptr,nullptr,0);X509_EXTENSION* e=X509V3_EXT_conf_nid(nullptr,&c,nid,value.c_str());require(e!=nullptr,"Certificate extension failed");X509_add_ext(cert,e,-1);X509_EXTENSION_free(e);}
void serial(X509* cert){unsigned char data[16];require(RAND_bytes(data,sizeof(data))==1,"Certificate serial failed");data[0]&=0x7f;BIGNUM* b=BN_bin2bn(data,sizeof(data),nullptr);BN_to_ASN1_INTEGER(b,X509_get_serialNumber(cert));BN_free(b);}
void protectKey(const std::filesystem::path& p){
#ifdef _WIN32
    HANDLE token=nullptr;require(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token),"Open user token failed");DWORD n=0;GetTokenInformation(token,TokenUser,nullptr,0,&n);std::vector<unsigned char> buf(n);bool ok=GetTokenInformation(token,TokenUser,buf.data(),n,&n)!=0;CloseHandle(token);require(ok,"Read user SID failed");LPWSTR sid=nullptr;require(ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(buf.data())->User.Sid,&sid),"User SID conversion failed");std::wstring sddl=L"D:P(A;;FA;;;"+std::wstring(sid)+L")";LocalFree(sid);PSECURITY_DESCRIPTOR sd=nullptr;require(ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(),SDDL_REVISION_1,&sd,nullptr),"Private key ACL failed");BOOL present=FALSE,def=FALSE;PACL acl=nullptr;GetSecurityDescriptorDacl(sd,&present,&acl,&def);auto result=SetNamedSecurityInfoW(const_cast<wchar_t*>(p.c_str()),SE_FILE_OBJECT,DACL_SECURITY_INFORMATION|PROTECTED_DACL_SECURITY_INFORMATION,nullptr,nullptr,acl,nullptr);LocalFree(sd);require(result==ERROR_SUCCESS,"Cannot restrict private key access");
#else
    std::filesystem::permissions(p,std::filesystem::perms::owner_read|std::filesystem::perms::owner_write,std::filesystem::perm_options::replace);
#endif
}
}
Tls::Tls(std::string d):directory(std::move(d)){}
Tls::~Tls(){for(auto& [h,c]:leaves)SSL_CTX_free(c);if(client)SSL_CTX_free(client);if(ca)X509_free(ca);if(caKey)EVP_PKEY_free(caKey);if(leafKey)EVP_PKEY_free(leafKey);}
void Tls::initialize(){std::lock_guard lock(mutex);if(client)return;std::filesystem::create_directories(utf8Path(directory));/* not path(std::string): that is the ANSI code page on Windows */auto certPath=utf8Path(directory)/"root-ca.pem";auto keyPath=utf8Path(directory)/"root-key.pem";
    if(!ca){
        bool certExists=std::filesystem::exists(certPath),keyExists=std::filesystem::exists(keyPath);if(certExists!=keyExists)throw std::runtime_error("Incomplete CA: root-ca.pem and root-key.pem must both exist");
        if(certExists){ca=parseCert(readFile(certPath));caKey=parseKey(readFile(keyPath));require(ca&&caKey&&X509_check_private_key(ca,caKey)==1,"CA certificate/key unreadable or mismatched");}
        else{caKey=EVP_RSA_gen(3072);require(caKey!=nullptr,"CA key generation failed");ca=X509_new();require(ca!=nullptr,"CA allocation failed");X509_set_version(ca,2);serial(ca);X509_gmtime_adj(X509_getm_notBefore(ca),-3600);X509_gmtime_adj(X509_getm_notAfter(ca),60L*60*24*365*5);X509_set_pubkey(ca,caKey);auto* name=X509_get_subject_name(ca);std::string cn="WireScope Local CA "+randomHex(4);X509_NAME_add_entry_by_txt(name,"CN",MBSTRING_ASC,reinterpret_cast<const unsigned char*>(cn.c_str()),-1,-1,0);X509_set_issuer_name(ca,name);extension(ca,ca,NID_basic_constraints,"critical,CA:TRUE");extension(ca,ca,NID_key_usage,"critical,keyCertSign,cRLSign");extension(ca,ca,NID_subject_key_identifier,"hash");require(X509_sign(ca,caKey,EVP_sha256())>0,"CA signing failed");
            {std::ofstream placeholder(keyPath,std::ios::binary);require(bool(placeholder),"Cannot create private key file");}protectKey(keyPath);
            writeFile(keyPath,pem([&](BIO* b){return PEM_write_bio_PrivateKey(b,caKey,nullptr,nullptr,0,nullptr,nullptr);}));writeFile(certPath,pem([&](BIO* b){return PEM_write_bio_X509(b,ca);}));
        }
    }
    if(!leafKey)leafKey=EVP_RSA_gen(2048);require(leafKey!=nullptr,"Leaf key generation failed");client=SSL_CTX_new(TLS_client_method());require(client!=nullptr,"TLS client allocation failed");SSL_CTX_set_min_proto_version(client,TLS1_2_VERSION);SSL_CTX_set_verify(client,SSL_VERIFY_PEER,nullptr);SSL_CTX_set_default_verify_paths(client);
#ifdef _WIN32
    HCERTSTORE roots=CertOpenSystemStoreW(0,L"ROOT");if(roots){PCCERT_CONTEXT c=nullptr;while((c=CertEnumCertificatesInStore(roots,c))!=nullptr){const unsigned char* der=c->pbCertEncoded;X509* x=d2i_X509(nullptr,&der,long(c->cbCertEncoded));if(x){X509_STORE_add_cert(SSL_CTX_get_cert_store(client),x);X509_free(x);}}CertCloseStore(roots,0);ERR_clear_error();}
#endif
}
SSL_CTX* Tls::leaf(const std::string& host){initialize();std::lock_guard lock(mutex);if(auto it=leaves.find(host);it!=leaves.end())return it->second;if(leaves.size()>=2048)throw std::runtime_error("Certificate cache limit reached; restart proxy application");X509* x=X509_new();require(x!=nullptr,"Leaf certificate allocation failed");X509_set_version(x,2);serial(x);X509_gmtime_adj(X509_getm_notBefore(x),-3600);X509_gmtime_adj(X509_getm_notAfter(x),60L*60*24*30);X509_set_pubkey(x,leafKey);X509_NAME_add_entry_by_txt(X509_get_subject_name(x),"CN",MBSTRING_ASC,reinterpret_cast<const unsigned char*>(host.c_str()),-1,-1,0);X509_set_issuer_name(x,X509_get_subject_name(ca));unsigned char ip[16];bool numeric=inet_pton(AF_INET,host.c_str(),ip)==1||inet_pton(AF_INET6,host.c_str(),ip)==1;extension(x,ca,NID_subject_alt_name,(numeric?"IP:":"DNS:")+host);extension(x,ca,NID_basic_constraints,"critical,CA:FALSE");extension(x,ca,NID_ext_key_usage,"serverAuth");require(X509_sign(x,caKey,EVP_sha256())>0,"Leaf signing failed");SSL_CTX* ctx=SSL_CTX_new(TLS_server_method());if(!ctx){X509_free(x);throw std::runtime_error("TLS server allocation failed");}SSL_CTX_set_min_proto_version(ctx,TLS1_2_VERSION);SSL_CTX_set_alpn_select_cb(ctx,[](SSL*,const unsigned char** out,unsigned char* len,const unsigned char* in,unsigned n,void*)->int{static const unsigned char protocols[]={2,'h','2',8,'h','t','t','p','/','1','.','1'};return SSL_select_next_proto(const_cast<unsigned char**>(out),len,protocols,sizeof(protocols),in,n)==OPENSSL_NPN_NEGOTIATED?SSL_TLSEXT_ERR_OK:SSL_TLSEXT_ERR_NOACK;},nullptr);int ok=SSL_CTX_use_certificate(ctx,x);ok&=SSL_CTX_use_PrivateKey(ctx,leafKey);X509_free(x);if(!ok){SSL_CTX_free(ctx);throw std::runtime_error("Leaf key setup failed");}leaves[host]=ctx;return ctx;}
json Tls::info()const{auto path=utf8Path(directory)/"root-ca.pem";auto text=readFile(path);std::string fingerprint,subject;
    // Fingerprint over the DER certificate, matching what certmgr/openssl x509 -fingerprint -sha256 show.
    if(X509* x=parseCert(text)){int n=i2d_X509(x,nullptr);if(n>0){std::string der(size_t(n),'\0');auto* p=reinterpret_cast<unsigned char*>(der.data());i2d_X509(x,&p);fingerprint=sha256(der);}char name[256]{};X509_NAME_oneline(X509_get_subject_name(x),name,sizeof(name));subject=name;X509_free(x);}
    return {{"exists",!text.empty()},{"path",utf8(path)},{"subject",subject},{"fingerprint",fingerprint},{"fingerprintType","SHA-256 (DER)"},{"pem",text}};}
void Tls::trust(bool install){initialize();
#ifdef _WIN32
    HCERTSTORE roots=CertOpenStore(CERT_STORE_PROV_SYSTEM_W,0,0,CERT_SYSTEM_STORE_CURRENT_USER,L"ROOT");require(roots!=nullptr,"Cannot open current-user certificate store");int n=i2d_X509(ca,nullptr);std::vector<unsigned char> der(size_t(n),0);auto* p=der.data();i2d_X509(ca,&p);PCCERT_CONTEXT cert=CertCreateCertificateContext(X509_ASN_ENCODING,der.data(),DWORD(n));if(!cert){CertCloseStore(roots,0);throw std::runtime_error("Invalid CA encoding");}bool ok=true;if(install)ok=CertAddCertificateContextToStore(roots,cert,CERT_STORE_ADD_REPLACE_EXISTING,nullptr)!=0;else{auto found=CertFindCertificateInStore(roots,X509_ASN_ENCODING,0,CERT_FIND_EXISTING,cert,nullptr);if(found)ok=CertDeleteCertificateFromStore(found)!=0;}CertFreeCertificateContext(cert);CertCloseStore(roots,0);require(ok,"Certificate store operation failed");
#else
    (void)install;throw std::runtime_error("Trust-store controls are available on Windows only");
#endif
}
}
