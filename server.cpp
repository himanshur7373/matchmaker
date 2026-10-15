// MatchMaker - C++17 backend, no external libraries.
// Build: g++ -std=c++17 -O2 -pthread server.cpp -o server
// Run:   ./server   (optional: PORT=8080)
#include <bits/stdc++.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
using namespace std;
typedef map<string,string> Form;

// ---------- SHA-256 (used for salted password hashing) ----------
static const uint32_t K[64]={0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
string sha256(const string&s){
  uint32_t h[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
  string m=s; uint64_t bl=(uint64_t)s.size()*8; m+=char(0x80); while(m.size()%64!=56)m+=char(0);
  for(int i=7;i>=0;i--)m+=char((bl>>(i*8))&0xff);
  auto rr=[](uint32_t x,int n){return (x>>n)|(x<<(32-n));};
  for(size_t o=0;o<m.size();o+=64){
    uint32_t w[64];
    for(int i=0;i<16;i++){w[i]=0;for(int j=0;j<4;j++)w[i]=(w[i]<<8)|(uint8_t)m[o+4*i+j];}
    for(int i=16;i<64;i++){uint32_t s0=rr(w[i-15],7)^rr(w[i-15],18)^(w[i-15]>>3),s1=rr(w[i-2],17)^rr(w[i-2],19)^(w[i-2]>>10);w[i]=w[i-16]+s0+w[i-7]+s1;}
    uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
    for(int i=0;i<64;i++){
      uint32_t S1=rr(e,6)^rr(e,11)^rr(e,25),ch=(e&f)^(~e&g),t1=hh+S1+ch+K[i]+w[i];
      uint32_t S0=rr(a,2)^rr(a,13)^rr(a,22),mj=(a&b)^(a&c)^(b&c),t2=S0+mj;
      hh=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;}
    h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh;
  }
  char buf[65];for(int i=0;i<8;i++)snprintf(buf+8*i,9,"%08x",h[i]);return buf;
}
string randhex(int n){ifstream u("/dev/urandom",ios::binary);string r;char b[3];for(int i=0;i<n;i++){u.read(b,1);snprintf(b,3,"%02x",(unsigned char)b[0]);r+=b;}return r;}
string hashpw(const string&salt,const string&pw){string h=salt+pw;for(int i=0;i<2000;i++)h=sha256(h+salt);return h;}

// ---------- data ----------
struct U{int id=0,age=0;string name,email,salt,hash,gender,city,interests,bio,status="pending",utr;};
struct M{int f,t;long ts;string text;};
vector<U> users; set<pair<int,int>> likes; vector<M> msgs; map<string,int> sess; // session -> user id (-1 = admin)
mutex mu; 
string env(const char*k,const char*d){const char*v=getenv(k);return v?v:d;}
string esc(const string&s){string r;for(char c:s){if(c=='\\')r+="\\\\";else if(c=='\t')r+="\\t";else if(c=='\n')r+="\\n";else if(c!='\r')r+=c;}return r;}
string unesc(const string&s){string r;for(size_t i=0;i<s.size();i++){if(s[i]=='\\'&&i+1<s.size()){char n=s[++i];r+=n=='t'?'\t':n=='n'?'\n':n;}else r+=s[i];}return r;}
vector<string> split(const string&s,char d){vector<string> v(1);for(char c:s){if(c==d)v.emplace_back();else v.back()+=c;}return v;}
string trim(const string&t){size_t a=t.find_first_not_of(" \t\r\n"),b=t.find_last_not_of(" \t\r\n");return a==string::npos?"":t.substr(a,b-a+1);}
string lower(string s){for(auto&c:s)c=tolower((unsigned char)c);return s;}
void save(){
  filesystem::create_directories("data");
  ofstream f("data/users.tsv");
  for(auto&u:users)f<<u.id<<'\t'<<esc(u.name)<<'\t'<<esc(u.email)<<'\t'<<u.salt<<'\t'<<u.hash<<'\t'<<u.age<<'\t'<<esc(u.gender)<<'\t'<<esc(u.city)<<'\t'<<esc(u.interests)<<'\t'<<esc(u.bio)<<'\t'<<u.status<<'\t'<<esc(u.utr)<<'\n';
  ofstream l("data/likes.tsv");for(auto&p:likes)l<<p.first<<'\t'<<p.second<<'\n';
  ofstream m("data/messages.tsv");for(auto&x:msgs)m<<x.f<<'\t'<<x.t<<'\t'<<x.ts<<'\t'<<esc(x.text)<<'\n';
}
void load(){
  string ln;
  ifstream f("data/users.tsv");
  while(getline(f,ln)){auto v=split(ln,'\t');if(v.size()<12)continue;U u;u.id=stoi(v[0]);u.name=unesc(v[1]);u.email=unesc(v[2]);u.salt=v[3];u.hash=v[4];u.age=stoi(v[5]);u.gender=unesc(v[6]);u.city=unesc(v[7]);u.interests=unesc(v[8]);u.bio=unesc(v[9]);u.status=v[10];u.utr=unesc(v[11]);users.push_back(u);}
  ifstream l("data/likes.tsv");while(getline(l,ln)){auto v=split(ln,'\t');if(v.size()>=2)likes.insert({stoi(v[0]),stoi(v[1])});}
  ifstream m("data/messages.tsv");while(getline(m,ln)){auto v=split(ln,'\t');if(v.size()>=4)msgs.push_back({stoi(v[0]),stoi(v[1]),stol(v[2]),unesc(v[3])});}
}
U* byId(int id){for(auto&u:users)if(u.id==id)return &u;return nullptr;}
U* byEmail(const string&e){for(auto&u:users)if(u.email==e)return &u;return nullptr;}
bool isMatch(int a,int b){return likes.count({a,b})&&likes.count({b,a});}

// ---------- compatibility score: Jaccard similarity of interests (0-100) ----------
set<string> tags(const string&s){set<string> r;for(auto t:split(s,',')){t=lower(trim(t));if(!t.empty())r.insert(t);}return r;}
int score(const U&a,const U&b){auto x=tags(a.interests),y=tags(b.interests);int in=0;for(auto&t:x)in+=y.count(t);int un=(int)(x.size()+y.size())-in;return un>0?100*in/un:0;}

// ---------- JSON helpers ----------
string js(const string&s){string r="\"";for(unsigned char c:s){if(c=='"')r+="\\\"";else if(c=='\\')r+="\\\\";else if(c<32)r+=' ';else r+=c;}return r+"\"";}
string ERR(const string&m){return "{\"ok\":false,\"error\":"+js(m)+"}";}
const string OK="{\"ok\":true}";

// ---------- HTTP ----------
struct Req{string method,path,sid;Form p;};
struct Res{int code=200;string body,cookie,type="application/json";};
string urldec(const string&s){string r;for(size_t i=0;i<s.size();i++){if(s[i]=='+')r+=' ';else if(s[i]=='%'&&i+2<s.size()){r+=(char)stoi(s.substr(i+1,2),nullptr,16);i+=2;}else r+=s[i];}return r;}
void parseForm(const string&s,Form&f){for(auto&kv:split(s,'&')){auto i=kv.find('=');if(i==string::npos)continue;f[urldec(kv.substr(0,i))]=urldec(kv.substr(i+1));}}
string clean(string s,size_t max){string r;for(unsigned char c:s)if(c>=32||c=='\n')r+=c;r=trim(r);return r.size()>max?r.substr(0,max):r;}

Res route(Req&r){
  Res o;
  auto P=[&](const string&k){auto i=r.p.find(k);return i==r.p.end()?string():i->second;};
  int me=0;{auto s=sess.find(r.sid);if(s!=sess.end())me=s->second;}
  U*u=me>0?byId(me):nullptr;
  auto login=[&](int id){string t=randhex(24);sess[t]=id;o.cookie="sid="+t+"; HttpOnly; Path=/; SameSite=Strict";};
  const string&path=r.path;

  if(path=="/api/register"&&r.method=="POST"){
    string name=clean(P("name"),50),email=lower(clean(P("email"),80)),pw=P("password"),g=P("gender");
    int age=atoi(P("age").c_str());
    if(name.empty())return o.body=ERR("Name is required"),o;
    if(email.find('@')==string::npos||email.find('.')==string::npos||email=="admin")return o.body=ERR("Enter a valid email"),o;
    if(pw.size()<6)return o.body=ERR("Password must be at least 6 characters"),o;
    if(age<18||age>80)return o.body=ERR("You must be 18 or older"),o;
    if(g!="M"&&g!="F"&&g!="O")return o.body=ERR("Select gender"),o;
    if(byEmail(email))return o.body=ERR("Email already registered"),o;
    U n;n.id=users.empty()?1:users.back().id+1;n.name=name;n.email=email;n.salt=randhex(8);n.hash=hashpw(n.salt,pw);n.age=age;n.gender=g;
    n.city=clean(P("city"),40);n.interests=clean(P("interests"),150);n.bio=clean(P("bio"),300);
    users.push_back(n);save();login(n.id);o.body=OK;return o;
  }
  if(path=="/api/login"&&r.method=="POST"){
    string e=lower(trim(P("email"))),pw=P("password");
    U*x=byEmail(e);
    if(!x||hashpw(x->salt,pw)!=x->hash)return o.body=ERR("Wrong email or password"),o;
    login(x->id);o.body=OK;return o;
  }
  if(path=="/api/logout"){sess.erase(r.sid);o.body=OK;return o;}
  if(path=="/api/me"){
    if(!u)return o.code=401,o.body=ERR("Not logged in"),o;
    o.body="{\"ok\":true,\"admin\":false,\"id\":"+to_string(u->id)+",\"name\":"+js(u->name)+",\"status\":"+js(u->status)+"}";return o;
  }
  // ----- paid members only -----
  if(!u&&path.rfind("/api/",0)==0)return o.code=401,o.body=ERR("Please login"),o;
  if(path=="/api/browse"){
    string city=lower(P("city")),tag=lower(trim(P("interest")));int mn=P("min").empty()?18:atoi(P("min").c_str()),mx=P("max").empty()?99:atoi(P("max").c_str());
    vector<pair<int,U*>> v;
    for(auto&x:users){
      if(x.id==u->id||x.age<mn||x.age>mx)continue;
      if(!city.empty()&&lower(x.city).find(city)==string::npos)continue;
      if(!tag.empty()&&!tags(x.interests).count(tag))continue;
      v.push_back({score(*u,x),&x});
    }
    sort(v.begin(),v.end(),[](auto&a,auto&b){return a.first>b.first;});
    string a="[";for(auto&p:v){U&x=*p.second;if(a.size()>1)a+=",";
      a+="{\"id\":"+to_string(x.id)+",\"name\":"+js(x.name)+",\"age\":"+to_string(x.age)+",\"city\":"+js(x.city)+",\"interests\":"+js(x.interests)+",\"bio\":"+js(x.bio)+",\"score\":"+to_string(p.first)+",\"liked\":"+(likes.count({u->id,x.id})?"true":"false")+"}";}
    o.body="{\"ok\":true,\"users\":"+a+"]}";return o;
  }
  if(path=="/api/like"&&r.method=="POST"){
    U*x=byId(atoi(P("to").c_str()));if(!x||x==u)return o.body=ERR("Invalid user"),o;
    likes.insert({u->id,x->id});save();o.body=string("{\"ok\":true,\"match\":")+(isMatch(u->id,x->id)?"true":"false")+"}";return o;
  }
  if(path=="/api/matches"){
    string a="[";for(auto&x:users)if(x.id!=u->id&&isMatch(u->id,x.id)){if(a.size()>1)a+=",";a+="{\"id\":"+to_string(x.id)+",\"name\":"+js(x.name)+",\"age\":"+to_string(x.age)+",\"city\":"+js(x.city)+"}";}
    o.body="{\"ok\":true,\"matches\":"+a+"]}";return o;
  }
  if(path=="/api/messages"){
    int w=atoi(P("with").c_str());if(!isMatch(u->id,w))return o.body=ERR("You can chat only with matches"),o;
    string a="[";for(auto&m:msgs)if((m.f==u->id&&m.t==w)||(m.f==w&&m.t==u->id)){if(a.size()>1)a+=",";a+="{\"mine\":"+string(m.f==u->id?"true":"false")+",\"text\":"+js(m.text)+"}";}
    o.body="{\"ok\":true,\"messages\":"+a+"]}";return o;
  }
  if(path=="/api/message"&&r.method=="POST"){
    int w=atoi(P("to").c_str());string t=clean(P("text"),500);
    if(!isMatch(u->id,w)||t.empty())return o.body=ERR("Cannot send"),o;
    msgs.push_back({u->id,w,(long)time(nullptr),t});save();o.body=OK;return o;
  }
  o.code=404;o.body=ERR("Not found");return o;
}

void handle(int fd){
  string raw;char buf[4096];size_t he;
  while((he=raw.find("\r\n\r\n"))==string::npos){ssize_t n=recv(fd,buf,sizeof buf,0);if(n<=0||raw.size()>65536){close(fd);return;}raw.append(buf,n);}
  string head=raw.substr(0,he),body=raw.substr(he+4);
  istringstream hs(head);Req r;string target,ver;hs>>r.method>>target>>ver;
  size_t cl=0;string ln;
  while(getline(hs,ln)){string l=lower(ln);
    if(l.rfind("content-length:",0)==0)cl=min<size_t>(stoul(trim(ln.substr(15))),65536);
    if(l.rfind("cookie:",0)==0){auto i=ln.find("sid=");if(i!=string::npos){size_t e=ln.find(';',i);r.sid=trim(ln.substr(i+4,e==string::npos?string::npos:e-i-4));}}}
  while(body.size()<cl){ssize_t n=recv(fd,buf,sizeof buf,0);if(n<=0)break;body.append(buf,n);}
  auto q=target.find('?');r.path=target.substr(0,q);if(q!=string::npos)parseForm(target.substr(q+1),r.p);parseForm(body,r.p);
  Res o;
  if(r.path=="/"||r.path=="/index.html"){ifstream f("public/index.html");stringstream s;s<<f.rdbuf();o.body=s.str();o.type="text/html; charset=utf-8";}
  else{lock_guard<mutex> g(mu);o=route(r);}
  const char*st=o.code==200?"OK":o.code==401?"Unauthorized":o.code==403?"Forbidden":"Not Found";
  string out="HTTP/1.1 "+to_string(o.code)+" "+st+"\r\nContent-Type: "+o.type+"\r\nContent-Length: "+to_string(o.body.size())+"\r\nX-Content-Type-Options: nosniff\r\nCache-Control: no-store\r\nConnection: close\r\n"+(o.cookie.empty()?"":"Set-Cookie: "+o.cookie+"\r\n")+"\r\n"+o.body;
  for(size_t s=0;s<out.size();){ssize_t n=send(fd,out.data()+s,out.size()-s,MSG_NOSIGNAL);if(n<=0)break;s+=n;}
  close(fd);
}

int main(){
  signal(SIGPIPE,SIG_IGN);
  int port=atoi(env("PORT","8080").c_str());
  load();
  int s=socket(AF_INET,SOCK_STREAM,0),one=1;setsockopt(s,SOL_SOCKET,SO_REUSEADDR,&one,sizeof one);
  sockaddr_in a{};a.sin_family=AF_INET;a.sin_addr.s_addr=INADDR_ANY;a.sin_port=htons(port);
  if(bind(s,(sockaddr*)&a,sizeof a)<0||listen(s,64)<0){perror("bind/listen");return 1;}
  printf("MatchMaker running at http://localhost:%d \n",port);
  while(true){int c=accept(s,nullptr,nullptr);if(c>=0)thread(handle,c).detach();}
}
