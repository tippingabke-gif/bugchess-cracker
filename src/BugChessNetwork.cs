using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

public static class BugChessNetwork {
    [StructLayout(LayoutKind.Sequential)] struct Display { [MarshalAs(UnmanagedType.LPWStr)] public string name; [MarshalAs(UnmanagedType.LPWStr)] public string description; }
    [StructLayout(LayoutKind.Sequential)] struct Blob { public uint size; public IntPtr data; }
    [StructLayout(LayoutKind.Explicit,Size=16)] struct Value { [FieldOffset(0)] public uint type; [FieldOffset(8)] public IntPtr pointer; [FieldOffset(8)] public byte small; [FieldOffset(8)] public uint numeric; }
    [StructLayout(LayoutKind.Sequential)] struct Condition { public Guid field; public uint match; public Value value; }
    [StructLayout(LayoutKind.Sequential)] struct Action { public uint type; public Guid key; }
    [StructLayout(LayoutKind.Sequential)] struct Filter {
        public Guid key; public Display display; public uint flags; public IntPtr provider; public Blob providerData;
        public Guid layer,sublayer; public Value weight; public uint conditionCount; public IntPtr conditions;
        public Action action; public ulong context; public IntPtr reserved; public ulong id; public Value effectiveWeight;
    }
    [StructLayout(LayoutKind.Sequential)] struct Sublayer { public Guid key; public Display display; public uint flags; public IntPtr provider; public Blob data; public ushort weight; }
    [DllImport("fwpuclnt.dll",CharSet=CharSet.Unicode)] static extern uint FwpmEngineOpen0(string server,uint auth,IntPtr identity,IntPtr session,out IntPtr engine);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmEngineClose0(IntPtr engine);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmTransactionBegin0(IntPtr engine,uint flags);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmTransactionCommit0(IntPtr engine);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmTransactionAbort0(IntPtr engine);
    [DllImport("fwpuclnt.dll",CharSet=CharSet.Unicode)] static extern uint FwpmGetAppIdFromFileName0(string file,out IntPtr appid);
    [DllImport("fwpuclnt.dll")] static extern void FwpmFreeMemory0(ref IntPtr memory);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmSubLayerAdd0(IntPtr engine,ref Sublayer layer,IntPtr security);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterAdd0(IntPtr engine,ref Filter filter,IntPtr security,out ulong id);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterGetByKey0(IntPtr engine,ref Guid key,out IntPtr filter);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterDeleteByKey0(IntPtr engine,ref Guid key);
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string text,uint revision,out IntPtr descriptor,out uint size);
    [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr pointer);
    static readonly Guid sublayer=new Guid("ab904f3e-f5ad-4748-8ba5-0d4528bab5ed");
    static readonly Guid loopbackFlags=new Guid("632ce23b-5167-435c-86d7-e903684aa80c");
    static readonly Guid application=new Guid("d78e1e87-8644-4ea5-9437-d809ecefc971");
    static readonly Guid[] layers={new Guid("c38d57d1-05a7-4c33-904f-7fbceee60e82"),new Guid("4a72393b-319f-44bc-84c3-ba54dcb3b6b4"),new Guid("e1cd9fe7-f4b5-4273-96c0-592e487b8650"),new Guid("a3b42c97-9f04-4672-b87e-cee9c483257f")};
    static void Check(uint code,string operation) { if(code!=0) throw new InvalidOperationException(operation+": 0x"+code.ToString("X8")); }
    static Guid Key(string file,Guid layer) { using(SHA256 hash=SHA256.Create()) { byte[] digest=hash.ComputeHash(Encoding.Unicode.GetBytes("BugChessLocalControl-v1|"+file.ToLowerInvariant()+"|"+layer.ToString())); byte[] bytes=new byte[16]; Array.Copy(digest,bytes,16); return new Guid(bytes); } }
    static byte[] Bytes(IntPtr blobPointer) { Blob blob=(Blob)Marshal.PtrToStructure(blobPointer,typeof(Blob)); if(blob.size>65536) throw new InvalidDataException("Invalid app id size"); byte[] data=new byte[blob.size]; Marshal.Copy(blob.data,data,0,data.Length); return data; }
    static bool Equal(byte[] a,byte[] b) { if(a.Length!=b.Length) return false; for(int i=0;i<a.Length;i++) if(a[i]!=b[i]) return false; return true; }
    static void Verify(IntPtr engine,string file,IntPtr appid) {
        foreach(Guid layer in layers) {
            Guid key=Key(file,layer); IntPtr pointer=IntPtr.Zero;
            try {
                Check(FwpmFilterGetByKey0(engine,ref key,out pointer),"Read filter");
                Filter filter=(Filter)Marshal.PtrToStructure(pointer,typeof(Filter));
                if(filter.layer!=layer || filter.sublayer!=sublayer || filter.action.type!=0x1001 || filter.conditionCount!=2 || (filter.flags&1)==0) throw new InvalidDataException("Unexpected filter properties");
                Condition condition=(Condition)Marshal.PtrToStructure(filter.conditions,typeof(Condition));
                if(condition.field!=application || condition.match!=0 || condition.value.type!=12 || !Equal(Bytes(appid),Bytes(condition.value.pointer))) throw new InvalidDataException("Unexpected app condition");
                Condition flags=(Condition)Marshal.PtrToStructure(IntPtr.Add(filter.conditions,40),typeof(Condition));
                if(flags.field!=loopbackFlags||flags.match!=8||flags.value.type!=3||flags.value.numeric!=1)throw new InvalidDataException("Unexpected loopback condition");
            } finally { if(pointer!=IntPtr.Zero) FwpmFreeMemory0(ref pointer); }
        }
    }
    public static int Main(string[] args) {
        IntPtr engine=IntPtr.Zero,security=IntPtr.Zero; bool transaction=false;
        try {
            if(args.Length<2 || (args[0]!="install" && args[0]!="verify" && args[0]!="remove")) throw new ArgumentException("Usage: BugChessNetwork install|verify|remove <exact exe path> [...]");
            if(Marshal.SizeOf(typeof(Filter))!=192 || Marshal.SizeOf(typeof(Condition))!=40 || Marshal.SizeOf(typeof(Sublayer))!=72) throw new InvalidOperationException("Unexpected x64 layout");
            Check(FwpmEngineOpen0(null,10,IntPtr.Zero,IntPtr.Zero,out engine),"Open filtering engine");
            bool mutation=args[0]!="verify";
            if(mutation) { Check(FwpmTransactionBegin0(engine,0),"Begin transaction"); transaction=true; }
            if(args[0]=="install") {
                uint securitySize;
                if(!ConvertStringSecurityDescriptorToSecurityDescriptor("D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;IU)",1,out security,out securitySize)) throw new Win32Exception(Marshal.GetLastWin32Error());
                Sublayer layer=new Sublayer { key=sublayer,display=new Display {name="BugChess offline rules",description="Per-program external network isolation; loopback control allowed"},flags=1,weight=65535 };
                uint status=FwpmSubLayerAdd0(engine,ref layer,IntPtr.Zero); if(status!=0x80320009) Check(status,"Add sublayer");
            }
            for(int n=1;n<args.Length;n++) {
                string file=Path.GetFullPath(args[n]);
                if(args[0]=="remove") {foreach(Guid layer in layers){Guid key=Key(file,layer);uint result=FwpmFilterDeleteByKey0(engine,ref key);if(result!=0x80320003)Check(result,"Remove filter");}continue;}
                if(!File.Exists(file)) throw new FileNotFoundException("Executable is missing",file);
                IntPtr appid=IntPtr.Zero;
                try {
                    Check(FwpmGetAppIdFromFileName0(file,out appid),"Get application id");
                    if(args[0]=="verify") { Verify(engine,file,appid); continue; }
                    foreach(Guid layer in layers) {
                        Guid key=Key(file,layer);
                        uint removal=FwpmFilterDeleteByKey0(engine,ref key); if(removal!=0x80320003) Check(removal,"Remove old filter");
                        if(args[0]=="remove") continue;
                        Condition condition=new Condition {field=application,match=0,value=new Value {type=12,pointer=appid}};
                        IntPtr conditionPointer=Marshal.AllocHGlobal(2*Marshal.SizeOf(typeof(Condition)));
                        try {
                            Marshal.StructureToPtr(condition,conditionPointer,false);
                            Condition flags=new Condition {field=loopbackFlags,match=8,value=new Value {type=3,numeric=1}};
                            Marshal.StructureToPtr(flags,IntPtr.Add(conditionPointer,40),false);
                            Filter filter=new Filter {key=key,display=new Display {name="BugChess offline - "+Path.GetFileName(file),description=file},flags=1,
                                layer=layer,sublayer=sublayer,weight=new Value {type=1,small=15},conditionCount=2,conditions=conditionPointer,action=new Action {type=0x1001}};
                            ulong id; Check(FwpmFilterAdd0(engine,ref filter,security,out id),"Add block filter");
                        } finally { Marshal.FreeHGlobal(conditionPointer); }
                    }
                } finally { if(appid!=IntPtr.Zero) FwpmFreeMemory0(ref appid); }
            }
            if(transaction) { Check(FwpmTransactionCommit0(engine),"Commit transaction"); transaction=false; }
            Console.WriteLine("OK "+args[0]+" "+(args.Length-1)+" programs; IPv4/IPv6 inbound/outbound"); return 0;
        } catch(Exception ex) { Console.Error.WriteLine(ex.Message); return 2; }
        finally { if(transaction) FwpmTransactionAbort0(engine); if(engine!=IntPtr.Zero) FwpmEngineClose0(engine); if(security!=IntPtr.Zero) LocalFree(security); }
    }
}
