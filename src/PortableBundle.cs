using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Text;

static class PortableBundle {
 internal const string BundleVersion="220";
 internal static void UpdateThreadRuntime(string support){
  string path=Path.Combine(support,"runtime","lab","guest_four_variant_bridge_v145.py");
  string text=File.ReadAllText(path,Encoding.UTF8);
  const string old="            p.write(cap,struct.pack('<I',4));assert p.read(cap,4)==struct.pack('<I',4)\n            p.report['testThreadCap']=4";
  const string replacement="            # Keep the signed-int representation range; do not impose a test or CPU-count cap.\n            p.write(cap,struct.pack('<I',0x7fffffff));assert p.read(cap,4)==struct.pack('<I',0x7fffffff)\n            p.report['threadOptionIntegerMax']=0x7fffffff";
  string normalized=text.Replace("\r\n","\n");
  if(normalized.Contains(replacement)&&!normalized.Contains(old))return;
  int at=normalized.IndexOf(old,StringComparison.Ordinal);
  if(at<0||at!=normalized.LastIndexOf(old,StringComparison.Ordinal))throw new Exception("线程设置组件与预期版本不一致，已保留原文件。");
  File.WriteAllText(path,normalized.Replace(old,replacement),new UTF8Encoding(false));
 }
 internal static void ProjectLink(string support){
  File.WriteAllText(Path.Combine(support,"项目地址.url"),"[InternetShortcut]\r\nURL=https://github.com/tippingabke-gif\r\n",Encoding.ASCII);
 }
 internal static void RenameReferences(string support){
  foreach(string file in Directory.GetFiles(Path.Combine(support,"runtime","lab"),"*.py",SearchOption.AllDirectories)){
   string text=File.ReadAllText(file,Encoding.UTF8);
   if(text.Contains("BugChessSupport-v148"))File.WriteAllText(file,text.Replace("BugChessSupport-v148",Components.SupportName),new UTF8Encoding(false));
  }
 }
 internal static void UpdateHook(string support){
  string path=Path.Combine(support,"BugChessHookPermanent.exe"),temp=path+".updating";
  if(File.Exists(temp))throw new Exception("上次组件更新文件仍在，请检查后重试。");
  try{
   using(var resource=Assembly.GetExecutingAssembly().GetManifestResourceStream("BugChess.Payload"))
   using(var zip=new System.IO.Compression.ZipArchive(resource,System.IO.Compression.ZipArchiveMode.Read)){
    var entry=zip.GetEntry("BugChessHookPermanent.exe");
    if(entry==null)throw new Exception("启动组件缺失。");
    using(var input=entry.Open())using(var output=new FileStream(temp,FileMode.CreateNew,FileAccess.Write,FileShare.None))input.CopyTo(output);
   }
   File.Replace(temp,path,null);
  }finally{if(File.Exists(temp))File.Delete(temp);}
 }
 [System.Runtime.InteropServices.DllImport("kernel32.dll",CharSet=System.Runtime.InteropServices.CharSet.Unicode,SetLastError=true)]
 static extern uint GetShortPathName(string path,StringBuilder result,uint capacity);
 static string SdeRoot(string root){
  string path=Path.GetFullPath(root).TrimEnd('\\');
  if(!path.Contains(" "))return path;
  var result=new StringBuilder(32768);uint size=GetShortPathName(path,result,(uint)result.Capacity);
  if(size>0&&size<result.Capacity&&!result.ToString().Contains(" "))return result.ToString();
  throw new Exception("此磁盘未提供可用短路径，请将原引擎放到不含空格的目录（例如 D:\\BugChess）后安装。");
 }
 static string Relocate(string text,string oldPath,string newPath){
  return text.Replace(oldPath.Replace("\\","\\\\"),newPath.Replace("\\","\\\\")).Replace(oldPath,newPath);
 }
 public static void Ensure(string root,string support){
  if(root.Contains("\"")||root.Contains("'"))throw new Exception("当前组件目录请使用不含引号的路径。");
  string sdeRoot=SdeRoot(root);
  string marker=Path.Combine(support,"bundle-version.txt");
  if(Directory.Exists(support)){
   if(File.Exists(marker)&&File.ReadAllText(marker)==BundleVersion&&File.Exists(Path.Combine(support,"runtime","python","python.exe")))return;
   throw new Exception("当前目录已有其他版本的组件。请先从原目录卸载组件，或将原引擎放在一个新目录后再安装。");
  }
  string stage=Path.GetFullPath(support+".installing-"+Process.GetCurrentProcess().Id);
  string allowed=Path.GetFullPath(root).TrimEnd('\\')+"\\";
  if(!stage.StartsWith(allowed,StringComparison.OrdinalIgnoreCase))throw new Exception("安装路径校验失败。");
  if(Directory.Exists(stage))throw new Exception("上次安装目录仍在，请检查后重试。");
  Directory.CreateDirectory(stage);
  try{
   using(var resource=Assembly.GetExecutingAssembly().GetManifestResourceStream("BugChess.Payload"))
   using(var zip=new System.IO.Compression.ZipArchive(resource,System.IO.Compression.ZipArchiveMode.Read)){
    long expanded=0;foreach(var entry in zip.Entries)expanded+=entry.Length;
    if(new DriveInfo(Path.GetPathRoot(stage)).AvailableFreeSpace<expanded+64L*1024*1024)
     throw new Exception("磁盘空间不足，请为组件解压预留至少 700 MB 空闲空间。");
    string prefix=stage.TrimEnd('\\')+"\\";
    foreach(var entry in zip.Entries){
     string target=Path.GetFullPath(Path.Combine(stage,entry.FullName.Replace('/','\\')));
     if(!target.StartsWith(prefix,StringComparison.OrdinalIgnoreCase))throw new Exception("组件压缩包路径异常。");
     if(entry.FullName.EndsWith("/")){Directory.CreateDirectory(target);continue;}
     Directory.CreateDirectory(Path.GetDirectoryName(target));
     using(var input=entry.Open())using(var output=new FileStream(target,FileMode.CreateNew,FileAccess.Write,FileShare.None))input.CopyTo(output);
    }
   }
   string lab=Path.Combine(support,"runtime","lab"),python=Path.Combine(support,"runtime","python"),sde=Path.Combine(sdeRoot,Components.SupportName,"runtime","sde");
   foreach(string file in Directory.GetFiles(Path.Combine(stage,"runtime","lab"),"*.py",SearchOption.AllDirectories)){
    string text=File.ReadAllText(file,Encoding.UTF8);
    text=Relocate(text,@"C:\Lab\BugChess20260627",lab);
    text=Relocate(text,@"C:\Lab\Tools\Python310",python);
    text=Relocate(text,@"C:\Lab\Tools\IntelSDE-10.13.1\sde-external-10.13.1-2026-07-28-win",sde);
    text=text.Replace("BugChessSupport-v148",Components.SupportName);
    File.WriteAllText(file,text,new UTF8Encoding(false));
   }
   foreach(string variant in new[]{"SSE4","AVX2","BMI2","AVX512"}){
    Directory.CreateDirectory(Path.Combine(stage,variant));
    File.Copy(Path.Combine(stage,"BugChessNetwork.exe"),Path.Combine(stage,variant,"BugChessNetwork.exe"));
   }
   ProjectLink(stage);
   File.WriteAllText(Path.Combine(stage,"bundle-version.txt"),BundleVersion,new UTF8Encoding(false));
   Directory.Move(stage,support);
  }finally{
   if(Directory.Exists(stage)&&Path.GetFullPath(stage).StartsWith(allowed,StringComparison.OrdinalIgnoreCase))Directory.Delete(stage,true);
  }
 }
}
