using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using System.Windows.Forms;
using Microsoft.Win32;

[assembly: AssemblyTitle("小虫引擎破解器")]
[assembly: AssemblyProduct("小虫引擎破解器")]
[assembly: AssemblyVersion("1.0.0.220")]

sealed class Installation {
 public int schema=1, oldUseFilter;
 public bool hadUseFilter;
 public string engine,hook,hookSha256,exeSha256,parent,filter,debugger;
}

static class Components {
 internal const string SupportName="tippingabke-gif";
 const string ProductName="小虫引擎破解器";
 const string AccountText="00000000\nhttps://github.com/tippingabke-gif\n";
 static readonly string Root=AppDomain.CurrentDomain.BaseDirectory;
 static readonly string Support=Path.Combine(Root,SupportName);
 static readonly string Hook=Path.Combine(Support,"BugChessHookPermanent.exe");
 static readonly string NetworkExe=Path.Combine(Support,"BugChessNetwork.exe");
 const string Ifeo=@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
 static readonly string[] Variants={"SSE4","AVX2","BMI2","AVX512"};
 static readonly string[] Hashes={
  "823ba67b56f18e9ea49ffeb18858410fa96f970008807e936b771f2372bfce9d",
  "20d0d7ff2cb83c9387649b495db126247e0ad1489d9364234e222ceae770d082",
  "11d1de3f2d17cfe5ac754d59ff2247a2b74eff1d65ee77ce6b1dcf1fb12931a0",
  "073dbe80801a9228d62cc84d0577c04cd1a87d7c6b7d7a4b598e2100efb563f8"};
 static readonly JavaScriptSerializer Json=new JavaScriptSerializer();
 static string Engine(string v){return Path.Combine(Root,"BugChessNN_20260627_release_"+v+".exe");}
 static string State(string v){return Path.Combine(Support,v,"installed-component.json");}
 static string Quote(string s){return "\""+s+"\"";}
 static string Digest(string p){using(var h=SHA256.Create())using(var f=File.OpenRead(p))return BitConverter.ToString(h.ComputeHash(f)).Replace("-","").ToLowerInvariant();}
 static string Filter(string p){using(var h=SHA256.Create())return "BugChessComponents_"+BitConverter.ToString(h.ComputeHash(Encoding.Unicode.GetBytes(p.ToLowerInvariant()))).Replace("-","").Substring(0,16);}
 static void Save(string v,Installation s){
  string path=State(v),temp=path+".tmp";
  File.WriteAllText(temp,Json.Serialize(s),new UTF8Encoding(false));
  if(File.Exists(path))File.Replace(temp,path,null);else File.Move(temp,path);
 }
 static Installation Read(string v){return ReadAt(v,Support);}
 static Installation ReadAt(string v,string support){
  string hook=Path.Combine(support,"BugChessHookPermanent.exe");
  var s=Json.Deserialize<Installation>(File.ReadAllText(Path.Combine(support,v,"installed-component.json"),Encoding.UTF8));
  if(s.schema!=1 || !String.Equals(s.engine,Engine(v),StringComparison.OrdinalIgnoreCase) ||
   !String.Equals(s.hook,hook,StringComparison.OrdinalIgnoreCase) || s.filter!=Filter(s.engine) ||
   s.parent!=Ifeo+"\\"+Path.GetFileName(s.engine) || s.debugger!=Quote(hook)+" --component")
   throw new Exception("组件安装记录与当前目录不一致："+v+"。请在原安装目录卸载后再移动。");
  return s;
 }
 static void CheckRule(RegistryKey parent,Installation s){
  if(parent==null)throw new Exception("组件启动规则缺失。");
  using(var filter=parent.OpenSubKey(s.filter)){
   if(filter==null || !String.Equals(filter.GetValue("FilterFullPath") as string,s.engine,StringComparison.OrdinalIgnoreCase) ||
    !Object.Equals(filter.GetValue("Debugger"),s.debugger))throw new Exception("组件启动规则已变化，已保留现状。");
  }
 }
 static void Network(string mode){
  var paths=new List<string>();foreach(string v in Variants)paths.Add(Engine(v));paths.Add(Hook);paths.Add(NetworkExe);
  var info=new ProcessStartInfo(NetworkExe,mode+" "+String.Join(" ",paths.ConvertAll(Quote).ToArray()));
  info.UseShellExecute=false;info.CreateNoWindow=true;info.RedirectStandardOutput=true;info.RedirectStandardError=true;
  using(var p=Process.Start(info)){
   string stdout=p.StandardOutput.ReadToEnd(),stderr=p.StandardError.ReadToEnd();
   if(!p.WaitForExit(20000))throw new Exception("程序网络规则处理超时。");
   if(p.ExitCode!=0)throw new Exception("程序网络规则处理失败："+stderr+stdout);
  }
 }
 static void EnsureIdle(){
  var names=new List<string>{"BugChessHookPermanent"};foreach(string v in Variants)names.Add(Path.GetFileNameWithoutExtension(Engine(v)));
  foreach(string name in names)foreach(var p in Process.GetProcessesByName(name))using(p){
   try{
    string file=p.MainModule.FileName;
    if(file.StartsWith(Root.TrimEnd('\\')+"\\",StringComparison.OrdinalIgnoreCase))
      throw new InvalidOperationException("请先在棋盘中卸载本目录的引擎，再更新或卸载组件。");
   }catch(System.ComponentModel.Win32Exception){throw new Exception("有同名进程的路径尚未核实，请先关闭它再卸载组件。");}
  }
 }
 static void MigrateLegacy(){
  string legacy=Path.Combine(Root,"BugChessSupport-v148");
  if(!Directory.Exists(legacy))return;
  EnsureIdle();
  if(Directory.Exists(Support))throw new Exception("新旧支持目录同时存在，请保留现场并检查组件安装记录。");
  if((File.GetAttributes(legacy)&FileAttributes.ReparsePoint)!=0)throw new Exception("旧支持目录为链接，请检查实际安装位置。");
  string marker=Path.Combine(legacy,"bundle-version.txt");
  if(!File.Exists(marker)||File.ReadAllText(marker)!="210")throw new Exception("此旧组件版本需先使用原安装器卸载，然后使用新的原包目录安装。");
  var states=new Dictionary<string,Installation>();
  var backup=new Dictionary<string,byte[]>();
  string oldHook=Path.Combine(legacy,"BugChessHookPermanent.exe");
  string oldDebugger=Quote(oldHook)+" --component",newDebugger=Quote(Hook)+" --component";
  using(var machine=RegistryKey.OpenBaseKey(RegistryHive.LocalMachine,RegistryView.Registry64)){
   foreach(string v in Variants){
    string state=Path.Combine(legacy,v,"installed-component.json");
    if(File.Exists(state)){
     var s=ReadAt(v,legacy);if(Digest(oldHook)!=s.hookSha256)throw new Exception("旧启动组件校验失败。");
     using(var parent=machine.OpenSubKey(s.parent)){CheckRule(parent,s);if(!Object.Equals(parent.GetValue("UseFilter"),1))throw new Exception("旧路径过滤开关已变化。");}
     states.Add(v,s);backup.Add(v+"\\installed-component.json",File.ReadAllBytes(state));
    }else using(var parent=machine.OpenSubKey(Ifeo+"\\"+Path.GetFileName(Engine(v))))if(parent!=null)using(var f=parent.OpenSubKey(Filter(Engine(v))))if(f!=null)throw new Exception("旧启动规则缺少对应安装记录，已保留现场。");
   }
  }
  backup.Add("bundle-version.txt",File.ReadAllBytes(marker));
  backup.Add("BugChessHookPermanent.exe",File.ReadAllBytes(oldHook));
  foreach(string file in Directory.GetFiles(Path.Combine(legacy,"runtime","lab"),"*.py",SearchOption.AllDirectories))
   if(File.ReadAllText(file,Encoding.UTF8).Contains("BugChessSupport-v148"))backup.Add(file.Substring(legacy.Length+1),File.ReadAllBytes(file));
  bool moved=false;var changed=new List<string>();
  try{
   Directory.Move(legacy,Support);moved=true;
   PortableBundle.RenameReferences(Support);PortableBundle.UpdateHook(Support);PortableBundle.UpdateThreadRuntime(Support);
   string hookHash=Digest(Hook);
   using(var machine=RegistryKey.OpenBaseKey(RegistryHive.LocalMachine,RegistryView.Registry64))foreach(var pair in states){
    var s=pair.Value;
    using(var parent=machine.OpenSubKey(s.parent,true)){
     CheckRule(parent,s);using(var f=parent.OpenSubKey(s.filter,true))f.SetValue("Debugger",newDebugger,RegistryValueKind.String);
    }
    changed.Add(pair.Key);s.hook=Hook;s.debugger=newDebugger;s.hookSha256=hookHash;Save(pair.Key,s);
   }
   PortableBundle.ProjectLink(Support);
   File.WriteAllText(Path.Combine(Support,"bundle-version.txt"),PortableBundle.BundleVersion,new UTF8Encoding(false));
  }catch(Exception original){
   try{
    using(var machine=RegistryKey.OpenBaseKey(RegistryHive.LocalMachine,RegistryView.Registry64))foreach(string v in changed){
     var s=states[v];using(var f=machine.OpenSubKey(s.parent+"\\"+s.filter,true)){
      if(f==null||!Object.Equals(f.GetValue("Debugger"),newDebugger))throw new Exception("迁移期间启动规则发生额外变化。");
      f.SetValue("Debugger",oldDebugger,RegistryValueKind.String);
     }
    }
    if(moved){foreach(var pair in backup)File.WriteAllBytes(Path.Combine(Support,pair.Key),pair.Value);Directory.Move(Support,legacy);}
   }catch(Exception rollback){throw new AggregateException("组件迁移和回滚均未完成，请保留目录供检查。",original,rollback);}
   throw;
  }
 }
 static void UpgradeCurrent(){
  string marker=Path.Combine(Support,"bundle-version.txt");
  if(!File.Exists(marker)||File.ReadAllText(marker)!="214")return;
  EnsureIdle();
  if((File.GetAttributes(Support)&FileAttributes.ReparsePoint)!=0)throw new Exception("支持目录为链接，请检查实际安装位置。");
  using(var machine=RegistryKey.OpenBaseKey(RegistryHive.LocalMachine,RegistryView.Registry64))foreach(string v in Variants){
   if(File.Exists(State(v))){
    var s=Read(v);if(Digest(Hook)!=s.hookSha256)throw new Exception("启动组件校验失败。");
    using(var parent=machine.OpenSubKey(s.parent)){CheckRule(parent,s);if(!Object.Equals(parent.GetValue("UseFilter"),1))throw new Exception("路径过滤开关已变化。");}
   }else using(var parent=machine.OpenSubKey(Ifeo+"\\"+Path.GetFileName(Engine(v))))if(parent!=null)using(var f=parent.OpenSubKey(Filter(Engine(v))))if(f!=null)throw new Exception("启动规则缺少对应安装记录，已保留现场。");
  }
  string bridge=Path.Combine(Support,"runtime","lab","guest_four_variant_bridge_v145.py");
  byte[] original=File.ReadAllBytes(bridge),oldMarker=File.ReadAllBytes(marker);
  try{
   PortableBundle.UpdateThreadRuntime(Support);
   File.WriteAllText(marker,PortableBundle.BundleVersion,new UTF8Encoding(false));
  }catch{File.WriteAllBytes(bridge,original);File.WriteAllBytes(marker,oldMarker);throw;}
 }
 static void Install(){
  if(!File.Exists(Hook)||!File.Exists(NetworkExe)||!File.Exists(Path.Combine(Root,"weights_20260627.bin")))throw new Exception("组件或权重文件不完整。");
  string hookHash=Digest(Hook);
  for(int i=0;i<Variants.Length;i++)if(!File.Exists(Engine(Variants[i]))||Digest(Engine(Variants[i]))!=Hashes[i])throw new Exception("原引擎校验失败："+Variants[i]);
  string account=Path.Combine(Root,"account.txt");
  if(File.Exists(account) && File.ReadAllText(account,Encoding.ASCII).Replace("\r\n","\n")!=AccountText)
   throw new Exception("account.txt 已存在其他内容，已保留。请备份并移走后重新运行破解器。");
  var additions=new List<string>();
  try{
   Network("install");Network("verify");
   using(var machine=RegistryKey.OpenBaseKey(RegistryHive.LocalMachine,RegistryView.Registry64)){
    for(int i=0;i<Variants.Length;i++){
     string v=Variants[i];
     if(File.Exists(State(v))){var existing=Read(v);using(var parent=machine.OpenSubKey(existing.parent)){CheckRule(parent,existing);if(!Object.Equals(parent.GetValue("UseFilter"),1))throw new Exception("路径过滤开关已变化。");}continue;}
     var s=new Installation{engine=Engine(v),hook=Hook,hookSha256=hookHash,exeSha256=Hashes[i],parent=Ifeo+"\\"+Path.GetFileName(Engine(v)),filter=Filter(Engine(v)),debugger=Quote(Hook)+" --component"};
     using(var parent=machine.CreateSubKey(s.parent)){
      if(parent.GetValue("Debugger")!=null)throw new Exception("存在全局启动规则，已保留："+v);
      object value=parent.GetValue("UseFilter");
      if(value!=null && !(value is int))throw new Exception("UseFilter 类型不兼容。");
      s.hadUseFilter=value!=null;s.oldUseFilter=value==null?0:(int)value;
      if(parent.SubKeyCount>0&&!Object.Equals(value,1))throw new Exception("存在未启用的其他路径过滤，已保留。");
      foreach(string name in parent.GetSubKeyNames())using(var f=parent.OpenSubKey(name))if(String.Equals(f.GetValue("FilterFullPath") as string,s.engine,StringComparison.OrdinalIgnoreCase))throw new Exception("此原文件路径已有其他接管，请先卸载原接管。");
      Save(v,s);additions.Add(v);
      using(var f=parent.CreateSubKey(s.filter)){f.SetValue("FilterFullPath",s.engine,RegistryValueKind.String);f.SetValue("Debugger",s.debugger,RegistryValueKind.String);}
      parent.SetValue("UseFilter",1,RegistryValueKind.DWord);
     }
    }
   }
   if(!File.Exists(account))using(var f=new FileStream(account,FileMode.CreateNew,FileAccess.Write,FileShare.None)){
    byte[] data=Encoding.ASCII.GetBytes(AccountText.Replace("\n","\r\n"));f.Write(data,0,data.Length);
   }
  }catch{for(int i=additions.Count-1;i>=0;i--){try{Remove(additions[i],false);}catch{}}throw;}
 }
 static void Remove(string v,bool strict){
  if(!File.Exists(State(v)))return;
  var s=Read(v);
  using(var machine=RegistryKey.OpenBaseKey(RegistryHive.LocalMachine,RegistryView.Registry64)){
   using(var parent=machine.OpenSubKey(s.parent,true))if(parent!=null){
    using(var f=parent.OpenSubKey(s.filter))if(f!=null)CheckRule(parent,s);else if(strict)throw new Exception("组件规则缺失，保留安装记录。");
    parent.DeleteSubKeyTree(s.filter,false);
    if(parent.SubKeyCount==0&&Object.Equals(parent.GetValue("UseFilter"),1)){
     if(s.hadUseFilter)parent.SetValue("UseFilter",s.oldUseFilter,RegistryValueKind.DWord);else parent.DeleteValue("UseFilter",false);
    }
   }
   using(var top=machine.OpenSubKey(Ifeo,true)){
    bool empty=false;using(var p=top.OpenSubKey(Path.GetFileName(s.engine)))if(p!=null)empty=p.ValueCount==0&&p.SubKeyCount==0;
    if(empty)top.DeleteSubKey(Path.GetFileName(s.engine),false);
   }
  }
  File.Delete(State(v));
 }
 [STAThread]public static int Main(string[] args){
  bool ui=args.Length==0;string mode=ui?"install":args[0];
  Mutex installerMutex=null;bool ownsMutex=false;
  try{
   installerMutex=new Mutex(false,"Local\\"+Filter(Root));
   try{ownsMutex=installerMutex.WaitOne(0);}catch(AbandonedMutexException){ownsMutex=true;}
   if(!ownsMutex)throw new Exception("组件安装或卸载正在进行，请等待当前操作完成。");
   if(mode=="install"){
    for(int i=0;i<Variants.Length;i++)if(!File.Exists(Engine(Variants[i]))||Digest(Engine(Variants[i]))!=Hashes[i])throw new Exception("请把破解器放在四个原引擎 EXE 所在目录。");
    if(!File.Exists(Path.Combine(Root,"weights_20260627.bin")))throw new Exception("请保留原权重 weights_20260627.bin。");
    MigrateLegacy();UpgradeCurrent();PortableBundle.Ensure(Root,Support);Install();
   }
   else if(mode=="uninstall"){EnsureIdle();foreach(string v in Variants)Remove(v,true);}
   else if(mode=="status"){
    using(var m=RegistryKey.OpenBaseKey(RegistryHive.LocalMachine,RegistryView.Registry64))foreach(string v in Variants){var s=Read(v);using(var p=m.OpenSubKey(s.parent))CheckRule(p,s);if(Digest(Hook)!=s.hookSha256)throw new Exception("组件哈希变化。");}
   }else throw new Exception("Usage: install | uninstall | status");
   File.WriteAllText(Path.Combine(Root,"component-status.json"),Json.Serialize(new {operation=mode,success=true}),new UTF8Encoding(false));
   if(ui)MessageBox.Show("组件已安装，account.txt 已写入指定账号。以后直接在鲨鱼中加载本目录的原 EXE，无需再次打开破解器。\n账号文件、支持目录与权重请保留；移动目录前请先卸载组件。",ProductName);
   Console.WriteLine("OK "+mode);return 0;
  }catch(Exception e){File.WriteAllText(Path.Combine(Root,"component-error.txt"),e.ToString(),new UTF8Encoding(false));if(ui)MessageBox.Show(e.Message,ProductName);Console.Error.WriteLine(e.Message);return 1;}
  finally{if(installerMutex!=null){if(ownsMutex)installerMutex.ReleaseMutex();installerMutex.Dispose();}}
 }
}
