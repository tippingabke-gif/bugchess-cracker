using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Windows.Forms;

static class BundleLauncher {
    static readonly string Root = AppDomain.CurrentDomain.BaseDirectory;
    static string Quote(string value) { return "\"" + value + "\""; }
    static int Run(string file, string arguments, int timeout) {
        var info = new ProcessStartInfo(file, arguments) {
            WorkingDirectory = Path.GetDirectoryName(file), UseShellExecute = false,
            CreateNoWindow = true
        };
        using (var child = Process.Start(info)) {
            if (!child.WaitForExit(timeout)) throw new Exception("准备仍在进行，请等待已有进程结束后再启动。\n" + Path.GetFileName(file));
            return child.ExitCode;
        }
    }
    [STAThread] static int Main() {
        string id;
        using (var hash = SHA256.Create()) id = BitConverter.ToString(hash.ComputeHash(Encoding.Unicode.GetBytes(Root.ToLowerInvariant()))).Replace("-", "");
        bool created;
        using (var mutex = new Mutex(true, "Local\\BugChessBundle_" + id, out created)) {
            if (!created) return 0;
            Application.EnableVisualStyles();
            var form = new Form { Text = "小虫引擎 · 鲨鱼整合包", Width = 490, Height = 145, StartPosition = FormStartPosition.CenterScreen, FormBorderStyle = FormBorderStyle.FixedDialog, MaximizeBox = false, MinimizeBox = false };
            var label = new Label { Left = 18, Top = 18, Width = 450, Height = 36, Text = "正在检查小虫组件，请稍候…" };
            var progress = new ProgressBar { Left = 18, Top = 58, Width = 440, Style = ProgressBarStyle.Marquee };
            form.Controls.Add(label); form.Controls.Add(progress);
            int code = 0;
            form.Shown += delegate {
                new Thread(delegate() {
                    try {
                        string engine = Path.Combine(Root, "小虫", "BugChessCracker.exe");
                        string launcher = Path.Combine(Root, "鲨鱼", "ChessShark_便携启动修复.exe");
                        string board = Path.Combine(Root, "鲨鱼", "ChessShark.exe");
                        if (!File.Exists(engine) || !File.Exists(launcher) || !File.Exists(board)) throw new Exception("请先完整解压整合包，再从根目录运行启动鲨鱼.exe。");
                        if (Run(engine, "status", 30000) != 0) {
                            form.Invoke((Action)(() => label.Text = "正在安装小虫组件，首次准备需要一些时间…"));
                            if (Run(engine, "install", 180000) != 0) throw new Exception("小虫组件安装未完成，请查看小虫目录中的 component-error.txt。");
                        }
                        form.Invoke((Action)(() => label.Text = "组件已就绪，正在打开鲨鱼…"));
                        if (Run(launcher, "--no-dialog --target " + Quote(board), 180000) != 0) throw new Exception("鲨鱼启动未完成，请查看鲨鱼目录下的启动器记录。");
                    } catch (Exception ex) {
                        code = 1;
                        try { File.WriteAllText(Path.Combine(Root, "启动错误.txt"), ex.ToString(), new UTF8Encoding(false)); } catch { }
                        MessageBox.Show(ex.Message, "小虫引擎 · 启动提示", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    } finally { if (!form.IsDisposed) form.BeginInvoke((Action)(() => form.Close())); }
                }) { IsBackground = true }.Start();
            };
            Application.Run(form);
            return code;
        }
    }
}
