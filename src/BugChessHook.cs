using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Text;
using System.Windows.Forms;

internal static class BugChessTestEntry
{
    private static int Main(string[] args)
    {
        if(args.Length!=2 || args[0]!="--component")return 2;
        bool interactive = !Console.IsInputRedirected && !Console.IsOutputRedirected;
        string userError = null;
        Console.OutputEncoding = new UTF8Encoding(false);
        string support = AppDomain.CurrentDomain.BaseDirectory;
        var start = new ProcessStartInfo {
            FileName = Path.Combine(support,"runtime","python","python.exe"),
            Arguments = "-I -X utf8 \""+Path.Combine(support,"runtime","lab","guest_original_bridge_v179.py")+"\" --component \""+args[1]+"\"",
            WorkingDirectory = Path.GetDirectoryName(args[1]),
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8
        };
        try {
            using (var child = Process.Start(start)) {
                var input = new Thread(() => {
                    try {
                        string line;
                        while ((line = Console.ReadLine()) != null) {
                            child.StandardInput.WriteLine(line);
                            child.StandardInput.Flush();
                            if (line.Trim() == "quit") break;
                        }
                        child.StandardInput.Close();
                    } catch (IOException) { } catch (ObjectDisposedException) { }
                });
                var output = new Thread(() => {
                    try {
                        string line;
                        while ((line = child.StandardOutput.ReadLine()) != null) {
                            Console.WriteLine(line);
                            Console.Out.Flush();
                        }
                    } catch (IOException) { }
                });
                var error = new Thread(() => {
                    try {
                        string line;
                        while ((line = child.StandardError.ReadLine()) != null) {
                            if (line.StartsWith("BUGCHESS_HELPER_ERROR:", StringComparison.Ordinal))
                                userError = line.Substring("BUGCHESS_HELPER_ERROR:".Length);
                            Console.Error.WriteLine(line);
                        }
                    } catch (IOException) { }
                });
                input.IsBackground = output.IsBackground = error.IsBackground = true;
                input.Start(); output.Start(); error.Start();
                child.WaitForExit();
                output.Join(3000); error.Join(3000);
                if (child.ExitCode != 0 && interactive)
                    MessageBox.Show(userError ?? "引擎启动未完成，请检查组件安装状态，并查看对应版本的 last-run.json。", "小虫引擎加载提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return child.ExitCode;
            }
        } catch (Exception ex) {
            Console.Error.WriteLine("BugChess test entry: " + ex.Message);
            return 1;
        }
    }
}
