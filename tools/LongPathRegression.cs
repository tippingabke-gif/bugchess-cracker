using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Web.Script.Serialization;

// Exercise the production extractor without starting engines or changing the system.
static class Components { internal const string SupportName = "tippingabke-gif"; }

static class LongPathRegression {
    // This access happens before Main, as in the production installer.
    static readonly string EarlyPath = Path.GetFullPath(AppDomain.CurrentDomain.BaseDirectory);
    static LongPathRegression() { }
    static void Require(bool condition, string message) {
        if (!condition) throw new Exception(message);
    }
    static string Hash(Stream input) {
        using (var hash = SHA256.Create()) return BitConverter.ToString(hash.ComputeHash(input));
    }
    static int Main(string[] args) {
        try {
            string root = Path.GetFullPath(args[0]), mode = args[1];
            string support = Path.Combine(root, Components.SupportName);
            string stage = support + ".installing-" + Process.GetCurrentProcess().Id;
            Require(!Directory.Exists(support), "Test requires a fresh support directory.");
            Directory.CreateDirectory(root);
            var watch = Stopwatch.StartNew();
            int files = 0, unchanged = 0, relocated = 0, longest = 0, stageLongest = 0;
            if (mode == "success") {
                PortableBundle.Ensure(root, support);
                Require(!Directory.Exists(stage), "Staging directory was not renamed.");
                using (var resource = Assembly.GetExecutingAssembly().GetManifestResourceStream("BugChess.Payload"))
                using (var zip = new ZipArchive(resource, ZipArchiveMode.Read)) {
                    foreach (var entry in zip.Entries) {
                        if (entry.FullName.EndsWith("/")) continue;
                        string relative = entry.FullName.Replace('/', '\\');
                        string file = Path.Combine(support, relative);
                        Require(File.Exists(file), "Missing extracted file: " + relative);
                        files++;
                        longest = Math.Max(longest, file.Length);
                        stageLongest = Math.Max(stageLongest, Path.Combine(stage, relative).Length);
                        if (entry.FullName.StartsWith("runtime/lab/") && entry.FullName.EndsWith(".py")) {
                            string text = File.ReadAllText(file, Encoding.UTF8);
                            Require(!text.Contains(@"C:\Lab\BugChess20260627") &&
                                !text.Contains(@"C:\\Lab\\BugChess20260627"), "Unrelocated script: " + relative);
                            Require(!text.Contains("BugChessSupport-v148"), "Old support reference: " + relative);
                            relocated++;
                        } else {
                            using (var original = entry.Open())
                            using (var extracted = File.OpenRead(file))
                                Require(Hash(original) == Hash(extracted), "Hash mismatch: " + relative);
                            unchanged++;
                        }
                    }
                }
                Require(stageLongest > 259, "Fixture did not exercise long paths.");
                Require(File.ReadAllText(Path.Combine(support, "bundle-version.txt")) == PortableBundle.BundleVersion,
                    "Completion marker missing.");
                string marker = Path.Combine(support, "bundle-version.txt");
                DateTime written = File.GetLastWriteTimeUtc(marker);
                PortableBundle.Ensure(root, support);
                Require(File.GetLastWriteTimeUtc(marker) == written, "Second call unexpectedly rewrote installation.");
            } else if (mode == "reject") {
                string sentinel = Path.Combine(root, "escape.txt");
                File.WriteAllText(sentinel, "keep");
                bool rejected = false;
                try { PortableBundle.Ensure(root, support); }
                catch (Exception e) { rejected = e.Message.Contains("组件压缩包路径异常"); }
                Require(rejected, "Traversal archive was not rejected at the containment check.");
                Require(!Directory.Exists(stage) && !Directory.Exists(support), "Partial extraction was not cleaned up.");
                Require(File.ReadAllText(sentinel) == "keep", "Existing outside file changed.");
            } else if (mode == "preserve") {
                Directory.CreateDirectory(support);
                string marker = Path.Combine(support, "bundle-version.txt");
                File.WriteAllText(marker, "unrelated-version");
                bool rejected = false;
                try { PortableBundle.Ensure(root, support); }
                catch (Exception e) { rejected = e.Message.Contains("已有其他版本"); }
                Require(rejected && File.ReadAllText(marker) == "unrelated-version", "Existing support was not preserved.");
                Require(!Directory.Exists(stage), "Unexpected staging directory.");
            } else throw new Exception("Unknown test mode.");
            watch.Stop();
            string report = new JavaScriptSerializer().Serialize(new {
                success = true, mode, files, unchanged, relocated, longest, stageLongest,
                elapsedMs = watch.ElapsedMilliseconds, root, framework = ".NET Framework 4.8",
                earlyPathAccess = !String.IsNullOrEmpty(EarlyPath)
            });
            File.WriteAllText(args[2], report, new UTF8Encoding(false));
            Console.WriteLine(report);
            return 0;
        } catch (Exception e) { Console.Error.WriteLine(e); return 1; }
    }
}
