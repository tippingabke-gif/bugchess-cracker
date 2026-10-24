# 源码范围与构建

本目录提供安装器、原 EXE 接入层、整合包入口及安装器实际携带的 Python 运行脚本。小虫和鲨鱼原程序源码不在此仓库；鲨鱼便携启动器源码及所需第三方材料在整合包的“鲨鱼/source”保留。

- BugChessComponents.cs + PortableBundle.cs：单文件安装器，版本 1.0.0.220。
- BugChessHook.cs：原 EXE 入口的 UCI 转发组件。
- BundleLauncher.cs：整合包启动入口。
- runtime/：发布安装器内对应的运行脚本；安装时完成目录重定位。
- payload-manifest.json：内嵌运行文件的路径、大小、SHA-256 清单；不含私人运行日志。

运行时包含 Python、依赖、参考数据、网络组件和 Intel SDE，未把这些二进制作为自有源码上传。已有发布安装器时，可用 tools/export-payload.ps1 提取内嵌 payload.zip，再执行 tools/build-check.ps1 -Payload <payload.zip> 编译安装器。完整匹配 payload-manifest.json 后再用于构建，勿混用其他版本资源。

不带 Payload 参数时，build-check.ps1 只编译源码检查产物，产物不用于安装。CI 负责 Python 语法与 C# 编译检查，不运行引擎，不代表恶意软件扫描、审局库命中或完整棋力验收。
