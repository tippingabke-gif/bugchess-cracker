using System.Runtime.Versioning;

// Select modern System.IO defaults before any static field accesses a path.
// Setting AppContext switches inside extraction is too late once cached.
[assembly: TargetFramework(".NETFramework,Version=v4.8", FrameworkDisplayName = ".NET Framework 4.8")]
