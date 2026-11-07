using System;
using System.Diagnostics;
using System.IO;
using System.Text.RegularExpressions;

namespace BCStorage
{
    internal static class Uninstall
    {
        public static ProcessStartInfo Prepare(string command)
        {
            if (String.IsNullOrWhiteSpace(command)) return null;
            command = Environment.ExpandEnvironmentVariables(command.Trim());
            var parts = Regex.Match(command,
                @"^(?:""(?<exe>[^""]+\.exe)""|(?<exe>[^""]+?\.exe)|(?<exe>msiexec))(?=\s|$)\s*(?<args>.*)$",
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
            if (!parts.Success) return null;
            string exe = parts.Groups["exe"].Value;
            string args = parts.Groups["args"].Value;
            if (exe.Equals("msiexec", StringComparison.OrdinalIgnoreCase) ||
                Path.GetFileName(exe).Equals("msiexec.exe", StringComparison.OrdinalIgnoreCase))
            {
                var product = Regex.Match(args, @"^/[ix]\s*(?<id>\{[0-9a-f-]{36}\})\s*$",
                    RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
                Guid id;
                if (!product.Success || !Guid.TryParseExact(product.Groups["id"].Value, "B", out id)) return null;
                exe = Path.Combine(Environment.SystemDirectory, "msiexec.exe");
                args = "/x " + id.ToString("B");
            }
            if (exe.Length < 4 || exe[1] != ':' || exe[2] != '\\' || !File.Exists(exe)) return null;
            return new ProcessStartInfo(exe, args) { UseShellExecute = true, WorkingDirectory = Path.GetDirectoryName(exe) };
        }
    }
}
