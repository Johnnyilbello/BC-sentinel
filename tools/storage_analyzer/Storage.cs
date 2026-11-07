using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

namespace BCStorage
{
    internal sealed class Entry
    {
        public readonly long Bytes;
        public readonly string Path;
        public Entry(string path, long bytes) { Path = path; Bytes = bytes; }
    }

    internal sealed class TopEntries
    {
        public const int Limit = 500;
        private readonly SortedSet<Entry> items = new SortedSet<Entry>(
            Comparer<Entry>.Create((a, b) =>
            {
                int size = a.Bytes.CompareTo(b.Bytes);
                return size != 0 ? size : -StringComparer.Ordinal.Compare(a.Path, b.Path);
            }));

        public void Add(string path, long bytes)
        {
            if (items.Count == Limit && bytes < items.Min.Bytes) return;
            if (items.Add(new Entry(path, bytes)) && items.Count > Limit) items.Remove(items.Min);
        }

        public IEnumerable<Entry> Descending { get { return items.Reverse(); } }
    }

    internal sealed class ExtensionStat
    {
        public long Bytes;
        public long Count;
    }

    internal sealed class ScanIssue
    {
        public readonly string Path;
        public readonly int Code;
        public ScanIssue(string path, int code) { Path = path; Code = code; }
    }

    internal sealed class ScanResult
    {
        public readonly TopEntries Files = new TopEntries();
        public readonly TopEntries Folders = new TopEntries();
        public readonly TopEntries RootFolders = new TopEntries();
        public readonly List<ScanIssue> Issues = new List<ScanIssue>();
        public readonly Dictionary<string, ExtensionStat> Extensions =
            new Dictionary<string, ExtensionStat>(StringComparer.OrdinalIgnoreCase);
        public long FileCount, FolderCount, Bytes, AccessDenied, OtherErrors, Links;
        public bool Cancelled;

        public void AddIssue(string path, int code)
        {
            if (code == 5) AccessDenied++;
            else OtherErrors++;
            if (Issues.Count < 200) Issues.Add(new ScanIssue(path, code));
        }
    }

    internal static class Scanner
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct FindData
        {
            public uint Attributes;
            public System.Runtime.InteropServices.ComTypes.FILETIME Creation, Access, Write;
            public uint SizeHigh, SizeLow, ReparseTag, Reserved;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string Name;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 14)] public string ShortName;
        }

        private sealed class FindHandle : SafeHandleMinusOneIsInvalid
        {
            private FindHandle() : base(true) { }
            protected override bool ReleaseHandle() { return FindClose(handle); }
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern FindHandle FindFirstFileEx(string path, int infoLevel, out FindData data,
            int searchOperation, IntPtr filter, int flags);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool FindNextFile(FindHandle handle, out FindData data);
        [DllImport("kernel32.dll")]
        private static extern bool FindClose(IntPtr handle);

        private sealed class Folder : IDisposable
        {
            public readonly string Path;
            private FindHandle handle;
            public long Bytes;
            public Folder(string path) { Path = path; }

            public bool Next(out FindData data, out int error)
            {
                bool success;
                if (handle == null)
                {
                    string pattern = @"\\?\" + Path.TrimEnd('\\') + @"\*";
                    handle = FindFirstFileEx(pattern, 1, out data, 0, IntPtr.Zero, 2);
                    error = Marshal.GetLastWin32Error();
                    // Some file systems do not accept the large fetch hint.
                    if (handle.IsInvalid && (error == 50 || error == 87))
                    {
                        handle.Dispose();
                        handle = FindFirstFileEx(pattern, 1, out data, 0, IntPtr.Zero, 0);
                        error = Marshal.GetLastWin32Error();
                    }
                    success = !handle.IsInvalid;
                    if (error == 2) error = 0; // Empty wildcard match.
                }
                else
                {
                    success = FindNextFile(handle, out data);
                    error = Marshal.GetLastWin32Error();
                    if (error == 18) error = 0; // End of directory.
                }
                return success;
            }

            public void Dispose() { if (handle != null) handle.Dispose(); }
        }

        public static ScanResult Run(IEnumerable<string> roots, CancellationToken token,
            Action<string, long, long> report)
        {
            var result = new ScanResult();
            var stack = new Stack<Folder>();
            var watch = Stopwatch.StartNew();
            foreach (string root in roots)
            {
                if (token.IsCancellationRequested) break;
                report(root, result.FileCount, result.Bytes);
                stack.Push(new Folder(root));
                try
                {
                    while (stack.Count > 0 && !token.IsCancellationRequested)
                    {
                        var folder = stack.Peek();
                        if (watch.ElapsedMilliseconds >= 250)
                        {
                            report(folder.Path, result.FileCount, result.Bytes);
                            watch.Restart();
                        }
                        FindData data;
                        int error;
                        if (!folder.Next(out data, out error))
                        {
                            stack.Pop().Dispose();
                            if (error != 0) result.AddIssue(folder.Path, error);
                            if (stack.Count > 0)
                            {
                                stack.Peek().Bytes += folder.Bytes;
                                if (folder.Bytes > 0)
                                {
                                    result.Folders.Add(folder.Path, folder.Bytes);
                                    if (stack.Count == 1) result.RootFolders.Add(folder.Path, folder.Bytes);
                                }
                            }
                            continue;
                        }
                        if (data.Name == "." || data.Name == "..") continue;
                        bool directory = (data.Attributes & 0x10) != 0;
                        bool reparse = (data.Attributes & 0x400) != 0;
                        if (reparse && (directory || data.ReparseTag == 0xA000000C))
                        {
                            result.Links++;
                            continue;
                        }
                        if (directory)
                        {
                            result.FolderCount++;
                            stack.Push(new Folder(Combine(folder.Path, data.Name)));
                            continue;
                        }
                        long bytes = ((long)data.SizeHigh << 32) | data.SizeLow;
                        folder.Bytes += bytes;
                        result.Bytes += bytes;
                        result.FileCount++;
                        result.Files.Add(Combine(folder.Path, data.Name), bytes);
                        int dot = data.Name.LastIndexOf('.');
                        string extension = dot <= 0 || dot == data.Name.Length - 1
                            ? "(senza estensione)" : data.Name.Substring(dot).ToLowerInvariant();
                        ExtensionStat stat;
                        if (!result.Extensions.TryGetValue(extension, out stat))
                            result.Extensions.Add(extension, stat = new ExtensionStat());
                        stat.Count++;
                        stat.Bytes += bytes;
                    }
                }
                finally
                {
                    while (stack.Count > 0) stack.Pop().Dispose();
                }
            }
            result.Cancelled = token.IsCancellationRequested;
            return result;
        }

        private static string Combine(string directory, string name)
        {
            return directory.EndsWith(@"\", StringComparison.Ordinal)
                ? directory + name : directory + @"\" + name;
        }
    }

    internal sealed class Volume
    {
        public string Root, Label, Kind;
        public long Total, Free;
        public bool Ready;
        public override string ToString()
        {
            return String.IsNullOrWhiteSpace(Label) ? Root : Root + "  ·  " + Label;
        }
    }

    internal sealed class InstalledApp
    {
        public string Name, Version, Publisher, Uninstall;
        public long? Bytes;
    }

    internal sealed class ProcessRam
    {
        public string Name;
        public int Pid;
        public long Bytes;
    }

    internal sealed class RamSnapshot
    {
        public long Total, Available;
        public int Skipped;
        public readonly List<ProcessRam> Processes = new List<ProcessRam>();
    }

    internal static class Inventory
    {
        public static List<Volume> Volumes()
        {
            var volumes = new List<Volume>();
            foreach (var drive in DriveInfo.GetDrives())
            {
                var volume = new Volume { Root = drive.Name };
                try
                {
                    switch (drive.DriveType)
                    {
                        case DriveType.Fixed: volume.Kind = "Disco locale"; break;
                        case DriveType.Removable: volume.Kind = "Rimovibile"; break;
                        case DriveType.Ram: volume.Kind = "Disco RAM"; break;
                        case DriveType.CDRom: volume.Kind = "Ottica"; break;
                        default: continue;
                    }
                    if (drive.IsReady)
                    {
                        volume.Total = drive.TotalSize;
                        volume.Free = drive.TotalFreeSpace;
                        volume.Label = drive.VolumeLabel;
                        volume.Ready = true;
                    }
                }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
                volumes.Add(volume);
            }
            return volumes.OrderByDescending(v => v.Ready ? (long?)(v.Total - v.Free) : null)
                .ThenBy(v => v.Root).ToList();
        }

        public static List<InstalledApp> Apps()
        {
            const string path = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
            var apps = new Dictionary<string, InstalledApp>(StringComparer.OrdinalIgnoreCase);
            var views = Environment.Is64BitOperatingSystem
                ? new[] { RegistryView.Registry64, RegistryView.Registry32 }
                : new[] { RegistryView.Registry32 };
            foreach (var hive in new[] { RegistryHive.LocalMachine, RegistryHive.CurrentUser })
            foreach (var view in views)
            {
                try
                {
                    using (var root = RegistryKey.OpenBaseKey(hive, view))
                    using (var list = root.OpenSubKey(path))
                    {
                        if (list == null) continue;
                        foreach (string subkey in list.GetSubKeyNames())
                        {
                            try
                            {
                                using (var key = list.OpenSubKey(subkey))
                                {
                                    if (key == null || Object.Equals(key.GetValue("SystemComponent"), 1)
                                        || !String.IsNullOrEmpty(key.GetValue("ParentKeyName") as string)) continue;
                                    string name = key.GetValue("DisplayName") as string;
                                    if (String.IsNullOrWhiteSpace(name)) continue;
                                    string version = key.GetValue("DisplayVersion") as string ?? "";
                                    string publisher = key.GetValue("Publisher") as string ?? "";
                                    long? bytes = AppSize(key.GetValue("EstimatedSize"));
                                    string id = hive + "|" + subkey + "|" + name + "|" + version + "|" + publisher;
                                    InstalledApp existing;
                                    string uninstall = key.GetValue("UninstallString") as string;
                                    if (!apps.TryGetValue(id, out existing))
                                        apps[id] = new InstalledApp { Name = name, Version = version,
                                            Publisher = publisher, Bytes = bytes, Uninstall = uninstall };
                                    else
                                    {
                                        if (bytes.HasValue && (!existing.Bytes.HasValue || bytes > existing.Bytes))
                                            existing.Bytes = bytes;
                                        if (String.IsNullOrWhiteSpace(existing.Uninstall)) existing.Uninstall = uninstall;
                                    }
                                }
                            }
                            catch (IOException) { }
                            catch (UnauthorizedAccessException) { }
                            catch (System.Security.SecurityException) { }
                        }
                    }
                }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
                catch (System.Security.SecurityException) { }
            }
            return apps.Values.OrderByDescending(app => app.Bytes).ThenBy(app => app.Name).ToList();
        }

        internal static long? AppSize(object value)
        {
            // EstimatedSize is an optional installer-supplied DWORD in KiB.
            if (!(value is int) || (int)value <= 0) return null;
            return (long)(int)value * 1024;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MemoryStatus
        {
            public uint Length, Load;
            public ulong Total, Available, TotalPage, AvailablePage, TotalVirtual, AvailableVirtual, Extended;
        }
        [DllImport("kernel32.dll")]
        private static extern bool GlobalMemoryStatusEx(ref MemoryStatus status);

        public static RamSnapshot Ram()
        {
            var result = new RamSnapshot();
            var status = new MemoryStatus { Length = (uint)Marshal.SizeOf(typeof(MemoryStatus)) };
            if (GlobalMemoryStatusEx(ref status))
            {
                result.Total = (long)status.Total;
                result.Available = (long)status.Available;
            }
            foreach (var process in Process.GetProcesses())
            {
                using (process)
                {
                    try
                    {
                        if (process.Id == 0) continue;
                        result.Processes.Add(new ProcessRam { Name = process.ProcessName,
                            Pid = process.Id, Bytes = process.WorkingSet64 });
                    }
                    catch (Win32Exception) { result.Skipped++; }
                    catch (InvalidOperationException) { result.Skipped++; }
                    catch (NotSupportedException) { result.Skipped++; }
                }
            }
            result.Processes.Sort((a, b) => b.Bytes.CompareTo(a.Bytes));
            return result;
        }
    }

    internal static class Csv
    {
        internal static string Field(object value)
        {
            string raw = Convert.ToString(value, CultureInfo.GetCultureInfo("it-IT")) ?? "";
            if (value is string)
            {
                string trimmed = raw.TrimStart();
                if ((raw.Length > 0 && (raw[0] == '\t' || raw[0] == '\r' || raw[0] == '\n'))
                    || (trimmed.Length > 0 && "=+-@".IndexOf(trimmed[0]) >= 0))
                    raw = "'" + raw;
            }
            return "\"" + raw.Replace("\"", "\"\"") + "\"";
        }

        public static void Write(string path, IEnumerable<string> headers, IEnumerable<object[]> rows)
        {
            using (var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            using (var writer = new StreamWriter(stream, new UTF8Encoding(true)))
            {
                writer.WriteLine(String.Join(";", headers.Select(Field)));
                foreach (var row in rows) writer.WriteLine(String.Join(";", row.Select(Field)));
            }
        }
    }
}
