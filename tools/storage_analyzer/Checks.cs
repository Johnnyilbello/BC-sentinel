using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using BCStorage;

internal static class Checks
{
    private static void Require(bool passed, string description)
    {
        if (!passed) throw new Exception(description);
        Console.WriteLine("OK  " + description);
    }

    private static void Main(string[] args)
    {
        string root = args[0];
        var scan = Scanner.Run(new[] { root + @"\Missing\Path", root }, CancellationToken.None, (p, n, b) => {});
        Require(scan.FileCount == 4 && scan.Bytes == 7952, "Exact file count and logical bytes");
        Require(scan.Files.Descending.Select(e => e.Bytes).SequenceEqual(new long[] { 4096, 3072, 777, 7 }),
            "Files sorted numerically, including a long path");
        Require(scan.RootFolders.Descending.Select(e => e.Bytes).SequenceEqual(new long[] { 4103, 3072 }),
            "First-level folders aggregate their descendants");
        Require(scan.Folders.Descending.Count() > scan.RootFolders.Descending.Count(), "Nested folder view");
        Require(scan.Extensions[".bin"].Count == 2 && scan.Extensions[".bin"].Bytes == 7168,
            "Case-insensitive extension aggregation");
        Require(scan.Extensions["(senza estensione)"].Bytes == 7 && scan.Extensions[".txt"].Bytes == 777,
            "Other extension totals");
        Require(scan.Links == 1 && scan.OtherErrors == 1 && scan.Issues.Count == 1, "Link and missing path handled");
        using (var cancel = new CancellationTokenSource())
        {
            var partial = Scanner.Run(new[] { root }, cancel.Token, (p, n, b) => cancel.Cancel());
            Require(partial.Cancelled && partial.FileCount == 0, "Cancellation and partial data");
        }
        var top = new TopEntries();
        for (int i = 1; i <= 800; i++) top.Add(i.ToString(), i);
        Require(top.Descending.Count() == 500 && top.Descending.First().Bytes == 800 &&
            top.Descending.Last().Bytes == 301, "Top 500 limit");
        var volumes = Inventory.Volumes();
        Require(volumes.Any(v => v.Ready && v.Total >= v.Free && v.Free >= 0), "Live local volume inventory");
        var apps = Inventory.Apps();
        Require(apps.Count > 0 && apps.Select(a => a.Bytes ?? 0).SequenceEqual(apps.Select(a => a.Bytes ?? 0)
            .OrderByDescending(n => n)) && Inventory.AppSize(1024) == 1048576 &&
            Inventory.AppSize(0) == null && Inventory.AppSize("1200") == null, "Apps sorted and sizes validated");
        var ram = Inventory.Ram();
        Require(ram.Processes.Count > 0 && ram.Total > ram.Available && ram.Available > 0 &&
            ram.Processes.Select(p => p.Bytes).SequenceEqual(ram.Processes.Select(p => p.Bytes).OrderByDescending(n => n)),
            "Live RAM and process sorting");
        var msi = Uninstall.Prepare("MsiExec.exe /I{A6E961C2-3F50-4B18-B3AD-34B9E9ED484B}");
        Require(msi != null && msi.Arguments == "/x {a6e961c2-3f50-4b18-b3ad-34b9e9ed484b}" &&
            Uninstall.Prepare(null) == null && Uninstall.Prepare("cmd.exe /c test") == null,
            "Uninstall command parsing without invoking any uninstaller");
        string csv = args[1];
        Csv.Write(csv, new[] { "Percorso", "Dimensione", "Percentuale" },
            new List<object[]> { new object[] { "=1; x\"è", 4096L, 99.5d } });
        string[] lines = File.ReadAllLines(csv);
        Require(lines[1] == "\"'=1; x\"\"è\";\"4096\";\"99,5\"" && File.ReadAllBytes(csv)[0] == 0xef,
            "CSV UTF-8, escaping, formula protection and Italian decimal");
        try
        {
            Csv.Write(csv, new[] { "Header" }, new object[0][]);
            throw new Exception("Export overwrote an existing file");
        }
        catch (IOException) { Require(File.ReadAllLines(csv)[1] == lines[1], "Existing CSV remains intact"); }
    }
}
