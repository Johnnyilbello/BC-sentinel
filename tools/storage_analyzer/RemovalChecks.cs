using System;
using System.IO;
using BCStorage;

internal static class RemovalChecks
{
    [STAThread]
    private static void Main(string[] args)
    {
        var root = args[0];
        string original = Path.Combine(root, "da-cestinare-" + Guid.NewGuid().ToString("N") + ".txt");
        string permanent = Path.Combine(root, "da-eliminare");
        Directory.CreateDirectory(permanent);
        File.WriteAllText(Path.Combine(permanent, "campione.txt"), "prova");
        File.WriteAllText(original, "prova");
        if (!Removal.IsProtected(@"C:\") || !Removal.IsProtected(@"C:\pagefile.sys"))
            throw new Exception("Protected path rule failed");
        try
        {
            Removal.Validate(permanent, false);
            throw new Exception("Type validation failed");
        }
        catch (IOException) { }
        if (!Removal.Execute(permanent, true, false, IntPtr.Zero) || Directory.Exists(permanent))
            throw new Exception("Permanent removal failed");
        if (!Removal.Execute(original, false, true, IntPtr.Zero) || File.Exists(original))
            throw new Exception("Recycle failed");
        Console.WriteLine(Path.GetFileName(original));
    }
}
