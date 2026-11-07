using System;
using System.IO;
using System.Runtime.InteropServices;

namespace BCStorage
{
    internal static class Removal
    {
        private const StringComparison IgnoreCase = StringComparison.OrdinalIgnoreCase;
        private static readonly string Windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        private static readonly string AppFolder = AppDomain.CurrentDomain.BaseDirectory.TrimEnd('\\');
        private static readonly string[] ProtectedTrees = { Windows,
            Path.Combine(Path.GetPathRoot(Windows), "System Volume Information"),
            Path.Combine(Path.GetPathRoot(Windows), "Recovery") };
        private static readonly string[] ProtectedRoots = { "Users", "Program Files", "Program Files (x86)",
            "ProgramData", "Documents and Settings", "$Recycle.Bin", "System Volume Information", "Recovery",
            "WindowsApps", "WpSystem", "Boot", "EFI", "pagefile.sys", "swapfile.sys", "hiberfil.sys", "bootmgr" };

        public static bool IsProtected(string path)
        {
            if (String.IsNullOrEmpty(path) || path.Length <= 3 || path[1] != ':' || path[2] != '\\'
                || path.IndexOf(':', 2) >= 0) return true;
            string first = path.Substring(3).Split('\\')[0];
            foreach (string name in ProtectedRoots)
            {
                if (!first.Equals(name, IgnoreCase)) continue;
                if (path.Length == first.Length + 3 || name == "$Recycle.Bin" || name == "Recovery"
                    || name == "System Volume Information" || name == "Boot" || name == "EFI"
                    || name == "WindowsApps" || name == "WpSystem") return true;
            }
            foreach (string root in ProtectedTrees)
                if (path.Equals(root, IgnoreCase) || path.StartsWith(root + "\\", IgnoreCase)) return true;
            string executable = System.Reflection.Assembly.GetEntryAssembly().Location;
            return path.Equals(executable, IgnoreCase) || AppFolder.Equals(path, IgnoreCase) ||
                AppFolder.StartsWith(path + "\\", IgnoreCase);
        }

        public static void Validate(string path, bool folder)
        {
            if (IsProtected(path) || !String.Equals(Path.GetFullPath(path), path, IgnoreCase))
                throw new IOException("Percorso protetto o non supportato.");
            string current = path;
            while (current.Length > 3)
            {
                FileAttributes attributes = File.GetAttributes(current);
                if ((attributes & FileAttributes.ReparsePoint) != 0)
                    throw new IOException("Il percorso contiene un collegamento o un segnaposto cloud.");
                if (current == path && ((attributes & FileAttributes.Directory) != 0) != folder)
                    throw new IOException("L’elemento è cambiato dopo la scansione.");
                current = Path.GetDirectoryName(current);
            }
        }

        public static bool Execute(string path, bool folder, bool recycle, IntPtr owner)
        {
            Validate(path, folder);
            Guid shellItemId = new Guid("43826D1E-E718-42EE-BC55-A1E261C37BFE");
            IntPtr item;
            Marshal.ThrowExceptionForHR(SHCreateItemFromParsingName(path, IntPtr.Zero, ref shellItemId, out item));
            IFileOperation operation = null;
            try
            {
                var type = Type.GetTypeFromCLSID(new Guid("3AD05575-8857-4850-9277-11B85BDB8E09"), true);
                operation = (IFileOperation)Activator.CreateInstance(type);
                const uint noConnectedElements = 0x2000, noConfirmation = 0x10;
                const uint recycleOnDelete = 0x80000, wantNukeWarning = 0x4000, allowUndo = 0x40;
                operation.SetOwnerWindow(owner);
                operation.SetOperationFlags(noConnectedElements |
                    (recycle ? recycleOnDelete | allowUndo | wantNukeWarning : noConfirmation));
                operation.DeleteItem(item, IntPtr.Zero);
                operation.PerformOperations();
                bool aborted;
                operation.GetAnyOperationsAborted(out aborted);
                return !aborted;
            }
            finally
            {
                if (operation != null) Marshal.FinalReleaseComObject(operation);
                Marshal.Release(item);
            }
        }

        [DllImport("shell32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        private static extern int SHCreateItemFromParsingName(string path, IntPtr bindContext,
            ref Guid interfaceId, out IntPtr item);

        [ComImport, Guid("947AAB5F-0A5C-4C13-B4D6-4BF7836FC9F8"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        private interface IFileOperation
        {
            // Keep the native vtable order, including the methods not used here.
            void Advise(IntPtr sink, out uint cookie);
            void Unadvise(uint cookie);
            void SetOperationFlags(uint flags);
            void SetProgressMessage([MarshalAs(UnmanagedType.LPWStr)] string message);
            void SetProgressDialog(IntPtr dialog);
            void SetProperties(IntPtr properties);
            void SetOwnerWindow(IntPtr window);
            void ApplyPropertiesToItem(IntPtr item);
            void ApplyPropertiesToItems(IntPtr items);
            void RenameItem(IntPtr item, IntPtr name, IntPtr sink);
            void RenameItems(IntPtr items, IntPtr name);
            void MoveItem(IntPtr item, IntPtr destination, IntPtr name, IntPtr sink);
            void MoveItems(IntPtr items, IntPtr destination);
            void CopyItem(IntPtr item, IntPtr destination, IntPtr name, IntPtr sink);
            void CopyItems(IntPtr items, IntPtr destination);
            void DeleteItem(IntPtr item, IntPtr sink);
            void DeleteItems(IntPtr items);
            void NewItem(IntPtr destination, uint attributes, IntPtr name, IntPtr template, IntPtr sink);
            void PerformOperations();
            void GetAnyOperationsAborted([MarshalAs(UnmanagedType.Bool)] out bool aborted);
        }
    }
}
