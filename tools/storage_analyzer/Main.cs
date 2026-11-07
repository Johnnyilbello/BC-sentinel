using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

[assembly: System.Reflection.AssemblyTitle("BC Storage Analyzer")]
[assembly: System.Reflection.AssemblyProduct("BC Storage Analyzer")]
[assembly: System.Reflection.AssemblyVersion("1.3.0.0")]

namespace BCStorage
{
    internal static class Program
    {
        [STAThread]
        private static void Main(string[] args)
        {
            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo("it-IT");
            CultureInfo.CurrentUICulture = CultureInfo.CurrentCulture;
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            var window = new MainWindow();
            if (args.Length == 1 && args[0] == "--smoke")
            {
                var timer = new System.Windows.Forms.Timer { Interval = 700 };
                timer.Tick += (sender, e) => { timer.Stop(); window.Close(); };
                window.Shown += (sender, e) => timer.Start();
                Application.Run(window);
                timer.Dispose();
                return;
            }
            Application.Run(window);
        }
    }

    internal sealed class MainWindow : Form
    {
        private static readonly Color Navy = Color.FromArgb(17, 30, 47);
        private static readonly Color Ink = Color.FromArgb(24, 43, 64);
        private static readonly Color Muted = Color.FromArgb(68, 87, 109);
        private static readonly Color Canvas = Color.FromArgb(239, 244, 249);
        private static readonly Color Border = Color.FromArgb(212, 224, 235);
        private static readonly Color Accent = Color.FromArgb(0, 100, 109);
        private static readonly Color White = Color.White;
        private static readonly CultureInfo Italian = CultureInfo.GetCultureInfo("it-IT");
        private readonly ComboBox scope = new ComboBox();
        private readonly TabControl tabs = new TabControl();
        private readonly Button start, cancel, open, export, refresh, refreshRam;
        private readonly Button recycleButton, deleteButton, uninstallButton;
        private readonly Label status, detail, diskSummary, folderSummary, fileSummary, extensionSummary,
            appSummary, ramSummary, issueSummary;
        private readonly ProgressBar progress = new ProgressBar();
        private readonly CheckBox nested = new CheckBox { Text = "Mostra anche le sottocartelle", AutoSize = true };
        private readonly DataGridView disks, folders, files, extensions, apps, ram, issues;
        private CancellationTokenSource cancellation;
        private ScanResult scan;
        private List<Volume> volumes = new List<Volume>();
        private bool readyToClose;
        private bool resultsStale, removing, uninstalling;

        public MainWindow()
        {
            Text = "BC Storage Analyzer 1.3";
            StartPosition = FormStartPosition.CenterScreen;
            AutoScaleMode = AutoScaleMode.Dpi;
            ClientSize = new Size(1130, 720);
            MinimumSize = new Size(825, 560);
            Font = new Font("Segoe UI", 10);
            BackColor = Canvas;
            ForeColor = Ink;

            var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 4 };
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 104));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 60));
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 104));
            Controls.Add(layout);

            var hero = new Panel { Dock = DockStyle.Fill, Margin = Padding.Empty, BackColor = Navy };
            var mark = LabelOf("BC", 16, FontStyle.Bold, White);
            mark.TextAlign = ContentAlignment.MiddleCenter;
            mark.SetBounds(22, 28, 48, 48);
            mark.BackColor = Accent;
            hero.Controls.Add(mark);
            var title = LabelOf("BC Storage Analyzer", 23, FontStyle.Bold, White);
            title.SetBounds(84, 13, 670, 47);
            hero.Controls.Add(title);
            var subtitle = LabelOf("Scopri cosa occupa più spazio sui dischi e quali processi usano più RAM.", 10,
                FontStyle.Regular, Color.FromArgb(209, 223, 239));
            subtitle.SetBounds(88, 62, 680, 25);
            hero.Controls.Add(subtitle);
            layout.Controls.Add(hero, 0, 0);

            var toolbar = new FlowLayoutPanel { Dock = DockStyle.Fill, WrapContents = false,
                Padding = new Padding(19, 10, 12, 0), Margin = Padding.Empty };
            var scopeLabel = LabelOf("Analizza", 10, FontStyle.Bold, Ink);
            scopeLabel.AutoSize = true;
            scopeLabel.Margin = new Padding(0, 8, 8, 0);
            scope.DropDownStyle = ComboBoxStyle.DropDownList;
            scope.AccessibleName = "Unità da analizzare";
            scope.Width = 176;
            scope.Margin = new Padding(0, 4, 12, 0);
            start = MakeButton("Avvia scansione", true);
            cancel = MakeButton("Annulla", false);
            cancel.Enabled = false;
            refresh = MakeButton("Aggiorna unità", false);
            toolbar.Controls.AddRange(new Control[] { scopeLabel, scope, start, cancel, refresh });
            layout.Controls.Add(toolbar, 0, 1);

            tabs.Dock = DockStyle.Fill;
            tabs.Margin = new Padding(19, 0, 19, 0);
            tabs.Padding = new Point(15, 7);
            layout.Controls.Add(tabs, 0, 2);

            disks = NewGrid(Column("Unità", 13), Column("Nome", 22), Column("Tipo", 14),
                Bytes("Occupato", 13), Bytes("Libero", 13), Bytes("Totale", 13), Column("% occupato", 12, typeof(double)));
            diskSummary = AddPage("Unità", "Spazio sui dischi",
                "Valori riportati da Windows. Scegli un’unità o avvia la scansione su tutte le unità locali.", disks);
            folders = NewGrid(Column("Cartella", 22), Bytes("Dimensione", 15),
                Column("% rilevato", 11, typeof(double)), Column("Percorso", 52));
            nested.Margin = new Padding(0, 0, 0, 7);
            folderSummary = AddPage("Cartelle", "Le cartelle più grandi",
                "Parti dalle cartelle al primo livello. Con le sottocartelle, una voce può includere altre voci della lista.",
                folders, nested);
            files = NewGrid(Column("File", 22), Bytes("Dimensione", 15), Column("% rilevato", 11, typeof(double)),
                Column("Ruolo", 16), Column("Percorso", 36));
            fileSummary = AddPage("File", "I file più grandi",
                "Seleziona un file e scegli «Mostra in Esplora file» per individuarlo sul disco.", files);
            extensions = NewGrid(Column("Estensione", 38), Bytes("Dimensione totale", 25),
                Column("% rilevato", 17, typeof(double)), Column("File", 20, typeof(long)));
            extensionSummary = AddPage("Estensioni", "Lo spazio per tipo di file",
                "Ogni riga somma i file con la stessa estensione, su tutte le unità scansionate.", extensions);
            apps = NewGrid(Column("Applicazione", 34), Bytes("Stima installata", 16),
                Column("Versione", 17), Column("Produttore", 33));
            uninstallButton = MakeButton("Disinstalla applicazione", false);
            uninstallButton.Enabled = false;
            uninstallButton.Margin = new Padding(0, 0, 0, 7);
            appSummary = AddPage("Applicazioni", "Applicazioni desktop installate",
                "Le dimensioni sono stime dichiarate dagli installer. Seleziona un’app per disinstallarla.", apps, uninstallButton);
            uninstallButton.Click += async (sender, e) => await UninstallSelectedAsync();
            ram = NewGrid(Column("Processo", 54), Bytes("RAM residente", 25), Column("PID", 21, typeof(int)));
            refreshRam = MakeButton("Aggiorna RAM", false);
            refreshRam.Margin = new Padding(0, 0, 0, 7);
            ramSummary = AddPage("RAM", "La RAM in uso per processo",
                "RAM residente al momento del rilevamento. Le pagine condivise possono comparire in più processi.",
                ram, refreshRam);
            issues = NewGrid(Column("Motivo", 43), Column("Percorso", 57));
            issueSummary = AddPage("Dettagli", "Copertura della scansione",
                "Mostra i primi 200 errori. I collegamenti a cartelle e i link simbolici a file vengono saltati.", issues);

            var footer = new TableLayoutPanel { Dock = DockStyle.Fill, Margin = Padding.Empty, ColumnCount = 2,
                RowCount = 3, Padding = new Padding(19, 6, 19, 4) };
            footer.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            footer.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            footer.RowStyles.Add(new RowStyle(SizeType.Absolute, 23));
            footer.RowStyles.Add(new RowStyle(SizeType.Absolute, 22));
            footer.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));
            status = LabelOf("Pronto per la scansione", 10, FontStyle.Bold, Ink);
            status.Dock = DockStyle.Fill;
            detail = LabelOf("Per capire dove partire, apri Cartelle dopo la scansione.", 9, FontStyle.Regular, Muted);
            detail.Dock = DockStyle.Fill;
            progress.Dock = DockStyle.Fill;
            progress.Margin = new Padding(2, 4, 14, 5);
            progress.AccessibleName = "Avanzamento scansione";
            footer.Controls.Add(status, 0, 0);
            footer.Controls.Add(detail, 0, 1);
            footer.Controls.Add(progress, 0, 2);
            var actions = new TableLayoutPanel { AutoSize = true, ColumnCount = 2, RowCount = 2,
                Anchor = AnchorStyles.Top | AnchorStyles.Right, Margin = new Padding(6, 0, 0, 0) };
            actions.RowStyles.Add(new RowStyle(SizeType.Absolute, 36));
            actions.RowStyles.Add(new RowStyle(SizeType.Absolute, 36));
            open = MakeButton("Mostra in Esplora file", false);
            export = MakeButton("Esporta CSV", false);
            recycleButton = MakeButton("Sposta nel Cestino", false);
            deleteButton = MakeButton("Elimina definitivamente", false);
            deleteButton.ForeColor = Color.FromArgb(159, 44, 24);
            foreach (var button in new[] { open, export, recycleButton, deleteButton })
                button.Dock = DockStyle.Fill;
            actions.Controls.Add(open, 0, 0);
            actions.Controls.Add(export, 1, 0);
            actions.Controls.Add(recycleButton, 0, 1);
            actions.Controls.Add(deleteButton, 1, 1);
            footer.Controls.Add(actions, 1, 0);
            footer.SetRowSpan(actions, 3);
            layout.Controls.Add(footer, 0, 3);

            start.Click += async (sender, e) => await ScanAsync();
            cancel.Click += (sender, e) => RequestCancel();
            refresh.Click += (sender, e) => LoadDisks();
            refreshRam.Click += async (sender, e) => await LoadRamAsync();
            nested.CheckedChanged += (sender, e) => ShowFolders();
            open.Click += (sender, e) => OpenSelected();
            export.Click += (sender, e) => ExportPage();
            recycleButton.Click += (sender, e) => RemoveSelected(true);
            deleteButton.Click += (sender, e) => RemoveSelected(false);
            tabs.SelectedIndexChanged += (sender, e) => UpdateActions();
            scope.SelectedIndexChanged += (sender, e) => UpdateActions();
            foreach (DataGridView grid in new[] { disks, folders, files, extensions, apps, ram, issues })
            {
                grid.SelectionChanged += (sender, e) => UpdateActions();
                grid.CellDoubleClick += (sender, e) =>
                {
                    if (e.RowIndex >= 0 && open.Enabled) OpenSelected();
                };
            }
            FormClosing += (sender, e) =>
            {
                if (removing) { e.Cancel = true; return; }
                if (cancellation == null) return;
                e.Cancel = true;
                readyToClose = true;
                RequestCancel();
            };
            ClearScanViews();
            appSummary.Text = "Rilevamento applicazioni in corso…";
            ramSummary.Text = "Rilevamento processi in corso…";
            Shown += async (sender, e) =>
            {
                LoadDisks();
                await Task.WhenAll(LoadAppsAsync(), LoadRamAsync());
            };
            UpdateActions();
        }

        private static Label LabelOf(string text, float size, FontStyle style, Color color)
        {
            return new Label { Text = text, Font = new Font("Segoe UI", size, style),
                ForeColor = color, AutoEllipsis = true, TextAlign = ContentAlignment.MiddleLeft,
                UseMnemonic = false, Margin = Padding.Empty };
        }

        private static Button MakeButton(string text, bool primary)
        {
            var button = new Button { Text = text, AutoSize = true, MinimumSize = new Size(72, 34),
                Padding = new Padding(8, 0, 8, 0), Margin = new Padding(0, 0, 8, 0),
                FlatStyle = FlatStyle.Flat, BackColor = primary ? Accent : White,
                ForeColor = primary ? White : Ink, UseVisualStyleBackColor = false };
            button.FlatAppearance.BorderColor = primary ? Accent : Border;
            button.FlatAppearance.MouseOverBackColor = primary ? Color.FromArgb(0, 84, 92) : Canvas;
            return button;
        }

        private static DataGridViewTextBoxColumn Column(string name, int weight, Type type = null)
        {
            return new DataGridViewTextBoxColumn { HeaderText = name, Name = name, FillWeight = weight,
                MinimumWidth = 65, ValueType = type ?? typeof(string),
                SortMode = DataGridViewColumnSortMode.Automatic };
        }

        private static DataGridViewTextBoxColumn Bytes(string name, int weight)
        {
            var column = Column(name, weight, typeof(long));
            column.Tag = "bytes";
            column.MinimumWidth = 115;
            column.DefaultCellStyle.Alignment = DataGridViewContentAlignment.MiddleRight;
            return column;
        }

        private static DataGridView NewGrid(params DataGridViewColumn[] columns)
        {
            var grid = new DataGridView
            {
                Dock = DockStyle.Fill, Margin = Padding.Empty, BackgroundColor = White,
                BorderStyle = BorderStyle.FixedSingle, GridColor = Canvas, RowHeadersVisible = false,
                ReadOnly = true, MultiSelect = false, SelectionMode = DataGridViewSelectionMode.FullRowSelect,
                AllowUserToAddRows = false, AllowUserToDeleteRows = false, AllowUserToResizeRows = false,
                AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill,
                EnableHeadersVisualStyles = false, ColumnHeadersHeightSizeMode = DataGridViewColumnHeadersHeightSizeMode.AutoSize,
                CellBorderStyle = DataGridViewCellBorderStyle.SingleHorizontal,
                ColumnHeadersBorderStyle = DataGridViewHeaderBorderStyle.None,
                ColumnHeadersDefaultCellStyle = new DataGridViewCellStyle { BackColor = Navy, ForeColor = White,
                    SelectionBackColor = Navy, SelectionForeColor = White, Padding = new Padding(7, 6, 6, 6),
                    Font = new Font("Segoe UI", 9, FontStyle.Bold), WrapMode = DataGridViewTriState.False },
                DefaultCellStyle = new DataGridViewCellStyle { BackColor = White, ForeColor = Ink,
                    SelectionBackColor = Color.FromArgb(208, 233, 236), SelectionForeColor = Ink,
                    Padding = new Padding(7, 3, 7, 3), NullValue = "—", WrapMode = DataGridViewTriState.False },
                AlternatingRowsDefaultCellStyle = new DataGridViewCellStyle { BackColor = Color.FromArgb(245, 248, 252) }
            };
            grid.RowTemplate.Height = 31;
            grid.Columns.AddRange(columns);
            grid.CellFormatting += (sender, e) =>
            {
                if (e.Value is long && Equals(grid.Columns[e.ColumnIndex].Tag, "bytes"))
                {
                    e.Value = SizeOf((long)e.Value);
                    e.FormattingApplied = true;
                }
                else if (e.Value is double)
                {
                    double percent = (double)e.Value;
                    e.Value = percent > 0 && percent < 0.05 ? "< 0,1 %" : percent.ToString("0.0", Italian) + " %";
                    if (grid.Columns[e.ColumnIndex].HeaderText == "% occupato" && percent >= 90)
                        e.CellStyle.ForeColor = Color.FromArgb(159, 44, 24);
                    e.FormattingApplied = true;
                }
            };
            return grid;
        }

        private Label AddPage(string tabName, string heading, string description, DataGridView grid, Control option = null)
        {
            var page = new TabPage(tabName) { BackColor = White, Tag = grid };
            var pane = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1,
                RowCount = option == null ? 4 : 5, Padding = new Padding(14, 8, 14, 14) };
            pane.RowStyles.Add(new RowStyle(SizeType.Absolute, 33));
            pane.RowStyles.Add(new RowStyle(SizeType.Absolute, 26));
            pane.RowStyles.Add(new RowStyle(SizeType.Absolute, 27));
            if (option != null) pane.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            pane.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            var title = LabelOf(heading, 17, FontStyle.Bold, Ink);
            var copy = LabelOf(description, 9.5f, FontStyle.Regular, Muted);
            var summary = LabelOf("", 10, FontStyle.Bold, Accent);
            title.Dock = copy.Dock = summary.Dock = DockStyle.Fill;
            pane.Controls.Add(title, 0, 0);
            pane.Controls.Add(copy, 0, 1);
            pane.Controls.Add(summary, 0, 2);
            if (option != null) pane.Controls.Add(option, 0, 3);
            pane.Controls.Add(grid, 0, option == null ? 3 : 4);
            page.Controls.Add(pane);
            grid.AccessibleName = heading;
            tabs.TabPages.Add(page);
            return summary;
        }

        private void LoadDisks()
        {
            string selected = (scope.SelectedItem as Volume ?? new Volume()).Root;
            volumes = Inventory.Volumes();
            scope.BeginUpdate();
            scope.Items.Clear();
            scope.Items.Add("Tutte le unità locali");
            var available = volumes.Where(v => v.Ready).ToArray();
            scope.Items.AddRange(available);
            scope.SelectedIndex = Array.FindIndex(available, v => v.Root == selected) + 1;
            scope.EndUpdate();
            ShowRows(disks, volumes.Select(v => Row(v.Ready ? v.Root : null, v.Root,
                v.Ready ? v.Label : "Non disponibile", v.Kind, v.Ready ? (long?)(v.Total - v.Free) : null,
                v.Ready ? (long?)v.Free : null, v.Ready ? (long?)v.Total : null,
                v.Ready && v.Total > 0 ? (double?)((v.Total - v.Free) * 100.0 / v.Total) : null)), 3);
            diskSummary.Text = available.Length == 0 ? "Nessuna unità locale pronta."
                : String.Format("{0:N0} unità pronte  ·  {1} occupati  ·  {2} liberi", available.Length,
                    SizeOf(available.Sum(v => v.Total - v.Free)), SizeOf(available.Sum(v => v.Free)));
            UpdateActions();
        }

        private async Task LoadAppsAsync()
        {
            var found = await Task.Run(() => Inventory.Apps());
            if (IsDisposed) return;
            ShowRows(apps, found.Select(a => Row(a, a.Name, a.Bytes, a.Version, a.Publisher)), 1);
            appSummary.Text = String.Format("{0:N0} applicazioni rilevate  ·  {1:N0} con stima disponibile",
                found.Count, found.Count(a => a.Bytes.HasValue));
        }

        private async Task LoadRamAsync()
        {
            refreshRam.Enabled = false;
            try
            {
                var snapshot = await Task.Run(() => Inventory.Ram());
                if (IsDisposed) return;
                ShowRows(ram, snapshot.Processes.Select(p => Row(null, p.Name, p.Bytes, p.Pid)), 1);
                string usage = snapshot.Total > 0
                    ? String.Format("{0} in uso su {1}  ·  ", SizeOf(snapshot.Total - snapshot.Available), SizeOf(snapshot.Total))
                    : "";
                ramSummary.Text = usage + String.Format("{0:N0} processi  ·  {1:N0} non leggibili  ·  Ore {2:HH:mm:ss}",
                    snapshot.Processes.Count, snapshot.Skipped, DateTime.Now);
            }
            finally { if (!IsDisposed) refreshRam.Enabled = true; }
        }

        private async Task ScanAsync()
        {
            if (cancellation != null) return;
            LoadDisks();
            var one = scope.SelectedItem as Volume;
            var roots = (one == null ? volumes.Where(v => v.Ready) : new[] { one }).Select(v => v.Root).ToArray();
            if (roots.Length == 0) return;
            cancellation = new CancellationTokenSource();
            var token = cancellation.Token;
            scan = null;
            resultsStale = false;
            ClearScanViews();
            status.Text = "Scansione in corso…";
            detail.Text = "Lettura dei metadati dei file.";
            progress.Style = ProgressBarStyle.Marquee;
            progress.MarqueeAnimationSpeed = 24;
            UpdateActions();
            try
            {
                var reporter = new Progress<ScanProgress>(p =>
                {
                    if (cancellation == null || cancellation.IsCancellationRequested) return;
                    status.Text = String.Format("Unità {0}/{1}  ·  {2:N0} file letti  ·  {3} rilevati",
                        p.Unit, roots.Length, p.Count, SizeOf(p.Bytes));
                    detail.Text = p.Path;
                });
                var notify = (IProgress<ScanProgress>)reporter;
                scan = await Task.Run(() => Scanner.Run(roots, token, (path, count, bytes) =>
                {
                    int unit = Array.FindIndex(roots, root => path.StartsWith(root, StringComparison.OrdinalIgnoreCase)) + 1;
                    notify.Report(new ScanProgress { Unit = unit, Path = path, Count = count, Bytes = bytes });
                }));
                if (readyToClose) return;
                ShowScan();
                if (tabs.SelectedIndex == 0) tabs.SelectedIndex = 1;
                string state = scan.Cancelled ? "Scansione annullata · risultati parziali"
                    : scan.AccessDenied + scan.OtherErrors > 0 ? "Scansione terminata · copertura parziale"
                    : "Scansione terminata";
                status.Text = String.Format("{0}  ·  {1:N0} file", state, scan.FileCount);
                detail.Text = String.Format("{0} rilevati  ·  {1:N0} errori  ·  {2:N0} collegamenti saltati",
                    SizeOf(scan.Bytes), scan.AccessDenied + scan.OtherErrors, scan.Links);
            }
            catch (Exception ex)
            {
                ClearScanViews();
                status.Text = "Scansione interrotta da un errore";
                detail.Text = ex.Message;
            }
            finally
            {
                cancellation.Dispose();
                cancellation = null;
                progress.Style = ProgressBarStyle.Continuous;
                progress.Value = scan != null && !scan.Cancelled ? 100 : 0;
                UpdateActions();
                if (readyToClose) Close();
            }
        }

        private sealed class ScanProgress
        {
            public int Unit;
            public string Path;
            public long Count, Bytes;
        }

        private void RequestCancel()
        {
            if (cancellation == null || cancellation.IsCancellationRequested) return;
            cancellation.Cancel();
            status.Text = "Annullamento in corso…";
            detail.Text = "Attendo la fine della lettura in corso.";
            UpdateActions();
        }

        private void ClearScanViews()
        {
            string hint = cancellation == null ? "Avvia una scansione per vedere i risultati." : "Scansione in corso…";
            foreach (var grid in new[] { folders, files, extensions, issues }) grid.Rows.Clear();
            folderSummary.Text = fileSummary.Text = extensionSummary.Text = issueSummary.Text = hint;
        }

        private void ShowScan()
        {
            ShowFolders();
            ShowRows(files, scan.Files.Descending.Select(e => Row(e.Path, NameOf(e.Path), e.Bytes, Share(e.Bytes),
                FileRole(e.Path), e.Path)), 1);
            fileSummary.Text = String.Format("{0:N0} in classifica su {1:N0} file letti  ·  dimensioni logiche",
                files.Rows.Count, scan.FileCount);
            ShowRows(extensions, scan.Extensions.OrderByDescending(e => e.Value.Bytes).ThenBy(e => e.Key)
                .Select(e => Row(null, e.Key, e.Value.Bytes, Share(e.Value.Bytes), e.Value.Count)), 1);
            extensionSummary.Text = String.Format("{0:N0} tipi  ·  {1} di dimensione logica rilevata",
                scan.Extensions.Count, SizeOf(scan.Bytes));
            ShowRows(issues, scan.Issues.Select(e => Row(null,
                e.Code == 5 ? "Accesso negato" : new Win32Exception(e.Code).Message, e.Path)), -1);
            issueSummary.Text = String.Format("{0:N0} accessi negati  ·  {1:N0} altri errori  ·  {2:N0} collegamenti saltati",
                scan.AccessDenied, scan.OtherErrors, scan.Links);
        }

        private void ShowFolders()
        {
            if (scan == null) return;
            var entries = nested.Checked ? scan.Folders : scan.RootFolders;
            ShowRows(folders, entries.Descending.Select(e => Row(e.Path, FolderName(e.Path), e.Bytes,
                Share(e.Bytes), e.Path)), 1);
            folderSummary.Text = String.Format("{0:N0} in classifica  ·  {1}  ·  dimensioni logiche",
                folders.Rows.Count, nested.Checked ? "incluse le sottocartelle" : "primo livello");
        }

        private double Share(long bytes) { return scan.Bytes > 0 ? bytes * 100.0 / scan.Bytes : 0; }

        private static string FileRole(string path)
        {
            if (path.LastIndexOf('\\') == 2)
            {
                switch (NameOf(path).ToLowerInvariant())
                {
                    case "pagefile.sys": case "swapfile.sys": return "Memoria virtuale";
                    case "hiberfil.sys": return "Ibernazione";
                }
            }
            if (Removal.IsProtected(path)) return "Percorso protetto";
            if (path.EndsWith(".vhdx", StringComparison.OrdinalIgnoreCase) ||
                path.EndsWith(".vhd", StringComparison.OrdinalIgnoreCase)) return "Disco virtuale";
            return "";
        }

        private sealed class GridRow
        {
            public object Tag;
            public object[] Cells;
        }

        private static GridRow Row(object tag, params object[] cells)
        {
            return new GridRow { Tag = tag, Cells = cells };
        }

        private void ShowRows(DataGridView grid, IEnumerable<GridRow> rows, int sortColumn)
        {
            grid.SuspendLayout();
            try
            {
                grid.Rows.Clear();
                foreach (DataGridViewColumn column in grid.Columns)
                    column.HeaderCell.SortGlyphDirection = SortOrder.None;
                var items = rows.Select(item =>
                {
                    var row = new DataGridViewRow { Tag = item.Tag };
                    row.CreateCells(grid, item.Cells);
                    return row;
                }).ToArray();
                if (items.Length > 0)
                {
                    grid.Rows.AddRange(items);
                    if (sortColumn >= 0) grid.Columns[sortColumn].HeaderCell.SortGlyphDirection = SortOrder.Descending;
                }
                grid.ClearSelection();
            }
            finally { grid.ResumeLayout(); }
            UpdateActions();
        }

        private DataGridView CurrentGrid { get { return tabs.SelectedTab == null ? null : tabs.SelectedTab.Tag as DataGridView; } }

        private void UpdateActions()
        {
            if (open == null || export == null || recycleButton == null || deleteButton == null) return;
            bool busy = cancellation != null || removing || uninstalling;
            scope.Enabled = refresh.Enabled = !busy;
            start.Enabled = !busy && volumes.Any(v => v.Ready);
            cancel.Enabled = cancellation != null && !cancellation.IsCancellationRequested;
            var grid = CurrentGrid;
            var row = grid == null || grid.SelectedRows.Count == 0 ? null : grid.SelectedRows[0];
            open.Enabled = row != null && row.Tag is string;
            export.Enabled = grid != null && grid.Rows.Count > 0;
            uninstallButton.Enabled = !busy && grid == apps && row != null && row.Tag is InstalledApp;
            recycleButton.Enabled = deleteButton.Enabled = !busy && !resultsStale && scan != null && !scan.Cancelled &&
                (grid == files || grid == folders) && row != null && !Removal.IsProtected(row.Tag as string);
        }

        private async Task UninstallSelectedAsync()
        {
            if (!uninstallButton.Enabled || apps.SelectedRows.Count != 1) return;
            var app = apps.SelectedRows[0].Tag as InstalledApp;
            if (app == null) return;
            try
            {
                var command = Uninstall.Prepare(app.Uninstall);
                if (command == null)
                {
                    if (MessageBox.Show(this, "Il comando di disinstallazione di «" + app.Name +
                        "» non è disponibile o non è supportato. Aprire App installate di Windows?",
                        "Disinstalla applicazione", MessageBoxButtons.YesNo, MessageBoxIcon.Information,
                        MessageBoxDefaultButton.Button2) == DialogResult.Yes)
                        using (Process.Start(new ProcessStartInfo("ms-settings:appsfeatures") { UseShellExecute = true })) { }
                    return;
                }
                if (MessageBox.Show(this, "Avviare la disinstallazione di «" + app.Name + "»?",
                    "Disinstalla applicazione", MessageBoxButtons.YesNo, MessageBoxIcon.Warning,
                    MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;
                uninstalling = true;
                if (scan != null)
                {
                    resultsStale = true;
                    detail.Text = "Avvia una nuova scansione per aggiornare le classifiche dopo la disinstallazione.";
                }
                UpdateActions();
                using (var process = Process.Start(command))
                    if (process != null) await Task.Run(() => process.WaitForExit());
                if (IsDisposed) return;
                await LoadAppsAsync();
                if (!IsDisposed) LoadDisks();
            }
            catch (Exception ex)
            {
                if (!IsDisposed) MessageBox.Show(this, ex.Message, "Disinstalla applicazione",
                    MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
            finally
            {
                uninstalling = false;
                if (!IsDisposed) UpdateActions();
            }
        }

        private void RemoveSelected(bool recycle)
        {
            if (!(recycle ? recycleButton : deleteButton).Enabled) return;
            var grid = CurrentGrid;
            var row = grid.SelectedRows[0];
            var path = (string)row.Tag;
            bool folder = grid == folders;
            string title = recycle ? "Sposta nel Cestino" : "Elimina definitivamente";
            try { Removal.Validate(path, folder); }
            catch (Exception ex) { MessageBox.Show(this, ex.Message, title, MessageBoxButtons.OK, MessageBoxIcon.Warning); return; }
            string scope = folder ? "La cartella e tutto il suo contenuto" : "Il file selezionato";
            string consequence = recycle ? "Lo spazio si libera quando l’elemento viene eliminato dal Cestino."
                : "L’elemento non passerà dal Cestino. L’operazione è irreversibile.";
            if (MessageBox.Show(this, scope + ":\n\n" + path + "\n\n" + consequence + "\n\nProcedere?",
                title, MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2)
                != DialogResult.Yes) return;
            removing = true;
            resultsStale = true;
            UpdateActions();
            try
            {
                bool done = Removal.Execute(path, folder, recycle, Handle);
                status.Text = done ? "Rimozione completata" : "Rimozione interrotta";
            }
            catch (Exception ex)
            {
                status.Text = "Rimozione non completata";
                MessageBox.Show(this, ex.Message, title, MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
            finally
            {
                removing = false;
                LoadDisks();
                detail.Text = "Le classifiche si riferiscono alla scansione precedente. Avvia una nuova scansione.";
                UpdateActions();
            }
        }

        private void OpenSelected()
        {
            var grid = CurrentGrid;
            if (grid == null || grid.SelectedRows.Count == 0) return;
            string path = grid.SelectedRows[0].Tag as string;
            if (path == null) return;
            try
            {
                string arguments = grid == files ? "/select,\"" + path + "\"" : "\"" + path + "\"";
                // A bare drive root is safe and avoids escaping the trailing backslash.
                if (grid == disks) arguments = path;
                string explorer = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe");
                using (Process.Start(new ProcessStartInfo(explorer, arguments) { UseShellExecute = false })) { }
            }
            catch (Win32Exception ex)
            {
                MessageBox.Show(this, ex.Message, "Esplora file", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        private void ExportPage()
        {
            var grid = CurrentGrid;
            if (grid == null || grid.Rows.Count == 0) return;
            string suffix = scan != null && (scan.Cancelled || scan.AccessDenied + scan.OtherErrors > 0) &&
                (grid == folders || grid == files || grid == extensions || grid == issues) ? "-parziale" : "";
            using (var dialog = new SaveFileDialog
            {
                Title = "Esporta la scheda " + tabs.SelectedTab.Text,
                Filter = "CSV (*.csv)|*.csv", DefaultExt = "csv", AddExtension = true,
                OverwritePrompt = false,
                FileName = "BC-Storage-" + tabs.SelectedTab.Text + suffix + "-" + DateTime.Now.ToString("yyyyMMdd-HHmmss") + ".csv"
            })
            {
                if (dialog.ShowDialog(this) != DialogResult.OK) return;
                try
                {
                    Csv.Write(dialog.FileName, grid.Columns.Cast<DataGridViewColumn>().Select(c =>
                        Equals(c.Tag, "bytes") ? c.HeaderText + " (byte)" : c.HeaderText),
                        grid.Rows.Cast<DataGridViewRow>().Select(r =>
                            r.Cells.Cast<DataGridViewCell>().Select(c => c.Value).ToArray()));
                    MessageBox.Show(this, "CSV salvato.", "Esportazione", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
                catch (IOException ex) { ExportError(ex); }
                catch (UnauthorizedAccessException ex) { ExportError(ex); }
            }
        }

        private void ExportError(Exception error)
        {
            MessageBox.Show(this, "Impossibile salvare il CSV. " + error.Message,
                "Esportazione", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }

        private static string NameOf(string path)
        {
            return path.Substring(path.LastIndexOf('\\') + 1);
        }

        private static string FolderName(string path)
        {
            string name = NameOf(path);
            if (path.LastIndexOf('\\') != 2) return name;
            switch (name.ToUpperInvariant())
            {
                case "$RECYCLE.BIN": return "Cestino di Windows";
                case "USERS": return "Profili utente";
                case "PROGRAM FILES": return "Programmi";
                case "PROGRAM FILES (X86)": return "Programmi (x86)";
                case "PROGRAMDATA": return "Dati condivisi dei programmi";
                default: return name;
            }
        }

        private static string SizeOf(long bytes)
        {
            double value = bytes;
            string[] units = { "B", "KiB", "MiB", "GiB", "TiB", "PiB" };
            int unit = 0;
            while (value >= 1024 && unit < units.Length - 1) { value /= 1024; unit++; }
            return value.ToString(unit == 0 ? "N0" : "N1", Italian) + " " + units[unit];
        }
    }
}
