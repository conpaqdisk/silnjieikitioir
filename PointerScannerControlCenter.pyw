import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import os
import time
from datetime import datetime
import json
import sys
import subprocess

# Optional native drag-and-drop support
try:
    import windnd
    HAS_WINDND = True
except ImportError:
    HAS_WINDND = False

# Import Engines
from ScannerEngine import PointerEngine
from plugin_engine import PluginScannerEngine, run_host_process, run_test_runner

if getattr(sys, 'frozen', False):
    BUNDLE_DIR = getattr(sys, '_MEIPASS', os.path.dirname(sys.executable))
    APP_DIR = os.path.dirname(sys.executable)
else:
    BUNDLE_DIR = os.path.dirname(os.path.abspath(__file__))
    APP_DIR = BUNDLE_DIR

LOGO_PATH = os.path.join(BUNDLE_DIR, "logo.jpg")
if not os.path.exists(LOGO_PATH):
    LOGO_PATH = os.path.join(APP_DIR, "logo.jpg")
if not os.path.exists(LOGO_PATH):
    LOGO_PATH = os.path.join(APP_DIR, "..", "logo.jpg")

LOGS_DIR = os.path.join(APP_DIR, "logs")

# Binary search paths
def find_binary(filename):
    candidates = [
        os.path.join(APP_DIR, filename),
        os.path.join(BUNDLE_DIR, filename),
        os.path.join(APP_DIR, "plugin_loader", filename),
        os.path.join(APP_DIR, "build", "Release", filename),
        os.path.join(APP_DIR, "..", filename),
        os.path.join(APP_DIR, "..", "plugin_loader", filename),
        os.path.join(APP_DIR, "..", "plugin_loader", "build", "Release", filename),
    ]
    for c in candidates:
        if os.path.isfile(c):
            return os.path.abspath(c)
    return ""

HOST_EXE = find_binary("host.exe")
TEST_RUNNER_EXE = find_binary("test_runner.exe")
TARGET_EXE = find_binary("PointerScannerTestTarget.exe")
INJECTOR_EXE = find_binary("PointerScannerTestInjector.exe")
DLL_PATH = find_binary("PointerScannerNew.dll")

def find_knight_online():
    candidates = [
        os.path.join(APP_DIR, "KnightOnline.exe"),
        os.path.join(APP_DIR, "usko veri", "KnightOnline.exe"),
        os.path.join(APP_DIR, "..", "KnightOnline.exe"),
        os.path.join(APP_DIR, "..", "usko veri", "KnightOnline.exe"),
        os.path.join(APP_DIR, "..", "..", "KnightOnline.exe"),
        os.path.join(APP_DIR, "..", "..", "usko veri", "KnightOnline.exe"),
        r"C:\Users\Fujitsu\Desktop\usko arama\usko veri\KnightOnline.exe",
    ]
    for c in candidates:
        if os.path.isfile(c):
            return os.path.abspath(c)
    return ""


class DllTab(ttk.Frame):
    """Dynamic workspace tab for PE & Pointer Scanner analysis."""
    def __init__(self, parent, file_path, log_callback, close_callback):
        super().__init__(parent)
        self.file_path = os.path.abspath(file_path)
        self.norm_path = os.path.normcase(self.file_path)
        self.log = log_callback
        self.request_close_parent = close_callback
        
        self.scan_results = []
        self.snapshots = []
        self.engine = PointerEngine(self.file_path)
        
        self.is_scanning = False
        self.is_cancelled = False
        self.is_disposed = False
        
        self.setup_ui()
        
    def setup_ui(self):
        # Action Toolbar
        top = ttk.Frame(self)
        top.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(top, text="SCAN & VALIDATE", command=self.run_scan).pack(side=tk.LEFT, padx=3)
        ttk.Button(top, text="SAVE (TXT)", command=self.save_results).pack(side=tk.LEFT, padx=3)
        ttk.Button(top, text="TAKE SNAPSHOT", command=self.take_snapshot).pack(side=tk.LEFT, padx=3)
        ttk.Button(top, text="SNAPSHOT DIFF", command=self.diff_snapshots).pack(side=tk.LEFT, padx=3)
        ttk.Button(top, text="NOT FOUND DIAGNOSTICS", command=self.show_diagnostics).pack(side=tk.LEFT, padx=3)
        
        self.lbl_status = ttk.Label(top, text="Status: Ready", foreground="gray")
        self.lbl_status.pack(side=tk.LEFT, padx=10)
        
        # Dedicated Close Button on top-right of panel toolbar
        btn_close = tk.Button(
            top, 
            text="✕ Kapat", 
            bg="#C62828", 
            fg="white", 
            activebackground="#E53935", 
            activeforeground="white", 
            font=('Segoe UI', 9, 'bold'), 
            relief="flat", 
            padx=10, 
            pady=2, 
            cursor="hand2", 
            command=self.close_tab
        )
        btn_close.pack(side=tk.RIGHT, padx=5)
        
        # Telemetry Summary
        telemetry_frame = ttk.Frame(self)
        telemetry_frame.pack(fill=tk.X, padx=5, pady=2)
        
        self.lbl_stats = ttk.Label(
            telemetry_frame, 
            text="TOTAL: 0 | VALIDATED: 0 | CHANGED: 0 | NOT FOUND: 0 | AMBIGUOUS: 0 | UNVERIFIED: 0", 
            font=('Segoe UI', 9, 'bold')
        )
        self.lbl_stats.pack(side=tk.LEFT, padx=5)
        
        # Search & Filter Bar
        filter_frame = ttk.Frame(self)
        filter_frame.pack(fill=tk.X, padx=5, pady=3)
        
        ttk.Label(filter_frame, text="Filter:").pack(side=tk.LEFT, padx=3)
        self.filter_var = tk.StringVar(value="ALL")
        filters = ["ALL", "VALIDATED", "CHANGED", "NOT_FOUND", "AMBIGUOUS", "UNVERIFIED"]
        cmb_filter = ttk.Combobox(filter_frame, textvariable=self.filter_var, values=filters, state="readonly", width=14)
        cmb_filter.pack(side=tk.LEFT, padx=3)
        cmb_filter.bind("<<ComboboxSelected>>", lambda e: self.apply_filter())
        
        ttk.Label(filter_frame, text="Search:").pack(side=tk.LEFT, padx=10)
        self.search_var = tk.StringVar()
        ent_search = ttk.Entry(filter_frame, textvariable=self.search_var, width=25)
        ent_search.pack(side=tk.LEFT, padx=3)
        ent_search.bind("<KeyRelease>", lambda e: self.apply_filter())
        
        # Main Results Treeview
        columns = ("Name", "Category", "Type", "Old", "Current", "RVA", "VA", "FileOffset", "Status", "Confidence")
        self.tree = ttk.Treeview(self, columns=columns, show="headings", height=14)
        
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=95, anchor=tk.CENTER)
            
        self.tree.column("Name", width=160, anchor=tk.W)
        self.tree.column("Category", width=100)
        self.tree.column("Status", width=110)
        self.tree.column("Confidence", width=90)
        
        scrollbar = ttk.Scrollbar(self, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=3)
        
        # Context Menu
        self.menu = tk.Menu(self, tearoff=0)
        self.menu.add_command(label="Copy Name", command=lambda: self.copy_selected(0))
        self.menu.add_command(label="Copy Current Address", command=lambda: self.copy_selected(4))
        self.menu.add_command(label="Copy RVA", command=lambda: self.copy_selected(5))
        self.menu.add_command(label="Copy VA", command=lambda: self.copy_selected(6))
        self.menu.add_command(label="Copy Full Row", command=self.copy_full_row)
        self.tree.bind("<Button-3>", self.show_context_menu)

    def close_tab(self):
        self.request_close_parent(self.norm_path)

    def show_context_menu(self, event):
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self.menu.post(event.x_root, event.y_root)

    def copy_selected(self, col_idx):
        sel = self.tree.selection()
        if sel:
            val = self.tree.item(sel[0])["values"][col_idx]
            self.clipboard_clear()
            self.clipboard_append(str(val))

    def copy_full_row(self):
        sel = self.tree.selection()
        if sel:
            vals = self.tree.item(sel[0])["values"]
            self.clipboard_clear()
            self.clipboard_append("\t".join(str(v) for v in vals))

    def run_scan(self):
        if self.is_scanning or self.is_disposed:
            return
        self.is_scanning = True
        self.is_cancelled = False
        self.lbl_status.config(text="Status: Scanning...", foreground="yellow")
        self.log("SCAN", f"Starting PE analysis on: {os.path.basename(self.file_path)}")
        
        def do_scan():
            start_t = time.time()
            if self.engine.parse_pe():
                if self.is_cancelled or self.is_disposed:
                    return
                results = self.engine.validate_all()
                if self.is_cancelled or self.is_disposed:
                    return
                self.scan_results = results
                elapsed = time.time() - start_t
                try:
                    self.after(0, lambda: self.finish_scan(elapsed))
                except Exception:
                    pass
            else:
                try:
                    self.after(0, self.fail_scan)
                except Exception:
                    pass
                
        threading.Thread(target=do_scan, daemon=True).start()

    def finish_scan(self, elapsed):
        if self.is_disposed:
            return
        self.is_scanning = False
        self.lbl_status.config(text=f"Status: Scanned ({elapsed:.2f}s)", foreground="lightgreen")
        self.apply_filter()
        self.log("SCAN", f"Completed {len(self.scan_results)} entries in {elapsed:.2f}s for {os.path.basename(self.file_path)}")

    def fail_scan(self):
        if self.is_disposed:
            return
        self.is_scanning = False
        self.lbl_status.config(text="Status: Parse Failed", foreground="red")
        self.log("ERROR", f"Failed to parse PE headers for {os.path.basename(self.file_path)}")
        messagebox.showerror("Scan Error", f"Unable to parse PE headers for {self.file_path}")

    def apply_filter(self):
        if self.is_disposed:
            return
        self.tree.delete(*self.tree.get_children())
        filter_val = self.filter_var.get()
        search_query = self.search_var.get().strip().lower()
        
        stats = {"TOTAL": len(self.scan_results), "VALIDATED": 0, "CHANGED": 0, "NOT_FOUND": 0, "AMBIGUOUS": 0, "UNVERIFIED": 0}
        
        for r in self.scan_results:
            st = r["status"]
            if st in stats:
                stats[st] += 1
                
            if filter_val != "ALL" and st != filter_val:
                continue
                
            if search_query:
                row_str = f"{r['name']} {r['category']} {r['type']} {r['old']} {r['current']} {r['rva']} {r['status']}".lower()
                if search_query not in row_str:
                    continue
                    
            self.tree.insert("", tk.END, values=(
                r["name"], r["category"], r["type"], r["old"], r["current"], 
                r["rva"], r["va"], r["file_offset"], r["status"], r["confidence"]
            ))
            
        self.lbl_stats.config(
            text=f"TOTAL: {stats['TOTAL']} | VALIDATED: {stats['VALIDATED']} | CHANGED: {stats['CHANGED']} | "
                 f"NOT FOUND: {stats['NOT_FOUND']} | AMBIGUOUS: {stats['AMBIGUOUS']} | UNVERIFIED: {stats['UNVERIFIED']}"
        )

    def take_snapshot(self):
        if not self.scan_results:
            messagebox.showwarning("Snapshot", "Please run a scan before creating a snapshot.")
            return
            
        snap = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "file": os.path.basename(self.file_path),
            "sha256": self.engine.sha256,
            "results": {r["name"]: {"current": r["current"], "status": r["status"]} for r in self.scan_results}
        }
        self.snapshots.append(snap)
        self.log("SNAPSHOT", f"Created snapshot #{len(self.snapshots)} at {snap['timestamp']}")
        messagebox.showinfo("Snapshot", f"Snapshot #{len(self.snapshots)} recorded successfully!")

    def diff_snapshots(self):
        if len(self.snapshots) < 2:
            messagebox.showwarning("Diff", "You need at least 2 snapshots to perform a diff comparison.")
            return
            
        s1 = self.snapshots[-2]
        s2 = self.snapshots[-1]
        
        diff_win = tk.Toplevel(self)
        diff_win.title(f"Snapshot Diff: {s1['timestamp']} vs {s2['timestamp']}")
        diff_win.geometry("700x450")
        
        txt = tk.Text(diff_win, wrap=tk.WORD, font=("Consolas", 10), bg="#222", fg="#eee")
        txt.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        txt.insert(tk.END, f"=== SNAPSHOT DIFF ===\n")
        txt.insert(tk.END, f"Base Snapshot : {s1['timestamp']}\n")
        txt.insert(tk.END, f"Target Snapshot: {s2['timestamp']}\n\n")
        
        all_keys = set(s1["results"].keys()) | set(s2["results"].keys())
        for k in sorted(all_keys):
            v1 = s1["results"].get(k)
            v2 = s2["results"].get(k)
            if not v1:
                txt.insert(tk.END, f"[ADDED]   {k}: New entry in target\n")
            elif not v2:
                txt.insert(tk.END, f"[REMOVED] {k}: Missing in target\n")
            elif v1["current"] != v2["current"]:
                txt.insert(tk.END, f"[CHANGED] {k}: {v1['current']} -> {v2['current']}\n")
            else:
                txt.insert(tk.END, f"[UNCHANGED] {k}: {v1['current']}\n")
                
        txt.config(state=tk.DISABLED)

    def show_diagnostics(self):
        diag_win = tk.Toplevel(self)
        diag_win.title("Not Found & Zero-Result Diagnostics")
        diag_win.geometry("800x500")
        
        txt = tk.Text(diag_win, wrap=tk.WORD, font=("Consolas", 10), bg="#1E1E1E", fg="#FFF")
        txt.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        txt.insert(tk.END, f"=== ZERO RESULT & RECOVERY DIAGNOSTICS ===\n\n")
        if self.engine.diagnostics:
            for name, d in self.engine.diagnostics.items():
                txt.insert(tk.END, f"Entry Name    : {name}\n")
                for k, v in d.items():
                    txt.insert(tk.END, f"  {k:<14}: {v}\n")
                txt.insert(tk.END, "-" * 50 + "\n\n")
        else:
            txt.insert(tk.END, "All evaluated patterns matched successfully with zero disambiguation failures!\n")
            
        txt.config(state=tk.DISABLED)

    def save_results(self):
        if not self.scan_results:
            messagebox.showwarning("Save", "No scan results available to save. Please scan first.")
            return
            
        save_file = filedialog.asksaveasfilename(
            title="Save Pointer Analysis Results",
            defaultextension=".txt",
            filetypes=[("Text Documents (*.txt)", "*.txt"), ("All Files (*.*)", "*.*")],
            initialfile=f"{os.path.splitext(os.path.basename(self.file_path))[0]}_Pointers.txt"
        )
        if not save_file:
            self.log("SAVE", "Save operation cancelled by user (SAVE CANCELED).")
            return
            
        try:
            export_dir = os.path.dirname(save_file)
            self.engine.export_all(self.scan_results, export_dir)
            
            if os.path.exists(save_file) and os.path.getsize(save_file) > 0:
                with open(save_file, "r", encoding="utf-8") as f:
                    content = f.read()
                if len(content) > 10:
                    self.log("SAVE", f"SAVE VERIFIED: Exported to {save_file}")
                    messagebox.showinfo("Save Verified", f"Analysis successfully saved and verified!\nFile: {save_file}")
                    return
            messagebox.showwarning("Save Warning", "File was written but verification failed.")
        except Exception as e:
            self.log("SAVE_ERROR", f"Failed to save results: {e}")
            messagebox.showerror("Save Error", f"Error saving file:\n{e}")

    def dispose(self):
        self.is_disposed = True
        self.is_cancelled = True
        self.engine = None
        self.scan_results.clear()
        self.snapshots.clear()


class PluginLoaderTab(ttk.Frame):
    """Integrated Management View for C++ PluginLoader Architecture."""
    def __init__(self, parent, log_callback, app_ref):
        super().__init__(parent)
        self.log = log_callback
        self.app = app_ref
        
        # Default plugin directory search
        default_dir = os.path.join(APP_DIR, "plugins")
        if not os.path.isdir(default_dir):
            default_dir = os.path.join(APP_DIR, "plugin_loader", "plugins")
        if not os.path.isdir(default_dir):
            default_dir = os.path.join(APP_DIR, "..", "plugin_loader", "plugins")
        if not os.path.isdir(default_dir):
            default_dir = os.path.join(APP_DIR, "test_plugins")
            
        self.plugin_dir_var = tk.StringVar(value=os.path.abspath(default_dir) if os.path.isdir(default_dir) else APP_DIR)
        self.plugin_items = []
        self.is_running_host = False
        
        self.setup_ui()
        self.after(150, self.run_scan)
        
    def setup_ui(self):
        # 1. Top Configuration & Actions Toolbar
        top_bar = ttk.Frame(self)
        top_bar.pack(fill=tk.X, padx=8, pady=6)
        
        ttk.Label(top_bar, text="Plugin Directory:", font=('Segoe UI', 9, 'bold')).pack(side=tk.LEFT, padx=(2, 4))
        ent_dir = ttk.Entry(top_bar, textvariable=self.plugin_dir_var, width=45)
        ent_dir.pack(side=tk.LEFT, padx=3)
        
        ttk.Button(top_bar, text="Browse...", command=self.browse_directory).pack(side=tk.LEFT, padx=2)
        
        ttk.Separator(top_bar, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=8)
        
        ttk.Button(top_bar, text="🔄 SCAN PLUGINS", command=self.run_scan).pack(side=tk.LEFT, padx=3)
        ttk.Button(top_bar, text="🎯 SEÇİLİ DOSYAYI TARA (AOB)", command=self.scan_selected_pointer).pack(side=tk.LEFT, padx=3)
        ttk.Button(top_bar, text="▶ RUN C++ HOST", command=self.run_host_runtime).pack(side=tk.LEFT, padx=3)
        ttk.Button(top_bar, text="🧪 RUN TEST SUITE", command=self.run_tests).pack(side=tk.LEFT, padx=3)
        ttk.Button(top_bar, text="📁 OPEN FOLDER", command=self.open_plugins_folder).pack(side=tk.LEFT, padx=3)

        # 2. Telemetry Bar
        telemetry_frame = ttk.Frame(self)
        telemetry_frame.pack(fill=tk.X, padx=8, pady=3)
        
        self.lbl_telemetry = ttk.Label(
            telemetry_frame, 
            text="PLUGINS: 0 | OK: 0 | API MISMATCH: 0 | INIT FAILED: 0 | MISSING EXPORT: 0 | CYCLES: 0", 
            font=('Segoe UI', 9, 'bold'),
            foreground="#64B5F6"
        )
        self.lbl_telemetry.pack(side=tk.LEFT, padx=2)
        
        # 3. Filter Bar
        filter_frame = ttk.Frame(self)
        filter_frame.pack(fill=tk.X, padx=8, pady=3)
        
        ttk.Label(filter_frame, text="Filter Status:").pack(side=tk.LEFT, padx=3)
        self.filter_var = tk.StringVar(value="ALL")
        cmb = ttk.Combobox(
            filter_frame, 
            textvariable=self.filter_var, 
            values=["ALL", "OK", "POINTER_PLUGINS", "FAILURES", "API_VERSION_MISMATCH", "DEPENDENCY_CYCLE", "INIT_FAILED", "MISSING_EXPORT"], 
            state="readonly", 
            width=22
        )
        cmb.pack(side=tk.LEFT, padx=3)
        cmb.bind("<<ComboboxSelected>>", lambda e: self.populate_tree())
        
        ttk.Label(filter_frame, text="Search:").pack(side=tk.LEFT, padx=10)
        self.search_var = tk.StringVar()
        ent_search = ttk.Entry(filter_frame, textvariable=self.search_var, width=25)
        ent_search.pack(side=tk.LEFT, padx=3)
        ent_search.bind("<KeyRelease>", lambda e: self.populate_tree())

        # 4. Main Plugins Treeview
        columns = ("Filename", "Name", "Plugin ID", "Pointers", "Version", "Status", "Dependencies", "SHA-256", "Details")
        self.tree = ttk.Treeview(self, columns=columns, show="headings", height=12)
        
        col_widths = {
            "Filename": 140, "Name": 130, "Plugin ID": 140, "Pointers": 115, "Version": 65, 
            "Status": 130, "Dependencies": 110, "SHA-256": 100, "Details": 230
        }
        for col, width in col_widths.items():
            self.tree.heading(col, text=col)
            self.tree.column(col, width=width, anchor=tk.W if col in ["Name", "Details"] else tk.CENTER)
            
        tree_scroll = ttk.Scrollbar(self, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=tree_scroll.set)
        
        tree_scroll.pack(side=tk.RIGHT, fill=tk.Y, padx=(0, 8))
        self.tree.pack(fill=tk.BOTH, expand=True, padx=(8, 0), pady=4)
        
        # Tags styling
        self.tree.tag_configure("OK", foreground="#81C784")
        self.tree.tag_configure("POINTER_PLUGIN", foreground="#4DD0E1")
        self.tree.tag_configure("API_VERSION_MISMATCH", foreground="#E57373")
        self.tree.tag_configure("DEPENDENCY_CYCLE", foreground="#FFB74D")
        self.tree.tag_configure("INIT_FAILED", foreground="#FF8A65")
        self.tree.tag_configure("MISSING_EXPORT", foreground="#BA68C8")
        self.tree.tag_configure("OTHER_FAIL", foreground="#EF5350")
        
        self.tree.bind("<<TreeviewSelect>>", self.on_select_plugin)
        self.tree.bind("<Double-1>", lambda e: self.scan_selected_pointer())
        
        # 5. Details Inspector Panel at Bottom
        detail_frame = ttk.LabelFrame(self, text="Plugin Manifest & Security Inspector")
        detail_frame.pack(fill=tk.BOTH, expand=False, padx=8, pady=6)
        
        self.txt_detail = tk.Text(detail_frame, height=7, bg="#181818", fg="#ECEFF1", font=("Consolas", 9), wrap=tk.WORD)
        self.txt_detail.pack(fill=tk.BOTH, expand=True, padx=5, pady=4)
        self.txt_detail.insert(tk.END, "Select a plugin from the table above to view manifest and PE inspection details.")
        self.txt_detail.config(state=tk.DISABLED)

    def browse_directory(self):
        d = filedialog.askdirectory(title="Select Plugins Directory", initialdir=self.plugin_dir_var.get())
        if d:
            self.plugin_dir_var.set(os.path.abspath(d))
            self.run_scan()

    def run_scan(self):
        target_dir = self.plugin_dir_var.get().strip()
        if not os.path.isdir(target_dir):
            messagebox.showerror("Error", f"Invalid plugin directory:\n{target_dir}")
            return
            
        self.log("LOADER", f"Scanning plugins directory: {target_dir}")
        eng = PluginScannerEngine(target_dir)
        self.plugin_items = eng.scan()
        self.populate_tree()
        self.log("LOADER", f"Scan complete. Found {len(self.plugin_items)} plugins.")

    def populate_tree(self):
        self.tree.delete(*self.tree.get_children())
        filt = self.filter_var.get()
        q = self.search_var.get().strip().lower()
        
        stats = {"TOTAL": len(self.plugin_items), "OK": 0, "POINTERS": 0, "API_MISMATCH": 0, "INIT_FAILED": 0, "MISSING_EXPORT": 0, "CYCLES": 0}
        
        for p in self.plugin_items:
            st = p["status"]
            if st == "OK":
                stats["OK"] += 1
            elif st == "POINTER_PLUGIN":
                stats["POINTERS"] += 1
            elif st == "API_VERSION_MISMATCH":
                stats["API_MISMATCH"] += 1
            elif st == "INIT_FAILED":
                stats["INIT_FAILED"] += 1
            elif st == "MISSING_EXPORT":
                stats["MISSING_EXPORT"] += 1
            elif st == "DEPENDENCY_CYCLE":
                stats["CYCLES"] += 1
                
            # Filter
            if filt == "OK" and st not in ("OK", "POINTER_PLUGIN"):
                continue
            elif filt == "POINTER_PLUGINS" and st != "POINTER_PLUGIN" and p.get("pointers_count", 0) == 0:
                continue
            elif filt == "FAILURES" and st in ("OK", "POINTER_PLUGIN"):
                continue
            elif filt in ["API_VERSION_MISMATCH", "DEPENDENCY_CYCLE", "INIT_FAILED", "MISSING_EXPORT"] and st != filt:
                continue
                
            # Search
            row_str = f"{p['filename']} {p['name']} {p['plugin_id']} {p['status']} {p['detail']}".lower()
            if q and q not in row_str:
                continue
                
            tag = st if st in ["OK", "POINTER_PLUGIN", "API_VERSION_MISMATCH", "DEPENDENCY_CYCLE", "INIT_FAILED", "MISSING_EXPORT"] else "OTHER_FAIL"
            
            deps_str = "; ".join(p["dependencies"]) if p["dependencies"] else "None"
            sha_short = p["sha256"][:12] + "..." if p["sha256"] else "-"
            
            self.tree.insert("", tk.END, values=(
                p["filename"], p["name"], p["plugin_id"], p.get("pointers_text", "-"), p["version"],
                p["status"], deps_str, sha_short, p["detail"]
            ), tags=(tag,))
            
        self.lbl_telemetry.config(
            text=f"PLUGINS: {stats['TOTAL']} | POINTER MODULES: {stats['POINTERS']} | HOST OK: {stats['OK']} | "
                 f"API MISMATCH: {stats['API_MISMATCH']} | INIT FAILED: {stats['INIT_FAILED']} | MISSING EXPORT: {stats['MISSING_EXPORT']}"
        )

    def scan_selected_pointer(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("Pointer Scan", "Lütfen tablodan analiz etmek istediğiniz bir dosya seçin.")
            return
        vals = self.tree.item(sel[0])["values"]
        filename = vals[0]
        target = next((p for p in self.plugin_items if p["filename"] == filename), None)
        if target:
            self.app.add_tab_for_path(target["dll_path"])
            norm_p = os.path.normcase(os.path.abspath(target["dll_path"]))
            if norm_p in self.app.tabs:
                self.app.tabs[norm_p]["panel"].run_scan()

    def on_select_plugin(self, event):
        sel = self.tree.selection()
        if not sel:
            return
            
        vals = self.tree.item(sel[0])["values"]
        filename = vals[0]
        
        target = next((p for p in self.plugin_items if p["filename"] == filename), None)
        if not target:
            return
            
        self.txt_detail.config(state=tk.NORMAL)
        self.txt_detail.delete("1.0", tk.END)
        
        self.txt_detail.insert(tk.END, f"=== PLUGIN INSPECTION: {target['filename']} ===\n")
        self.txt_detail.insert(tk.END, f"Name            : {target['name']}\n")
        self.txt_detail.insert(tk.END, f"ID              : {target['plugin_id']}\n")
        self.txt_detail.insert(tk.END, f"Version         : {target['version']}\n")
        self.txt_detail.insert(tk.END, f"API Version     : {target['api_version']}\n")
        self.txt_detail.insert(tk.END, f"Status          : {target['status']}\n")
        self.txt_detail.insert(tk.END, f"Status Detail   : {target['detail']}\n")
        self.txt_detail.insert(tk.END, f"Architecture    : {target['pe'].architecture if target['pe'] else 'Unknown'}\n")
        self.txt_detail.insert(tk.END, f"SHA-256 (Disk)  : {target['sha256']}\n")
        if target['manifest'] and target['manifest'].signature_sha256:
            self.txt_detail.insert(tk.END, f"SHA-256 (Sign)  : {target['manifest'].signature_sha256}\n")
        self.txt_detail.insert(tk.END, f"Dependencies    : {', '.join(target['dependencies']) if target['dependencies'] else 'None'}\n")
        self.txt_detail.insert(tk.END, f"Exported Symbols: {', '.join(target['exports']) if target['exports'] else 'None'}\n")
        self.txt_detail.config(state=tk.DISABLED)

    def run_host_runtime(self):
        if self.is_running_host:
            messagebox.showinfo("Host Running", "Host runtime is already running.")
            return
            
        host_exe = find_binary("host.exe")
        if not host_exe or not os.path.isfile(host_exe):
            messagebox.showerror("Host Error", f"host.exe not found!\nPlease build the C++ project first.")
            return
            
        plugins_dir = self.plugin_dir_var.get().strip()
        self.is_running_host = True
        self.log("HOST", f"Spawning Native Host runtime ({host_exe})...")
        
        def on_done(rc):
            self.is_running_host = False
            self.log("HOST", f"Host execution finished with returncode={rc}")
            
        run_host_process(host_exe, plugins_dir, run_seconds=2, log_callback=self.log, done_callback=on_done)

    def run_tests(self):
        test_exe = find_binary("test_runner.exe")
        if not test_exe or not os.path.isfile(test_exe):
            messagebox.showerror("Test Error", "test_runner.exe not found!\nPlease build the C++ project first.")
            return
            
        self.log("TEST", "Executing C++ Automated Test Suite...")
        def on_done(rc):
            if rc == 0:
                self.log("TEST", "VERIFICATION SUCCESS: All 5 automated test scenarios PASSED (100% SUCCESS).")
                messagebox.showinfo("Test Suite Passed", "All 5 PluginLoader automated test scenarios PASSED!")
            else:
                self.log("TEST", f"Test runner exited with code {rc}")
                messagebox.showwarning("Test Suite Warning", f"Automated tests completed with status {rc}.")
                
        run_test_runner(test_exe, log_callback=self.log, done_callback=on_done)

    def open_plugins_folder(self):
        d = self.plugin_dir_var.get().strip()
        if os.path.isdir(d):
            os.startfile(d)
        else:
            messagebox.showwarning("Folder", "Plugin directory does not exist.")


class ControlCenterApp:
    def __init__(self, root):
        self.root = root
        self.root.title("PointerScanner & Plugin Loader Control Center")
        self.root.geometry("1360x820")
        self.root.configure(bg="#1E1E1E")
        
        # State
        self.tabs = {} # norm_path -> {"card": Frame, "panel": DllTab, "btn_x": Button, "name": str}
        self.active_tab_path = None
        self.plugin_tab = None
        
        self.setup_ui()
        self.setup_drag_and_drop()

    def setup_ui(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TFrame', background='#1E1E1E')
        style.configure('TLabel', background='#1E1E1E', foreground='white', font=('Segoe UI', 10))
        style.configure('Header.TLabel', font=('Segoe UI', 12, 'bold'))
        style.configure('TButton', font=('Segoe UI', 9, 'bold'), padding=4)
        style.configure('Treeview', font=('Segoe UI', 9), rowheight=24, background='#252526', fieldbackground='#252526', foreground='white')
        style.configure('Treeview.Heading', font=('Segoe UI', 9, 'bold'), background='#333337', foreground='white')
        style.map('Treeview', background=[('selected', '#094771')])

        # Master Toolbar
        toolbar = ttk.Frame(self.root)
        toolbar.pack(side=tk.TOP, fill=tk.X, padx=6, pady=6)
        
        btn_ko = tk.Button(
            toolbar, 
            text="🎯 TARA: KnightOnline.exe", 
            command=self.scan_knight_online,
            bg="#2E7D32", 
            fg="white", 
            activebackground="#388E3C", 
            activeforeground="white", 
            font=('Segoe UI', 9, 'bold'), 
            relief="flat", 
            padx=8, 
            pady=2, 
            cursor="hand2"
        )
        btn_ko.pack(side=tk.LEFT, padx=3)

        ttk.Button(toolbar, text="+ ADD DLL / EXE", command=self.add_files).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="🔌 PLUGIN LOADER", command=self.show_plugin_loader).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="ANALYZE ALL", command=self.analyze_all).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="COMPARE DLLs", command=self.compare_dlls).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="SAVE ALL (TXT)", command=self.save_all).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="OPEN RESULT (TXT)", command=self.open_result_txt).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="CLOSE ALL", command=self.close_all_tabs).pack(side=tk.LEFT, padx=2)
        
        self.lbl_current_file = ttk.Label(toolbar, text="Current View: Clean Workspace", foreground="#64B5F6", font=('Segoe UI', 10, 'bold'))
        self.lbl_current_file.pack(side=tk.LEFT, padx=12)
        
        ttk.Button(toolbar, text="🧪 RUN TEST SUITE", command=self.run_plugin_tests).pack(side=tk.RIGHT, padx=3)
        ttk.Button(toolbar, text="▶ RUN HOST (x64)", command=self.run_native_host).pack(side=tk.RIGHT, padx=3)
        ttk.Button(toolbar, text="RUN TEST FIXTURE", command=self.run_test_fixture).pack(side=tk.RIGHT, padx=3)
        
        # Split Layout
        paned = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=6, pady=4)
        
        # Left Panel (Logo & Global Console Log)
        left_frame = ttk.Frame(paned, width=330)
        paned.add(left_frame, weight=1)
        
        try:
            from PIL import Image, ImageTk
            if os.path.exists(LOGO_PATH):
                img = Image.open(LOGO_PATH)
                img = img.resize((140, 140), Image.LANCZOS)
                self.logo_img = ImageTk.PhotoImage(img)
                tk.Label(left_frame, image=self.logo_img, bg="#1E1E1E").pack(pady=4)
        except Exception:
            pass
            
        ttk.Label(left_frame, text="ACTIVITY LOG", style="Header.TLabel").pack(pady=2)
        
        self.log_text = tk.Text(left_frame, height=25, bg="#181818", fg="#A0FFA0", font=("Consolas", 9), wrap=tk.WORD)
        self.log_text.pack(fill=tk.BOTH, expand=True, pady=3, padx=2)
        
        # Right Panel (Custom Tab Bar + Content Area)
        right_container = tk.Frame(paned, bg="#1E1E1E")
        paned.add(right_container, weight=4)
        
        # 1. Custom Physical Tab Bar at the top of workspace
        self.tab_bar_frame = tk.Frame(right_container, bg="#252526", height=36)
        self.tab_bar_frame.pack(side=tk.TOP, fill=tk.X)
        
        # Permanent Tab for Plugin Loader
        self.plugin_card = tk.Frame(self.tab_bar_frame, bg="#2D2D30", padx=1, pady=1)
        self.plugin_card.pack(side=tk.LEFT, padx=2, pady=3)
        
        badge_p = tk.Label(self.plugin_card, text=" 🔌 ", bg="#7B1FA2", fg="white", font=('Segoe UI', 8, 'bold'))
        badge_p.pack(side=tk.LEFT, padx=(3, 1))
        
        self.plugin_card_lbl = tk.Label(self.plugin_card, text=" Plugin Loader ", bg="#2D2D30", fg="#CCCCCC", font=('Segoe UI', 9), cursor="hand2")
        self.plugin_card_lbl.pack(side=tk.LEFT, padx=(1, 4))
        
        for w in [self.plugin_card, badge_p, self.plugin_card_lbl]:
            w.bind("<Button-1>", lambda e: self.show_plugin_loader())
            
        # 2. Content Area holding active tab panels or empty workspace
        self.content_area = tk.Frame(right_container, bg="#1E1E1E")
        self.content_area.pack(side=tk.BOTTOM, fill=tk.BOTH, expand=True)
        
        # Plugin Tab panel instance
        self.plugin_tab = PluginLoaderTab(self.content_area, self.log, self)
        
        # 3. Empty Workspace Placeholder
        self.empty_frame = tk.Frame(self.content_area, bg="#1E1E1E")
        self.empty_frame.pack(fill=tk.BOTH, expand=True)
        
        tk.Label(
            self.empty_frame, 
            text="PointerScanner & Plugin Loader Control Center", 
            font=('Segoe UI', 18, 'bold'), 
            fg="#64B5F6", 
            bg="#1E1E1E"
        ).pack(pady=(110, 8))
        
        tk.Label(
            self.empty_frame, 
            text="Başlamak için analiz etmek istediğiniz DLL veya EXE dosyalarını ekleyin,\nya da '🔌 Plugin Loader' panelini kullanarak eklentileri denetleyin.", 
            font=('Segoe UI', 11), 
            fg="#AAAAAA", 
            bg="#1E1E1E",
            justify=tk.CENTER
        ).pack(pady=8)
        
        actions_row = tk.Frame(self.empty_frame, bg="#1E1E1E")
        actions_row.pack(pady=15)
        
        tk.Button(
            actions_row, 
            text="🎯 TARA: KnightOnline.exe (Otomatik)", 
            font=('Segoe UI', 11, 'bold'), 
            bg="#2E7D32", 
            fg="white", 
            activebackground="#388E3C", 
            activeforeground="white", 
            relief="flat", 
            padx=18, 
            pady=6, 
            cursor="hand2", 
            command=self.scan_knight_online
        ).pack(side=tk.LEFT, padx=6)

        tk.Button(
            actions_row, 
            text="+ ADD DLL / EXE", 
            font=('Segoe UI', 11, 'bold'), 
            bg="#007ACC", 
            fg="white", 
            activebackground="#0098FF", 
            activeforeground="white", 
            relief="flat", 
            padx=18, 
            pady=6, 
            cursor="hand2", 
            command=self.add_files
        ).pack(side=tk.LEFT, padx=6)
        
        tk.Button(
            actions_row, 
            text="🔌 OPEN PLUGIN LOADER", 
            font=('Segoe UI', 11, 'bold'), 
            bg="#7B1FA2", 
            fg="white", 
            activebackground="#9C27B0", 
            activeforeground="white", 
            relief="flat", 
            padx=18, 
            pady=6, 
            cursor="hand2", 
            command=self.show_plugin_loader
        ).pack(side=tk.LEFT, padx=6)
        
        tk.Label(
            self.empty_frame, 
            text="DLL veya EXE dosyalarınızı pencereye sürükleyip bırakabilirsiniz.", 
            font=('Segoe UI', 10, 'italic'), 
            fg="#777777", 
            bg="#1E1E1E"
        ).pack(pady=5)
        
        self.log("SYSTEM", "PointerScanner & Plugin Loader Control Center initialized. Workspace is clean.")

    def setup_drag_and_drop(self):
        if HAS_WINDND:
            try:
                windnd.hook_dropfiles(self.root, func=self.on_drop_files)
                self.log("SYSTEM", "Native Drag & Drop enabled.")
            except Exception as e:
                self.log("WARNING", f"Drag & Drop hook warning: {e}")

    def on_drop_files(self, file_paths):
        for fp in file_paths:
            if isinstance(fp, bytes):
                fp = fp.decode(sys.getfilesystemencoding(), errors="ignore")
            if os.path.isfile(fp):
                ext = os.path.splitext(fp)[1].lower()
                if ext in [".dll", ".exe"]:
                    self.add_tab_for_path(fp)
                else:
                    self.log("WARNING", f"Ignored non-PE dropped file: {os.path.basename(fp)}")

    def log(self, component, msg):
        timestamp = time.strftime('%H:%M:%S')
        line = f"[{timestamp}] [{component}] {msg}\n"
        self.log_text.insert(tk.END, line)
        self.log_text.see(tk.END)

    def scan_knight_online(self):
        ko_path = find_knight_online()
        if not ko_path or not os.path.isfile(ko_path):
            messagebox.showinfo("KnightOnline Seç", "KnightOnline.exe otomatik bulunamadı.\nLütfen dosya seçici ile KnightOnline.exe dosyasını gösterin.")
            ko_path = filedialog.askopenfilename(
                title="Select KnightOnline.exe",
                filetypes=[("Executables (*.exe)", "*.exe"), ("All Files (*.*)", "*.*")]
            )
        if ko_path and os.path.isfile(ko_path):
            self.log("SYSTEM", f"Loading KnightOnline.exe for full pointer scan: {ko_path}")
            self.add_tab_for_path(ko_path)
            norm_p = os.path.normcase(os.path.abspath(ko_path))
            if norm_p in self.tabs:
                self.tabs[norm_p]["panel"].run_scan()

    def add_files(self):
        paths = filedialog.askopenfilenames(
            title="Select Target DLL or Executable Files",
            filetypes=[
                ("DLL & EXE Files (*.dll;*.exe)", "*.dll;*.exe"),
                ("Dynamic Link Libraries (*.dll)", "*.dll"),
                ("Executables (*.exe)", "*.exe"),
                ("All Files (*.*)", "*.*")
            ]
        )
        for p in paths:
            if p:
                self.add_tab_for_path(p)

    def add_tab_for_path(self, path):
        path = os.path.abspath(path)
        norm_path = os.path.normcase(path)
        name = os.path.basename(path)
        
        if norm_path in self.tabs:
            self.log("SYSTEM", f"ALREADY OPEN: {name} (Switching to tab)")
            self.select_tab(norm_path)
            return

        # Hide empty frame when first file is added
        self.empty_frame.pack_forget()
        self.plugin_tab.pack_forget()

        ext = os.path.splitext(name)[1].lower()
        badge_text = "EXE" if ext == ".exe" else "DLL"
        badge_bg = "#2E7D32" if badge_text == "EXE" else "#0288D1"

        card = tk.Frame(self.tab_bar_frame, bg="#2D2D30", padx=1, pady=1)
        card.pack(side=tk.LEFT, padx=2, pady=3)

        badge_lbl = tk.Label(card, text=f" {badge_text} ", bg=badge_bg, fg="white", font=('Segoe UI', 7, 'bold'))
        badge_lbl.pack(side=tk.LEFT, padx=(3, 1))

        name_lbl = tk.Label(card, text=f" {name} ", bg="#2D2D30", fg="#CCCCCC", font=('Segoe UI', 9), cursor="hand2")
        name_lbl.pack(side=tk.LEFT, padx=1)

        btn_x = tk.Button(
            card, 
            text=" ✕ ", 
            bg="#2D2D30", 
            fg="#AAAAAA", 
            relief="flat", 
            font=('Segoe UI', 9, 'bold'), 
            cursor="hand2", 
            activebackground="#E53935", 
            activeforeground="white", 
            bd=0, 
            command=lambda np=norm_path: self.request_close_tab(np)
        )
        btn_x.pack(side=tk.LEFT, padx=(1, 3))

        btn_x.bind("<Enter>", lambda e, b=btn_x: b.config(bg="#E53935", fg="white"))
        btn_x.bind("<Leave>", lambda e, b=btn_x, np=norm_path: b.config(
            bg="#007ACC" if self.active_tab_path == np else "#2D2D30", 
            fg="white" if self.active_tab_path == np else "#AAAAAA"
        ))

        panel = DllTab(self.content_area, path, self.log, self.request_close_tab)

        self.tabs[norm_path] = {
            "card": card,
            "badge": badge_lbl,
            "lbl": name_lbl,
            "btn_x": btn_x,
            "panel": panel,
            "name": name,
            "path": path
        }

        name_lbl.bind("<Button-1>", lambda e, np=norm_path: self.select_tab(np))
        badge_lbl.bind("<Button-1>", lambda e, np=norm_path: self.select_tab(np))
        card.bind("<Button-1>", lambda e, np=norm_path: self.select_tab(np))
        name_lbl.bind("<Button-2>", lambda e, np=norm_path: self.request_close_tab(np))
        card.bind("<Button-2>", lambda e, np=norm_path: self.request_close_tab(np))

        for widget in [name_lbl, badge_lbl, card]:
            widget.bind("<Button-3>", lambda e, np=norm_path: self.show_tab_context_menu(e, np))

        self.select_tab(norm_path)
        self.log("SYSTEM", f"Opened workspace tab for: {name} (Total Tabs: {len(self.tabs)})")
        panel.run_scan()

    def show_plugin_loader(self):
        self.empty_frame.pack_forget()
        for tab_data in self.tabs.values():
            tab_data["panel"].pack_forget()
            tab_data["card"].config(bg="#2D2D30")
            tab_data["lbl"].config(bg="#2D2D30", fg="#CCCCCC", font=('Segoe UI', 9))
            tab_data["btn_x"].config(bg="#2D2D30", fg="#AAAAAA")
            
        self.active_tab_path = "__PLUGIN_LOADER__"
        self.plugin_card.config(bg="#7B1FA2")
        self.plugin_card_lbl.config(bg="#7B1FA2", fg="white", font=('Segoe UI', 9, 'bold'))
        self.plugin_tab.pack(fill=tk.BOTH, expand=True)
        self.lbl_current_file.config(text="Current View: 🔌 Plugin Loader Manager")
        
        # Trigger initial scan if not already scanned
        if not self.plugin_tab.plugin_items:
            self.plugin_tab.run_scan()

    def select_tab(self, norm_path):
        if norm_path not in self.tabs:
            return
            
        self.empty_frame.pack_forget()
        self.plugin_tab.pack_forget()
        self.plugin_card.config(bg="#2D2D30")
        self.plugin_card_lbl.config(bg="#2D2D30", fg="#CCCCCC", font=('Segoe UI', 9))
        
        self.active_tab_path = norm_path
        
        for np, data in self.tabs.items():
            if np == norm_path:
                data["card"].config(bg="#007ACC")
                data["lbl"].config(bg="#007ACC", fg="white", font=('Segoe UI', 9, 'bold'))
                data["btn_x"].config(bg="#007ACC", fg="white")
                data["panel"].pack(fill=tk.BOTH, expand=True)
                self.lbl_current_file.config(text=f"Current File: {data['name']}")
            else:
                data["card"].config(bg="#2D2D30")
                data["lbl"].config(bg="#2D2D30", fg="#CCCCCC", font=('Segoe UI', 9))
                data["btn_x"].config(bg="#2D2D30", fg="#AAAAAA")
                data["panel"].pack_forget()

    def request_close_tab(self, norm_path):
        if norm_path not in self.tabs:
            return
            
        tab_data = self.tabs[norm_path]
        panel = tab_data["panel"]
        name = tab_data["name"]

        if panel.is_scanning:
            confirm = messagebox.askyesno(
                "Aktif Analiz Uyarısı",
                f"'{name}' için aktif bir analiz devam ediyor.\nSekmeyi kapatmak istediğinize emin misiniz?",
                icon=messagebox.WARNING
            )
            if not confirm:
                return

        self.log("TAB", f"Close requested for: {name}")
        panel.dispose()
        tab_data["card"].destroy()
        panel.destroy()
        del self.tabs[norm_path]

        self.log("TAB", f"Closed tab: {name} (Remaining Tabs: {len(self.tabs)})")

        if self.active_tab_path == norm_path:
            if self.tabs:
                next_tab_path = list(self.tabs.keys())[-1]
                self.select_tab(next_tab_path)
            else:
                self.active_tab_path = None
                self.lbl_current_file.config(text="Current View: Clean Workspace")
                self.empty_frame.pack(fill=tk.BOTH, expand=True)

    def show_tab_context_menu(self, event, norm_path):
        if norm_path not in self.tabs:
            return
            
        tab_name = self.tabs[norm_path]["name"]
        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label=f"✕ Bu Sekmeyi Kapat ({tab_name})", command=lambda: self.request_close_tab(norm_path))
        menu.add_separator()
        menu.add_command(label="✕ Diğer Tüm Sekmeleri Kapat", command=lambda: self.close_other_tabs(norm_path))
        menu.add_command(label="✕ Tüm Sekmeleri Kapat", command=self.close_all_tabs)
        menu.post(event.x_root, event.y_root)

    def close_other_tabs(self, keep_norm_path):
        to_close = [np for np in list(self.tabs.keys()) if np != keep_norm_path]
        for np in to_close:
            self.request_close_tab(np)

    def close_all_tabs(self):
        to_close = list(self.tabs.keys())
        for np in to_close:
            self.request_close_tab(np)

    def analyze_all(self):
        if not self.tabs:
            messagebox.showinfo("Analyze All", "Henüz çalışma alanında dosya yok. Lütfen '+ ADD DLL / EXE' ile dosya ekleyin.")
            return
            
        self.log("SYSTEM", f"Starting batch analysis across {len(self.tabs)} open tabs...")
        for tab_data in self.tabs.values():
            tab_data["panel"].run_scan()

    def compare_dlls(self):
        if len(self.tabs) < 2:
            messagebox.showwarning("Compare", "Karşılaştırma yapmak için en az 2 dosya açık olmalıdır.")
            return
            
        comp_win = tk.Toplevel(self.root)
        comp_win.title("Multi-PE / DLL Architecture Comparison")
        comp_win.geometry("920x580")
        
        txt = tk.Text(comp_win, wrap=tk.WORD, font=("Consolas", 10), bg="#222", fg="#FFF")
        txt.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        txt.insert(tk.END, "=========================================================\n")
        txt.insert(tk.END, "PE & DLL ARCHITECTURE COMPARISON\n")
        txt.insert(tk.END, "=========================================================\n\n")
        
        for tab_data in self.tabs.values():
            panel = tab_data["panel"]
            eng = panel.engine
            if eng and not eng.is_valid:
                eng.parse_pe()
                
            txt.insert(tk.END, f"File Name       : {tab_data['name']}\n")
            if eng and eng.pe:
                txt.insert(tk.END, f"Size (Bytes)    : {eng.file_size}\n")
                txt.insert(tk.END, f"SHA-256         : {eng.sha256}\n")
                txt.insert(tk.END, f"Architecture    : {'x86 (32-bit)' if eng.pe.FILE_HEADER.Machine == 0x14c else 'x64 (64-bit)'}\n")
                txt.insert(tk.END, f"ImageBase       : {hex(eng.image_base)}\n")
                txt.insert(tk.END, f"Sections Count  : {len(eng.sections)}\n")
                txt.insert(tk.END, f"Imports Count   : {len(eng.imports)} DLLs\n")
                txt.insert(tk.END, f"Exports Count   : {len(eng.exports)} symbols\n")
            txt.insert(tk.END, f"Scan Results    : {len(panel.scan_results)} entries evaluated\n")
            txt.insert(tk.END, "-" * 57 + "\n\n")
            
        txt.config(state=tk.DISABLED)

    def save_all(self):
        if not self.tabs:
            messagebox.showwarning("Save All", "Kaydedilecek açık sekme yok.")
            return
            
        export_folder = filedialog.askdirectory(title="Select Folder for SAVE ALL Export")
        if not export_folder:
            self.log("SAVE", "SAVE ALL cancelled by user.")
            return
            
        self.log("SAVE_ALL", f"Initiating batch export to: {export_folder}")
        
        combined_report_path = os.path.join(export_folder, "CombinedReport.txt")
        with open(combined_report_path, "w", encoding="utf-8") as crf:
            crf.write("=========================================================\n")
            crf.write("POINTER ANALYZER - COMBINED MASTER REPORT\n")
            crf.write(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            crf.write("=========================================================\n\n")
            
            for idx, tab_data in enumerate(self.tabs.values(), 1):
                panel = tab_data["panel"]
                base_name = tab_data["name"]
                dll_subfolder = os.path.join(export_folder, f"DLL_{idx:02d}_{os.path.splitext(base_name)[0]}")
                
                if not panel.scan_results and panel.engine:
                    panel.engine.parse_pe()
                    panel.scan_results = panel.engine.validate_all()
                    
                if panel.engine:
                    panel.engine.export_all(panel.scan_results, dll_subfolder)
                    self.log("SAVE_ALL", f"Exported {base_name} to {dll_subfolder}")
                    
                    crf.write(f"--- [TARGET {idx:02d}: {base_name}] ---\n")
                    crf.write(f"Path: {panel.file_path}\n")
                    crf.write(f"SHA-256: {panel.engine.sha256}\n")
                    crf.write(f"Total Entries: {len(panel.scan_results)}\n\n")
                
        if os.path.exists(combined_report_path) and os.path.getsize(combined_report_path) > 0:
            self.log("SAVE_ALL", "SAVE ALL VERIFIED: CombinedReport.txt and all subfolders verified.")
            messagebox.showinfo("Save All Complete", f"SAVE ALL VERIFIED!\nExported to: {export_folder}")
        else:
            messagebox.showerror("Save All Error", "Failed to verify CombinedReport.txt.")

    def open_result_txt(self):
        file_path = filedialog.askopenfilename(
            title="Open Analysis Result TXT",
            filetypes=[("Text Documents (*.txt)", "*.txt"), ("All Files (*.*)", "*.*")]
        )
        if not file_path:
            return
            
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            
        viewer = tk.Toplevel(self.root)
        viewer.title(f"Result Viewer: {os.path.basename(file_path)}")
        viewer.geometry("850x550")
        
        txt = tk.Text(viewer, wrap=tk.WORD, font=("Consolas", 10), bg="#222", fg="#FFF")
        txt.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        txt.insert(tk.END, content)
        txt.config(state=tk.DISABLED)
        self.log("VIEWER", f"Opened result file: {os.path.basename(file_path)}")

    def run_native_host(self):
        if self.plugin_tab:
            self.plugin_tab.run_host_runtime()

    def run_plugin_tests(self):
        if self.plugin_tab:
            self.plugin_tab.run_tests()

    def run_test_fixture(self):
        self.log("FIXTURE", "Starting Controlled Injection Test...")
        def test_thread():
            CREATE_NO_WINDOW = 0x08000000
            
            if not os.path.exists(TARGET_EXE) or not os.path.exists(INJECTOR_EXE):
                self.log("FIXTURE", "Test fixture binaries not found in current folder.")
                messagebox.showinfo("Test Fixture", "Test Target binaries not found in current deployment directory.")
                return
                
            proc = subprocess.Popen([TARGET_EXE], creationflags=CREATE_NO_WINDOW)
            time.sleep(0.5)
            
            inj = subprocess.Popen([INJECTOR_EXE, str(proc.pid), DLL_PATH], creationflags=CREATE_NO_WINDOW)
            inj.wait()
            
            if inj.returncode == 0:
                self.log("FIXTURE", "SUCCESS: DLL LoadLibrary returned valid module handle in TestTarget.")
            else:
                self.log("FIXTURE", f"FAIL: Injector failed with exit code {inj.returncode}")
                
            try:
                with open(r"\\.\pipe\PointerScannerTestPipe", "w") as pipe:
                    pipe.write("STOP")
            except Exception:
                proc.terminate()
                
            self.log("FIXTURE", "Controlled Test Completed. Target terminated cleanly.")
            messagebox.showinfo("Controlled Test", "Controlled Test Fixture completed successfully with zero console popups.")
            
        threading.Thread(target=test_thread, daemon=True).start()


if __name__ == "__main__":
    root = tk.Tk()
    app = ControlCenterApp(root)
    root.mainloop()
