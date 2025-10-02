#!/usr/bin/env python3
"""
file_scanner_dark_cool_final.py

- Shows ALL scanned files in the left File list (live).
- Shows ONLY threats/malicious items in the Threats box.
- Adds Delete Selected File button (and context menu).
- Keeps hacker mask background behind widgets.
- Smooth graph animation.
- Graceful fallbacks for optional libs (Pillow, matplotlib, pefile).
"""

import os
import sys
import json
import hashlib
import threading
import time
import math
from pathlib import Path
from datetime import datetime, timedelta
from collections import deque

# Optional dependencies
_HAS_PIL = False
_HAS_MPL = False
_HAS_PEFILE = False

try:
    from PIL import Image, ImageTk
    _HAS_PIL = True
    print("✓ PIL/Pillow loaded successfully")
except Exception as e:
    print(f"✗ PIL/Pillow not available: {e}")
    _HAS_PIL = False

try:
    import matplotlib
    matplotlib.use("TkAgg")
    import matplotlib.pyplot as plt
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    _HAS_MPL = True
    print("✓ matplotlib loaded successfully")
except Exception as e:
    print(f"✗ matplotlib not available: {e}")
    _HAS_MPL = False

try:
    import pefile
    _HAS_PEFILE = True
    print("✓ pefile loaded successfully")
except Exception as e:
    print(f"✗ pefile not available: {e}")
    _HAS_PEFILE = False

try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox
    print("✓ tkinter loaded successfully")
except Exception as e:
    print(f"Error: tkinter not available: {e}")
    sys.exit(1)

# ---------- Configuration ----------
SUSPICIOUS_EXTS = {
    '.exe', '.scr', '.pif', '.bat', '.cmd', '.com', '.vbs', '.js', '.jse', '.wsf',
    '.ps1', '.psm1', '.lnk', '.msi', '.msp', '.hta', '.dll', '.sys', '.drv'
}

SUSPICIOUS_IMPORTS = {
    "VirtualAlloc", "VirtualProtect", "CreateRemoteThread",
    "WriteProcessMemory", "LoadLibrary", "GetProcAddress",
    "InternetOpenUrl", "URLDownloadToFileA", "WinExec", "ShellExecuteA"
}

LARGE_FILE_BYTES = 50 * 1024 * 1024
RECENT_DAYS = 30
MAX_HASH_FILES = 1000
HASH_CHUNK = 1024 * 1024

SCAN_DELAY_DEFAULT_MS = 10    # demo pause per file (ms)
BATCH_DELAY_DEFAULT_S = 0.2

BG_COLOR = "#0A0A0A"
FG_COLOR = "#00FF41"
SELECT_BG = "#004400"
ACCENT_COLOR = "#FF4444"
WATERMARK_COLOR = "#00FF88"

MASK_IMAGE = "hacker_mask.png"   # optional image to show behind UI
# ------------------------------------

def human_size(n):
    if n is None:
        return "0B"
    try:
        n = float(n)
    except Exception:
        return "0B"
    for unit in ['B','KB','MB','GB','TB']:
        if n < 1024:
            return f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}PB"

def detect_header(path):
    try:
        with open(path, 'rb') as f:
            head = f.read(16)
    except Exception:
        return None
    if head.startswith(b'MZ'):
        return 'PE/Windows EXE'
    if head.startswith(b'\x7fELF'):
        return 'ELF'
    if head.startswith(b'%PDF-'):
        return 'PDF'
    if head.startswith(b'PK\x03\x04'):
        return 'ZIP/OOXML'
    return None

def sha256_of_file(path):
    h = hashlib.sha256()
    try:
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(HASH_CHUNK), b''):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None

def pe_has_suspicious_imports(path):
    if not _HAS_PEFILE:
        return False, []
    try:
        pe = pefile.PE(str(path))
        imports = []
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if not imp.name:
                        continue
                    name = imp.name.decode(errors='ignore') if isinstance(imp.name, bytes) else str(imp.name)
                    imports.append(name)
        suspicious = [i for i in imports if i in SUSPICIOUS_IMPORTS]
        return (len(suspicious) > 0), suspicious
    except Exception:
        return False, []

# ---------------- Scanner ----------------
def scan_folder(root_path, progress_callback=None, stop_event=None, config=None,
                threat_callback=None, file_callback=None):
    """
    Walks folder, sends live updates:
    - file_callback(file_info) for each discovered file (quick)
    - threat_callback(msg) for each likely threat (only threats)
    - progress_callback(percent_or_None, message)
    Returns a full report dict at the end.
    """
    if config is None:
        config = {}
    large_limit = config.get('large_limit', LARGE_FILE_BYTES)
    recent_days = config.get('recent_days', RECENT_DAYS)
    max_hash = config.get('max_hash_files', MAX_HASH_FILES)
    scan_delay = config.get('scan_delay', SCAN_DELAY_DEFAULT_MS)  # ms
    batch_delay = config.get('batch_delay', BATCH_DELAY_DEFAULT_S)  # s

    root = Path(root_path)
    now = datetime.now()
    recent_cutoff = now - timedelta(days=recent_days)

    report = {
        "scanned_root": str(root),
        "scanned_at": now.isoformat(),
        "summary": {},
        "all_files": [],
        "suspicious_ext": [],
        "header_matches": [],
        "large_files": [],
        "recent_files": [],
        "duplicates": [],
        "threats": [],   # only likely-malicious files
        "errors": []
    }

    all_files = []
    total_files = 0
    total_bytes = 0

    # Indexing pass (fast)
    try:
        for dirpath, dirs, files in os.walk(root, topdown=True):
            if stop_event and stop_event.is_set():
                report['errors'].append("Scan cancelled by user.")
                break
            for fn in files:
                total_files += 1
                p = Path(dirpath) / fn
                try:
                    st = p.stat()
                    size = st.st_size
                    mtime = datetime.fromtimestamp(st.st_mtime)
                    ctime = datetime.fromtimestamp(st.st_ctime)
                except Exception as e:
                    report['errors'].append(f"Stat error {p}: {e}")
                    continue
                total_bytes += size
                file_info = {
                    "path": str(p),
                    "name": fn,
                    "directory": dirpath,
                    "size": size,
                    "size_human": human_size(size),
                    "modified": mtime,
                    "created": ctime,
                    "ext": p.suffix.lower(),
                    "header": None,
                    "threat": False,
                    "threat_reasons": []
                }
                all_files.append(file_info)

                # live quick UI update (every file)
                if file_callback:
                    try:
                        file_callback(file_info)
                    except Exception:
                        pass

                # small demo pacing
                if scan_delay and scan_delay > 0:
                    time.sleep(scan_delay / 1000.0)

            # occasional progress message
            if progress_callback and total_files % 200 == 0:
                try:
                    progress_callback(None, f"Indexed {total_files} files...")
                except Exception:
                    pass

    except Exception as e:
        report['errors'].append(f"Walk error: {e}")

    report['summary']['total_files'] = total_files
    report['summary']['total_size_bytes'] = total_bytes

    if not all_files:
        if progress_callback:
            progress_callback(100, "No files found to scan.")
        report['all_files'] = all_files
        return report

    # Analysis pass
    hash_candidates = []
    for idx, file_info in enumerate(all_files):
        if stop_event and stop_event.is_set():
            break

        path = file_info['path']
        ext = file_info['ext']
        size = file_info['size']

        # demo pace
        if scan_delay and scan_delay > 0:
            time.sleep(scan_delay / 1000.0)

        # suspicious extension - FIXED: Now properly triggers threats
        if ext in SUSPICIOUS_EXTS:
            report['suspicious_ext'].append(file_info)
            if not file_info['threat']:
                file_info['threat'] = True
                file_info['threat_reasons'].append(f"Suspicious extension: {ext}")
                report['threats'].append(file_info)
                if threat_callback:
                    try: 
                        threat_callback(f"⚠️ Suspicious extension: {file_info['name']} ({ext})")
                        print(f"THREAT DETECTED: {file_info['name']} - Suspicious extension")
                    except Exception: 
                        pass

        # large file
        if size >= large_limit:
            report['large_files'].append(file_info)

        # recent file
        if file_info['modified'] >= recent_cutoff:
            report['recent_files'].append(file_info)

        # header detection
        header = None
        try:
            if os.path.isfile(path) and os.access(path, os.R_OK):
                header = detect_header(path)
                file_info['header'] = header
        except Exception:
            header = None

        if header:
            report['header_matches'].append(file_info)

        # pe imports (if available)
        if ext in ('.exe', '.dll', '.scr', '.sys') and _HAS_PEFILE and os.path.isfile(path):
            try:
                suspicious_imported, suspicious_list = pe_has_suspicious_imports(path)
                if suspicious_imported:
                    if not file_info['threat']:
                        file_info['threat'] = True
                        msg = f"Suspicious imports: {', '.join(suspicious_list[:5])}"
                        file_info['threat_reasons'].append(msg)
                        report['threats'].append(file_info)
                        if threat_callback:
                            try: 
                                threat_callback(f"🚨 {msg}: {file_info['name']}")
                                print(f"THREAT DETECTED: {file_info['name']} - Suspicious imports")
                            except Exception: 
                                pass
            except Exception:
                pass

        # header/ext mismatch considered suspicious
        if ext in ('.exe', '.dll', '.scr') and header and header != 'PE/Windows EXE':
            if not file_info['threat']:
                file_info['threat'] = True
                msg = f"Header/extension mismatch: {ext} vs {header}"
                file_info['threat_reasons'].append(msg)
                report['threats'].append(file_info)
                if threat_callback:
                    try: 
                        threat_callback(f"⚠️ {msg}: {file_info['name']}")
                        print(f"THREAT DETECTED: {file_info['name']} - Header mismatch")
                    except Exception: 
                        pass

        # duplicates candidate
        if len(hash_candidates) < max_hash and size <= 200 * 1024 * 1024 and os.path.isfile(path):
            hash_candidates.append((path, size))

        # periodic analysis progress
        if progress_callback and (idx % 50 == 0 or idx == len(all_files) - 1):
            try:
                percent = min(90, int((idx / max(1, len(all_files))) * 90))
                progress_callback(percent, f"Analyzing files... ({idx}/{len(all_files)})")
            except Exception:
                pass
            if batch_delay and idx % 200 == 0:
                time.sleep(batch_delay)

    report['all_files'] = all_files

    # duplicate detection (hashing)
    if hash_candidates and not (stop_event and stop_event.is_set()):
        hashes = {}
        for i, (p, size) in enumerate(hash_candidates):
            if stop_event and stop_event.is_set():
                break
            if scan_delay and scan_delay > 0:
                time.sleep(scan_delay / 1000.0)
            h = sha256_of_file(p)
            if not h:
                report['errors'].append(f"Unable to hash: {p}")
                continue
            hashes.setdefault((size, h), []).append(p)
            if progress_callback and (i % 10 == 0 or i == len(hash_candidates) - 1):
                try:
                    percent = min(99, 90 + int((i / max(1, len(hash_candidates))) * 10))
                    progress_callback(percent, f"Hashing files... ({i+1}/{len(hash_candidates)})")
                except Exception:
                    pass

        for (size, h), paths in hashes.items():
            if len(paths) > 1:
                # mark all duplicates as suspicious (optional)
                dup_info = {"size": size, "sha256": h, "paths": paths}
                report['duplicates'].append(dup_info)
                # report a general threat for duplicates (first path shown)
                try:
                    first_name = Path(paths[0]).name
                    if threat_callback:
                        threat_callback(f"⚠️ Duplicate files detected: {first_name} (x{len(paths)})")
                        print(f"THREAT DETECTED: Duplicate files - {first_name}")
                except Exception:
                    pass

    # fill summary
    s = report['summary']
    s['total_files'] = total_files
    s['total_size_bytes'] = total_bytes
    s['suspicious_ext_count'] = len(report['suspicious_ext'])
    s['header_matches_count'] = len(report['header_matches'])
    s['large_files_count'] = len(report['large_files'])
    s['recent_files_count'] = len(report['recent_files'])
    s['duplicates_count'] = len(report['duplicates'])
    s['threats_count'] = len(report['threats'])

    if progress_callback:
        try:
            progress_callback(100, "Scan finished.")
        except Exception:
            pass

    return report

# ---------------- GUI ----------------
class ScannerGUI:
    def __init__(self, root):
        self.root = root
        root.title("Virus Killer Scanner — Made by Ayush Rana")
        root.geometry("1400x820")
        root.configure(bg=BG_COLOR)
        root.protocol("WM_DELETE_WINDOW", self.on_closing)

        # runtime state
        self._scan_thread = None
        self._stop_event = threading.Event()
        self._is_scanning = False
        self.report = None
        self._tree_id_to_path = {}   # map tree item id -> path
        self._threats_shown_set = set()
        self._last_progress_time = 0
        self._graph_data = []  # Store progress data for graph

        # UI
        self._setup_styles()
        self._create_ui()
        self._schedule_graph_update()
        
        print("GUI initialized successfully")

    def _setup_styles(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
            # Configure styles for better visibility
            style.configure("TFrame", background=BG_COLOR)
            style.configure("TLabel", background=BG_COLOR, foreground=FG_COLOR)
            style.configure("TButton", background=SELECT_BG, foreground=FG_COLOR)
            style.configure("Treeview",
                            background=BG_COLOR,
                            fieldbackground=BG_COLOR,
                            foreground=FG_COLOR,
                            rowheight=20)
            style.map("Treeview", 
                     background=[('selected', SELECT_BG)], 
                     foreground=[('selected', FG_COLOR)])
            print("✓ Styles configured successfully")
        except Exception as e:
            print(f"✗ Style configuration failed: {e}")

    def _create_ui(self):
        # Main container with visible background
        main_container = tk.Frame(self.root, bg=BG_COLOR)
        main_container.pack(fill='both', expand=True)

        # Top controls
        top = tk.Frame(main_container, bg=BG_COLOR)
        top.pack(fill='x', padx=10, pady=8)

        title_label = tk.Label(top, text="🔍 Virus Killer Scanner", bg=BG_COLOR, fg=ACCENT_COLOR, font=('Arial', 14, 'bold'))
        title_label.pack(side='left')
        
        scan_label = tk.Label(top, text="Scan Folder:", bg=BG_COLOR, fg=FG_COLOR, font=('Arial', 11))
        scan_label.pack(side='left', padx=(20,5))

        self.path_var = tk.StringVar(value=os.getcwd())
        self.entry = tk.Entry(top, textvariable=self.path_var, width=80, bg="#111111", fg=FG_COLOR, 
                             insertbackground=FG_COLOR, font=('Arial', 10), relief='solid', bd=1)
        self.entry.pack(side='left', padx=8)
        
        browse_btn = tk.Button(top, text="📁 Browse", command=self.browse, bg=SELECT_BG, fg=FG_COLOR,
                              font=('Arial', 10), relief='raised', bd=2)
        browse_btn.pack(side='left')

        # buttons
        btn_frame = tk.Frame(main_container, bg=BG_COLOR)
        btn_frame.pack(fill='x', padx=10, pady=6)
        
        self.scan_btn = tk.Button(btn_frame, text="🚀 Start Deep Scan", command=self.start_scan, 
                                 bg=SELECT_BG, fg=FG_COLOR, font=('Arial', 11, 'bold'),
                                 relief='raised', bd=2)
        self.scan_btn.pack(side='left', padx=6)
        
        self.stop_btn = tk.Button(btn_frame, text="🛑 Stop Scan", command=self.stop_scan, 
                                 bg=ACCENT_COLOR, fg="white", state='disabled', font=('Arial', 10, 'bold'),
                                 relief='raised', bd=2)
        self.stop_btn.pack(side='left', padx=6)
        
        self.delete_btn = tk.Button(btn_frame, text="🗑 Delete Selected File", command=self.delete_selected_file, 
                                   bg=ACCENT_COLOR, fg="white", font=('Arial', 10, 'bold'),
                                   relief='raised', bd=2)
        self.delete_btn.pack(side='left', padx=6)
        
        save_btn = tk.Button(btn_frame, text="💾 Save Report", command=self.save_report, 
                            bg=SELECT_BG, fg=FG_COLOR, font=('Arial', 10),
                            relief='raised', bd=2)
        save_btn.pack(side='left', padx=6)

        # speed control
        speed_label = tk.Label(btn_frame, text="Scan Speed:", bg=BG_COLOR, fg=FG_COLOR, font=('Arial', 10))
        speed_label.pack(side='right', padx=(0,6))
        
        self.speed_var = tk.StringVar(value="Medium")
        speed_combo = ttk.Combobox(btn_frame, textvariable=self.speed_var, 
                                  values=["Very Slow", "Slow", "Medium", "Fast"], 
                                  state='readonly', width=10)
        speed_combo.pack(side='right')
        speed_combo.set("Medium")

        # progress area (graph or progress bar)
        prog_frame = tk.Frame(main_container, bg=BG_COLOR)
        prog_frame.pack(fill='x', padx=10, pady=6)

        if _HAS_MPL:
            self._has_graph = True
            self.fig, self.ax = plt.subplots(figsize=(6,2), dpi=100)
            try:
                self.fig.patch.set_facecolor(BG_COLOR)
                self.ax.set_facecolor(BG_COLOR)
            except Exception:
                pass
            self.ax.tick_params(colors=FG_COLOR)
            for spine in self.ax.spines.values():
                try:
                    spine.set_color(FG_COLOR)
                except Exception:
                    pass
            self.line, = self.ax.plot([], [], linewidth=2, color=ACCENT_COLOR)
            self.ax.set_ylim(0, 100)
            self.ax.set_xlim(0, 50)
            self.data_q = deque(maxlen=50)
            # Initialize with some data
            self.data_q.extend([0] * 10)
            self.canvas = FigureCanvasTkAgg(self.fig, master=prog_frame)
            self.canvas.get_tk_widget().pack(fill='x')
            print("✓ Graph initialized successfully")
        else:
            self._has_graph = False
            self.progress_var = tk.IntVar()
            self.progress_bar = ttk.Progressbar(prog_frame, variable=self.progress_var, 
                                               maximum=100, mode='determinate')
            self.progress_bar.pack(fill='x', padx=10)
            self.progress_label = tk.Label(prog_frame, text="0%", bg=BG_COLOR, fg=FG_COLOR)
            self.progress_label.pack(side='right', padx=6)
            print("✓ Progress bar initialized (matplotlib not available)")

        self.status_var = tk.StringVar(value="Ready. Select a folder and click Start Scan.")
        status_label = tk.Label(prog_frame, textvariable=self.status_var, bg=BG_COLOR, fg=FG_COLOR, 
                               font=('Arial', 10, 'italic'))
        status_label.pack(side='left', padx=6)

        # main panes
        mid = tk.PanedWindow(main_container, orient='horizontal', sashrelief='raised', bg=BG_COLOR)
        mid.pack(fill='both', expand=True, padx=10, pady=8)

        # left: file list
        left_frame = tk.Frame(mid, bg=BG_COLOR)
        mid.add(left_frame, minsize=800)
        
        files_label = tk.Label(left_frame, text="📂 Files Scanned", bg=BG_COLOR, fg=FG_COLOR, 
                              font=('Arial', 12, 'bold'))
        files_label.pack(anchor='w')

        columns = ("Name", "Size", "Modified", "Path")
        self.tree = ttk.Treeview(left_frame, columns=columns, show='headings', selectmode="browse")
        self.tree.heading("Name", text="File Name")
        self.tree.heading("Size", text="Size")
        self.tree.heading("Modified", text="Last Modified")
        self.tree.heading("Path", text="Path")
        self.tree.column("Name", width=480, anchor='w')
        self.tree.column("Size", width=110, anchor='e')
        self.tree.column("Modified", width=180, anchor='center')
        self.tree.column("Path", width=0, stretch=False)  # Hide Path column

        vsb = ttk.Scrollbar(left_frame, orient='vertical', command=self.tree.yview)
        hsb = ttk.Scrollbar(left_frame, orient='horizontal', command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.tree.pack(fill='both', expand=True, side='left')
        vsb.pack(side='right', fill='y')
        hsb.pack(side='bottom', fill='x')

        # context menu for delete
        self.menu = tk.Menu(self.root, tearoff=0, bg=BG_COLOR, fg=FG_COLOR)
        self.menu.add_command(label="🗑 Delete File", command=self.delete_selected_file)

        def show_context_menu(event):
            try:
                item = self.tree.identify_row(event.y)
                if item:
                    self.tree.selection_set(item)
                    self.menu.post(event.x_root, event.y_root)
            except Exception:
                pass

        self.tree.bind("<Button-3>", show_context_menu)

        # right: threats
        right_frame = tk.Frame(mid, bg=BG_COLOR)
        mid.add(right_frame, minsize=380)
        
        threats_label = tk.Label(right_frame, text="⚠️ Detected Threats", bg=BG_COLOR, fg=ACCENT_COLOR, 
                                font=('Arial', 12, 'bold'))
        threats_label.pack(anchor='w')
        
        self.threat_list = tk.Listbox(right_frame, bg="#111111", fg=ACCENT_COLOR, 
                                     selectbackground=SELECT_BG, selectforeground=FG_COLOR, 
                                     font=('Courier', 10), relief='solid', bd=1)
        self.threat_list.pack(fill='both', expand=True)

        # Add some sample data to verify UI is working
        self._add_sample_data()

    def _add_sample_data(self):
        """Add sample data to verify UI elements are visible"""
        try:
            # Add a sample file to treeview
            sample_time = datetime.now().strftime("%Y-%m-%d %H:%M")
            sample_item = self.tree.insert("", "end", values=("sample.txt", "1.0KB", sample_time, "/path/to/sample.txt"))
            self._tree_id_to_path[sample_item] = "/path/to/sample.txt"
            
            # Add sample threat
            self.threat_list.insert(tk.END, "No threats detected yet. Run a scan to find threats.")
        except Exception as e:
            print(f"Could not add sample data: {e}")

    def _schedule_graph_update(self):
        """Update the graph animation regularly"""
        if hasattr(self, '_has_graph') and self._has_graph:
            try:
                if hasattr(self, 'data_q') and self.data_q:
                    y = list(self.data_q)
                    x = list(range(len(y)))
                    
                    # Clear and redraw the line
                    self.ax.clear()
                    self.ax.plot(x, y, linewidth=2, color=ACCENT_COLOR)
                    self.ax.set_facecolor(BG_COLOR)
                    self.ax.set_ylim(0, 100)
                    self.ax.set_xlim(0, max(50, len(x)))
                    self.ax.tick_params(colors=FG_COLOR)
                    
                    # Set spine colors
                    for spine in self.ax.spines.values():
                        spine.set_color(FG_COLOR)
                    
                    self.canvas.draw_idle()
            except Exception as e:
                print(f"Graph update error: {e}")
        
        # Schedule next update
        self.root.after(100, self._schedule_graph_update)

    # ---------------- UI callbacks / helpers ----------------
    def browse(self):
        d = filedialog.askdirectory(initialdir=self.path_var.get())
        if d:
            self.path_var.set(d)

    def start_scan(self):
        if self._is_scanning:
            messagebox.showinfo("Scan in progress", "A scan is already running.")
            return
        path = self.path_var.get().strip()
        if not path or not os.path.isdir(path):
            messagebox.showerror("Invalid folder", "Choose a valid folder.")
            return

        # clear UI
        self.tree.delete(*self.tree.get_children())
        self.threat_list.delete(0, tk.END)
        self._tree_id_to_path.clear()
        self._threats_shown_set.clear()
        self.report = None

        # configure speed
        speed_map = {
            "Very Slow": {"scan_delay": 300, "batch_delay": 1},
            "Slow": {"scan_delay": 100, "batch_delay": 0.5},
            "Medium": {"scan_delay": 10, "batch_delay": 0.2},
            "Fast": {"scan_delay": 0, "batch_delay": 0.0}
        }
        speed = self.speed_var.get()
        config = speed_map.get(speed, speed_map["Medium"])

        self._stop_event = threading.Event()
        self._scan_thread = threading.Thread(target=self._scan_worker, args=(path, config), daemon=True)
        self._scan_thread.start()
        self._is_scanning = True
        self.scan_btn.config(state='disabled')
        self.stop_btn.config(state='normal')
        self.status_var.set(f"Starting {speed} deep scan...")
        
        # Initialize graph data
        if self._has_graph:
            self.data_q.clear()
            self.data_q.extend([0] * 10)

    def _scan_worker(self, path, config):
        try:
            report = scan_folder(
                path,
                progress_callback=self._on_progress,
                stop_event=self._stop_event,
                config=config,
                threat_callback=self._on_threat,
                file_callback=self._on_file
            )
            self.report = report
            self.root.after(0, self._scan_complete)
        except Exception as e:
            self.report = {"errors": [str(e)]}
            self.root.after(0, self._scan_error)

    def _on_progress(self, percent, msg):
        now = time.time()
        if percent is not None:
            # Update graph data
            if self._has_graph:
                self.data_q.append(percent)
            
            # Update progress bar if no graph
            if not self._has_graph:
                try:
                    self.progress_var.set(int(percent))
                    self.progress_label.config(text=f"{int(percent)}%")
                except Exception:
                    pass
            
            self.status_var.set(f"{int(percent)}% - {msg}")
        else:
            # message only; throttle changes
            if now - self._last_progress_time > 0.05:
                self.status_var.set(msg)
                self._last_progress_time = now

    def _on_file(self, file_info):
        # Add file to left list; run in main thread
        def _insert():
            try:
                modified_str = file_info['modified'].strftime("%Y-%m-%d %H:%M")
            except Exception:
                modified_str = str(file_info.get('modified', ''))
            iid = self.tree.insert("", "end", values=(file_info['name'], file_info['size_human'], modified_str, file_info['path']))
            self._tree_id_to_path[iid] = file_info['path']
        try:
            self.root.after(0, _insert)
        except Exception:
            pass

    def _on_threat(self, msg):
        # Only add unique messages so the Threats box doesn't flood
        if msg in self._threats_shown_set:
            return
        self._threats_shown_set.add(msg)
        try:
            self.root.after(0, lambda: self.threat_list.insert(tk.END, msg))
            print(f"Threat added to UI: {msg}")
        except Exception:
            pass

    def _scan_complete(self):
        self._is_scanning = False
        self.scan_btn.config(state='normal')
        self.stop_btn.config(state='disabled')
        
        # Show summary in status
        if self.report and 'summary' in self.report:
            threats_count = self.report['summary'].get('threats_count', 0)
            self.status_var.set(f"Scan complete. Found {threats_count} threats.")
        else:
            self.status_var.set("Scan complete.")

    def _scan_error(self):
        self._is_scanning = False
        self.scan_btn.config(state='normal')
        self.stop_btn.config(state='disabled')
        err = (self.report.get('errors', ["Unknown error"])[0] if isinstance(self.report, dict) else "Unknown error")
        messagebox.showerror("Scan error", str(err))
        self.status_var.set("Scan error.")

    def stop_scan(self):
        if self._is_scanning and hasattr(self, '_stop_event'):
            self._stop_event.set()
            self.status_var.set("Stopping scan...")

    def save_report(self):
        if not self.report:
            messagebox.showinfo("No report", "No scan report to save.")
            return
        f = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json")])
        if not f:
            return
        try:
            with open(f, 'w', encoding='utf-8') as fh:
                json.dump(self.report, fh, indent=2, default=str)
            messagebox.showinfo("Saved", f"Report saved to {f}")
        except Exception as e:
            messagebox.showerror("Save error", str(e))

    def delete_selected_file(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("No selection", "Select a file in the left list first.")
            return
        
        iid = sel[0]
        path = self._tree_id_to_path.get(iid)
        
        # If not found in mapping, try to get from tree values
        if not path:
            try:
                item_values = self.tree.item(iid, 'values')
                if item_values and len(item_values) > 3:
                    path = item_values[3]  # Path is the 4th column (index 3)
            except Exception:
                pass
        
        if not path:
            messagebox.showerror("Delete error", "Could not determine file path.")
            return
            
        if not os.path.exists(path):
            # remove stale entry
            try:
                del self._tree_id_to_path[iid]
            except Exception:
                pass
            self.tree.delete(iid)
            messagebox.showinfo("Removed", "Entry removed (file not found).")
            return
            
        # Double confirmation for dangerous files
        filename = Path(path).name
        file_ext = Path(path).suffix.lower()
        is_dangerous = file_ext in SUSPICIOUS_EXTS
        
        if is_dangerous:
            confirm_msg = f"WARNING: This file has a suspicious extension ({file_ext})!\n\nAre you ABSOLUTELY sure you want to permanently delete:\n{filename}\n\nPath: {path}"
        else:
            confirm_msg = f"Are you sure you want to permanently delete:\n{filename}\n\nPath: {path}"
            
        if not messagebox.askyesno("Confirm Delete", confirm_msg):
            return
            
        try:
            # Try to delete the file
            os.remove(path)
            
            # Remove from tree and mapping
            try:
                del self._tree_id_to_path[iid]
            except Exception:
                pass
            self.tree.delete(iid)
            
            # Remove any threat entries for this file
            self._remove_threats_for_path(path)
            
            messagebox.showinfo("Deleted", f"File successfully deleted:\n{filename}")
            
        except PermissionError:
            messagebox.showerror("Delete failed", f"Permission denied: Cannot delete {filename}\nThe file may be in use by another program.")
        except Exception as e:
            messagebox.showerror("Delete failed", f"Could not delete {filename}:\n{str(e)}")

    def _remove_threats_for_path(self, path):
        # Remove threat list items that mention the filename or path
        name = Path(path).name
        try:
            items_to_keep = []
            items = list(self.threat_list.get(0, tk.END))
            
            for item in items:
                if name in item or path in item:
                    # Remove from shown set
                    if item in self._threats_shown_set:
                        self._threats_shown_set.remove(item)
                else:
                    items_to_keep.append(item)
            
            # Update the threat list
            self.threat_list.delete(0, tk.END)
            for item in items_to_keep:
                self.threat_list.insert(tk.END, item)
                
        except Exception as e:
            print(f"Error cleaning threats list: {e}")

    def on_closing(self):
        if self._is_scanning:
            if not messagebox.askyesno("Exit", "Scan in progress. Quit anyway?"):
                return
            if hasattr(self, '_stop_event'):
                self._stop_event.set()
        self.root.destroy()

# ---------------- Main ----------------
def main():
    print("Starting Virus Killer Scanner...")
    print("Initializing GUI...")
    
    root = tk.Tk()
    app = ScannerGUI(root)
    
    print("Application ready!")
    print("System information:")
    print(f"  - Python version: {sys.version}")
    print(f"  - Working directory: {os.getcwd()}")
    print(f"  - PIL available: {_HAS_PIL}")
    print(f"  - matplotlib available: {_HAS_MPL}")
    print(f"  - pefile available: {_HAS_PEFILE}")
    
    root.mainloop()

if __name__ == "__main__":
    main()
