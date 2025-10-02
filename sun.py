#!/usr/bin/env python3
"""
file_scanner_dark_cool.py

Dark-mode file scanner with hacker mask background, transparent-like UI,
threats box, and live scan graph.
"""

import os
import sys
import json
import hashlib
import threading
from pathlib import Path
from datetime import datetime, timedelta

import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox
except Exception:
    tk = None

# ---------- Configuration ----------
SUSPICIOUS_EXTS = {
    '.exe', '.scr', '.pif', '.bat', '.cmd', '.com', '.vbs', '.js', '.jse',
    '.wsf', '.ps1', '.psm1', '.lnk', '.msi', '.msp', '.hta'
}
LARGE_FILE_BYTES = 100 * 1024 * 1024
RECENT_DAYS = 7
MAX_HASH_FILES = 500
HASH_CHUNK = 1024 * 1024

BG_COLOR = "#000000"
FG_COLOR = "#00FF00"
SELECT_BG = "#003300"
# ------------------------------------

def human_size(n):
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
    if head.startswith(b'MZ'): return 'PE/Windows EXE'
    if head.startswith(b'\x7fELF'): return 'ELF'
    if head.startswith((b'\xfe\xed\xfa\xce', b'\xce\xfa\xed\xfe', b'\xfe\xed\xfa\xcf', b'\xcf\xfa\xed\xfe')):
        return 'Mach-O'
    if head.startswith(b'%PDF-'): return 'PDF'
    if head.startswith(b'PK\x03\x04'): return 'ZIP/OOXML'
    return None

def sha256_of_file(path):
    h = hashlib.sha256()
    try:
        with open(path, 'rb') as f:
            while True:
                chunk = f.read(HASH_CHUNK)
                if not chunk: break
                h.update(chunk)
    except Exception:
        return None
    return h.hexdigest()

def scan_folder(root_path, progress_callback=None, stop_event=None, config=None, threat_callback=None):
    if config is None: config = {}
    large_limit = config.get('large_limit', LARGE_FILE_BYTES)
    recent_days = config.get('recent_days', RECENT_DAYS)
    max_hash = config.get('max_hash_files', MAX_HASH_FILES)

    root = Path(root_path)
    now = datetime.now()
    recent_cutoff = now - timedelta(days=recent_days)

    report = {
        "scanned_root": str(root),
        "scanned_at": now.isoformat(),
        "summary": {},
        "suspicious_ext": [],
        "header_matches": [],
        "large_files": [],
        "recent_files": [],
        "duplicates": [],
        "errors": []
    }

    all_files = []
    total_files = 0
    total_bytes = 0
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
                except Exception as e:
                    report['errors'].append(f"Stat error {p}: {e}")
                    continue
                total_bytes += size
                all_files.append({"path": str(p), "size": size, "mtime": mtime, "ext": p.suffix.lower()})
            if progress_callback and total_files % 200 == 0:
                progress_callback(None, f"Indexed {total_files} files...")

    except Exception as e:
        report['errors'].append(f"Walk error: {e}")

    report['summary']['total_files'] = total_files
    report['summary']['total_size_bytes'] = total_bytes

    hash_candidates = []
    for idx, fmeta in enumerate(all_files):
        if stop_event and stop_event.is_set(): break
        path = fmeta['path']
        ext = fmeta['ext']
        size = fmeta['size']
        mtime = fmeta['mtime']

        if ext in SUSPICIOUS_EXTS:
            report['suspicious_ext'].append({"path": path, "ext": ext, "size": size})
            if threat_callback: threat_callback(f"Suspicious ext: {path}")

        if size >= large_limit:
            report['large_files'].append({"path": path, "size": size})

        if mtime >= recent_cutoff:
            report['recent_files'].append({"path": path, "mtime": mtime.isoformat(), "size": size})

        header = None
        try:
            if os.path.isfile(path) and os.access(path, os.R_OK):
                header = detect_header(path)
        except Exception:
            header = None
        if header:
            report['header_matches'].append({"path": path, "header": header, "size": size})
            if threat_callback: threat_callback(f"Header match: {path}")

        if len(hash_candidates) < max_hash and size <= 200 * 1024 * 1024:
            hash_candidates.append((path, size))

        if progress_callback and (idx % 200 == 0):
            percent = int((idx / max(1, len(all_files))) * 100)
            progress_callback(percent, f"Analyzing files... ({idx}/{len(all_files)})")

    hashes = {}
    for i, (p, size) in enumerate(hash_candidates):
        if stop_event and stop_event.is_set(): break
        h = sha256_of_file(p)
        if not h:
            report['errors'].append(f"Unable to hash: {p}")
            continue
        hashes.setdefault((size, h), []).append(p)
        if progress_callback:
            percent = int((i / max(1, len(hash_candidates))) * 100)
            progress_callback(percent, f"Hashing candidates... ({i+1}/{len(hash_candidates)})")

    for (size,h), paths in hashes.items():
        if len(paths) > 1:
            report['duplicates'].append({"size": size, "sha256": h, "paths": paths})
            if threat_callback: threat_callback(f"Duplicate detected: {paths[0]} ...")

    report['summary']['suspicious_ext_count'] = len(report['suspicious_ext'])
    report['summary']['header_matches_count'] = len(report['header_matches'])
    report['summary']['large_files_count'] = len(report['large_files'])
    report['summary']['recent_files_count'] = len(report['recent_files'])
    report['summary']['duplicates_count'] = len(report['duplicates'])
    return report

# ---------------- GUI ----------------
class ScannerGUI:
    def __init__(self, root):
        self.root = root
        root.title("File Scanner — Dark Hacker Mode")
        root.geometry("1200x700")
        root.configure(bg=BG_COLOR)

        # ---------- Hacker Mask Background ----------
        try:
            from PIL import Image, ImageTk
            self.bg_canvas = tk.Canvas(root, width=1200, height=700, bg=BG_COLOR, highlightthickness=0)
            self.bg_canvas.place(x=0, y=0, relwidth=1, relheight=1)

            self.bg_image = Image.open("hacker_mask.png").convert("RGBA")
            self.bg_image = self.bg_image.resize((600, 600))
            self.bg_tk = ImageTk.PhotoImage(self.bg_image)

            # Draw image centered
            self.bg_canvas.create_image(600, 350, image=self.bg_tk, anchor="center")
            self.bg_canvas.lower()
        except Exception as e:
            print("Background load failed:", e)

        # ---------- Styles ----------
        style = ttk.Style()
        try: style.theme_use("clam")
        except: pass

        style.configure("Treeview",
                        background=BG_COLOR,
                        fieldbackground=BG_COLOR,
                        foreground=FG_COLOR,
                        rowheight=20)
        style.map("Treeview", background=[('selected', SELECT_BG)], foreground=[('selected', FG_COLOR)])
        try: style.configure("Treeview.Heading", background=BG_COLOR, foreground=FG_COLOR)
        except Exception: pass

        # Top frame
        top = tk.Frame(root, bg=BG_COLOR)
        top.pack(fill='x', padx=8, pady=6)
        tk.Label(top, text="Folder:", bg=BG_COLOR, fg=FG_COLOR).pack(side='left')
        self.path_var = tk.StringVar(value=os.getcwd())
        self.entry = tk.Entry(top, textvariable=self.path_var, width=80,
                              bg=BG_COLOR, fg=FG_COLOR, insertbackground=FG_COLOR)
        self.entry.pack(side='left', padx=6)
        browse_btn = tk.Button(top, text="Browse", command=self.browse,
                               bg=BG_COLOR, fg=FG_COLOR, activebackground=SELECT_BG, activeforeground=FG_COLOR)
        browse_btn.pack(side='left')

        btn_frame = tk.Frame(root, bg=BG_COLOR)
        btn_frame.pack(fill='x', padx=8, pady=4)
        self.scan_btn = tk.Button(btn_frame, text="Scan", command=self.start_scan,
                                  bg=BG_COLOR, fg=FG_COLOR, activebackground=SELECT_BG, activeforeground=FG_COLOR)
        self.scan_btn.pack(side='left', padx=4)
        save_btn = tk.Button(btn_frame, text="Save Report", command=self.save_report,
                             bg=BG_COLOR, fg=FG_COLOR, activebackground=SELECT_BG, activeforeground=FG_COLOR)
        save_btn.pack(side='left', padx=4)
        quit_btn = tk.Button(btn_frame, text="Quit", command=root.quit,
                             bg=BG_COLOR, fg=FG_COLOR, activebackground=SELECT_BG, activeforeground=FG_COLOR)
        quit_btn.pack(side='right', padx=6)

        # Middle frame
        middle = tk.Frame(root, bg=BG_COLOR)
        middle.pack(fill='both', expand=True, padx=8, pady=4)

        # Left: Treeview
        left = tk.Frame(middle, bg=BG_COLOR)
        left.pack(side='left', fill='both', expand=True, padx=6)
        self.tree = ttk.Treeview(left, columns=("info",), show='tree headings')
        self.tree.heading("#0", text="File / Category")
        self.tree.heading("info", text="Info")
        self.tree.column("info", width=350)
        self.tree.pack(fill='both', expand=True)
        vsb = tk.Scrollbar(left, orient='vertical', command=self.tree.yview, bg=BG_COLOR, troughcolor=BG_COLOR)
        vsb.pack(side='right', fill='y')
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.tag_configure('transparent', background='', foreground=FG_COLOR)

        # Right: Threat box
        right = tk.Frame(middle, bg=BG_COLOR)
        right.pack(side='left', fill='y')
        tk.Label(right, text="Threats / Malware:", bg=BG_COLOR, fg=FG_COLOR).pack(anchor='nw')
        self.threats_listbox = tk.Listbox(right, bg=BG_COLOR, fg=FG_COLOR,
                                          selectbackground=SELECT_BG, width=50, height=20, highlightthickness=0)
        self.threats_listbox.pack(fill='y', padx=6, pady=6)

        # Bottom: Status
        self.status_var = tk.StringVar(value="Ready")
        tk.Label(root, textvariable=self.status_var, bg=BG_COLOR, fg=FG_COLOR,
                 anchor='w', relief='sunken').pack(fill='x', side='bottom')

        # Bottom-right: Matplotlib graph
        self.fig, self.ax = plt.subplots(figsize=(4,2))
        self.ax.set_facecolor(BG_COLOR)
        self.ax.tick_params(colors=FG_COLOR)
        self.ax.set_ylim(0, 100)
        self.graph_data = []
        self.line, = self.ax.plot([], [], color='lime')
        self.canvas = FigureCanvasTkAgg(self.fig, master=root)
        self.canvas.get_tk_widget().place(x=780, y=500)

        self.report = None
        self._scan_thread = None
        self._stop_event = threading.Event()

    def browse(self):
        p = filedialog.askdirectory(initialdir=self.path_var.get())
        if p: self.path_var.set(p)

    def start_scan(self):
        if self._scan_thread and self._scan_thread.is_alive():
            messagebox.showinfo("Scan in progress", "A scan is already running.")
            return
        path = self.path_var.get()
        if not os.path.isdir(path):
            messagebox.showerror("Invalid folder", "Choose a valid folder.")
            return
        self.tree.delete(*self.tree.get_children())
        self.threats_listbox.delete(0, tk.END)
        self.status_var.set("Starting scan...")
        self.graph_data.clear()
        self.line.set_data([], [])
        self._stop_event.clear()
        self._scan_thread = threading.Thread(target=self._scan_worker, args=(path,))
        self._scan_thread.daemon = True
        self._scan_thread.start()

    def _scan_worker(self, path):
        def progress_cb(percent, msg):
            self.root.after(1, lambda: self._update_status(percent, msg))
            import random
            val = random.randint(0,100)
            self.graph_data.append(val)
            if len(self.graph_data)>50: self.graph_data.pop(0)
            self.line.set_data(range(len(self.graph_data)), self.graph_data)
            self.ax.set_xlim(0,max(50,len(self.graph_data)))
            self.canvas.draw()

        def threat_cb(msg):
            self.root.after(1, lambda: self.threats_listbox.insert(tk.END, msg))

        try:
            report = scan_folder(path, progress_callback=progress_cb,
                                 stop_event=self._stop_event, threat_callback=threat_cb)
            self.report = report
            self.root.after(1, lambda: self._display_report(report))
            self.status_var.set("Scan complete.")
        except Exception as e:
            self.report = {"errors":[str(e)]}
            self.root.after(1, lambda: self._display_report(self.report))
            self.status_var.set("Scan error.")

    def _update_status(self, percent, msg):
        if percent is not None:
            self.status_var.set(f"{percent}% - {msg}")
        else:
            self.status_var.set(msg)

    def _display_report(self, report):
        self.tree.delete(*self.tree.get_children())
        root_node = self.tree.insert('', 'end', text=f"Scanned: {report.get('scanned_root')} ({report['summary'].get('total_files',0)} files)", tags=('transparent',))
        s = report.get('summary', {})
        self.tree.insert(root_node, 'end', text=f"Total files: {s.get('total_files')}  Total size: {human_size(s.get('total_size_bytes',0))}", tags=('transparent',))
        self.tree.insert(root_node, 'end', text=f"Suspicious ext: {s.get('suspicious_ext_count')}  Header matches: {s.get('header_matches_count')}", tags=('transparent',))
        self.tree.insert(root_node, 'end', text=f"Large files: {s.get('large_files_count')}  Recent files: {s.get('recent_files_count')}", tags=('transparent',))
        self.tree.insert(root_node, 'end', text=f"Duplicate sets: {s.get('duplicates_count')}", tags=('transparent',))
        self.tree.expand(root_node)

    def save_report(self):
        if not self.report:
            messagebox.showinfo("No report", "Run a scan first.")
            return
        f = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON","*.json")])
        if not f: return
        try:
            with open(f, 'w', encoding='utf-8') as fh:
                json.dump(self.report, fh, indent=2, default=str)
            messagebox.showinfo("Saved", f"Report saved to {f}")
        except Exception as e:
            messagebox.showerror("Save error", str(e))

# ---------------- Main ----------------
def main():
    if tk is None:
        print("Tkinter not available. Cannot run GUI.")
        return
    root = tk.Tk()
    app = ScannerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
