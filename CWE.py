import os
import sys
import datetime
import threading
import subprocess
import json
import shutil
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from typing import Dict, Any, List, Optional


class ProtocolManager:
    
    def __init__(self):
        self.protocols: Dict[str, Dict[str, Any]] = {
            # Local & Hardware Devices
            "DIRECT": {"category": "Local", "handler": "local"},
            "MTP": {"category": "Device", "handler": "mtp"},
            "PTP": {"category": "Device", "handler": "ptp"},
            "UASP / UMS": {"category": "Hardware", "handler": "block"},
            "NVMe-oF / Fibre Channel": {"category": "Storage SAN", "handler": "san"},
            
            # Traditional Network Shares
            "SMB / SMB2 / SMB3": {"category": "Network Shares", "handler": "rclone", "rclone_type": "smb"},
            "NFS": {"category": "Network Shares", "handler": "nfs"},
            "AFP": {"category": "Network Shares", "handler": "afp"},
            "WebDAV": {"category": "Network Shares", "handler": "rclone", "rclone_type": "webdav"},
            "iSCSI": {"category": "Block Storage", "handler": "iscsi"},
            
            # File Transfer Protocols
            "FTP / FTPS": {"category": "File Transfer", "handler": "rclone", "rclone_type": "ftp"},
            "SFTP / SCP": {"category": "File Transfer", "handler": "rclone", "rclone_type": "sftp"},
            "HTTP / HTTPS / HTTP/3": {"category": "Web", "handler": "rclone", "rclone_type": "http"},
            "Rsync": {"category": "Sync", "handler": "rsync"},
            
            # Cloud & Object Storage
            "S3 (AWS / MinIO)": {"category": "Cloud / Object", "handler": "rclone", "rclone_type": "s3"},
            "OpenStack Swift": {"category": "Cloud / Object", "handler": "rclone", "rclone_type": "swift"},
            "Google Cloud Storage": {"category": "Cloud / Object", "handler": "rclone", "rclone_type": "gcs"},
            "Azure Blob Storage": {"category": "Cloud / Object", "handler": "rclone", "rclone_type": "azureblob"},
            
            # Peer-to-Peer & Distributed Networks
            "IPFS": {"category": "P2P / Web3", "handler": "ipfs"},
            "Torrent": {"category": "P2P", "handler": "torrent"},
            "Syncthing": {"category": "P2P Sync", "handler": "syncthing"},
            
            # Cluster & HPC File Systems
            "CephFS": {"category": "Cluster FS", "handler": "ceph"},
            "GlusterFS": {"category": "Cluster FS", "handler": "gluster"},
            "HDFS": {"category": "HPC / Big Data", "handler": "rclone", "rclone_type": "hdfs"},
            "9P": {"category": "Virtualization", "handler": "9p"},
        }

    def get_categories(self) -> List[str]:
        return sorted(list(set(p["category"] for p in self.protocols.values())))

    def get_protocols_by_category(self, category: str) -> List[str]:
        return [proto for proto, data in self.protocols.items() if data["category"] == category]


class UniversalFileManager(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("CWE File Manager")
        self.geometry("1100x700")
        self.minsize(800, 500)
        
        self.pm = ProtocolManager()
        self.current_path = os.path.expanduser("~")
        self.sort_state = {"column": "Name", "reverse": False}

        self._setup_styles()
        self._setup_ui()
        self.refresh_directory(self.current_path)

    def _setup_styles(self):
        self.style = ttk.Style(self)
        if "clam" in self.style.theme_names():
            self.style.theme_use("clam")
            
        self.style.configure("Treeview", rowheight=24, font=("Segoe UI", 9))
        self.style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"))

    def _setup_ui(self):
        # --- TOP CONTROL BAR ---
        top_frame = ttk.Frame(self, padding=6)
        top_frame.pack(side=tk.TOP, fill=tk.X)

        ttk.Label(top_frame, text="Category:").pack(side=tk.LEFT, padx=(0, 2))
        self.cat_combo = ttk.Combobox(top_frame, values=self.pm.get_categories(), state="readonly", width=18)
        self.cat_combo.pack(side=tk.LEFT, padx=(0, 8))
        self.cat_combo.bind("<<ComboboxSelected>>", self._on_category_change)

        ttk.Label(top_frame, text="Protocol:").pack(side=tk.LEFT, padx=(0, 2))
        self.proto_combo = ttk.Combobox(top_frame, state="readonly", width=22)
        self.proto_combo.pack(side=tk.LEFT, padx=(0, 8))

        btn_connect = ttk.Button(top_frame, text="Connect / Mount", command=self._open_connection_dialog)
        btn_connect.pack(side=tk.LEFT, padx=2)

        # --- NAVIGATION BAR ---
        path_frame = ttk.Frame(self, padding=6)
        path_frame.pack(side=tk.TOP, fill=tk.X)

        btn_up = ttk.Button(path_frame, text="↑ Parent", width=8, command=self._navigate_up)
        btn_up.pack(side=tk.LEFT, padx=(0, 4))

        ttk.Label(path_frame, text="Path / URI:").pack(side=tk.LEFT, padx=2)
        self.path_entry = ttk.Entry(path_frame)
        self.path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)
        self.path_entry.insert(0, self.current_path)
        self.path_entry.bind("<Return>", lambda e: self.refresh_directory(self.path_entry.get()))

        btn_go = ttk.Button(path_frame, text="Go", width=6, command=lambda: self.refresh_directory(self.path_entry.get()))
        btn_go.pack(side=tk.LEFT, padx=2)

        # --- MAIN PANED WINDOW ---
        main_pane = ttk.PanedWindow(self, orient=tk.HORIZONTAL)
        main_pane.pack(fill=tk.BOTH, expand=True, padx=6, pady=4)

        # Left Panel: Sidebar / Connections
        left_frame = ttk.LabelFrame(main_pane, text=" Endpoints & Mounts ", padding=4)
        main_pane.add(left_frame, weight=1)

        self.tree_endpoints = ttk.Treeview(left_frame, columns=("Type",), show="tree headings")
        self.tree_endpoints.heading("#0", text="Endpoint Name")
        self.tree_endpoints.heading("Type", text="Protocol")
        self.tree_endpoints.column("Type", width=90, anchor="center")
        self.tree_endpoints.pack(fill=tk.BOTH, expand=True)

        self._populate_sidebar()

        # Right Panel: File Grid
        right_frame = ttk.LabelFrame(main_pane, text=" File Explorer ", padding=4)
        main_pane.add(right_frame, weight=3)

        columns = ("Name", "Size", "Type", "Modified")
        self.file_tree = ttk.Treeview(right_frame, columns=columns, show="headings", selectmode="extended")
        
        self.file_tree.heading("Name", text="Name", command=lambda: self._sort_column("Name"))
        self.file_tree.heading("Size", text="Size", command=lambda: self._sort_column("Size"))
        self.file_tree.heading("Type", text="Type", command=lambda: self._sort_column("Type"))
        self.file_tree.heading("Modified", text="Date Modified", command=lambda: self._sort_column("Modified"))

        self.file_tree.column("Name", width=280, anchor="w")
        self.file_tree.column("Size", width=90, anchor="e")
        self.file_tree.column("Type", width=100, anchor="center")
        self.file_tree.column("Modified", width=140, anchor="w")

        scrollbar = ttk.Scrollbar(right_frame, orient=tk.VERTICAL, command=self.file_tree.yview)
        self.file_tree.configure(yscroll=scrollbar.set)

        self.file_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.file_tree.bind("<Double-1>", self._on_file_double_click)

        # --- STATUS BAR ---
        status_frame = ttk.Frame(self, padding=2)
        status_frame.pack(side=tk.BOTTOM, fill=tk.X)

        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(status_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W, padding=3)
        status_bar.pack(side=tk.LEFT, fill=tk.X, expand=True)

        self.progress = ttk.Progressbar(status_frame, mode="indeterminate", length=120)

    def _populate_sidebar(self):
        local_node = self.tree_endpoints.insert("", "end", text="Local Machine", open=True)
        self.tree_endpoints.insert(local_node, "end", text="Root (/) ", values=("DIRECT",))
        self.tree_endpoints.insert(local_node, "end", text="User Home (~)", values=("DIRECT",))

        remote_node = self.tree_endpoints.insert("", "end", text="Remote / Cloud", open=True)
        self.tree_endpoints.insert(remote_node, "end", text="NAS Server", values=("SMB3",))
        self.tree_endpoints.insert(remote_node, "end", text="S3 Vault", values=("S3",))
        self.tree_endpoints.insert(remote_node, "end", text="Hadoop Cluster", values=("HDFS",))

    def _on_category_change(self, event):
        cat = self.cat_combo.get()
        protocols = self.pm.get_protocols_by_category(cat)
        self.proto_combo["values"] = protocols
        if protocols:
            self.proto_combo.current(0)

    def refresh_directory(self, path: str):
        self.progress.pack(side=tk.RIGHT, padx=4)
        self.progress.start(10)
        self.status_var.set(f"Loading directory: {path}...")
        
        threading.Thread(target=self._async_load_directory, args=(path,), daemon=True).start()

    def _async_load_directory(self, path: str):
        path = os.path.expanduser(path)
        items_data = []
        error_msg = None

        if os.path.exists(path):
            try:
                with os.scandir(path) as entries:
                    for entry in entries:
                        try:
                            stats = entry.stat(follow_symlinks=False)
                            is_dir = entry.is_dir(follow_symlinks=False)
                            
                            f_type = "Folder" if is_dir else "File"
                            f_size_bytes = stats.st_size if not is_dir else -1
                            f_size_str = "-" if is_dir else self._format_size(stats.st_size)
                            
                            mtime = datetime.datetime.fromtimestamp(stats.st_mtime).strftime("%Y-%m-%d %H:%M")
                            prefix = "📁 " if is_dir else "📄 "

                            items_data.append({
                                "display_name": prefix + entry.name,
                                "raw_name": entry.name,
                                "size_str": f_size_str,
                                "size_bytes": f_size_bytes,
                                "type": f_type,
                                "mtime": mtime,
                                "is_dir": is_dir
                            })
                        except PermissionError:
                            continue
            except Exception as e:
                error_msg = str(e)
        else:
            error_msg = f"Path does not exist: {path}"

        self.after(0, lambda: self._update_ui_after_load(path, items_data, error_msg))

    def _update_ui_after_load(self, path: str, items: List[Dict[str, Any]], error: Optional[str]):
        self.progress.stop()
        self.progress.pack_forget()

        if error:
            messagebox.showerror("Access Error", error)
            self.status_var.set("Error loading directory.")
            return

        self.current_path = os.path.abspath(path)
        self.path_entry.delete(0, tk.END)
        self.path_entry.insert(0, self.current_path)

        for item in self.file_tree.get_children():
            self.file_tree.delete(item)

        for item in items:
            self.file_tree.insert(
                "", "end",
                values=(item["display_name"], item["size_str"], item["type"], item["mtime"]),
                tags=(str(item["size_bytes"]), item["raw_name"])
            )

        self.status_var.set(f"Directory loaded: {self.current_path} ({len(items)} items)")

    def _on_file_double_click(self, event):
        selected = self.file_tree.selection()
        if not selected:
            return

        item = self.file_tree.item(selected[0])
        f_type = item["values"][2]
        raw_name = item["tags"][1]

        target_path = os.path.join(self.current_path, raw_name)

        if f_type == "Folder":
            self.refresh_directory(target_path)

    def _navigate_up(self):
        parent = os.path.dirname(self.current_path)
        if parent and parent != self.current_path:
            self.refresh_directory(parent)

    def _sort_column(self, col: str):
        reverse = self.sort_state["reverse"] if self.sort_state["column"] == col else False
        self.sort_state = {"column": col, "reverse": not reverse}

        items = self.file_tree.get_children("")

        if col == "Size":
            items_sorted = sorted(items, key=lambda k: int(self.file_tree.item(k)["tags"][0]), reverse=reverse)
        else:
            col_index = ("Name", "Size", "Type", "Modified").index(col)
            items_sorted = sorted(items, key=lambda k: self.file_tree.item(k)["values"][col_index].lower(), reverse=reverse)

        for index, item_id in enumerate(items_sorted):
            self.file_tree.move(item_id, "", index)

    def _open_connection_dialog(self):
        proto = self.proto_combo.get()
        if not proto:
            messagebox.showwarning("Warning", "Please select a protocol first.")
            return

        dialog = tk.Toplevel(self)
        dialog.title(f"Connection Config: {proto}")
        dialog.geometry("480x360")
        dialog.resizable(False, False)
        dialog.transient(self)
        dialog.grab_set()

        ttk.Label(dialog, text=f"Protocol Settings: {proto}", font=("Segoe UI", 10, "bold")).pack(pady=12)

        form_frame = ttk.Frame(dialog, padding=12)
        form_frame.pack(fill=tk.BOTH, expand=True)

        fields = ["Host / URL / Bucket", "Port", "Username / Access Key", "Password / Secret Key", "Mount Point / Path"]
        entries = {}

        for i, field in enumerate(fields):
            ttk.Label(form_frame, text=f"{field}:").grid(row=i, column=0, sticky=tk.W, pady=6)
            ent = ttk.Entry(form_frame, width=32)
            if "Password" in field:
                ent.config(show="*")
            ent.grid(row=i, column=1, sticky=tk.E, pady=6, padx=(10, 0))
            entries[field] = ent

        def _connect():
            self.status_var.set(f"Establishing protocol bridge for {proto}...")
            messagebox.showinfo("Bridge Initiated", f"Backend initialization logged for [{proto}].")
            dialog.destroy()

        ttk.Button(dialog, text="Establish Bridge", command=_connect).pack(pady=12)

    @staticmethod
    def _format_size(size_bytes: int) -> str:
        if size_bytes < 1024:
            return f"{size_bytes} B"
        elif size_bytes < 1024 ** 2:
            return f"{size_bytes / 1024:.1f} KB"
        elif size_bytes < 1024 ** 3:
            return f"{size_bytes / (1024 ** 2):.1f} MB"
        else:
            return f"{size_bytes / (1024 ** 3):.2f} GB"


if __name__ == "__main__":
    app = UniversalFileManager()
    app.mainloop()
