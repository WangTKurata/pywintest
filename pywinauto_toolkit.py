"""
PyWinAuto Toolkit - A comprehensive toolkit for developing and debugging PyWinAuto scripts

MIT License

Copyright (c) 2025 PyWinAuto Toolkit Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import os
import subprocess
import sys
import time
import tkinter as tk
from threading import Thread
from tkinter import messagebox, scrolledtext, ttk

import psutil
from PIL import ImageGrab, ImageTk
from pywinauto import Application, Desktop

# Import the application logger
from app_logger import AppLogger, LogCategory, LogLevel


class PyWinAutoToolkit(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("PyWinAuto Toolkit")
        self.geometry("900x700")
        self.minsize(800, 600)

        # Initialize data storage first to avoid reference errors
        self.current_windows = []
        self.current_controls = []
        self.selected_window = None
        self.selected_control = None

        # Initialize status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        self.status_bar = ttk.Label(
            self, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W
        )
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        # Initialize logger
        self.logger = AppLogger(log_file="pywinauto_toolkit.log")
        self.logger.info(LogCategory.SYSTEM, "PyWinAuto Toolkit started")

        # Set icon if available
        try:
            self.iconbitmap("icon.ico")
        except:
            pass

        # Create notebook for tabs
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Create tabs
        self.process_tab = ttk.Frame(self.notebook)
        self.window_tab = ttk.Frame(self.notebook)
        self.control_tab = ttk.Frame(self.notebook)
        self.code_tab = ttk.Frame(self.notebook)
        self.screenshot_tab = ttk.Frame(self.notebook)
        self.log_tab = ttk.Frame(self.notebook)

        self.notebook.add(self.process_tab, text="Process Explorer")
        self.notebook.add(self.window_tab, text="Window Inspector")
        self.notebook.add(self.control_tab, text="Control Inspector")
        self.notebook.add(self.code_tab, text="Code Generator")
        self.notebook.add(self.screenshot_tab, text="Screenshot Tool")
        self.notebook.add(self.log_tab, text="Application Logs")

        # Initialize tabs
        self.init_process_tab()
        self.init_window_tab()
        self.init_control_tab()
        self.init_code_tab()
        self.init_screenshot_tab()
        self.init_log_tab()

        # Bind close event
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    def init_process_tab(self):
        frame = ttk.Frame(self.process_tab)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Controls frame
        controls_frame = ttk.Frame(frame)
        controls_frame.pack(fill=tk.X, pady=5)

        ttk.Label(controls_frame, text="Filter:").pack(side=tk.LEFT, padx=5)
        self.process_filter = ttk.Entry(controls_frame)
        self.process_filter.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

        refresh_btn = ttk.Button(
            controls_frame, text="Refresh", command=self.refresh_processes
        )
        refresh_btn.pack(side=tk.LEFT, padx=5)

        # Process list
        columns = ("pid", "name", "status", "memory")
        self.process_tree = ttk.Treeview(frame, columns=columns, show="headings")

        # Define headings
        self.process_tree.heading("pid", text="PID")
        self.process_tree.heading("name", text="Process Name")
        self.process_tree.heading("status", text="Status")
        self.process_tree.heading("memory", text="Memory Usage (MB)")

        # Define columns
        self.process_tree.column("pid", width=80)
        self.process_tree.column("name", width=200)
        self.process_tree.column("status", width=100)
        self.process_tree.column("memory", width=150)

        # Scrollbar
        scrollbar = ttk.Scrollbar(
            frame, orient=tk.VERTICAL, command=self.process_tree.yview
        )
        self.process_tree.configure(yscroll=scrollbar.set)

        # Pack
        self.process_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Bind events
        self.process_tree.bind("<Double-1>", self.on_process_select)

        # Action buttons
        action_frame = ttk.Frame(self.process_tab)
        action_frame.pack(fill=tk.X, padx=10, pady=5)

        attach_btn = ttk.Button(
            action_frame, text="Attach to Process", command=self.attach_to_process
        )
        attach_btn.pack(side=tk.LEFT, padx=5)

        generate_btn = ttk.Button(
            action_frame,
            text="Generate Connection Code",
            command=lambda: self.generate_code("process"),
        )
        generate_btn.pack(side=tk.LEFT, padx=5)

        # Initial load
        self.refresh_processes()

    def init_window_tab(self):
        frame = ttk.Frame(self.window_tab)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Controls frame
        controls_frame = ttk.Frame(frame)
        controls_frame.pack(fill=tk.X, pady=5)

        ttk.Label(controls_frame, text="Filter:").pack(side=tk.LEFT, padx=5)
        self.window_filter = ttk.Entry(controls_frame)
        self.window_filter.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

        refresh_btn = ttk.Button(
            controls_frame, text="Refresh", command=self.refresh_windows
        )
        refresh_btn.pack(side=tk.LEFT, padx=5)

        # Window list
        columns = ("title", "class", "handle", "visible")
        self.window_tree = ttk.Treeview(frame, columns=columns, show="headings")

        # Define headings
        self.window_tree.heading("title", text="Window Title")
        self.window_tree.heading("class", text="Class Name")
        self.window_tree.heading("handle", text="Handle")
        self.window_tree.heading("visible", text="Visible")

        # Define columns
        self.window_tree.column("title", width=250)
        self.window_tree.column("class", width=150)
        self.window_tree.column("handle", width=100)
        self.window_tree.column("visible", width=80)

        # Scrollbar
        scrollbar = ttk.Scrollbar(
            frame, orient=tk.VERTICAL, command=self.window_tree.yview
        )
        self.window_tree.configure(yscroll=scrollbar.set)

        # Pack
        self.window_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Bind events
        self.window_tree.bind("<Double-1>", self.on_window_select)

        # Properties frame
        props_frame = ttk.LabelFrame(self.window_tab, text="Window Properties")
        props_frame.pack(fill=tk.BOTH, padx=10, pady=5, expand=False)

        self.window_props_text = scrolledtext.ScrolledText(props_frame, height=8)
        self.window_props_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Action buttons
        action_frame = ttk.Frame(self.window_tab)
        action_frame.pack(fill=tk.X, padx=10, pady=5)

        inspect_btn = ttk.Button(
            action_frame, text="Inspect Controls", command=self.inspect_window_controls
        )
        inspect_btn.pack(side=tk.LEFT, padx=5)

        highlight_btn = ttk.Button(
            action_frame, text="Highlight Window", command=self.highlight_window
        )
        highlight_btn.pack(side=tk.LEFT, padx=5)

        generate_btn = ttk.Button(
            action_frame,
            text="Generate Window Code",
            command=lambda: self.generate_code("window"),
        )
        generate_btn.pack(side=tk.LEFT, padx=5)

    def init_control_tab(self):
        frame = ttk.Frame(self.control_tab)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Window selector
        selector_frame = ttk.Frame(frame)
        selector_frame.pack(fill=tk.X, pady=5)

        ttk.Label(selector_frame, text="Selected Window:").pack(side=tk.LEFT, padx=5)
        self.selected_window_var = tk.StringVar()
        self.selected_window_var.set("None")
        ttk.Label(selector_frame, textvariable=self.selected_window_var).pack(
            side=tk.LEFT, padx=5
        )

        refresh_btn = ttk.Button(
            selector_frame, text="Refresh Controls", command=self.refresh_controls
        )
        refresh_btn.pack(side=tk.RIGHT, padx=5)

        # Control tree
        columns = ("id", "control_type", "name", "auto_id")
        self.control_tree = ttk.Treeview(frame, columns=columns, show="tree headings")

        # Define headings
        self.control_tree.heading("#0", text="Control")
        self.control_tree.heading("id", text="ID")
        self.control_tree.heading("control_type", text="Control Type")
        self.control_tree.heading("name", text="Name")
        self.control_tree.heading("auto_id", text="AutomationID")

        # Define columns
        self.control_tree.column("#0", width=150)
        self.control_tree.column("id", width=50)
        self.control_tree.column("control_type", width=100)
        self.control_tree.column("name", width=150)
        self.control_tree.column("auto_id", width=100)

        # Scrollbar
        scrollbar = ttk.Scrollbar(
            frame, orient=tk.VERTICAL, command=self.control_tree.yview
        )
        self.control_tree.configure(yscroll=scrollbar.set)

        # Pack
        self.control_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Bind events
        self.control_tree.bind("<ButtonRelease-1>", self.on_control_select)

        # Properties frame
        props_frame = ttk.LabelFrame(self.control_tab, text="Control Properties")
        props_frame.pack(fill=tk.BOTH, padx=10, pady=5, expand=False)

        self.control_props_text = scrolledtext.ScrolledText(props_frame, height=8)
        self.control_props_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Action buttons
        action_frame = ttk.Frame(self.control_tab)
        action_frame.pack(fill=tk.X, padx=10, pady=5)

        highlight_btn = ttk.Button(
            action_frame, text="Highlight Control", command=self.highlight_control
        )
        highlight_btn.pack(side=tk.LEFT, padx=5)

        generate_btn = ttk.Button(
            action_frame,
            text="Generate Control Code",
            command=lambda: self.generate_code("control"),
        )
        generate_btn.pack(side=tk.LEFT, padx=5)

    def init_code_tab(self):
        frame = ttk.Frame(self.code_tab)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Code text area
        self.code_text = scrolledtext.ScrolledText(frame, font=("Courier New", 10))
        self.code_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Default code template
        self.code_text.insert(
            tk.END,
            """# PyWinAuto Script Template
from pywinauto import Application, Desktop
import time

# Connect to application
app = Application(backend="uia")
# app.connect(process=PID)  # Connect by PID
# app.connect(title="Window Title")  # Connect by window title

# Work with window
# window = app.window(title="Window Title")
# window.wait('ready', timeout=10)

# Interact with controls
# control = window.child_window(control_type="Button", title="OK")
# control.click()

""",
        )

        # Action buttons
        action_frame = ttk.Frame(self.code_tab)
        action_frame.pack(fill=tk.X, padx=10, pady=5)

        copy_btn = ttk.Button(
            action_frame, text="Copy to Clipboard", command=self.copy_code_to_clipboard
        )
        copy_btn.pack(side=tk.LEFT, padx=5)

        save_btn = ttk.Button(
            action_frame, text="Save to File", command=self.save_code_to_file
        )
        save_btn.pack(side=tk.LEFT, padx=5)

        run_btn = ttk.Button(action_frame, text="Run Code", command=self.run_code)
        run_btn.pack(side=tk.LEFT, padx=5)

    def init_screenshot_tab(self):
        frame = ttk.Frame(self.screenshot_tab)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Controls frame
        controls_frame = ttk.Frame(frame)
        controls_frame.pack(fill=tk.X, pady=5)

        ttk.Label(controls_frame, text="Window:").pack(side=tk.LEFT, padx=5)
        self.screenshot_window_var = tk.StringVar()
        self.screenshot_window_combo = ttk.Combobox(
            controls_frame, textvariable=self.screenshot_window_var
        )
        self.screenshot_window_combo.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

        capture_btn = ttk.Button(
            controls_frame, text="Capture", command=self.capture_screenshot
        )
        capture_btn.pack(side=tk.LEFT, padx=5)

        # Screenshot display
        self.screenshot_frame = ttk.LabelFrame(frame, text="Screenshot")
        self.screenshot_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.screenshot_label = ttk.Label(self.screenshot_frame)
        self.screenshot_label.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Action buttons
        action_frame = ttk.Frame(self.screenshot_tab)
        action_frame.pack(fill=tk.X, padx=10, pady=5)

        save_btn = ttk.Button(
            action_frame, text="Save Screenshot", command=self.save_screenshot
        )
        save_btn.pack(side=tk.LEFT, padx=5)

        # Initialize screenshot window list
        self.refresh_screenshot_windows()

    # Process tab methods
    def init_log_tab(self):
        """Initialize the log tab."""
        frame = ttk.Frame(self.log_tab)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Controls frame
        controls_frame = ttk.Frame(frame)
        controls_frame.pack(fill=tk.X, pady=5)

        # Filter controls
        filter_frame = ttk.LabelFrame(controls_frame, text="Log Filters")
        filter_frame.pack(fill=tk.X, pady=5)

        # Level filter
        level_frame = ttk.Frame(filter_frame)
        level_frame.pack(fill=tk.X, pady=2)
        ttk.Label(level_frame, text="Level:").pack(side=tk.LEFT, padx=5)
        self.log_level_var = tk.StringVar(value="INFO")
        level_combo = ttk.Combobox(
            level_frame,
            textvariable=self.log_level_var,
            values=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        )
        level_combo.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

        # Category filter
        category_frame = ttk.Frame(filter_frame)
        category_frame.pack(fill=tk.X, pady=2)
        ttk.Label(category_frame, text="Category:").pack(side=tk.LEFT, padx=5)
        self.log_category_var = tk.StringVar(value="ALL")
        category_combo = ttk.Combobox(
            category_frame,
            textvariable=self.log_category_var,
            values=["ALL", "WINDOW", "CONTROL", "PROCESS", "SYSTEM", "SCRIPT", "USER"],
        )
        category_combo.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

        # Search filter
        search_frame = ttk.Frame(filter_frame)
        search_frame.pack(fill=tk.X, pady=2)
        ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT, padx=5)
        self.log_search_var = tk.StringVar()
        search_entry = ttk.Entry(search_frame, textvariable=self.log_search_var)
        search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

        # Apply filter button
        apply_btn = ttk.Button(
            filter_frame, text="Apply Filters", command=self.refresh_logs
        )
        apply_btn.pack(side=tk.RIGHT, padx=5, pady=5)

        # Log display
        log_frame = ttk.LabelFrame(frame, text="Log Entries")
        log_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        # Log list
        columns = ("time", "level", "category", "message")
        self.log_tree = ttk.Treeview(log_frame, columns=columns, show="headings")

        # Define headings
        self.log_tree.heading("time", text="Time")
        self.log_tree.heading("level", text="Level")
        self.log_tree.heading("category", text="Category")
        self.log_tree.heading("message", text="Message")

        # Define columns
        self.log_tree.column("time", width=150)
        self.log_tree.column("level", width=80)
        self.log_tree.column("category", width=100)
        self.log_tree.column("message", width=400)

        # Scrollbar
        scrollbar = ttk.Scrollbar(
            log_frame, orient=tk.VERTICAL, command=self.log_tree.yview
        )
        self.log_tree.configure(yscroll=scrollbar.set)

        # Pack
        self.log_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Bind events
        self.log_tree.bind("<Double-1>", self.on_log_select)

        # Log details
        details_frame = ttk.LabelFrame(frame, text="Log Details")
        details_frame.pack(fill=tk.BOTH, pady=5, expand=False)

        self.log_details_text = scrolledtext.ScrolledText(details_frame, height=8)
        self.log_details_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Action buttons
        action_frame = ttk.Frame(self.log_tab)
        action_frame.pack(fill=tk.X, padx=10, pady=5)

        refresh_btn = ttk.Button(
            action_frame, text="Refresh", command=self.refresh_logs
        )
        refresh_btn.pack(side=tk.LEFT, padx=5)

        clear_btn = ttk.Button(action_frame, text="Clear Logs", command=self.clear_logs)
        clear_btn.pack(side=tk.LEFT, padx=5)

        save_btn = ttk.Button(action_frame, text="Save Logs", command=self.save_logs)
        save_btn.pack(side=tk.LEFT, padx=5)

        stats_btn = ttk.Button(
            action_frame, text="Log Statistics", command=self.show_log_statistics
        )
        stats_btn.pack(side=tk.LEFT, padx=5)

        # Initial load
        self.refresh_logs()

    def refresh_logs(self):
        """Refresh the log display."""
        # Clear existing items
        for item in self.log_tree.get_children():
            self.log_tree.delete(item)

        # Get filter values
        level_str = self.log_level_var.get()
        category_str = self.log_category_var.get()
        search_text = self.log_search_var.get()

        # Convert to enum values
        level = None
        if level_str != "ALL":
            level = getattr(LogLevel, level_str, None)

        category = None
        if category_str != "ALL":
            category = getattr(LogCategory, category_str, None)

        # Get filtered logs
        logs = self.logger.get_logs(
            level=level, category=category, search_text=search_text
        )

        # Insert into tree
        for log in logs:
            time_str = log["datetime"].split("T")[1].split(".")[0]  # Extract time part
            self.log_tree.insert(
                "",
                tk.END,
                values=(time_str, log["level"], log["category"], log["message"]),
                tags=(log["level"].lower(),),
            )

        # Configure tag colors
        self.log_tree.tag_configure("debug", foreground="gray")
        self.log_tree.tag_configure("info", foreground="black")
        self.log_tree.tag_configure("warning", foreground="orange")
        self.log_tree.tag_configure("error", foreground="red")
        self.log_tree.tag_configure("critical", foreground="red", background="yellow")

        self.status_var.set(f"Found {len(self.log_tree.get_children())} log entries")

    def on_log_select(self, event):
        """Handle log selection."""
        # Get selected item
        selection = self.log_tree.selection()
        if not selection:
            return

        # Get log index
        item = self.log_tree.item(selection[0])
        time_str = item["values"][0]
        level = item["values"][1]
        category = item["values"][2]
        message = item["values"][3]

        # Find matching log
        for log in self.logger.logs:
            log_time = log["datetime"].split("T")[1].split(".")[0]
            if (
                log_time == time_str
                and log["level"] == level
                and log["category"] == category
                and log["message"] == message
            ):
                # Show details
                self.show_log_details(log)
                break

    def show_log_details(self, log):
        """Show log details."""
        # Clear text
        self.log_details_text.delete(1.0, tk.END)

        # Format details
        details = f"Time: {log['datetime']}\n"
        details += f"Level: {log['level']}\n"
        details += f"Category: {log['category']}\n"
        details += f"Message: {log['message']}\n"
        details += f"Elapsed: {log['elapsed']:.2f} seconds\n"

        if log["data"]:
            details += "\nData:\n"
            for key, value in log["data"].items():
                details += f"  {key}: {value}\n"

        # Display details
        self.log_details_text.insert(tk.END, details)

    def clear_logs(self):
        """Clear all logs."""
        if messagebox.askyesno(
            "Clear Logs", "Are you sure you want to clear all logs?"
        ):
            self.logger.clear_logs()
            self.refresh_logs()

    def save_logs(self):
        """Save logs to a file."""
        from tkinter import filedialog

        # Ask for file path
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[
                ("JSON Files", "*.json"),
                ("Text Files", "*.txt"),
                ("All Files", "*.*"),
            ],
            title="Save Logs As",
        )

        if not file_path:
            return

        # Determine format
        format = "json" if file_path.endswith(".json") else "txt"

        # Save logs
        if self.logger.save_logs(file_path, format=format):
            self.status_var.set(f"Logs saved to {file_path}")
        else:
            messagebox.showerror("Error", "Failed to save logs")

    def show_log_statistics(self):
        """Show log statistics."""
        stats = self.logger.get_statistics()

        # Create statistics window
        stats_window = tk.Toplevel(self)
        stats_window.title("Log Statistics")
        stats_window.geometry("400x300")

        # Statistics text
        stats_text = scrolledtext.ScrolledText(stats_window)
        stats_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Format statistics
        text = f"Total Logs: {stats['total_logs']}\n"
        if stats["start_time"]:
            text += f"Start Time: {stats['start_time']}\n"
            text += f"End Time: {stats['end_time']}\n"
            text += f"Duration: {stats['duration']:.2f} seconds\n"

            text += "\nLog Levels:\n"
            for level, count in stats["levels"].items():
                text += f"  {level}: {count}\n"

            text += "\nLog Categories:\n"
            for category, count in stats["categories"].items():
                text += f"  {category}: {count}\n"

        # Display statistics
        stats_text.insert(tk.END, text)

    def refresh_processes(self):
        # Clear existing items
        for item in self.process_tree.get_children():
            self.process_tree.delete(item)

        # Get filter text
        filter_text = self.process_filter.get().lower()

        # Get processes
        for proc in psutil.process_iter(["pid", "name", "status", "memory_info"]):
            try:
                info = proc.info
                name = info["name"].lower()

                # Apply filter
                if filter_text and filter_text not in name:
                    continue

                # Format memory
                memory = round(info["memory_info"].rss / (1024 * 1024), 2)

                # Insert into tree
                self.process_tree.insert(
                    "",
                    tk.END,
                    values=(info["pid"], info["name"], info["status"], memory),
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass

        self.status_var.set(f"Found {len(self.process_tree.get_children())} processes")
        self.logger.info(
            LogCategory.PROCESS,
            "Process list refreshed",
            {"count": len(self.process_tree.get_children())},
        )

    def on_process_select(self, event):
        # Get selected item
        selection = self.process_tree.selection()
        if not selection:
            return

        # Get process info
        item = self.process_tree.item(selection[0])
        pid = item["values"][0]

        try:
            # Get detailed process info
            proc = psutil.Process(pid)
            info = {
                "pid": proc.pid,
                "name": proc.name(),
                "exe": proc.exe(),
                "cwd": proc.cwd(),
                "status": proc.status(),
                "created": time.ctime(proc.create_time()),
                "cpu_percent": proc.cpu_percent(),
                "memory_percent": proc.memory_percent(),
                "memory_info": {
                    k: getattr(proc.memory_info(), k) / (1024 * 1024)
                    for k in dir(proc.memory_info())
                    if not k.startswith("_")
                },
                "num_threads": proc.num_threads(),
                "username": proc.username(),
            }

            # Show in code tab
            self.generate_process_code(info)

            # Switch to code tab
            self.notebook.select(self.code_tab)

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
            messagebox.showerror("Error", f"Could not access process: {e}")

    def attach_to_process(self):
        # Get selected item
        selection = self.process_tree.selection()
        if not selection:
            messagebox.showinfo("Info", "Please select a process first")
            return

        # Get process info
        item = self.process_tree.item(selection[0])
        pid = item["values"][0]
        process_name = item["values"][1]

        try:
            # Try to attach to process
            app = Application(backend="uia").connect(process=pid)

            # Update status
            self.status_var.set(f"Attached to process {pid}")

            # Log the event
            self.logger.log_process_event("attach", process_name, pid)

            # Refresh windows
            self.refresh_windows()

            # Switch to window tab
            self.notebook.select(self.window_tab)

        except Exception as e:
            error_msg = f"Could not attach to process: {e}"
            messagebox.showerror("Error", error_msg)
            self.logger.error(
                LogCategory.PROCESS,
                error_msg,
                {"process_id": pid, "process_name": process_name},
            )

    # Window tab methods
    def refresh_windows(self):
        # Clear existing items
        for item in self.window_tree.get_children():
            self.window_tree.delete(item)

        # Get filter text
        filter_text = self.window_filter.get().lower()

        # Get windows
        self.current_windows = []
        for window in Desktop(backend="uia").windows():
            try:
                title = window.window_text()
                class_name = window.class_name()
                handle = window.handle

                # Store window
                self.current_windows.append(window)

                # Apply filter
                if (
                    filter_text
                    and filter_text not in title.lower()
                    and filter_text not in class_name.lower()
                ):
                    continue

                # Check visibility
                visible = "Yes" if window.is_visible() else "No"

                # Insert into tree
                self.window_tree.insert(
                    "", tk.END, values=(title, class_name, handle, visible)
                )
            except Exception:
                pass

        self.status_var.set(f"Found {len(self.window_tree.get_children())} windows")

        # Also update screenshot window list
        self.refresh_screenshot_windows()

    def on_window_select(self, event):
        # Get selected item
        selection = self.window_tree.selection()
        if not selection:
            return

        # Get window info
        item = self.window_tree.item(selection[0])
        handle = item["values"][2]

        # Find window
        for window in self.current_windows:
            if window.handle == handle:
                self.selected_window = window
                self.selected_window_var.set(
                    f"{window.window_text()} ({window.class_name()})"
                )

                # Show properties
                self.show_window_properties(window)
                break

    def show_window_properties(self, window):
        # Clear text
        self.window_props_text.delete(1.0, tk.END)

        try:
            # Get properties
            props = {
                "Title": window.window_text(),
                "Class Name": window.class_name(),
                "Handle": window.handle,
                "Process ID": window.process_id(),
                "Rectangle": window.rectangle(),
                "Is Visible": window.is_visible(),
                "Is Enabled": window.is_enabled(),
                "Control ID": getattr(window, "control_id", "N/A"),
                "Control Type": getattr(window, "control_type", "N/A"),
                "Parent": getattr(window, "parent", "N/A"),
            }

            # Format and display
            for key, value in props.items():
                self.window_props_text.insert(tk.END, f"{key}: {value}\n")

        except Exception as e:
            self.window_props_text.insert(tk.END, f"Error getting properties: {e}")

    def inspect_window_controls(self):
        if not self.selected_window:
            messagebox.showinfo("Info", "Please select a window first")
            return

        # Switch to control tab
        self.notebook.select(self.control_tab)

        # Refresh controls
        self.refresh_controls()

    def highlight_window(self):
        if not self.selected_window:
            messagebox.showinfo("Info", "Please select a window first")
            return

        try:
            # Highlight window
            self.selected_window.draw_outline(colour="red", thickness=2)

            # Log the event
            self.logger.log_window_event(
                "highlight",
                self.selected_window.window_text(),
                self.selected_window.class_name(),
                self.selected_window.handle,
            )

            # Clear after 2 seconds
            self.after(2000, self.clear_highlight)

        except Exception as e:
            error_msg = f"Could not highlight window: {e}"
            messagebox.showerror("Error", error_msg)
            self.logger.error(
                LogCategory.WINDOW,
                error_msg,
                {"window_title": self.selected_window.window_text()},
            )

    def clear_highlight(self):
        try:
            # Redraw without highlight
            if self.selected_window:
                self.selected_window.draw_outline(colour=0, thickness=0)
        except:
            pass

    # Control tab methods
    def refresh_controls(self):
        if not self.selected_window:
            messagebox.showinfo("Info", "Please select a window first")
            return

        # Clear existing items
        for item in self.control_tree.get_children():
            self.control_tree.delete(item)

        try:
            # Get controls
            self.current_controls = []
            self.add_control_to_tree("", self.selected_window)

            self.status_var.set(
                f"Found controls for {self.selected_window.window_text()}"
            )

        except Exception as e:
            messagebox.showerror("Error", f"Could not get controls: {e}")

    def add_control_to_tree(self, parent, control, index=0):
        try:
            # Get control info
            control_type = getattr(control, "control_type", "Unknown")
            name = getattr(control, "window_text", lambda: "Unknown")()
            auto_id = getattr(control, "automation_id", lambda: "Unknown")()

            # Store control
            self.current_controls.append(control)
            control_index = len(self.current_controls) - 1

            # Insert into tree
            item_id = self.control_tree.insert(
                parent,
                tk.END,
                text=f"Control {index}",
                values=(control_index, control_type, name, auto_id),
            )

            # Add children
            child_index = 0
            for child in control.children():
                self.add_control_to_tree(item_id, child, child_index)
                child_index += 1

        except Exception as e:
            print(f"Error adding control: {e}")

    def on_control_select(self, event):
        # Get selected item
        selection = self.control_tree.selection()
        if not selection:
            return

        # Get control info
        item = self.control_tree.item(selection[0])
        control_index = item["values"][0]

        if control_index is not None and 0 <= control_index < len(
            self.current_controls
        ):
            self.selected_control = self.current_controls[control_index]
            self.show_control_properties(self.selected_control)

    def show_control_properties(self, control):
        # Clear text
        self.control_props_text.delete(1.0, tk.END)

        try:
            # Get properties
            props = {
                "Control Type": getattr(control, "control_type", "Unknown"),
                "Name": getattr(control, "window_text", lambda: "Unknown")(),
                "Automation ID": getattr(control, "automation_id", lambda: "Unknown")(),
                "Class Name": getattr(control, "class_name", lambda: "Unknown")(),
                "Rectangle": getattr(control, "rectangle", lambda: "Unknown")(),
                "Is Visible": getattr(control, "is_visible", lambda: "Unknown")(),
                "Is Enabled": getattr(control, "is_enabled", lambda: "Unknown")(),
                "Control ID": getattr(control, "control_id", "Unknown"),
                "Handle": getattr(control, "handle", "Unknown"),
            }

            # Get supported patterns
            supported_patterns = []
            for pattern in [
                "invoke",
                "toggle",
                "selection",
                "value",
                "range",
                "scroll",
                "grid",
            ]:
                if hasattr(control, pattern) and callable(getattr(control, pattern)):
                    supported_patterns.append(pattern)

            props["Supported Patterns"] = (
                ", ".join(supported_patterns) if supported_patterns else "None"
            )

            # Format and display
            for key, value in props.items():
                self.control_props_text.insert(tk.END, f"{key}: {value}\n")

        except Exception as e:
            self.control_props_text.insert(tk.END, f"Error getting properties: {e}")

    def highlight_control(self):
        if not self.selected_control:
            messagebox.showinfo("Info", "Please select a control first")
            return

        try:
            # Highlight control
            self.selected_control.draw_outline(colour="green", thickness=2)

            # Log the event
            control_name = getattr(
                self.selected_control, "window_text", lambda: "Unknown"
            )()
            control_type = getattr(self.selected_control, "control_type", "Unknown")
            control_id = getattr(
                self.selected_control, "automation_id", lambda: "Unknown"
            )()

            self.logger.log_control_event(
                "highlight",
                control_type,
                control_name,
                control_id,
                self.selected_window.window_text() if self.selected_window else None,
            )

            # Clear after 2 seconds
            self.after(2000, self.clear_control_highlight)

        except Exception as e:
            error_msg = f"Could not highlight control: {e}"
            messagebox.showerror("Error", error_msg)
            self.logger.error(LogCategory.CONTROL, error_msg)

    def clear_control_highlight(self):
        try:
            # Redraw without highlight
            if self.selected_control:
                self.selected_control.draw_outline(colour=0, thickness=0)
        except:
            pass

    # Code generation methods
    def generate_code(self, code_type):
        if code_type == "process":
            selection = self.process_tree.selection()
            if not selection:
                messagebox.showinfo("Info", "Please select a process first")
                return

            # Get process info
            item = self.process_tree.item(selection[0])
            pid = item["values"][0]
            name = item["values"][1]

            # Generate code
            code = f"""# Connect to {name} (PID: {pid})
from pywinauto import Application

# Connect to existing application
app = Application(backend="uia").connect(process={pid})

# Get top-level windows
windows = app.windows()
"""
            # Log the event
            self.logger.log_script_event(
                "generate",
                "process_connection",
                {"process_id": pid, "process_name": name},
            )

        elif code_type == "window":
            if not self.selected_window:
                messagebox.showinfo("Info", "Please select a window first")
                return

            # Get window info
            title = self.selected_window.window_text()
            class_name = self.selected_window.class_name()

            # Generate code
            code = f"""# Connect to window: "{title}" (Class: {class_name})
from pywinauto import Application, Desktop

# Method 1: Connect via Desktop
window = Desktop(backend="uia").window(title="{title}", class_name="{class_name}")

# Method 2: Connect via Application
# app = Application(backend="uia").connect(title="{title}")
# window = app.window(title="{title}")

# Wait for window to be ready
window.wait('ready', timeout=10)

# Print window information
print(f"Window title: {{window.window_text()}}")
print(f"Window class: {{window.class_name()}}")
print(f"Window rectangle: {{window.rectangle()}}")
"""
            # Log the event
            self.logger.log_script_event(
                "generate",
                "window_connection",
                {"window_title": title, "window_class": class_name},
            )

        elif code_type == "control":
            if not self.selected_control:
                messagebox.showinfo("Info", "Please select a control first")
                return

            if not self.selected_window:
                messagebox.showinfo("Info", "Window information is missing")
                return

            # Get window info
            window_title = self.selected_window.window_text()
            window_class = self.selected_window.class_name()

            # Get control info
            control_type = getattr(self.selected_control, "control_type", "Unknown")
            name = getattr(self.selected_control, "window_text", lambda: "Unknown")()
            auto_id = getattr(
                self.selected_control, "automation_id", lambda: "Unknown"
            )()

            # Generate code
            code = f"""# Access control: {name} (Type: {control_type})
from pywinauto import Application, Desktop

# First connect to the window
window = Desktop(backend="uia").window(title="{window_title}", class_name="{window_class}")
window.wait('ready', timeout=10)

# Method 1: Access by control type and name
control = window.child_window(control_type="{control_type}", title="{name}")

# Method 2: Access by automation ID (if available)
# control = window.child_window(auto_id="{auto_id}")

# Wait for control to be ready
control.wait('ready', timeout=5)

# Interact with control (examples)
# control.click()
# control.type_keys("text")
# control.select("item")
"""
            # Log the event
            self.logger.log_script_event(
                "generate",
                "control_access",
                {
                    "control_type": control_type,
                    "control_name": name,
                    "window_title": window_title,
                },
            )

    def on_close(self):
        """Handle window close event."""
        # Log the event
        self.logger.info(LogCategory.SYSTEM, "PyWinAuto Toolkit closing")

        # Destroy the window
        self.destroy()

    def generate_process_code(self, info):
        # Generate code
        code = f"""# Connect to {info["name"]} (PID: {info["pid"]})
from pywinauto import Application

# Process information:
# - Name: {info["name"]}
# - PID: {info["pid"]}
# - Executable: {info["exe"]}
# - Working Directory: {info["cwd"]}
# - Created: {info["created"]}

# Connect to existing application
app = Application(backend="uia").connect(process={info["pid"]})

# Get top-level windows
windows = app.windows()

# Print window information
for window in windows:
    print(f"Window title: {{window.window_text()}}")
    print(f"Window class: {{window.class_name()}}")
"""

        # Update code text
        self.code_text.delete(1.0, tk.END)
        self.code_text.insert(tk.END, code)

    def copy_code_to_clipboard(self):
        code = self.code_text.get(1.0, tk.END)
        self.clipboard_clear()
        self.clipboard_append(code)
        self.status_var.set("Code copied to clipboard")

    def save_code_to_file(self):
        from tkinter import filedialog

        # Get code
        code = self.code_text.get(1.0, tk.END)

        # Ask for file path
        file_path = filedialog.asksaveasfilename(
            defaultextension=".py",
            filetypes=[("Python Files", "*.py"), ("All Files", "*.*")],
            title="Save Code As",
        )

        if not file_path:
            return

        # Save code
        try:
            with open(file_path, "w") as f:
                f.write(code)

            self.status_var.set(f"Code saved to {file_path}")

        except Exception as e:
            messagebox.showerror("Error", f"Could not save code: {e}")

    def run_code(self):
        import tempfile

        # Get code
        code = self.code_text.get(1.0, tk.END)

        # Create temporary file
        with tempfile.NamedTemporaryFile(suffix=".py", delete=False) as f:
            temp_path = f.name
            f.write(code.encode())

        # Run code
        try:
            self.status_var.set("Running code...")

            # Create new window for output
            output_window = tk.Toplevel(self)
            output_window.title("Code Execution Output")
            output_window.geometry("600x400")

            # Output text
            output_text = scrolledtext.ScrolledText(output_window)
            output_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

            # Run in thread
            def run_code_thread():
                try:
                    # Run code
                    process = subprocess.Popen(
                        [sys.executable, temp_path],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                    )

                    # Get output
                    stdout, stderr = process.communicate()

                    # Show output
                    if stdout:
                        output_text.insert(tk.END, "=== STDOUT ===\n")
                        output_text.insert(tk.END, stdout)

                    if stderr:
                        output_text.insert(tk.END, "\n=== STDERR ===\n")
                        output_text.insert(tk.END, stderr)

                    # Update status
                    self.status_var.set(
                        f"Code execution completed with exit code {process.returncode}"
                    )

                except Exception as e:
                    output_text.insert(tk.END, f"Error running code: {e}")
                    self.status_var.set("Error running code")

                finally:
                    # Delete temporary file
                    try:
                        os.unlink(temp_path)
                    except:
                        pass

            # Start thread
            Thread(target=run_code_thread).start()

        except Exception as e:
            messagebox.showerror("Error", f"Could not run code: {e}")

    # Screenshot tab methods
    def refresh_screenshot_windows(self):
        # Get window titles
        window_titles = []
        for window in self.current_windows:
            try:
                title = window.window_text()
                if title:
                    window_titles.append(title)
            except:
                pass

        # Update combobox
        self.screenshot_window_combo["values"] = window_titles

    def capture_screenshot(self):
        # Get selected window title
        window_title = self.screenshot_window_var.get()

        if not window_title:
            messagebox.showinfo("Info", "Please select a window")
            return

        # Find window
        target_window = None
        for window in self.current_windows:
            try:
                if window.window_text() == window_title:
                    target_window = window
                    break
            except:
                pass

        if not target_window:
            messagebox.showinfo("Info", "Window not found")
            return

        try:
            # Get window rectangle
            rect = target_window.rectangle()

            # Capture screenshot
            screenshot = ImageGrab.grab(
                bbox=(rect.left, rect.top, rect.right, rect.bottom)
            )

            # Resize if too large
            max_width = 800
            max_height = 600
            width, height = screenshot.size

            if width > max_width or height > max_height:
                ratio = min(max_width / width, max_height / height)
                new_width = int(width * ratio)
                new_height = int(height * ratio)
                screenshot = screenshot.resize((new_width, new_height))

            # Convert to PhotoImage
            self.current_screenshot = screenshot
            photo = ImageTk.PhotoImage(screenshot)

            # Display
            self.screenshot_label.configure(image=photo)
            self.screenshot_label.image = photo

            self.status_var.set(f"Captured screenshot of {window_title}")

        except Exception as e:
            messagebox.showerror("Error", f"Could not capture screenshot: {e}")

    def save_screenshot(self):
        if not hasattr(self, "current_screenshot"):
            messagebox.showinfo("Info", "No screenshot to save")
            return

        from tkinter import filedialog

        # Ask for file path
        file_path = filedialog.asksaveasfilename(
            defaultextension=".png",
            filetypes=[
                ("PNG Files", "*.png"),
                ("JPEG Files", "*.jpg"),
                ("All Files", "*.*"),
            ],
            title="Save Screenshot As",
        )

        if not file_path:
            return

        # Save screenshot
        try:
            self.current_screenshot.save(file_path)
            self.status_var.set(f"Screenshot saved to {file_path}")

        except Exception as e:
            messagebox.showerror("Error", f"Could not save screenshot: {e}")


def main():
    app = PyWinAutoToolkit()
    app.mainloop()


if __name__ == "__main__":
    main()
