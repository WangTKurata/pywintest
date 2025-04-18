"""
PyWinAuto Toolkit Launcher

A launcher script for the PyWinAuto Toolkit that checks for dependencies
and launches the main application.

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

import importlib.util
import subprocess
import sys
import tkinter as tk
from tkinter import messagebox


def check_dependency(package_name):
    """Check if a package is installed."""
    return importlib.util.find_spec(package_name) is not None


def install_dependencies():
    """Install required dependencies from requirements.txt."""
    try:
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "-r", "requirements.txt"]
        )
        return True
    except subprocess.CalledProcessError:
        return False


def main():
    # Check for required dependencies
    required_packages = ["pywinauto", "psutil", "PIL"]
    missing_packages = [pkg for pkg in required_packages if not check_dependency(pkg)]

    if missing_packages:
        root = tk.Tk()
        root.withdraw()  # Hide the main window

        message = f"The following required packages are missing:\n{', '.join(missing_packages)}\n\nWould you like to install them now?"
        install = messagebox.askyesno("Missing Dependencies", message)

        if install:
            success = install_dependencies()
            if not success:
                messagebox.showerror(
                    "Installation Failed",
                    "Failed to install dependencies. Please install them manually:\n\n"
                    "pip install -r requirements.txt",
                )
                return
        else:
            messagebox.showinfo(
                "Launch Cancelled",
                "The toolkit cannot run without the required dependencies.",
            )
            return

    # Launch the toolkit
    try:
        import pywinauto_toolkit

        app = pywinauto_toolkit.PyWinAutoToolkit()
        app.mainloop()
    except Exception as e:
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("Error", f"Failed to launch the toolkit: {str(e)}")


if __name__ == "__main__":
    main()
