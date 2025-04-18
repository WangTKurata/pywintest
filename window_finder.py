"""
Window Finder Utility

A simple utility to help find windows and their properties.
This can be used as a standalone tool or alongside the PyWinAuto Toolkit.

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

import argparse
import sys
import time

from pywinauto import Desktop


def list_windows(filter_text=None, visible_only=True, detailed=False):
    """List all windows matching the filter criteria."""
    windows = Desktop(backend="uia").windows()

    print(f"\n{'=' * 80}")
    print(f"{'WINDOW TITLE':<40} {'CLASS NAME':<25} {'HANDLE':<10} {'VISIBLE'}")
    print(f"{'-' * 40} {'-' * 25} {'-' * 10} {'-' * 7}")

    count = 0
    for window in windows:
        try:
            title = window.window_text()
            class_name = window.class_name()
            handle = window.handle
            is_visible = window.is_visible()

            # Apply filters
            if visible_only and not is_visible:
                continue

            if (
                filter_text
                and filter_text.lower() not in title.lower()
                and filter_text.lower() not in class_name.lower()
            ):
                continue

            # Print window info
            print(f"{title[:39]:<40} {class_name[:24]:<25} {handle:<10} {is_visible}")
            count += 1

            # Print detailed info if requested
            if detailed:
                try:
                    rect = window.rectangle()
                    pid = window.process_id()
                    print(f"  - Process ID: {pid}")
                    print(f"  - Rectangle: {rect}")
                    print(f"  - Control Type: {getattr(window, 'control_type', 'N/A')}")
                    print(
                        f"  - Automation ID: {getattr(window, 'automation_id', lambda: 'N/A')()}"
                    )
                    print()
                except:
                    print("  - Error getting detailed properties")
                    print()
        except:
            # Skip windows that can't be accessed
            pass

    print(f"{'=' * 80}")
    print(f"Found {count} windows matching criteria")


def highlight_window(title=None, class_name=None, handle=None):
    """Highlight a specific window to make it easy to identify."""
    windows = Desktop(backend="uia").windows()

    target_window = None
    for window in windows:
        try:
            if title and title in window.window_text():
                target_window = window
                break

            if class_name and class_name in window.class_name():
                target_window = window
                break

            if handle and int(handle) == window.handle:
                target_window = window
                break
        except:
            pass

    if not target_window:
        print("Window not found. Use list mode to see available windows.")
        return

    print(
        f"Highlighting window: {target_window.window_text()} ({target_window.class_name()})"
    )

    # Highlight window with red outline
    try:
        target_window.draw_outline(colour="red", thickness=2)
        time.sleep(3)  # Keep highlighted for 3 seconds
        target_window.draw_outline(colour=0, thickness=0)  # Remove highlight
    except Exception as e:
        print(f"Error highlighting window: {e}")


def show_window_controls(title=None, class_name=None, handle=None):
    """Show the control hierarchy of a specific window."""
    windows = Desktop(backend="uia").windows()

    target_window = None
    for window in windows:
        try:
            if title and title in window.window_text():
                target_window = window
                break

            if class_name and class_name in window.class_name():
                target_window = window
                break

            if handle and int(handle) == window.handle:
                target_window = window
                break
        except:
            pass

    if not target_window:
        print("Window not found. Use list mode to see available windows.")
        return

    print(
        f"\nControls for window: {target_window.window_text()} ({target_window.class_name()})"
    )
    print("=" * 80)

    def print_control_hierarchy(control, level=0):
        try:
            indent = "  " * level
            control_type = getattr(control, "control_type", "Unknown")
            name = getattr(control, "window_text", lambda: "")()
            auto_id = getattr(control, "automation_id", lambda: "")()

            # Format the control information
            control_info = f"{control_type}"
            if name:
                control_info += f" '{name}'"
            if auto_id:
                control_info += f" (ID: {auto_id})"

            print(f"{indent}- {control_info}")

            # Print children recursively
            for child in control.children():
                print_control_hierarchy(child, level + 1)
        except Exception as e:
            print(f"{indent}- Error: {e}")

    # Print the control hierarchy
    print_control_hierarchy(target_window)
    print("=" * 80)


def main():
    parser = argparse.ArgumentParser(description="Window Finder Utility")

    # Create subparsers for different modes
    subparsers = parser.add_subparsers(dest="mode", help="Operation mode")

    # List mode
    list_parser = subparsers.add_parser("list", help="List windows")
    list_parser.add_argument(
        "-f", "--filter", help="Filter windows by title or class name"
    )
    list_parser.add_argument(
        "-a",
        "--all",
        action="store_true",
        help="Show all windows, including invisible ones",
    )
    list_parser.add_argument(
        "-d", "--detailed", action="store_true", help="Show detailed window properties"
    )

    # Highlight mode
    highlight_parser = subparsers.add_parser(
        "highlight", help="Highlight a specific window"
    )
    highlight_parser.add_argument("-t", "--title", help="Window title (partial match)")
    highlight_parser.add_argument(
        "-c", "--class-name", help="Window class name (partial match)"
    )
    highlight_parser.add_argument("-n", "--handle", type=int, help="Window handle")

    # Controls mode
    controls_parser = subparsers.add_parser("controls", help="Show window controls")
    controls_parser.add_argument("-t", "--title", help="Window title (partial match)")
    controls_parser.add_argument(
        "-c", "--class-name", help="Window class name (partial match)"
    )
    controls_parser.add_argument("-n", "--handle", type=int, help="Window handle")

    # Parse arguments
    args = parser.parse_args()

    # Default to list mode if no mode specified
    if not args.mode:
        args.mode = "list"
        args.filter = None
        args.all = False
        args.detailed = False

    # Execute the appropriate function based on the mode
    if args.mode == "list":
        list_windows(args.filter, not args.all, args.detailed)
    elif args.mode == "highlight":
        highlight_window(args.title, args.class_name, args.handle)
    elif args.mode == "controls":
        show_window_controls(args.title, args.class_name, args.handle)


if __name__ == "__main__":
    main()
