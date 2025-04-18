"""
Control Inspector Utility

A simple utility to help inspect UI controls within a window.
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
import time

from pywinauto import Application, Desktop


class ControlInspector:
    def __init__(self):
        self.window = None
        self.controls = []

    def connect_to_window(
        self, title=None, class_name=None, process_id=None, handle=None
    ):
        """Connect to a window using various identification methods."""
        try:
            # Try to find the window
            if handle:
                # Connect by handle
                for window in Desktop(backend="uia").windows():
                    if window.handle == handle:
                        self.window = window
                        break
            elif title or class_name:
                # Connect by title and/or class name
                criteria = {}
                if title:
                    criteria["title"] = title
                if class_name:
                    criteria["class_name"] = class_name

                self.window = Desktop(backend="uia").window(**criteria)
            elif process_id:
                # Connect by process ID
                app = Application(backend="uia").connect(process=process_id)
                windows = app.windows()
                if windows:
                    self.window = windows[0]

            # Check if window was found
            if not self.window:
                print("Window not found. Please check your criteria.")
                return False

            # Verify window is accessible
            self.window.wait("ready", timeout=5)
            print(
                f"Connected to window: {self.window.window_text()} ({self.window.class_name()})"
            )
            return True

        except Exception as e:
            print(f"Error connecting to window: {e}")
            return False

    def collect_controls(self):
        """Collect all controls in the window."""
        if not self.window:
            print("No window connected. Use connect_to_window() first.")
            return

        self.controls = []
        self._collect_controls_recursive(self.window, [])
        print(f"Found {len(self.controls)} controls")

    def _collect_controls_recursive(self, control, path):
        """Recursively collect controls and their paths."""
        try:
            # Add current control to the list
            control_info = {
                "control": control,
                "path": path.copy(),
                "type": getattr(control, "control_type", "Unknown"),
                "name": getattr(control, "window_text", lambda: "")(),
                "auto_id": getattr(control, "automation_id", lambda: "")(),
                "class_name": getattr(control, "class_name", lambda: "")(),
                "handle": getattr(control, "handle", None),
                "rectangle": getattr(control, "rectangle", lambda: None)(),
            }

            self.controls.append(control_info)

            # Process children
            for i, child in enumerate(control.children()):
                new_path = path.copy()
                new_path.append(i)
                self._collect_controls_recursive(child, new_path)

        except Exception as e:
            print(f"Error collecting control: {e}")

    def print_control_tree(self):
        """Print the control hierarchy as a tree."""
        if not self.window:
            print("No window connected. Use connect_to_window() first.")
            return

        print("\nControl Hierarchy:")
        print("=" * 80)
        self._print_control_recursive(self.window, 0)
        print("=" * 80)

    def _print_control_recursive(self, control, level):
        """Recursively print the control hierarchy."""
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
                self._print_control_recursive(child, level + 1)

        except Exception as e:
            print(f"{indent}- Error: {e}")

    def find_control_by_property(self, property_name, property_value):
        """Find controls matching a specific property value."""
        if not self.controls:
            self.collect_controls()

        matching_controls = []
        for control_info in self.controls:
            if (
                property_name in control_info
                and str(control_info[property_name]).lower()
                == str(property_value).lower()
            ):
                matching_controls.append(control_info)

        return matching_controls

    def print_control_details(self, control_info):
        """Print detailed information about a control."""
        print("\nControl Details:")
        print("=" * 80)

        # Print basic properties
        print(f"Control Type: {control_info['type']}")
        print(f"Name: {control_info['name']}")
        print(f"Automation ID: {control_info['auto_id']}")
        print(f"Class Name: {control_info['class_name']}")
        print(f"Handle: {control_info['handle']}")
        print(f"Rectangle: {control_info['rectangle']}")

        # Print path
        path_str = " > ".join([str(i) for i in control_info["path"]])
        print(f"Path: {path_str}")

        # Get additional properties
        control = control_info["control"]
        print("\nAdditional Properties:")

        try:
            print(f"Is Visible: {control.is_visible()}")
        except:
            print("Is Visible: Unknown")

        try:
            print(f"Is Enabled: {control.is_enabled()}")
        except:
            print("Is Enabled: Unknown")

        # Check supported patterns
        print("\nSupported Patterns:")
        patterns = []
        for pattern in [
            "invoke",
            "toggle",
            "selection",
            "value",
            "range",
            "scroll",
            "grid",
        ]:
            try:
                if hasattr(control, pattern) and callable(getattr(control, pattern)):
                    patterns.append(pattern)
            except:
                pass

        if patterns:
            for pattern in patterns:
                print(f"- {pattern}")
        else:
            print("- None detected")

        print("=" * 80)

    def highlight_control(self, control_info):
        """Highlight a control to make it easy to identify."""
        try:
            control = control_info["control"]
            print(
                f"Highlighting control: {control_info['type']} '{control_info['name']}'"
            )

            # Highlight control with green outline
            control.draw_outline(colour="green", thickness=2)
            time.sleep(3)  # Keep highlighted for 3 seconds
            control.draw_outline(colour=0, thickness=0)  # Remove highlight

        except Exception as e:
            print(f"Error highlighting control: {e}")

    def generate_code(self, control_info):
        """Generate PyWinAuto code to access this control."""
        if not self.window:
            print("No window connected.")
            return

        window_title = self.window.window_text()
        window_class = self.window.class_name()

        control_type = control_info["type"]
        name = control_info["name"]
        auto_id = control_info["auto_id"]

        print("\nPyWinAuto Code:")
        print("=" * 80)

        code = f"""from pywinauto import Application, Desktop

# Connect to the window
window = Desktop(backend="uia").window(title="{window_title}", class_name="{window_class}")
window.wait('ready', timeout=10)

# Access the control"""

        # Generate different methods to access the control
        if auto_id:
            code += f"""
# Method 1: By automation_id (most reliable if available)
control = window.child_window(auto_id="{auto_id}")"""

        if control_type:
            if name:
                code += f"""
# Method 2: By control type and name
control = window.child_window(control_type="{control_type}", title="{name}")"""
            else:
                code += f"""
# Method 2: By control type
control = window.child_window(control_type="{control_type}")"""

        # Add path-based access as a fallback
        if control_info["path"]:
            path_code = "window"
            for i in control_info["path"]:
                path_code += f".children()[{i}]"

            code += f"""
# Method 3: By control path (fallback, may break if UI changes)
control = {path_code}"""

        # Add interaction examples based on supported patterns
        code += """

# Wait for control to be ready
control.wait('ready', timeout=5)

# Interact with the control (examples)"""

        control = control_info["control"]

        # Check for common patterns and add examples
        if hasattr(control, "invoke") and callable(getattr(control, "invoke")):
            code += """
# Click the control
control.click()"""

        if hasattr(control, "toggle") and callable(getattr(control, "toggle")):
            code += """
# Toggle the control
control.toggle()"""

        if hasattr(control, "value") and callable(getattr(control, "value")):
            code += """
# Get the value
value = control.value()
# Set the value
control.value = "new value" """

        if control_type == "Edit":
            code += """
# Type text into the control
control.type_keys("Hello World")"""

        print(code)
        print("=" * 80)


def main():
    parser = argparse.ArgumentParser(description="Control Inspector Utility")

    # Window identification arguments
    group = parser.add_argument_group("Window Identification (use at least one)")
    group.add_argument("-t", "--title", help="Window title (exact match)")
    group.add_argument("-c", "--class-name", help="Window class name (exact match)")
    group.add_argument("-p", "--process", type=int, help="Process ID")
    group.add_argument("-n", "--handle", type=int, help="Window handle")

    # Control identification arguments
    control_group = parser.add_argument_group("Control Identification (optional)")
    control_group.add_argument("--type", help="Control type to find")
    control_group.add_argument("--name", help="Control name/text to find")
    control_group.add_argument("--id", help="Control automation ID to find")

    # Action arguments
    action_group = parser.add_argument_group("Actions")
    action_group.add_argument("--tree", action="store_true", help="Print control tree")
    action_group.add_argument(
        "--highlight", action="store_true", help="Highlight matching controls"
    )
    action_group.add_argument(
        "--details", action="store_true", help="Print detailed control information"
    )
    action_group.add_argument(
        "--code", action="store_true", help="Generate PyWinAuto code"
    )

    # Parse arguments
    args = parser.parse_args()

    # Check if at least one window identification method is provided
    if not (args.title or args.class_name or args.process or args.handle):
        parser.print_help()
        print("\nError: At least one window identification method is required.")
        return

    # Create inspector
    inspector = ControlInspector()

    # Connect to window
    if not inspector.connect_to_window(
        title=args.title,
        class_name=args.class_name,
        process_id=args.process,
        handle=args.handle,
    ):
        return

    # Print control tree if requested
    if args.tree:
        inspector.print_control_tree()

    # Find specific controls if criteria provided
    if args.type or args.name or args.id:
        inspector.collect_controls()

        matching_controls = []

        if args.type:
            type_matches = inspector.find_control_by_property("type", args.type)
            matching_controls.extend(type_matches)

        if args.name:
            name_matches = inspector.find_control_by_property("name", args.name)
            matching_controls.extend(name_matches)

        if args.id:
            id_matches = inspector.find_control_by_property("auto_id", args.id)
            matching_controls.extend(id_matches)

        # Remove duplicates
        unique_controls = []
        for control in matching_controls:
            if control not in unique_controls:
                unique_controls.append(control)

        # Process matching controls
        if unique_controls:
            print(f"\nFound {len(unique_controls)} matching controls:")
            for i, control_info in enumerate(unique_controls):
                print(
                    f"{i + 1}. {control_info['type']} '{control_info['name']}' (ID: {control_info['auto_id']})"
                )

                if args.highlight:
                    inspector.highlight_control(control_info)

                if args.details:
                    inspector.print_control_details(control_info)

                if args.code:
                    inspector.generate_code(control_info)
        else:
            print("No controls found matching the criteria.")
    elif args.details or args.highlight or args.code:
        print(
            "Please specify control criteria (--type, --name, or --id) to use --details, --highlight, or --code."
        )


if __name__ == "__main__":
    main()
