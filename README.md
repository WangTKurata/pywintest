# PyWinAuto Toolkit

A comprehensive toolkit for developing and debugging PyWinAuto scripts. This toolkit provides a graphical interface to help you identify windows, controls, and their properties, making it easier to create robust automation scripts.

## Features

- **Process Explorer**: View and attach to running processes
- **Window Inspector**: Identify windows and their properties
- **Control Inspector**: Explore UI controls within windows
- **Code Generator**: Automatically generate PyWinAuto code snippets
- **Screenshot Tool**: Capture screenshots of windows for documentation
- **Application Logs**: Record and analyze automation activities

## Installation

1. Ensure you have Python 3.6+ installed
2. Clone or download this repository
3. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

## Usage

### Quick Start

Run the launcher script to start the toolkit:

```
python launch_toolkit.py
```

The launcher will check for required dependencies and install them if needed.

### Manual Start

Alternatively, you can run the toolkit directly:

```
python pywinauto_toolkit.py
```

## Working with the Toolkit

### Process Explorer

1. The Process Explorer tab shows all running processes
2. Use the filter to find specific processes
3. Double-click a process to view detailed information
4. Click "Attach to Process" to connect to a process and view its windows

### Window Inspector

1. Lists all visible windows on your system
2. Select a window to view its properties
3. Click "Highlight Window" to visually identify a window
4. Click "Inspect Controls" to examine the controls within the window
5. Click "Generate Window Code" to create PyWinAuto code for connecting to the window

### Control Inspector

1. Shows the control hierarchy of the selected window
2. Select a control to view its properties
3. Click "Highlight Control" to visually identify a control
4. Click "Generate Control Code" to create PyWinAuto code for interacting with the control

### Code Generator

1. Displays automatically generated PyWinAuto code
2. Edit the code as needed
3. Click "Copy to Clipboard" to copy the code
4. Click "Save to File" to save the code to a Python file
5. Click "Run Code" to execute the code and see the results

### Screenshot Tool

1. Select a window from the dropdown
2. Click "Capture" to take a screenshot of the window
3. Click "Save Screenshot" to save the image to a file

### Application Logs

1. View logs of all automation activities
2. Filter logs by level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
3. Filter logs by category (WINDOW, CONTROL, PROCESS, SYSTEM, SCRIPT, USER)
4. Search logs for specific text
5. View detailed information about each log entry
6. Save logs to JSON or text files for later analysis
7. View statistics about log entries

## Logging and Debugging

The toolkit includes a comprehensive logging system that records all automation activities. This can be extremely helpful for debugging complex automation scripts.

### Log Categories

- **WINDOW**: Window-related events (opening, closing, focusing)
- **CONTROL**: Control-related events (clicking, typing, selecting)
- **PROCESS**: Process-related events (starting, attaching)
- **SYSTEM**: System-related events (toolkit startup, shutdown)
- **SCRIPT**: Script-related events (code generation)
- **USER**: User-defined events

### Log Levels

- **DEBUG**: Detailed information for debugging
- **INFO**: General information about normal operation
- **WARNING**: Potential issues that don't prevent operation
- **ERROR**: Errors that prevent specific operations
- **CRITICAL**: Critical errors that prevent the toolkit from functioning

### Using Logs for Debugging

1. Run your automation script with the toolkit open
2. Check the Application Logs tab for any errors or warnings
3. Filter logs by category to focus on specific areas
4. Use the search function to find specific events
5. Save logs to a file for later analysis

## Tips for PyWinAuto Script Development

1. **Use UIA backend**: The toolkit uses the UIA backend by default, which provides better support for modern Windows applications.
2. **Wait for windows and controls**: Always use `wait()` methods to ensure windows and controls are ready before interacting with them.
3. **Handle exceptions**: Wrap your automation code in try/except blocks to handle unexpected situations.
4. **Use multiple identification methods**: When identifying controls, try using multiple properties (control_type, title, automation_id) for more robust scripts.
5. **Test incrementally**: Build and test your scripts in small increments to identify issues early.

## Troubleshooting

### Common Issues

1. **Window not found**: Try using different identification properties or check if the window is minimized.
2. **Control not accessible**: Some controls may require special handling or elevated permissions.
3. **Automation fails**: Try adding delays or wait conditions to ensure the application is in the expected state.

### Getting Help

If you encounter issues with the toolkit or PyWinAuto in general:

1. Check the [PyWinAuto documentation](https://pywinauto.readthedocs.io/)
2. Look for similar issues on the [PyWinAuto GitHub repository](https://github.com/pywinauto/pywinauto)
3. Use the PyWinAuto Toolkit to inspect the problematic window or control

## License

This toolkit is provided under the MIT License. Feel free to modify and distribute it as needed.
