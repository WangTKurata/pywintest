"""
Application Logger Module

A module for recording and analyzing application interactions.
This can be used to log window events, control operations, and other activities
to help debug PyWinAuto scripts.

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

import datetime
import json
import logging
import os
import time
from enum import Enum
from typing import Any, Dict, List, Optional, Union


class LogLevel(Enum):
    DEBUG = 10
    INFO = 20
    WARNING = 30
    ERROR = 40
    CRITICAL = 50


class LogCategory(Enum):
    WINDOW = "window"
    CONTROL = "control"
    PROCESS = "process"
    SYSTEM = "system"
    SCRIPT = "script"
    USER = "user"


class AppLogger:
    """Main logger class for recording application interactions."""

    def __init__(self, log_file: Optional[str] = None, console_output: bool = True):
        """Initialize the logger.

        Args:
            log_file: Path to the log file. If None, logs will not be saved to a file.
            console_output: Whether to output logs to the console.
        """
        self.logs: List[Dict[str, Any]] = []
        self.log_file = log_file
        self.console_output = console_output
        self.start_time = time.time()

        # Set up Python's logging module
        self.logger = logging.getLogger("AppLogger")
        self.logger.setLevel(logging.DEBUG)

        # Clear existing handlers
        for handler in self.logger.handlers[:]:
            self.logger.removeHandler(handler)

        # Add console handler if requested
        if console_output:
            console_handler = logging.StreamHandler()
            console_handler.setLevel(logging.DEBUG)
            formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
            console_handler.setFormatter(formatter)
            self.logger.addHandler(console_handler)

        # Add file handler if log file is specified
        if log_file:
            os.makedirs(os.path.dirname(os.path.abspath(log_file)), exist_ok=True)
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(logging.DEBUG)
            formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)

        # Log initialization
        self.log(
            LogLevel.INFO,
            LogCategory.SYSTEM,
            "Logger initialized",
            {"log_file": log_file, "console_output": console_output},
        )

    def log(
        self,
        level: LogLevel,
        category: LogCategory,
        message: str,
        data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Log an event.

        Args:
            level: The log level.
            category: The log category.
            message: The log message.
            data: Additional data to log.

        Returns:
            The log entry.
        """
        timestamp = time.time()
        elapsed = timestamp - self.start_time

        entry = {
            "timestamp": timestamp,
            "datetime": datetime.datetime.fromtimestamp(timestamp).isoformat(),
            "elapsed": elapsed,
            "level": level.name,
            "level_value": level.value,
            "category": category.value,
            "message": message,
            "data": data or {},
        }

        self.logs.append(entry)

        # Log using Python's logging module
        log_message = f"[{category.value.upper()}] {message}"
        if data:
            log_message += f" - {json.dumps(data, default=str)}"

        if level == LogLevel.DEBUG:
            self.logger.debug(log_message)
        elif level == LogLevel.INFO:
            self.logger.info(log_message)
        elif level == LogLevel.WARNING:
            self.logger.warning(log_message)
        elif level == LogLevel.ERROR:
            self.logger.error(log_message)
        elif level == LogLevel.CRITICAL:
            self.logger.critical(log_message)

        return entry

    def debug(
        self, category: LogCategory, message: str, data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Log a debug event."""
        return self.log(LogLevel.DEBUG, category, message, data)

    def info(
        self, category: LogCategory, message: str, data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Log an info event."""
        return self.log(LogLevel.INFO, category, message, data)

    def warning(
        self, category: LogCategory, message: str, data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Log a warning event."""
        return self.log(LogLevel.WARNING, category, message, data)

    def error(
        self, category: LogCategory, message: str, data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Log an error event."""
        return self.log(LogLevel.ERROR, category, message, data)

    def critical(
        self, category: LogCategory, message: str, data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Log a critical event."""
        return self.log(LogLevel.CRITICAL, category, message, data)

    def log_window_event(
        self,
        event_type: str,
        window_title: str,
        window_class: Optional[str] = None,
        window_handle: Optional[int] = None,
        additional_data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Log a window event.

        Args:
            event_type: The type of event (e.g., "open", "close", "focus").
            window_title: The title of the window.
            window_class: The class of the window.
            window_handle: The handle of the window.
            additional_data: Additional data to log.

        Returns:
            The log entry.
        """
        data = {
            "event_type": event_type,
            "window_title": window_title,
            "window_class": window_class,
            "window_handle": window_handle,
        }

        if additional_data:
            data.update(additional_data)

        return self.info(
            LogCategory.WINDOW, f"Window {event_type}: {window_title}", data
        )

    def log_control_event(
        self,
        event_type: str,
        control_type: str,
        control_name: Optional[str] = None,
        control_id: Optional[str] = None,
        window_title: Optional[str] = None,
        additional_data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Log a control event.

        Args:
            event_type: The type of event (e.g., "click", "type", "select").
            control_type: The type of control.
            control_name: The name of the control.
            control_id: The ID of the control.
            window_title: The title of the window containing the control.
            additional_data: Additional data to log.

        Returns:
            The log entry.
        """
        data = {
            "event_type": event_type,
            "control_type": control_type,
            "control_name": control_name,
            "control_id": control_id,
            "window_title": window_title,
        }

        if additional_data:
            data.update(additional_data)

        control_desc = control_name or control_id or control_type
        return self.info(
            LogCategory.CONTROL, f"Control {event_type}: {control_desc}", data
        )

    def log_process_event(
        self,
        event_type: str,
        process_name: str,
        process_id: Optional[int] = None,
        additional_data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Log a process event.

        Args:
            event_type: The type of event (e.g., "start", "end", "attach").
            process_name: The name of the process.
            process_id: The ID of the process.
            additional_data: Additional data to log.

        Returns:
            The log entry.
        """
        data = {
            "event_type": event_type,
            "process_name": process_name,
            "process_id": process_id,
        }

        if additional_data:
            data.update(additional_data)

        return self.info(
            LogCategory.PROCESS, f"Process {event_type}: {process_name}", data
        )

    def log_script_event(
        self,
        event_type: str,
        script_name: Optional[str] = None,
        additional_data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Log a script event.

        Args:
            event_type: The type of event (e.g., "start", "end", "error").
            script_name: The name of the script.
            additional_data: Additional data to log.

        Returns:
            The log entry.
        """
        data = {"event_type": event_type, "script_name": script_name}

        if additional_data:
            data.update(additional_data)

        return self.info(
            LogCategory.SCRIPT, f"Script {event_type}: {script_name or 'unknown'}", data
        )

    def get_logs(
        self,
        level: Optional[LogLevel] = None,
        category: Optional[LogCategory] = None,
        start_time: Optional[float] = None,
        end_time: Optional[float] = None,
        search_text: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Get filtered logs.

        Args:
            level: Filter by log level.
            category: Filter by log category.
            start_time: Filter by start time.
            end_time: Filter by end time.
            search_text: Filter by search text.

        Returns:
            Filtered logs.
        """
        filtered_logs = self.logs

        if level:
            filtered_logs = [
                log for log in filtered_logs if log["level_value"] >= level.value
            ]

        if category:
            filtered_logs = [
                log for log in filtered_logs if log["category"] == category.value
            ]

        if start_time:
            filtered_logs = [
                log for log in filtered_logs if log["timestamp"] >= start_time
            ]

        if end_time:
            filtered_logs = [
                log for log in filtered_logs if log["timestamp"] <= end_time
            ]

        if search_text:
            search_text = search_text.lower()
            filtered_logs = [
                log
                for log in filtered_logs
                if search_text in log["message"].lower()
                or any(search_text in str(v).lower() for v in log["data"].values())
            ]

        return filtered_logs

    def save_logs(self, file_path: str, format: str = "json") -> bool:
        """Save logs to a file.

        Args:
            file_path: The path to save the logs to.
            format: The format to save the logs in ("json" or "txt").

        Returns:
            True if successful, False otherwise.
        """
        try:
            if format == "json":
                with open(file_path, "w") as f:
                    json.dump(self.logs, f, indent=2, default=str)
            elif format == "txt":
                with open(file_path, "w") as f:
                    for log in self.logs:
                        f.write(
                            f"{log['datetime']} - {log['level']} - [{log['category']}] {log['message']}\n"
                        )
                        if log["data"]:
                            f.write(f"  Data: {json.dumps(log['data'], default=str)}\n")
            else:
                self.error(LogCategory.SYSTEM, f"Unsupported log format: {format}")
                return False

            self.info(
                LogCategory.SYSTEM, f"Logs saved to {file_path}", {"format": format}
            )
            return True
        except Exception as e:
            self.error(LogCategory.SYSTEM, f"Error saving logs: {str(e)}")
            return False

    def clear_logs(self) -> None:
        """Clear all logs."""
        self.logs = []
        self.info(LogCategory.SYSTEM, "Logs cleared")

    def get_statistics(self) -> Dict[str, Any]:
        """Get statistics about the logs.

        Returns:
            Statistics about the logs.
        """
        if not self.logs:
            return {
                "total_logs": 0,
                "start_time": None,
                "end_time": None,
                "duration": 0,
                "levels": {},
                "categories": {},
            }

        start_time = min(log["timestamp"] for log in self.logs)
        end_time = max(log["timestamp"] for log in self.logs)

        level_counts = {}
        for log in self.logs:
            level = log["level"]
            level_counts[level] = level_counts.get(level, 0) + 1

        category_counts = {}
        for log in self.logs:
            category = log["category"]
            category_counts[category] = category_counts.get(category, 0) + 1

        return {
            "total_logs": len(self.logs),
            "start_time": datetime.datetime.fromtimestamp(start_time).isoformat(),
            "end_time": datetime.datetime.fromtimestamp(end_time).isoformat(),
            "duration": end_time - start_time,
            "levels": level_counts,
            "categories": category_counts,
        }


class LogViewer:
    """A class for viewing and analyzing logs."""

    def __init__(self, logs: List[Dict[str, Any]]):
        """Initialize the log viewer.

        Args:
            logs: The logs to view.
        """
        self.logs = logs

    def get_logs_by_level(self, level: LogLevel) -> List[Dict[str, Any]]:
        """Get logs by level.

        Args:
            level: The log level.

        Returns:
            Logs with the specified level.
        """
        return [log for log in self.logs if log["level_value"] == level.value]

    def get_logs_by_category(self, category: LogCategory) -> List[Dict[str, Any]]:
        """Get logs by category.

        Args:
            category: The log category.

        Returns:
            Logs with the specified category.
        """
        return [log for log in self.logs if log["category"] == category.value]

    def get_logs_by_time_range(
        self, start_time: float, end_time: float
    ) -> List[Dict[str, Any]]:
        """Get logs by time range.

        Args:
            start_time: The start time.
            end_time: The end time.

        Returns:
            Logs within the specified time range.
        """
        return [log for log in self.logs if start_time <= log["timestamp"] <= end_time]

    def get_logs_by_search(self, search_text: str) -> List[Dict[str, Any]]:
        """Get logs by search text.

        Args:
            search_text: The search text.

        Returns:
            Logs containing the search text.
        """
        search_text = search_text.lower()
        return [
            log
            for log in self.logs
            if search_text in log["message"].lower()
            or any(search_text in str(v).lower() for v in log["data"].values())
        ]

    def get_window_events(self) -> List[Dict[str, Any]]:
        """Get window events.

        Returns:
            Window events.
        """
        return self.get_logs_by_category(LogCategory.WINDOW)

    def get_control_events(self) -> List[Dict[str, Any]]:
        """Get control events.

        Returns:
            Control events.
        """
        return self.get_logs_by_category(LogCategory.CONTROL)

    def get_process_events(self) -> List[Dict[str, Any]]:
        """Get process events.

        Returns:
            Process events.
        """
        return self.get_logs_by_category(LogCategory.PROCESS)

    def get_script_events(self) -> List[Dict[str, Any]]:
        """Get script events.

        Returns:
            Script events.
        """
        return self.get_logs_by_category(LogCategory.SCRIPT)

    def get_events_by_window(self, window_title: str) -> List[Dict[str, Any]]:
        """Get events for a specific window.

        Args:
            window_title: The window title.

        Returns:
            Events for the specified window.
        """
        window_events = []

        # Get direct window events
        for log in self.get_window_events():
            if log["data"].get("window_title") == window_title:
                window_events.append(log)

        # Get control events for the window
        for log in self.get_control_events():
            if log["data"].get("window_title") == window_title:
                window_events.append(log)

        # Sort by timestamp
        window_events.sort(key=lambda x: x["timestamp"])

        return window_events

    def get_events_by_control(self, control_id: str) -> List[Dict[str, Any]]:
        """Get events for a specific control.

        Args:
            control_id: The control ID.

        Returns:
            Events for the specified control.
        """
        control_events = []

        for log in self.get_control_events():
            if log["data"].get("control_id") == control_id:
                control_events.append(log)

        # Sort by timestamp
        control_events.sort(key=lambda x: x["timestamp"])

        return control_events

    def get_events_by_process(self, process_id: int) -> List[Dict[str, Any]]:
        """Get events for a specific process.

        Args:
            process_id: The process ID.

        Returns:
            Events for the specified process.
        """
        process_events = []

        for log in self.get_process_events():
            if log["data"].get("process_id") == process_id:
                process_events.append(log)

        # Sort by timestamp
        process_events.sort(key=lambda x: x["timestamp"])

        return process_events

    def get_event_sequence(self) -> List[Dict[str, Any]]:
        """Get the sequence of events.

        Returns:
            The sequence of events.
        """
        # Sort by timestamp
        return sorted(self.logs, key=lambda x: x["timestamp"])

    def get_event_timeline(self) -> Dict[str, List[Dict[str, Any]]]:
        """Get a timeline of events.

        Returns:
            A timeline of events.
        """
        timeline = {}

        for log in self.logs:
            timestamp = log["datetime"].split("T")[0]  # Get date part
            if timestamp not in timeline:
                timeline[timestamp] = []
            timeline[timestamp].append(log)

        # Sort each day's logs by timestamp
        for day in timeline:
            timeline[day].sort(key=lambda x: x["timestamp"])

        return timeline

    def get_error_events(self) -> List[Dict[str, Any]]:
        """Get error events.

        Returns:
            Error events.
        """
        return [log for log in self.logs if log["level"] in ("ERROR", "CRITICAL")]

    def get_statistics(self) -> Dict[str, Any]:
        """Get statistics about the logs.

        Returns:
            Statistics about the logs.
        """
        if not self.logs:
            return {
                "total_logs": 0,
                "start_time": None,
                "end_time": None,
                "duration": 0,
                "levels": {},
                "categories": {},
            }

        start_time = min(log["timestamp"] for log in self.logs)
        end_time = max(log["timestamp"] for log in self.logs)

        level_counts = {}
        for log in self.logs:
            level = log["level"]
            level_counts[level] = level_counts.get(level, 0) + 1

        category_counts = {}
        for log in self.logs:
            category = log["category"]
            category_counts[category] = category_counts.get(category, 0) + 1

        return {
            "total_logs": len(self.logs),
            "start_time": datetime.datetime.fromtimestamp(start_time).isoformat(),
            "end_time": datetime.datetime.fromtimestamp(end_time).isoformat(),
            "duration": end_time - start_time,
            "levels": level_counts,
            "categories": category_counts,
        }


# Create a global logger instance
logger = AppLogger(log_file="app_logs.log")

# Example usage
if __name__ == "__main__":
    # Log some events
    logger.info(LogCategory.SYSTEM, "Application started")

    logger.log_window_event("open", "Notepad", "Notepad", 12345)
    logger.log_control_event("click", "Button", "OK", "btn_ok", "Notepad")
    logger.log_process_event("start", "notepad.exe", 1234)

    # Log an error
    try:
        1 / 0
    except Exception as e:
        logger.error(LogCategory.SYSTEM, f"Error: {str(e)}")

    # Get statistics
    stats = logger.get_statistics()
    print(f"Total logs: {stats['total_logs']}")
    print(f"Levels: {stats['levels']}")
    print(f"Categories: {stats['categories']}")

    # Save logs
    logger.save_logs("app_logs.json")

    # Create a log viewer
    viewer = LogViewer(logger.logs)

    # Get window events
    window_events = viewer.get_window_events()
    print(f"Window events: {len(window_events)}")

    # Get error events
    error_events = viewer.get_error_events()
    print(f"Error events: {len(error_events)}")
