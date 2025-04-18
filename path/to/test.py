# Write this Python script that uses pywinauto's pyautogui module to open Notepad and type "test.txt":
import time  # Importing time module for delay functionality
from pywinauto import win32 (or use other methods from PyAutoGUI as needed)
win32.start_app('notepad')  # Open the notepad application on Windows
time.sleep(5)       # Wait for Notepad to load, with a delay of 5 seconds
pyautogui.typewrite('test.txt')   # Type 'test.txt' into Notepad
win32.close_app()     # Close the notepad application after typing
