import os
import time

from pywinauto import Application, Desktop

# Notepad を起動
app = Application(backend="uia").start("notepad.exe")

# ウィンドウが現れるのを明示的に待つ
notepad = None
for _ in range(10):
    try:
        # クラス名 'Notepad' のウィンドウを探す（タイトル不要）
        notepad = Desktop(backend="uia").window(class_name="Notepad")
        notepad.wait("ready", timeout=3)
        break
    except Exception:
        time.sleep(1)

if not notepad:
    raise RuntimeError("Notepad window not found after waiting")

# エディットコントロールにアクセスしてテキスト入力
editor = notepad.child_window(control_type="Edit")
editor.wait("ready", timeout=5)
editor.type_keys("test.txt", with_spaces=True)

# Ctrl+Sで保存ダイアログを開く
notepad.type_keys("^s")
time.sleep(1)

# "Save As" ウィンドウを取得（タイトル言語に依存しない方法）
save_as = None
for w in Desktop(backend="uia").windows():
    if "Edit" in [c.control_type() for c in w.children()]:
        save_as = w
        break

if not save_as:
    raise RuntimeError("Save As window not found")

# ファイル名入力
file_path = os.path.abspath("test.txt")
filename_edit = save_as.child_window(control_type="Edit", found_index=0)
filename_edit.wait("ready", timeout=5)
filename_edit.type_keys(file_path, with_spaces=True)

# 保存ボタンを押す（auto_idが1で共通のはず）
save_button = save_as.child_window(auto_id="1", control_type="Button")
save_button.wait("enabled", timeout=5)
save_button.click()

# 少し待って閉じる
time.sleep(1)
notepad.close()

# 「保存しますか？」ダイアログが出た場合の処理
try:
    Desktop(backend="uia").window(auto_id="CommandButton_7").click()
except:
    pass
