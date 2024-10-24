import sys
import os
import numpy as np
import tkinter as tk
import threading

import tkinter.ttk as ttk
from PIL import Image, ImageTk
from tkinter import messagebox as tkMessageBox
from tkinter import filedialog as tkFileDialog

import Crypto
from Crypto.Cipher import AES

# AES-256の暗号化オブジェクトを作成
def create_aes_cipher(password, iv):
    sha = Crypto.Hash.SHA256.new()
    sha.update(password.encode())
    return AES.new(sha.digest(), AES.MODE_CFB, iv)

# データを暗号化する関数
def encrypt_data(data, password):
    iv = Crypto.Random.new().read(AES.block_size)
    return iv + create_aes_cipher(password, iv).encrypt(data)

# データを復号化する関数
def decrypt_data(data, password):
    iv, cipher_text = data[:AES.block_size], data[AES.block_size:]
    return create_aes_cipher(password, iv).decrypt(cipher_text)

# ファイルパスの存在チェックを行う関数
def is_file_valid(file_path):
    return os.path.isfile(file_path)

# ディレクトリパスの存在チェックを行う関数
def is_directory_valid(directory_path):
    return os.path.isdir(directory_path)

# アプリケーションクラス（GUI）
class EncryptionApp(tk.Frame):
    DEBUG_LOG = True
    
    def __init__(self, master=None):
        super().__init__(master)
        self.pack()
        self.status_var = tk.StringVar()
        self.status_var.set("0")
        self.status_var2 = tk.StringVar()
        self.status_var2.set("0")
        self.create_widgets()

    # ウィジェットを作成
    def create_widgets(self):
        # メインのPanedWindowを作成
        pw_main = tk.PanedWindow(self.master, orient='horizontal')
        pw_main.pack(expand=True, fill=tk.BOTH, side="left")

        # 左側のエリア
        pw_left = tk.PanedWindow(pw_main, bg="cyan", orient='vertical')
        pw_main.add(pw_left)

        # 右側のエリア
        pw_right = tk.PanedWindow(pw_main, bg="yellow", orient='vertical')
        pw_main.add(pw_right, stretch="always")

        # フレームの作成
        frame_select = tk.Frame(pw_left, bd=5, relief="ridge")
        pw_left.add(frame_select, stretch="always")

        # ラベルとエントリ（暗号化対象ファイルパス入力）
        label_input_path = tk.Label(frame_select, text="暗号化対象ファイルパス", width=20)
        label_input_path.grid(row=0, column=0, padx=2, pady=2, sticky=tk.EW)

        self.entry_input_path = tk.Entry(frame_select, justify="left", width=50)
        self.entry_input_path.insert(0, "input your file path...")
        self.entry_input_path.grid(row=0, column=1, sticky=tk.EW, padx=2, pady=2)

        # ファイル選択ボタン
        btn_select_input = tk.Button(frame_select, text="・・・", command=lambda: self.select_file(self.entry_input_path))
        btn_select_input.grid(row=0, column=2, sticky=tk.W + tk.E, padx=2, pady=10)

        # ラベルとエントリ（暗号化出力ファイルパス入力）
        label_output_path = tk.Label(frame_select, text="暗号化出力ファイルパス", width=20)
        label_output_path.grid(row=1, column=0, padx=2, pady=2, sticky=tk.EW)

        self.entry_output_path = tk.Entry(frame_select, justify="left", width=50)
        self.entry_output_path.insert(0, "output your file path...")
        self.entry_output_path.grid(row=1, column=1, sticky=tk.EW, padx=2, pady=2)

        # 出力ファイル選択ボタン
        btn_select_output = tk.Button(frame_select, text="・・・", command=lambda: self.select_directory(self.entry_output_path))
        btn_select_output.grid(row=1, column=2, sticky=tk.W + tk.E, padx=2, pady=10)

        # 出力ファイル名入力
        label_output_file_name = tk.Label(frame_select, text="暗号化出力ファイル名", width=20)
        label_output_file_name.grid(row=2, column=0, padx=2, pady=2, sticky=tk.EW)

        self.entry_output_file_name = tk.Entry(frame_select, justify="left", width=50)
        self.entry_output_file_name.insert(0, "")
        self.entry_output_file_name.grid(row=2, column=1, sticky=tk.EW, padx=2, pady=2)

        # パスワード入力
        label_password = tk.Label(frame_select, text="暗号化パスワード", width=20)
        label_password.grid(row=3, column=0, padx=2, pady=2, sticky=tk.EW)

        self.entry_password = tk.Entry(frame_select, justify="left", width=50, show='*')
        self.entry_password.grid(row=3, column=1, sticky=tk.EW, padx=2, pady=2)

        # ステータス表示ラベル
        self.label_status = tk.Label(frame_select, textvariable=self.status_var, width=20)
        self.label_status.grid(row=4, column=0, padx=5, pady=5, sticky=tk.EW)

        # 暗号化実行ボタン
        frame_buttons = tk.Frame(pw_left, bd=2, relief="ridge")
        pw_left.add(frame_buttons)

        btn_encrypt = tk.Button(frame_buttons, text="暗号化", command=self.encrypt_file, width=20)
        btn_encrypt.grid(row=4, column=0, sticky=tk.W + tk.E, padx=2, pady=10)

        # フレームの作成（復号化用）
        frame_select_decrypt = tk.Frame(pw_right, bd=5, relief="ridge")
        pw_right.add(frame_select_decrypt, stretch="always")

        # ラベルとエントリ（復号化対象ファイルパス入力）
        label_input_path_decrypt = tk.Label(frame_select_decrypt, text="復号化対象ファイルパス", width=20)
        label_input_path_decrypt.grid(row=0, column=0, padx=2, pady=2, sticky=tk.EW)

        self.entry_input_path_decrypt = tk.Entry(frame_select_decrypt, justify="left", width=50)
        self.entry_input_path_decrypt.insert(0, "input your file path...")
        self.entry_input_path_decrypt.grid(row=0, column=1, sticky=tk.EW, padx=2, pady=2)

        # ファイル選択ボタン
        btn_select_input_decrypt = tk.Button(frame_select_decrypt, text="・・・", command=lambda: self.select_file(self.entry_input_path_decrypt))
        btn_select_input_decrypt.grid(row=0, column=2, sticky=tk.W + tk.E, padx=2, pady=10)

        # 復号化出力ファイルパス入力
        label_output_path_decrypt = tk.Label(frame_select_decrypt, text="復号化出力ファイルパス", width=20)
        label_output_path_decrypt.grid(row=1, column=0, padx=2, pady=2, sticky=tk.EW)

        self.entry_output_path_decrypt = tk.Entry(frame_select_decrypt, justify="left", width=50)
        self.entry_output_path_decrypt.insert(0, "output your file path...")
        self.entry_output_path_decrypt.grid(row=1, column=1, sticky=tk.EW, padx=2, pady=2)

        # 出力ファイル選択ボタン
        btn_select_output_decrypt = tk.Button(frame_select_decrypt, text="・・・", command=lambda: self.select_directory(self.entry_output_path_decrypt))
        btn_select_output_decrypt.grid(row=1, column=2, sticky=tk.W + tk.E, padx=2, pady=10)

        # 復号化出力ファイル名入力
        label_output_file_name_decrypt = tk.Label(frame_select_decrypt, text="復号化出力ファイル名", width=20)
        label_output_file_name_decrypt.grid(row=2, column=0, padx=2, pady=2, sticky=tk.EW)

        self.entry_output_file_name_decrypt = tk.Entry(frame_select_decrypt, justify="left", width=50)
        self.entry_output_file_name_decrypt.insert(0, "")
        self.entry_output_file_name_decrypt.grid(row=2, column=1, sticky=tk.EW, padx=2, pady=2)

        # パスワード入力
        label_password_decrypt = tk.Label(frame_select_decrypt, text="復号化パスワード", width=20)
        label_password_decrypt.grid(row=3, column=0, padx=2, pady=2, sticky=tk.EW)

        self.entry_password_decrypt = tk.Entry(frame_select_decrypt, justify="left", width=50, show='*')
        self.entry_password_decrypt.grid(row=3, column=1, sticky=tk.EW, padx=2, pady=2)

        # ステータス表示ラベル
        self.label_status2 = tk.Label(frame_select_decrypt, textvariable=self.status_var2, width=20)
        self.label_status2.grid(row=4, column=0, padx=5, pady=5, sticky=tk.EW)

        # 復号化実行ボタン
        frame_buttons_decrypt = tk.Frame(pw_right, bd=2, relief="ridge")
        pw_right.add(frame_buttons_decrypt)

        btn_decrypt = tk.Button(frame_buttons_decrypt, text="復号化", command=self.decrypt_file, width=20)
        btn_decrypt.grid(row=4, column=0, sticky=tk.W + tk.E, padx=2, pady=10)

    # ファイル選択ダイアログを表示してエントリにパスをセットする
    def select_file(self, entry_widget):
        file_path = tkFileDialog.askopenfilename()
        if file_path:
            entry_widget.delete(0, tk.END)
            entry_widget.insert(0, file_path)

    # ディレクトリ選択ダイアログを表示してエントリにパスをセットする
    def select_directory(self, entry_widget):
        directory_path = tkFileDialog.askdirectory()
        if directory_path:
            entry_widget.delete(0, tk.END)
            entry_widget.insert(0, directory_path)

    # 暗号化を実行する
    def encrypt_file(self):
        input_path = self.entry_input_path.get()
        output_directory = self.entry_output_path.get()
        output_file_name = self.entry_output_file_name.get()
        password = self.entry_password.get()

        # ファイルの存在確認
        if not is_file_valid(input_path):
            self.status_var.set("Invalid input file path!")
            return

        if not is_directory_valid(output_directory):
            self.status_var.set("Invalid output directory!")
            return

        if not output_file_name:
            self.status_var.set("Please enter a valid output file name!")
            return

        if not password:
            self.status_var.set("Please enter a valid password!")
            return

        try:
            with open(input_path, "rb") as file_in:
                data = file_in.read()

            encrypted_data = encrypt_data(data, password)

            output_path = os.path.join(output_directory, output_file_name)

            with open(output_path, "wb") as file_out:
                file_out.write(encrypted_data)

            self.status_var.set(f"File successfully encrypted to {output_path}")

        except Exception as e:
            self.status_var.set(f"Error: {str(e)}")

    # 復号化を実行する
    def decrypt_file(self):
        input_path = self.entry_input_path_decrypt.get()
        output_directory = self.entry_output_path_decrypt.get()
        output_file_name = self.entry_output_file_name_decrypt.get()
        password = self.entry_password_decrypt.get()

        # ファイルの存在確認
        if not is_file_valid(input_path):
            self.status_var2.set("Invalid input file path!")
            return

        if not is_directory_valid(output_directory):
            self.status_var2.set("Invalid output directory!")
            return

        if not output_file_name:
            self.status_var2.set("Please enter a valid output file name!")
            return

        if not password:
            self.status_var2.set("Please enter a valid password!")
            return

        try:
            with open(input_path, "rb") as file_in:
                encrypted_data = file_in.read()

            decrypted_data = decrypt_data(encrypted_data, password)

            output_path = os.path.join(output_directory, output_file_name)

            with open(output_path, "wb") as file_out:
                file_out.write(decrypted_data)

            self.status_var2.set(f"File successfully decrypted to {output_path}")

        except Exception as e:
            self.status_var2.set(f"Error: {str(e)}")


# メインの実行部分
def main():
    root = tk.Tk()
    root.geometry("1025x300")
    root.title(u"EncryptApp")
    app = EncryptionApp(master=root)
    app.mainloop()

if __name__ == "__main__":
    main()
