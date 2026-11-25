"""Aplikasi GUI Tkinter untuk enkripsi, dekripsi, dan analisis DES."""

import os
import sys
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from analysis.avalanche import avalanche_key, avalanche_plaintext, average_avalanche
from analysis.bruteforce import bruteforce_reduced_key, estimate_full_bruteforce
from analysis.weak_keys import SEMI_WEAK_KEYS, WEAK_KEYS, check_complementation, is_weak_key
from des.core import encrypt_block
from des.modes import decrypt, encrypt
from des.utils import bytes_to_hex, hex_to_bytes


class DesApp(tk.Tk):
    def __init__(self) -> None:
        """Inisialisasi komponen antarmuka, tata letak tab, dan variabel state."""
        super().__init__()
        self.title("DES - Kriptografi")
        self.geometry("900x700")
        self.minsize(800, 600)

        notebook = ttk.Notebook(self)
        notebook.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        crypto_tab = ttk.Frame(notebook)
        analysis_tab = ttk.Frame(notebook)

        notebook.add(crypto_tab, text=" Enkripsi & Dekripsi ")
        notebook.add(analysis_tab, text=" Analisis Kriptografi ")

        self._build_crypto_tab(crypto_tab)
        self._build_analysis_tab(analysis_tab)

    def _build_crypto_tab(self, parent: ttk.Frame) -> None:
        """Bangun kontrol konfigurasi kunci, mode, serta panel enkripsi dan dekripsi."""
        config_frame = ttk.LabelFrame(parent, text="Konfigurasi Kunci & Mode", padding=10)
        config_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Label(config_frame, text="Kunci DES (16 Hex):").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.key_var = tk.StringVar(value="133457799BBCDFF1")
        key_entry = ttk.Entry(config_frame, textvariable=self.key_var, width=28, font=("Consolas", 10))
        key_entry.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)

        ttk.Button(config_frame, text="Kunci Acak", command=self._generate_random_key).grid(
            row=0, column=2, padx=5, pady=5
        )

        ttk.Label(config_frame, text="Mode Operasi:").grid(row=0, column=3, sticky=tk.W, padx=(20, 5), pady=5)
        self.mode_var = tk.StringVar(value="CBC")
        ttk.Radiobutton(config_frame, text="CBC", variable=self.mode_var, value="CBC").grid(
            row=0, column=4, padx=5, pady=5
        )
        ttk.Radiobutton(config_frame, text="ECB", variable=self.mode_var, value="ECB").grid(
            row=0, column=5, padx=5, pady=5
        )

        self.input_type_var = tk.StringVar(value="text")
        type_frame = ttk.Frame(config_frame)
        type_frame.grid(row=1, column=0, columnspan=6, sticky=tk.W, pady=(5, 0))
        ttk.Label(type_frame, text="Tipe Data:").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(
            type_frame, text="Teks", variable=self.input_type_var, value="text", command=self._toggle_input_type
        ).pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(
            type_frame, text="File", variable=self.input_type_var, value="file", command=self._toggle_input_type
        ).pack(side=tk.LEFT, padx=5)

        body_frame = ttk.Frame(parent)
        body_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.enc_frame = ttk.LabelFrame(body_frame, text="Enkripsi", padding=10)
        self.enc_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))

        self.dec_frame = ttk.LabelFrame(body_frame, text="Dekripsi", padding=10)
        self.dec_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5, 0))

        self._setup_encryption_panel(self.enc_frame)
        self._setup_decryption_panel(self.dec_frame)

    def _setup_encryption_panel(self, parent: ttk.Frame) -> None:
        """Bangun widget input teks/file dan output ciphertext."""
        self.enc_file_frame = ttk.Frame(parent)
        self.enc_file_path_var = tk.StringVar()
        ttk.Button(self.enc_file_frame, text="Pilih File Plaintext", command=self._browse_enc_file).pack(
            anchor=tk.W, pady=2
        )
        ttk.Label(self.enc_file_frame, textvariable=self.enc_file_path_var, foreground="gray").pack(
            anchor=tk.W, pady=2
        )

        self.enc_text_label = ttk.Label(parent, text="Plaintext:")
        self.enc_text_label.pack(anchor=tk.W)
        self.enc_text_input = tk.Text(parent, height=8, font=("Consolas", 10))
        self.enc_text_input.pack(fill=tk.BOTH, expand=True, pady=4)
        self.enc_text_input.insert(tk.END, "Kami dari Kelompok 2 Algoritma DES")

        ttk.Button(parent, text="Enkripsi Sekarang ->", command=self._do_encrypt).pack(pady=6)

        ttk.Label(parent, text="Ciphertext (Hex):").pack(anchor=tk.W)
        self.enc_hex_output = tk.Text(parent, height=8, font=("Consolas", 10))
        self.enc_hex_output.pack(fill=tk.BOTH, expand=True, pady=4)

    def _setup_decryption_panel(self, parent: ttk.Frame) -> None:
        """Bangun widget input ciphertext hex/file dan output plaintext."""
        self.dec_file_frame = ttk.Frame(parent)
        self.dec_file_path_var = tk.StringVar()
        ttk.Button(self.dec_file_frame, text="Pilih File Terenkripsi", command=self._browse_dec_file).pack(
            anchor=tk.W, pady=2
        )
        ttk.Label(self.dec_file_frame, textvariable=self.dec_file_path_var, foreground="gray").pack(
            anchor=tk.W, pady=2
        )

        self.dec_text_label = ttk.Label(parent, text="Ciphertext (Hex):")
        self.dec_text_label.pack(anchor=tk.W)
        self.dec_text_input = tk.Text(parent, height=8, font=("Consolas", 10))
        self.dec_text_input.pack(fill=tk.BOTH, expand=True, pady=4)

        ttk.Button(parent, text="<- Dekripsi Sekarang", command=self._do_decrypt).pack(pady=6)

        ttk.Label(parent, text="Hasil Dekripsi (Plaintext):").pack(anchor=tk.W)
        self.dec_plain_output = tk.Text(parent, height=8, font=("Consolas", 10))
        self.dec_plain_output.pack(fill=tk.BOTH, expand=True, pady=4)

    def _toggle_input_type(self) -> None:
        """Alihkan tampilan antara mode teks dan mode berkas."""
        if self.input_type_var.get() == "file":
            self.enc_text_label.pack_forget()
            self.enc_text_input.pack_forget()
            self.enc_file_frame.pack(before=self.enc_frame.winfo_children()[3], fill=tk.X, pady=4)
            self.dec_text_label.pack_forget()
            self.dec_text_input.pack_forget()
            self.dec_file_frame.pack(before=self.dec_frame.winfo_children()[3], fill=tk.X, pady=4)
        else:
            self.enc_file_frame.pack_forget()
            self.dec_file_frame.pack_forget()
            self.enc_text_label.pack(before=self.enc_frame.winfo_children()[3], anchor=tk.W)
            self.enc_text_input.pack(before=self.enc_frame.winfo_children()[3], fill=tk.BOTH, expand=True, pady=4)
            self.dec_text_label.pack(before=self.dec_frame.winfo_children()[3], anchor=tk.W)
            self.dec_text_input.pack(before=self.dec_frame.winfo_children()[3], fill=tk.BOTH, expand=True, pady=4)

    def _generate_random_key(self) -> None:
        """Buat kunci acak delapan byte dalam format heksadesimal."""
        self.key_var.set(bytes_to_hex(os.urandom(8)))

    def _browse_enc_file(self) -> None:
        """Pilih berkas plaintext untuk dienkripsi."""
        path = filedialog.askopenfilename()
        if path:
            self.enc_file_path_var.set(path)

    def _browse_dec_file(self) -> None:
        """Pilih berkas ciphertext biner untuk didekripsi."""
        path = filedialog.askopenfilename()
        if path:
            self.dec_file_path_var.set(path)

    def _get_key(self) -> bytes | None:
        """Validasi dan ubah kunci heksadesimal menjadi bytes."""
        raw_key = self.key_var.get().strip()
        try:
            return hex_to_bytes(raw_key)
        except Exception as err:
            messagebox.showerror("Kunci Tidak Sah", f"Kunci harus berupa 16 karakter heksadesimal:\n{err}")
            return None

    def _do_encrypt(self) -> None:
        """Jalankan proses enkripsi teks atau berkas menggunakan mode terpilih."""
        key = self._get_key()
        if not key:
            return
        mode = self.mode_var.get()
        if self.input_type_var.get() == "text":
            plaintext = self.enc_text_input.get("1.0", tk.END).strip().encode("utf-8")
            if not plaintext:
                messagebox.showwarning("Peringatan", "Plaintext tidak boleh kosong.")
                return
            try:
                ciphertext = encrypt(plaintext, key, mode=mode)
                self.enc_hex_output.delete("1.0", tk.END)
                self.enc_hex_output.insert(tk.END, bytes_to_hex(ciphertext))
                self.dec_text_input.delete("1.0", tk.END)
                self.dec_text_input.insert(tk.END, bytes_to_hex(ciphertext))
            except Exception as err:
                messagebox.showerror("Gagal Enkripsi", str(err))
        else:
            file_path = self.enc_file_path_var.get()
            if not file_path or not os.path.isfile(file_path):
                messagebox.showwarning("Peringatan", "Pilih berkas plaintext yang sah.")
                return
            save_path = filedialog.asksaveasfilename(title="Simpan File Terenkripsi")
            if not save_path:
                return
            try:
                with open(file_path, "rb") as source:
                    data = source.read()
                ciphertext = encrypt(data, key, mode=mode)
                with open(save_path, "wb") as destination:
                    destination.write(ciphertext)
                self.enc_hex_output.delete("1.0", tk.END)
                self.enc_hex_output.insert(tk.END, f"File tersimpan di:\n{save_path}\nHex (preview 128 byte):\n{bytes_to_hex(ciphertext[:128])}")
                messagebox.showinfo("Sukses", "File berhasil dienkripsi!")
            except Exception as err:
                messagebox.showerror("Gagal Enkripsi File", str(err))

    def _do_decrypt(self) -> None:
        """Jalankan proses dekripsi ciphertext teks atau berkas."""
        key = self._get_key()
        if not key:
            return
        mode = self.mode_var.get()
        if self.input_type_var.get() == "text":
            raw_hex = self.dec_text_input.get("1.0", tk.END).strip().replace(" ", "").replace("\n", "")
            if not raw_hex:
                messagebox.showwarning("Peringatan", "Ciphertext hex tidak boleh kosong.")
                return
            try:
                ciphertext = hex_to_bytes(raw_hex)
                decrypted = decrypt(ciphertext, key, mode=mode)
                self.dec_plain_output.delete("1.0", tk.END)
                try:
                    self.dec_plain_output.insert(tk.END, decrypted.decode("utf-8"))
                except UnicodeDecodeError:
                    self.dec_plain_output.insert(tk.END, f"[Biner / Non-UTF8 Hex]:\n{bytes_to_hex(decrypted)}")
            except Exception as err:
                messagebox.showerror("Gagal Dekripsi", f"Gagal mendekripsi:\n{err}")
        else:
            file_path = self.dec_file_path_var.get()
            if not file_path or not os.path.isfile(file_path):
                messagebox.showwarning("Peringatan", "Pilih berkas terenkripsi yang sah.")
                return
            save_path = filedialog.asksaveasfilename(title="Simpan File Hasil Dekripsi")
            if not save_path:
                return
            try:
                with open(file_path, "rb") as source:
                    ciphertext = source.read()
                decrypted = decrypt(ciphertext, key, mode=mode)
                with open(save_path, "wb") as destination:
                    destination.write(decrypted)
                self.dec_plain_output.delete("1.0", tk.END)
                self.dec_plain_output.insert(tk.END, f"File tersimpan di:\n{save_path}")
                messagebox.showinfo("Sukses", "File berhasil didekripsi!")
            except Exception as err:
                messagebox.showerror("Gagal Dekripsi File", str(err))

    def _build_analysis_tab(self, parent: ttk.Frame) -> None:
        """Bangun tab analisis avalanche effect, weak keys, dan simulasi brute force."""
        sub_notebook = ttk.Notebook(parent)
        sub_notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        avalanche_page = ttk.Frame(sub_notebook)
        weak_key_page = ttk.Frame(sub_notebook)
        bruteforce_page = ttk.Frame(sub_notebook)

        sub_notebook.add(avalanche_page, text=" Avalanche Effect ")
        sub_notebook.add(weak_key_page, text=" Weak Key & Komplementasi ")
        sub_notebook.add(bruteforce_page, text=" Demo Brute Force ")

        self._setup_avalanche_page(avalanche_page)
        self._setup_weak_key_page(weak_key_page)
        self._setup_bruteforce_page(bruteforce_page)

    def _setup_avalanche_page(self, parent: ttk.Frame) -> None:
        """Bangun antarmuka uji avalanche effect per ronde dan rata-rata posisi bit."""
        ctrl_frame = ttk.LabelFrame(parent, text="Parameter Analisis", padding=10)
        ctrl_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Label(ctrl_frame, text="Plaintext (16 Hex):").grid(row=0, column=0, sticky=tk.W, padx=5, pady=4)
        self.aval_pt_var = tk.StringVar(value="0123456789ABCDEF")
        ttk.Entry(ctrl_frame, textvariable=self.aval_pt_var, width=22, font=("Consolas", 10)).grid(
            row=0, column=1, sticky=tk.W, padx=5, pady=4
        )

        ttk.Label(ctrl_frame, text="Key (16 Hex):").grid(row=0, column=2, sticky=tk.W, padx=5, pady=4)
        self.aval_key_var = tk.StringVar(value="133457799BBCDFF1")
        ttk.Entry(ctrl_frame, textvariable=self.aval_key_var, width=22, font=("Consolas", 10)).grid(
            row=0, column=3, sticky=tk.W, padx=5, pady=4
        )

        ttk.Label(ctrl_frame, text="Target Flip:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=4)
        self.aval_target_var = tk.StringVar(value="plaintext")
        ttk.Radiobutton(ctrl_frame, text="Plaintext", variable=self.aval_target_var, value="plaintext").grid(
            row=1, column=1, sticky=tk.W, padx=5, pady=4
        )
        ttk.Radiobutton(ctrl_frame, text="Key", variable=self.aval_target_var, value="key").grid(
            row=1, column=2, sticky=tk.W, padx=5, pady=4
        )

        ttk.Label(ctrl_frame, text="Posisi Bit (0-63):").grid(row=2, column=0, sticky=tk.W, padx=5, pady=4)
        self.aval_bit_spin = ttk.Spinbox(ctrl_frame, from_=0, to=63, width=6)
        self.aval_bit_spin.set(0)
        self.aval_bit_spin.grid(row=2, column=1, sticky=tk.W, padx=5, pady=4)

        btn_box = ttk.Frame(ctrl_frame)
        btn_box.grid(row=2, column=2, columnspan=2, sticky=tk.W, pady=4)
        ttk.Button(btn_box, text="Hitung Bit Tunggal", command=self._do_avalanche_single).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_box, text="Rata-rata Semua Bit (64)", command=self._do_avalanche_average).pack(side=tk.LEFT, padx=4)

        table_frame = ttk.LabelFrame(parent, text="Persebaran Bit Berbeda per Ronde (Maks 64 bit)", padding=10)
        table_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        columns = ("round", "diff", "pct", "bar")
        self.aval_tree = ttk.Treeview(table_frame, columns=columns, show="headings", height=16)
        self.aval_tree.heading("round", text="Ronde")
        self.aval_tree.heading("diff", text="Bit Berbeda")
        self.aval_tree.heading("pct", text="Persentase")
        self.aval_tree.heading("bar", text="Visualisasi (50% = 32 bit)")

        self.aval_tree.column("round", width=80, anchor=tk.CENTER)
        self.aval_tree.column("diff", width=110, anchor=tk.CENTER)
        self.aval_tree.column("pct", width=110, anchor=tk.CENTER)
        self.aval_tree.column("bar", width=380, anchor=tk.W)

        self.aval_tree.pack(fill=tk.BOTH, expand=True)

    def _do_avalanche_single(self) -> None:
        """Hitung dan visualisasikan avalanche effect dari perubahan satu bit."""
        try:
            pt = hex_to_bytes(self.aval_pt_var.get().strip())
            key = hex_to_bytes(self.aval_key_var.get().strip())
            bit_idx = int(self.aval_bit_spin.get())
            target = self.aval_target_var.get()
            diffs = avalanche_plaintext(pt, key, bit_idx) if target == "plaintext" else avalanche_key(pt, key, bit_idx)
            self._render_avalanche_table(diffs)
        except Exception as err:
            messagebox.showerror("Kesalahan Parameter", str(err))

    def _do_avalanche_average(self) -> None:
        """Hitung dan tampilkan rata-rata avalanche effect untuk seluruh 64 posisi bit."""
        try:
            pt = hex_to_bytes(self.aval_pt_var.get().strip())
            key = hex_to_bytes(self.aval_key_var.get().strip())
            target = self.aval_target_var.get()
            avg_diffs = average_avalanche(pt, key, target)
            self._render_avalanche_table(avg_diffs, is_average=True)
        except Exception as err:
            messagebox.showerror("Kesalahan Parameter", str(err))

    def _render_avalanche_table(self, values: list[int] | list[float], is_average: bool = False) -> None:
        """Perbarui baris Treeview dengan angka dan grafik visualisasi batang."""
        for item in self.aval_tree.get_children():
            self.aval_tree.delete(item)
        for idx, val in enumerate(values, start=1):
            val_float = float(val)
            pct = (val_float / 64.0) * 100
            bar_len = int(round(val_float / 2))
            bar_str = "#" * bar_len + "-" * (32 - bar_len)
            diff_display = f"{val_float:.2f}" if is_average else str(int(val))
            self.aval_tree.insert("", tk.END, values=(f"Ronde {idx}", diff_display, f"{pct:.1f}%", bar_str))

    def _setup_weak_key_page(self, parent: ttk.Frame) -> None:
        """Bangun widget pengecekan kunci lemah dan pembuktian komplementasi."""
        frame = ttk.LabelFrame(parent, text="Pengecekan Kunci", padding=15)
        frame.pack(fill=tk.X, padx=10, pady=10)

        ttk.Label(frame, text="Kunci DES (16 Hex):").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.wk_key_var = tk.StringVar(value="0101010101010101")
        ttk.Entry(frame, textvariable=self.wk_key_var, width=28, font=("Consolas", 10)).grid(
            row=0, column=1, sticky=tk.W, padx=5, pady=5
        )

        btn_box = ttk.Frame(frame)
        btn_box.grid(row=0, column=2, padx=10, pady=5)
        ttk.Button(btn_box, text="Cek Status Kunci", command=self._do_check_weak_key).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_box, text="Uji Komplementasi", command=self._do_check_complementation).pack(side=tk.LEFT, padx=4)

        self.wk_result_var = tk.StringVar(value="Status: Belum diuji")
        ttk.Label(frame, textvariable=self.wk_result_var, font=("Consolas", 11, "bold")).grid(
            row=1, column=0, columnspan=3, sticky=tk.W, padx=5, pady=10
        )

        ref_frame = ttk.LabelFrame(parent, text="Referensi Weak & Semi-Weak Key Standar", padding=10)
        ref_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        ref_text = tk.Text(ref_frame, font=("Consolas", 9), height=14)
        ref_text.pack(fill=tk.BOTH, expand=True)
        ref_info = [
            "4 WEAK KEYS (Enkripsi dua kali menghasilkan teks semula: E(E(P, K), K) == P):",
            " - 0101010101010101",
            " - FEFEFEFEFEFEFEFE",
            " - E0E0E0E0F1F1F1F1",
            " - 1F1F1F1F0E0E0E0E\n",
            "12 SEMI-WEAK KEYS (6 Pasangan Kunci K1 dan K2: E(E(P, K1), K2) == P):",
            " - 01FE01FE01FE01FE <-> FE01FE01FE01FE01",
            " - 1FE01FE00EF10EF1 <-> E01FE01FF10EF10E",
            " - 01E001E001F101F1 <-> E001E001F101F101",
            " - 1FFE1FFE0EFE0EFE <-> FE1FFE1FFE0EFE0E",
            " - 011F011F010E010E <-> 1F011F010E010E01",
            " - E0FEE0FEF1FEF1FE <-> FEE0FEE0FEF1FEF1",
        ]
        ref_text.insert(tk.END, "\n".join(ref_info))
        ref_text.configure(state="disabled")

    def _do_check_weak_key(self) -> None:
        """Periksa apakah kunci yang dimasukkan adalah weak, semi-weak, atau normal."""
        try:
            key = hex_to_bytes(self.wk_key_var.get().strip())
            if key in WEAK_KEYS:
                self.wk_result_var.set("Status: WEAK KEY terdeteksi! (Subkey identik di setiap ronde)")
            elif key in SEMI_WEAK_KEYS:
                self.wk_result_var.set("Status: SEMI-WEAK KEY terdeteksi! (Hanya menghasilkan 2 subkey bergantian)")
            else:
                self.wk_result_var.set("Status: KUNCI NORMAL (Bukan weak/semi-weak key)")
        except Exception as err:
            messagebox.showerror("Kesalahan Kunci", str(err))

    def _do_check_complementation(self) -> None:
        """Uji apakah properti komplementasi E(~P, ~K) == ~E(P, K) terpenuhi."""
        try:
            key = hex_to_bytes(self.wk_key_var.get().strip())
            pt = hex_to_bytes("0123456789ABCDEF")
            success = check_complementation(pt, key)
            if success:
                self.wk_result_var.set("Status: PROPERTI KOMPLEMENTASI TERPENUHI! E(~P, ~K) == ~E(P, K)")
            else:
                self.wk_result_var.set("Status: Komplementasi gagal.")
        except Exception as err:
            messagebox.showerror("Kesalahan Kunci", str(err))

    def _setup_bruteforce_page(self, parent: ttk.Frame) -> None:
        """Bangun widget demonstrasi pemecahan kunci kecil dan estimasi 2^56."""
        ctrl_frame = ttk.LabelFrame(parent, text="Parameter Simulasi Brute Force", padding=10)
        ctrl_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Label(ctrl_frame, text="Plaintext (16 Hex):").grid(row=0, column=0, sticky=tk.W, padx=5, pady=4)
        self.bf_pt_var = tk.StringVar(value="0123456789ABCDEF")
        ttk.Entry(ctrl_frame, textvariable=self.bf_pt_var, width=22, font=("Consolas", 10)).grid(
            row=0, column=1, sticky=tk.W, padx=5, pady=4
        )

        ttk.Label(ctrl_frame, text="Kunci Target Asli (16 Hex):").grid(row=0, column=2, sticky=tk.W, padx=5, pady=4)
        self.bf_target_key_var = tk.StringVar(value="133457799BBCD000")
        ttk.Entry(ctrl_frame, textvariable=self.bf_target_key_var, width=22, font=("Consolas", 10)).grid(
            row=0, column=3, sticky=tk.W, padx=5, pady=4
        )

        ttk.Label(ctrl_frame, text="Unknown Bits (Kunci Tereduksi):").grid(row=1, column=0, sticky=tk.W, padx=5, pady=4)
        self.bf_bits_combo = ttk.Combobox(ctrl_frame, values=["8 bit (256)", "12 bit (4,096)", "16 bit (65,536)", "20 bit (1,048,576)"], state="readonly", width=18)
        self.bf_bits_combo.set("12 bit (4,096)")
        self.bf_bits_combo.grid(row=1, column=1, sticky=tk.W, padx=5, pady=4)

        ttk.Button(ctrl_frame, text="Mulai Demo Brute Force", command=self._do_bruteforce).grid(
            row=1, column=2, columnspan=2, sticky=tk.W, padx=5, pady=4
        )

        res_frame = ttk.LabelFrame(parent, text="Hasil Brute Force & Estimasi 2^56", padding=10)
        res_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.bf_res_text = tk.Text(res_frame, font=("Consolas", 10))
        self.bf_res_text.pack(fill=tk.BOTH, expand=True)

    def _do_bruteforce(self) -> None:
        """Eksekusi pencarian kunci tereduksi dan kalkulasi estimasi waktu 2^56 kunci."""
        try:
            pt = hex_to_bytes(self.bf_pt_var.get().strip())
            target_key = hex_to_bytes(self.bf_target_key_var.get().strip())
            ciphertext = encrypt_block(pt, target_key)
            bits_str = self.bf_bits_combo.get().split()[0]
            unknown_bits = int(bits_str)

            self.bf_res_text.delete("1.0", tk.END)
            self.bf_res_text.insert(tk.END, f"Memulai brute force pada ruang 2^{unknown_bits} ({1 << unknown_bits:,} kemungkinan)...\n")
            self.update_idletasks()

            found_key, trials, elapsed = bruteforce_reduced_key(pt, ciphertext, target_key, unknown_bits)
            speed = trials / elapsed if elapsed > 0 else 0
            full_years = estimate_full_bruteforce(speed)

            output = [
                f"\nPlaintext Target       : {bytes_to_hex(pt)}",
                f"Ciphertext Target      : {bytes_to_hex(ciphertext)}",
                f"Kunci Ditemukan        : {bytes_to_hex(found_key) if found_key else 'TIDAK DITEMUKAN'}",
                f"Kunci Sebenarnya       : {bytes_to_hex(target_key)}",
                f"Jumlah Percobaan       : {trials:,} kunci",
                f"Waktu Eksekusi         : {elapsed:.4f} detik",
                f"Kecepatan Pencarian    : {speed:,.1f} kunci / detik",
                "-" * 60,
                f"ESTIMASI WAKTU BRUTE FORCE 2^56 KUNCI (DES LENGKAP):",
                f"Total kombinasi kunci  : 72,057,594,037,927,936 kunci",
                f"Waktu yang dibutuhkan  : {full_years:,.2f} TAHUN (dengan kecepatan core tunggal ini)",
                "-" * 60,
                "Kesimpulan: DES tidak aman terhadap brute force modern oleh supercomputer/ASIC cluster,",
                "namun ruang 2^56 tetap tidak realistis untuk dipecahkan secara serial di laptop standar.",
            ]
            self.bf_res_text.insert(tk.END, "\n".join(output))
        except Exception as err:
            messagebox.showerror("Kesalahan Brute Force", str(err))


def main() -> None:
    """Fungsi pembuka untuk memulai siklus event loop aplikasi Tkinter."""
    app = DesApp()
    app.mainloop()


if __name__ == "__main__":
    main()
