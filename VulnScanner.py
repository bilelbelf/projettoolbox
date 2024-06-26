import tkinter as tk
import threading
from scanners.VulnChecker import scan_vulns

class VulnScanner(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Scan de Vulnérabilité")
        self.geometry('400x300')

        self.label_target = tk.Label(self, text="Rentrez votre IP pour le scan :", font=('Helvetica', 12))
        self.label_target.pack(pady=5)
        self.entry_target = tk.Entry(self, font=('Helvetica', 12))
        self.entry_target.pack(pady=5)
        
        self.label_port_range = tk.Label(self, text="Rentrez la plage de ports (ex: 1-1024) :", font=('Helvetica', 12))
        self.label_port_range.pack(pady=5)
        self.entry_port_range = tk.Entry(self, font=('Helvetica', 12))
        self.entry_port_range.pack(pady=5)

        self.text_results = tk.Text(self, height=10, width=50)
        self.text_results.pack(pady=5)

        self.btn_start_scan = tk.Button(self, text="Démarrer le Scan", command=self.start_vuln_scan, bg='#4682b4', fg='white', font=('Helvetica', 12, 'bold'))
        self.btn_start_scan.pack(pady=5)

    def start_vuln_scan(self):
        target = self.entry_target.get()
        port_range = self.entry_port_range.get()
        if not target or not port_range:
            tk.messagebox.showerror("Erreur", "Veuillez entrer une IP et une plage de ports.")
            return

        def scan_vulns_thread():
            results = scan_vulns(target, port_range, "C:\\Program Files (x86)\\Nmap")
            self.text_results.delete(1.0, tk.END)
            if not results:
                self.text_results.insert(tk.END, "Aucun résultat. Vérifiez l'API ou l'IP.")
                return
            for res in results:
                self.text_results.insert(tk.END, f"{res[0]}:{res[1]} ({res[2]})\n")
                for vuln in res[3
