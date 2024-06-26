import tkinter as tk
from tkinter import messagebox
from GUI.MainWindow import MainWindow

class LoginWindow(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title('Authentification')
        self.geometry('400x250')
        self.configure(bg='#b0e0e6')

        self.username_label = tk.Label(self, text="Nom d'utilisateur :", bg='#b0e0e6', font=('Helvetica', 12))
        self.username_entry = tk.Entry(self, font=('Helvetica', 12))
        
        self.password_label = tk.Label(self, text="Mot de passe :", bg='#b0e0e6', font=('Helvetica', 12))
        self.password_entry = tk.Entry(self, show="*", font=('Helvetica', 12))
        
        self.login_button = tk.Button(self, text="Connexion", command=self.check_credentials, bg='#4682b4', fg='white', font=('Helvetica', 12, 'bold'))

        self.username_label.pack(pady=10)
        self.username_entry.pack(pady=5)
        self.password_label.pack(pady=10)
        self.password_entry.pack(pady=5)
        self.login_button.pack(pady=20)

    def check_credentials(self):
        entered_username = self.username_entry.get()
        entered_password = self.password_entry.get()

        if entered_username == "admin" and entered_password == "admin":
            messagebox.showinfo('Succès', 'Bienvenue admin!')
            self.withdraw()
            self.main_window = MainWindow(self)
            self.main_window.mainloop()
        else:
            messagebox.showerror('Erreur', 'Nom d\'utilisateur ou mot de passe incorrect.')

if __name__ == '__main__':
    login_window = LoginWindow()
    login_window.mainloop()
