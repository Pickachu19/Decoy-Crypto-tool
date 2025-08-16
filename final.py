import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import os
import datetime
import random
import string
import base64
import secrets

# Color palette
COLORS = {
    "primary": "#4a6fa5",
    "secondary": "#166088",
    "accent": "#4fc3f7",
    "background": "#e8f4f8",
    "text": "#333333",
    "success": "#4caf50",
    "warning": "#ff9800",
    "error": "#f44336",
    "light": "#ffffff",
    "dark": "#212121",
    "highlight": "#ffeb3b"
}

# Generate or load Fernet key
KEY_FILE = "secret.key"
if not os.path.exists(KEY_FILE):
    with open(KEY_FILE, 'wb') as f:
        f.write(Fernet.generate_key())
with open(KEY_FILE, 'rb') as f:
    aes_key = f.read()
cipher_suite = Fernet(aes_key)

# Generate or load RSA keys
PRIVATE_KEY_FILE = "rsa_private.pem"
PUBLIC_KEY_FILE = "rsa_public.pem"
if not os.path.exists(PRIVATE_KEY_FILE):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    with open(PRIVATE_KEY_FILE, 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open(PUBLIC_KEY_FILE, 'wb') as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
with open(PRIVATE_KEY_FILE, 'rb') as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)
with open(PUBLIC_KEY_FILE, 'rb') as f:
    public_key = serialization.load_pem_public_key(f.read())

def generate_encrypted_looking_data(method, length=None):
    """Generate random data that looks like encrypted text"""
    if method == "AES":
        # AES encrypted text is base64 encoded with Fernet format
        random_bytes = secrets.token_bytes(length if length else random.randint(50, 200))
        return base64.urlsafe_b64encode(random_bytes).decode('utf-8')
    elif method == "RSA":
        # RSA encrypted text is hex encoded
        random_length = length if length else random.randint(100, 500)
        return ''.join(secrets.choice('0123456789abcdef') for _ in range(random_length))

def generate_decoy(method, original_length=None):
    """Generate a decoy that looks like encrypted text"""
    return generate_encrypted_looking_data(method, original_length)

def encrypt_text(text, method):
    if method == "AES":
        return cipher_suite.encrypt(text.encode()).decode()
    elif method == "RSA":
        ciphertext = public_key.encrypt(text.encode(), padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        return ciphertext.hex()

def decrypt_text(cipher, method):
    if method == "AES":
        return cipher_suite.decrypt(cipher.encode()).decode()
    elif method == "RSA":
        decrypted = private_key.decrypt(bytes.fromhex(cipher), padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        return decrypted.decode()

def save_log(original, encrypted, decoys):
    with open("crypto_log.txt", "a") as log:
        log.write(f"[{datetime.datetime.now()}]\n")
        log.write(f"Original: {original}\nEncrypted: {encrypted}\n")
        for i, d in enumerate(decoys, 1):
            log.write(f"Decoy {i}: {d}\n")
        log.write("\n")

def export_to_file(label, content):
    file_path = filedialog.asksaveasfilename(title="Save File", defaultextension=".txt",
                                             filetypes=[("Text Files", "*.txt")])
    if file_path:
        with open(file_path, "w") as f:
            f.write(f"{label}\n{content}")
        messagebox.showinfo("Exported", f"{label} saved to {file_path}")

def create_gradient(canvas, width, height, color1, color2):
    """Create a vertical gradient background"""
    for i in range(height):
        ratio = i / height
        r = int(int(color1[1:3], 16) * (1 - ratio) + int(color2[1:3], 16) * ratio)
        g = int(int(color1[3:5], 16) * (1 - ratio) + int(color2[3:5], 16) * ratio)
        b = int(int(color1[5:7], 16) * (1 - ratio) + int(color2[5:7], 16) * ratio)
        color = f"#{r:02x}{g:02x}{b:02x}"
        canvas.create_line(0, i, width, i, fill=color)

def main_app():
    app = tk.Tk()
    app.title("Decoy-Based Cryptography")
    app.geometry("900x750")
    app.configure(bg=COLORS['background'])

    # Create a gradient background
    canvas = tk.Canvas(app, width=900, height=750)
    canvas.pack(fill="both", expand=True)
    create_gradient(canvas, 900, 750, COLORS['secondary'], COLORS['background'])

    # Main container frame
    main_frame = tk.Frame(canvas, bg=COLORS['light'], bd=2, relief=tk.RAISED)
    main_frame.place(relx=0.5, rely=0.5, anchor="center", width=850, height=700)

    # Configure styles
    style = ttk.Style()
    style.theme_use('clam')
    
    # Button style
    style.configure('TButton', 
                   font=('Helvetica', 10, 'bold'),
                   padding=8,
                   foreground=COLORS['light'],
                   background=COLORS['primary'],
                   bordercolor=COLORS['secondary'],
                   lightcolor=COLORS['accent'],
                   darkcolor=COLORS['secondary'])
    style.map('TButton',
              background=[('active', COLORS['secondary']), ('pressed', COLORS['dark'])],
              foreground=[('active', COLORS['light']), ('pressed', COLORS['light'])])

    # Label style
    style.configure('TLabel', 
                   font=('Helvetica', 10),
                   background=COLORS['light'],
                   foreground=COLORS['text'],
                   padding=5)

    # Combobox style
    style.configure('TCombobox',
                   fieldbackground=COLORS['light'],
                   background=COLORS['light'],
                   foreground=COLORS['text'],
                   selectbackground=COLORS['accent'])

    # Header with gradient
    header = tk.Frame(main_frame, bg=COLORS['primary'], height=60)
    header.pack(fill=tk.X)
    header_label = tk.Label(header, 
                          text="Decoy-Based Cryptography System", 
                          font=("Helvetica", 16, "bold"), 
                          bg=COLORS['primary'],
                          fg=COLORS['light'])
    header_label.pack(pady=15)

    # Content area
    content_frame = tk.Frame(main_frame, bg=COLORS['light'])
    content_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    # Input section
    input_frame = tk.Frame(content_frame, bg=COLORS['light'])
    input_frame.pack(fill=tk.X, pady=(0, 10))
    
    tk.Label(input_frame, 
            text="Enter your message:", 
            font=("Helvetica", 10, "bold"),
            bg=COLORS['light'],
            fg=COLORS['secondary']).pack(anchor='w', pady=(0, 5))
    
    input_entry = tk.Text(input_frame, 
                         height=5, 
                         font=("Helvetica", 10),
                         bg=COLORS['light'],
                         fg=COLORS['text'],
                         insertbackground=COLORS['text'],
                         selectbackground=COLORS['accent'],
                         wrap=tk.WORD,
                         padx=5,
                         pady=5,
                         relief=tk.SOLID,
                         bd=1)
    input_entry.pack(fill=tk.X)

    # Options frame
    options_frame = tk.Frame(content_frame, bg=COLORS['light'])
    options_frame.pack(fill=tk.X, pady=5)
    
    # Number of decoys
    num_frame = tk.Frame(options_frame, bg=COLORS['light'])
    num_frame.pack(side=tk.LEFT, padx=5)
    tk.Label(num_frame, 
            text="Number of decoys:", 
            bg=COLORS['light'],
            fg=COLORS['text']).pack(anchor='w')
    num_entry = ttk.Entry(num_frame)
    num_entry.insert(0, "1")
    num_entry.pack()

    # Encryption method
    method_frame = tk.Frame(options_frame, bg=COLORS['light'])
    method_frame.pack(side=tk.RIGHT, padx=5)
    tk.Label(method_frame, 
            text="Encryption Method:", 
            bg=COLORS['light'],
            fg=COLORS['text']).pack(anchor='w')
    method_var = tk.StringVar(value="AES")
    method_combo = ttk.Combobox(method_frame, 
                              textvariable=method_var, 
                              values=["AES", "RSA"], 
                              state="readonly",
                              width=10)
    method_combo.pack()

    # Results section
    results_frame = tk.Frame(content_frame, bg=COLORS['light'])
    results_frame.pack(fill=tk.BOTH, expand=True, pady=(10, 0))

    # Encrypted output
    result_frame = tk.Frame(results_frame, bg=COLORS['light'])
    result_frame.pack(fill=tk.X, pady=(0, 10))
    
    tk.Label(result_frame, 
            text="Encrypted Output:", 
            font=("Helvetica", 10, "bold"),
            bg=COLORS['light'],
            fg=COLORS['secondary']).pack(anchor='w')
    
    result_var = tk.StringVar()
    result_output = tk.Label(result_frame, 
                           textvariable=result_var, 
                           wraplength=700, 
                           bg=COLORS['light'],
                           fg=COLORS['dark'],
                           relief=tk.SUNKEN, 
                           font=("Courier", 9),
                           padx=5,
                           pady=5,
                           anchor='w',
                           justify=tk.LEFT)
    result_output.pack(fill=tk.X)

    # Decoys output
    decoy_frame = tk.Frame(results_frame, bg=COLORS['light'])
    decoy_frame.pack(fill=tk.BOTH, expand=True)
    
    tk.Label(decoy_frame, 
            text="Generated Decoys:", 
            font=("Helvetica", 10, "bold"),
            bg=COLORS['light'],
            fg=COLORS['secondary']).pack(anchor='w')
    
    decoy_text = tk.Text(decoy_frame, 
                        height=10, 
                        wrap='word', 
                        bg=COLORS['light'],
                        fg=COLORS['dark'],
                        font=("Courier", 9),
                        padx=5,
                        pady=5,
                        relief=tk.SUNKEN,
                        insertbackground=COLORS['text'],
                        selectbackground=COLORS['accent'])
    decoy_text.pack(fill=tk.BOTH, expand=True)

    # Button frame
    button_frame = tk.Frame(content_frame, bg=COLORS['light'])
    button_frame.pack(fill=tk.X, pady=(10, 0))

    def process():
        plain_text = input_entry.get("1.0", tk.END).strip()
        method = method_var.get()
        try:
            num = int(num_entry.get())
        except ValueError:
            messagebox.showerror("Error", "Enter a valid number of decoys")
            return
        if not plain_text:
            messagebox.showwarning("Input Needed", "Please enter some text to encrypt.")
            return
        
        # Encrypt the original message
        encrypted = encrypt_text(plain_text, method)
        result_var.set(encrypted)
        
        # Generate decoys that look like encrypted text
        decoys = [generate_decoy(method, len(encrypted)) for _ in range(num)]
        
        # Display decoys
        decoy_text.config(state=tk.NORMAL)
        decoy_text.delete("1.0", tk.END)
        for i, d in enumerate(decoys, 1):
            decoy_text.insert(tk.END, f"Decoy {i}: {d}\n")
        decoy_text.config(state=tk.DISABLED)
        
        # Save to log
        save_log(plain_text, encrypted, decoys)

    def decrypt_popup():
        def do_decrypt():
            try:
                method = method_var.get()
                decrypted = decrypt_text(entry.get(), method)
                messagebox.showinfo("Decrypted Message", decrypted)
            except Exception as e:
                messagebox.showerror("Error", str(e))

        popup = tk.Toplevel()
        popup.title("Decrypt Message")
        popup.geometry("400x200")
        popup.configure(bg=COLORS['light'])
        
        tk.Label(popup, 
                text="Enter Encrypted Text:", 
                bg=COLORS['light'],
                fg=COLORS['text']).pack(pady=5)
        
        entry = ttk.Entry(popup, width=50)
        entry.pack(pady=5)
        
        btn_frame = tk.Frame(popup, bg=COLORS['light'])
        btn_frame.pack(pady=10)
        
        ttk.Button(btn_frame, text="Decrypt", command=do_decrypt).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Cancel", command=popup.destroy).pack(side=tk.LEFT, padx=5)

    # Buttons
    ttk.Button(button_frame, text="🔒 Encrypt + Generate Decoys", command=process).pack(side=tk.LEFT, padx=5)
    ttk.Button(button_frame, text="🔓 Decrypt Message", command=decrypt_popup).pack(side=tk.LEFT, padx=5)
    ttk.Button(button_frame, text="💾 Export Encrypted", command=lambda: export_to_file("Encrypted Text", result_var.get())).pack(side=tk.LEFT, padx=5)
    ttk.Button(button_frame, text="📁 Export Decoys", command=lambda: export_to_file("Decoy Text", decoy_text.get("1.0", tk.END))).pack(side=tk.LEFT, padx=5)

    app.mainloop()

def show_login():
    login = tk.Tk()
    login.title("Login")
    login.geometry("350x250")
    login.configure(bg=COLORS['background'])
    
    # Gradient background
    canvas = tk.Canvas(login, width=350, height=250)
    canvas.pack(fill="both", expand=True)
    create_gradient(canvas, 350, 250, COLORS['primary'], COLORS['background'])
    
    # Login frame
    login_frame = tk.Frame(canvas, bg=COLORS['light'], bd=2, relief=tk.RAISED, padx=20, pady=20)
    login_frame.place(relx=0.5, rely=0.5, anchor="center")
    
    tk.Label(login_frame, 
            text="Welcome to Crypto System", 
            font=("Helvetica", 14, "bold"), 
            bg=COLORS['light'],
            fg=COLORS['primary']).pack(pady=(0, 20))
    
    tk.Label(login_frame, 
            text="Username", 
            bg=COLORS['light'],
            fg=COLORS['text']).pack(anchor='w')
    user_entry = ttk.Entry(login_frame)
    user_entry.pack(pady=5, fill=tk.X)

    tk.Label(login_frame, 
            text="Password", 
            bg=COLORS['light'],
            fg=COLORS['text']).pack(anchor='w', pady=(10, 0))
    pass_entry = ttk.Entry(login_frame, show="*")
    pass_entry.pack(pady=5, fill=tk.X)

    def check_login():
        user = user_entry.get()
        pwd = pass_entry.get()
        if user == "admin" and pwd == "1234":
            login.destroy()
            main_app()
        else:
            messagebox.showerror("Login Failed", "Invalid username or password")

    btn_frame = tk.Frame(login_frame, bg=COLORS['light'])
    btn_frame.pack(pady=(15, 0))
    
    ttk.Button(btn_frame, text="Login", command=check_login).pack(side=tk.LEFT, padx=5)
    ttk.Button(btn_frame, text="Exit", command=login.destroy).pack(side=tk.LEFT, padx=5)

    login.mainloop()

show_login()