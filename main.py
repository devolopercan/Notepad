from tkinter import *
from tkinter import messagebox
import base64

#apply cryptography with vigenere ciphher
#https://stackoverflow.com/a/38223403

def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)

#save notes
def save_and_encrypt_notes():
    title = title_entry.get()
    message = input_text.get("1.0",END)
    master_secret = master_secret_input.get()

    if len(title) == 0 or len(message) == 0 or len(master_secret) == 0:
            messagebox.showinfo(title="Error!", message="Please enter all information.")
    else:
        message_encrypted = encode(master_secret, message)

        try:
            with open("mysecret.txt", "a") as data_file:
                data_file.write(f'\n{title}\n{message_encrypted}')
        except FileNotFoundError:
            with open("mysecret.txt", "w") as data_file:
                data_file.write(f'\n{title}\n{message_encrypted}')
        finally:
            title_entry.delete(0, END)
            master_secret_input.delete(0, END)
            input_text.delete("1.0",END)

#decrypt notes

def decrypt_notes():
    message_encrypted = input_text.get("1.0", END)
    master_secret = master_secret_input.get()

    if len(message_encrypted) == 0 or len(master_secret) == 0:
        messagebox.showinfo(title="Error!", message="Please enter all information.")
    else:
        try:
            decrypted_message = decode(master_secret,message_encrypted)
            input_text.delete("1.0", END)
            input_text.insert("1.0", decrypted_message)
        except:
            messagebox.showinfo(title="Error!", message="Please make sure of encrypted info.")

# Button hover effects
def on_enter_save(event):
    save_button.config(bg="#5cb85c")

def on_leave_save(event):
    save_button.config(bg="#4CAF50")

def on_enter_decrypt(event):
    decrypt_button.config(bg="#FF5733")

def on_leave_decrypt(event):
    decrypt_button.config(bg="#FF5733")

#UI

window = Tk()
window.title("Secret Notes")
window.config(padx=30, pady=30, bg="#f0f0f0")

canvas = Canvas(height=150, width=150, bg="#f0f0f0", highlightthickness=0)
logo = PhotoImage(file="topsecret.png")
canvas.create_image(75,75,image=logo)
canvas.pack()

title_info_label = Label(text="Enter your title",font=("Verdana",14), bg="#f0f0f0")
title_info_label.pack()

title_entry = Entry(width=30)
title_entry.pack()

input_info_label = Label(text="Enter your secret",font=("Verdana",14), bg="#f0f0f0")
input_info_label.pack()

input_text = Text(width=50, height=25)
input_text.pack()

master_secret_label = Label(text="Enter master key",font=("Verdana",14), bg="#f0f0f0")
master_secret_label.pack()

master_secret_input = Entry(width=30)
master_secret_input.pack()

save_button = Button(text="Save & Encrypt", command=save_and_encrypt_notes, bg="#4CAF50", fg="white", bd=0, padx=10, pady=5, font=("Arial", 12, "bold"))
save_button.pack(pady=10)
save_button.bind("<Enter>", on_enter_save)
save_button.bind("<Leave>", on_leave_save)

decrypt_button = Button(text="Decrypt",command=decrypt_notes, bg="#FF5733", fg="white", bd=0, padx=10, pady=5, font=("Arial", 12, "bold"))
decrypt_button.pack()
decrypt_button.bind("<Enter>", on_enter_decrypt)
decrypt_button.bind("<Leave>", on_leave_decrypt)

window.mainloop()
