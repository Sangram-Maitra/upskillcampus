from cProfile import label
from email.mime import image
import sqlite3
import hashlib
from tkinter import *
import tkinter as tk
from tkinter import simpledialog
from functools import partial
from tkinter import font
import uuid
import pyperclip
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import random
import string
from PIL import ImageTk, Image
from tkinter import ttk
import tkinter

backend = default_backend()
salt = b'2444'


# I have to put the kdf into a function as the generation of the key could be needed multiple times
# if declare once then one time declaration can not generate twice
def keyGenerate(password):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=10,
        backend=backend
    )
    return base64.urlsafe_b64encode(kdf.derive(password.get().encode()))


def keyGenerateMigration(password):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=10,
        backend=backend
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


encryptionKey = 0


def encrypt(message: bytes, key: bytes) -> bytes:
    return Fernet(key).encrypt(message)


def decrypt(message: bytes, token: bytes) -> bytes:
    return Fernet(token).decrypt(message)


# database code
with sqlite3.connect('password_vault.db') as db:
    cursor = db.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS masterpassword(
id INTEGER PRIMARY KEY,
password TEXT NOT NULL,
recoveryKey TEXT NOT NULL,
backupkey TEXT NOT NULL);
""")


cursor.execute('''CREATE TABLE IF NOT EXISTS vault(
    id INTEGER PRIMARY KEY,
    website TEXT NOT NULL,
    userid TEXT NOT NULL,
    username TEXT NOT NULL,
    password TEXT NOT NULL);''')


# Create PopUp
def popUp(text):
    answer = simpledialog.askstring("input string", text)
    return answer


# Initiate window
window = Tk()
window.update()

window.title("Password Vault")

custom_font = ("Consolas", 10)
dataMigration = False


def hashPassword(input):
    hash1 = hashlib.sha256(input)
    hash1 = hash1.hexdigest()
    return hash1


def firstTimeScreen():
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry('600x400')
    # Add image file
    bg = PhotoImage(file="img/Register.png")

    # Show image using label
    label1 = Label(window, image=bg)
    label1.place(x=0, y=0, width=600, height=400)

    lbl = ttk.Label(window, text="Choose a Master Password", font=custom_font)
    lbl.config(anchor=CENTER)
    lbl.place(x=350, y=178)

    txt = ttk.Entry(window, width=20, show="*", font=custom_font)
    txt.place(x=365, y=200)
    txt.focus()

    lbl1 = ttk.Label(window, text="Re-enter password", font=custom_font)
    lbl1.config(anchor=CENTER)
    lbl1.place(x=378, y=230)

    txt1 = ttk.Entry(window, width=20, show="*", font=custom_font)
    txt1.place(x=365, y=254)

    def savePassword():
        if txt.get() == txt1.get():
            hashedPassword = hashPassword(txt.get().encode('utf-8'))
            # hashedPassword = txt.get().encode('utf-8')
            backupKey = txt.get().encode('utf-8')
            key = str(uuid.uuid4().hex)
            recoveryKey = hashPassword(key.encode('utf-8'))
            # recoveryKey = key.encode('utf-8')
            global encryptionKey
            encryptionKey = keyGenerate(txt)

            # data migration
            if dataMigration:
                cursor.execute("Select * from masterpassword")
                oldKey = cursor.fetchone()
                # print("The old key is:", oldKey[3].decode('utf-8'))

                oldEncryptKey = keyGenerateMigration(oldKey[3].decode('utf-8'))
                # Data Migration
                cursor.execute('SELECT * FROM vault')
                records = cursor.fetchall()
                for record in records:
                    # Decrypt the data using the old encryption key
                    old_website = decrypt(record[1], oldEncryptKey)
                    old_userid = decrypt(record[2], oldEncryptKey)
                    old_username = decrypt(record[3], oldEncryptKey)
                    old_password = decrypt(record[4], oldEncryptKey)

                    # Encrypt the data using the new encryption key
                    new_website = encrypt(old_website, encryptionKey)
                    new_userid = encrypt(old_userid, encryptionKey)
                    new_username = encrypt(
                        old_username, encryptionKey)
                    new_password = encrypt(
                        old_password, encryptionKey)

                    # Update the record with the re-encrypted data
                    cursor.execute('UPDATE vault SET website=?, userid=?, username=?, password=? WHERE id=?',
                                   (new_website, new_userid, new_username, new_password, record[0]))
                    db.commit()
            # data Migration

            sql = "DELETE FROM masterpassword WHERE id = 1"
            cursor.execute(sql)
            insert_password = """INSERT INTO masterpassword(password, recoveryKey,backupkey)
            VALUES(?, ?,?) """
            cursor.execute(insert_password, ((hashedPassword),
                           (recoveryKey), (backupKey)))
            db.commit()

            recoveryScreen(key)
        else:
            lbl.config(text="Passwords dont match")

    btn = ttk.Button(window, text="Save", command=savePassword)
    btn.place(x=400, y=280)
    window.mainloop()


def recoveryScreen(key):
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry('400x400')

    # Add image file
    bg = PhotoImage(file="img/tik.png")

    # Show image using label
    label1 = Label(window, image=bg)
    label1.place(x=0, y=0, width=400, height=400)
    lbl = ttk.Label(
        window, text="Save this key to be able to recover account", font=custom_font)
    lbl.config(anchor=CENTER)
    lbl.place(x=50, y=240)

    lbl1 = ttk.Label(window, text=key)
    lbl1.config(anchor=CENTER)
    lbl1.place(x=85, y=270)

    def copyKey():
        pyperclip.copy(lbl1.cget("text"))

    btn = ttk.Button(window, text="Copy Key", command=copyKey)
    btn.place(x=150, y=300)

    def done():
        vaultScreen()

    btn = ttk.Button(window, text="Done", command=done)
    btn.place(x=150, y=330)

    window.mainloop()


def resetScreen():
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry('250x125')
    lbl = ttk.Label(window, text="Enter Recovery Key")
    lbl.config(anchor=CENTER)
    lbl.pack()

    txt = ttk.Entry(window, width=20)
    txt.pack()
    txt.focus()

    lbl1 = ttk.Label(window)
    lbl1.config(anchor=CENTER)
    lbl1.pack()

    def getRecoveryKey():
        recoveryKeyCheck = hashPassword(str(txt.get()).encode('utf-8'))
        # recoveryKeyCheck = str(txt.get()).encode('utf-8')
        cursor.execute(
            'SELECT * FROM masterpassword WHERE id = 1 AND recoveryKey = ?', [(recoveryKeyCheck)])
        return cursor.fetchall()

    def checkRecoveryKey():
        checked = getRecoveryKey()

        if checked:
            global dataMigration
            dataMigration = True
            firstTimeScreen()
        else:
            txt.delete(0, 'end')
            lbl1.config(text='Wrong Key')

    btn = ttk.Button(window, text="Check Key", command=checkRecoveryKey)
    btn.pack(pady=5)


# the login Part is completely done and customized for the best user interface
def loginScreen():
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry("600x400")

    # Add image file
    bg = PhotoImage(file="img/login_img.png")

    # Show image using label
    label1 = Label(window, image=bg)
    label1.place(x=0, y=0, width=600, height=400)

    lbl = ttk.Label(window, text="Enter  Master Password", font=custom_font)
    lbl.config(anchor=CENTER)
    lbl.place(x=100, y=200)

    txt = ttk.Entry(window, width=20, show="*", font=custom_font)
    txt.place(x=100, y=225)
    txt.focus()

    lbl1 = ttk.Label(window, font=custom_font)
    lbl1.config(anchor=CENTER)
    lbl1.place(x=100, y=170)

    def getMasterPassword():
        checkHashedPassword = hashPassword(txt.get().encode('utf-8'))
        # checkHashedPassword = txt.get().encode('utf-8')
        global encryptionKey
        encryptionKey = keyGenerate(txt)
        cursor.execute(
            'SELECT * FROM masterpassword WHERE id = 1 AND password = ?', [(checkHashedPassword)])
        return cursor.fetchall()

    def checkPassword():
        password = getMasterPassword()

        if password:
            vaultScreen()
        else:
            txt.delete(0, 'end')
            lbl1.config(text="Wrong Password")

    def resetPassword():
        resetScreen()

    btn = ttk.Button(window, text="Submit", command=checkPassword)
    btn.place(x=130, y=260)

    btn = ttk.Button(window, text="Reset Password", command=resetPassword)
    btn.place(x=121, y=300)
    window.mainloop()

####################################


def vaultScreen():
    for widget in window.winfo_children():
        widget.destroy()

    # Add image file
    bg = PhotoImage(file="img/vaultScreen.png")

    # Show image using label
    label1 = Label(window, image=bg)
    label1.place(x=0, y=0, width=900, height=550)

    # Input Window ###################################

    def popUpWindow():

        def addEntry(websiteEntry, idEntry, nameEntry, passwordEntry):
            def hide_label():
                lbl4.config(text="")

            def show_label(textData):
                lbl4.config(text=textData)
                # Hide the label again after 5000 milliseconds (2 seconds)
                lbl4.after(2000, hide_label)

            if websiteEntry.get() == "" or idEntry.get() == "" or nameEntry.get() == "" or passwordEntry.get() == "":
                # lbl4 = ttk.Label(inputWindow, text="Some Data is missing")
                show_label("Some Data Is missing")
                lbl4.pack(side=TOP)
            else:
                input0 = websiteEntry.get()
                input1 = idEntry.get()
                input2 = nameEntry.get()
                input3 = passwordEntry.get()
                inputWindow.destroy()

                website = encrypt(input0.encode(), encryptionKey)
                userid = encrypt(input1.encode(), encryptionKey)
                username = encrypt(input2.encode(), encryptionKey)
                password = encrypt(input3.encode(), encryptionKey)

                insert_fields = '''INSERT INTO vault(website,userid,username,password)VALUES(?,?,?,?)'''

                cursor.execute(
                    insert_fields, (website, userid, username, password))
                db.commit()

                vaultScreen()

        inputWindow = tkinter.Tk()
        inputWindow.title("Input Window")

        inputWindow.geometry('600x400')

        lbl = ttk.Label(inputWindow, text="website")
        lbl.config(anchor=CENTER)
        lbl.pack()

        websiteEntry = ttk.Entry(inputWindow, width=20)  # show="*"
        websiteEntry.pack()
        websiteEntry.focus()

        lbl1 = ttk.Label(inputWindow, text="User Id")
        lbl1.config(anchor=CENTER)
        lbl1.pack(side=TOP)

        idEntry = ttk.Entry(inputWindow, width=20)  # show="*"
        idEntry.pack()
        idEntry.focus()

        lbl2 = ttk.Label(inputWindow, text="User Name")
        lbl2.config(anchor=CENTER)
        lbl2.pack(side=TOP)

        nameEntry = ttk.Entry(inputWindow, width=20)  # show="*"
        nameEntry.pack()
        nameEntry.focus()

        lbl3 = ttk.Label(inputWindow, text="PassWord")
        lbl3.config(anchor=CENTER)
        lbl3.pack(side=TOP)

        passwordEntry = ttk.Entry(inputWindow, width=20)  # show="*"
        passwordEntry.pack()
        passwordEntry.focus()

        lbl4 = ttk.Label(inputWindow)
        lbl4.pack(side=TOP)

        btn = ttk.Button(inputWindow, text="submit", command=lambda: addEntry(
            websiteEntry, idEntry, nameEntry, passwordEntry))
        btn.pack(pady=10)

# generate password #######################
        def generate_random_password(length=8, include_symbols=True):
            # Define the characters that can be used to generate the password
            characters = string.ascii_letters + string.digits
            if include_symbols:
                characters += string.punctuation
                include_symbols = False

            # Generate a random password of specified length using the defined characters
            password = ''.join(random.choice(characters)
                               for _ in range(length))

            # Return the generated password
            return password

        def generatePass(passwordEntry):
            passwordEntry.delete(0, tk.END)
            passwordEntry.insert(0, generate_random_password())
            # print("abcPass")

        btn2 = ttk.Button(inputWindow, text="Generate Password",
                          command=lambda: generatePass(passwordEntry))
        btn2.pack(pady=5)

    def removeEntry(input):
        cursor.execute("DELETE FROM vault WHERE id = ?", (input,))
        db.commit()
        vaultScreen()

    def updateEntry(input):
        def addEntry(websiteEntry, idEntry, nameEntry, passwordEntry):

            def hide_label():
                lbl4.config(text="")

            def show_label(textData):
                lbl4.config(text=textData)
                # Hide the label again after 5000 milliseconds (2 seconds)
                lbl4.after(2000, hide_label)

            if websiteEntry.get() == "" or idEntry.get() == "" or nameEntry.get() == "" or passwordEntry.get() == "":
                # lbl4 = ttk.Label(inputWindow, text="Some Data is missing")
                show_label("Some Data Is missing")
                lbl4.pack()
            else:
                input0 = websiteEntry.get()
                input1 = idEntry.get()
                input2 = nameEntry.get()
                input3 = passwordEntry.get()
                inputWindow.destroy()

                website = encrypt(input0.encode(), encryptionKey)
                userid = encrypt(input1.encode(), encryptionKey)
                username = encrypt(input2.encode(), encryptionKey)
                password = encrypt(input3.encode(), encryptionKey)

                cursor.execute('''UPDATE vault
                        SET website = ?, userid = ?, username = ?, password = ?
                        WHERE id = ?;
                    ''', (website, userid, username, password, input))
                db.commit()
                vaultScreen()

        inputWindow = Tk()
        inputWindow.title("Input Window")
        inputWindow.geometry('400x300')

        # for retriving the previous update results
        cursor.execute('SELECT * FROM vault where id=?', (input,))
        array = cursor.fetchall()
        # print(decrypt(array[0][1], encryptionKey))

        lbl = ttk.Label(inputWindow, text="website")
        lbl.config(anchor=CENTER)
        lbl.pack()

        websiteEntry = ttk.Entry(inputWindow, width=20)
        websiteEntry.insert(0, decrypt(array[0][1], encryptionKey))
        websiteEntry.pack()
        websiteEntry.focus()

        lbl1 = ttk.Label(inputWindow, text="User Id")
        lbl1.config(anchor=CENTER)
        lbl1.pack(side=TOP)

        idEntry = ttk.Entry(inputWindow, width=20)
        idEntry.insert(0, decrypt(array[0][2], encryptionKey))
        idEntry.pack()
        idEntry.focus()

        lbl2 = ttk.Label(inputWindow, text="User Name")
        lbl2.config(anchor=CENTER)
        lbl2.pack(side=TOP)

        nameEntry = ttk.Entry(inputWindow, width=20)
        nameEntry.insert(0, decrypt(array[0][3], encryptionKey))
        nameEntry.pack()
        nameEntry.focus()

        lbl3 = ttk.Label(inputWindow, text="PassWord")
        lbl3.config(anchor=CENTER)
        lbl3.pack(side=TOP)

        passwordEntry = ttk.Entry(inputWindow, width=20)
        passwordEntry.insert(0, decrypt(array[0][4], encryptionKey))
        passwordEntry.pack()
        passwordEntry.focus()

        lbl4 = ttk.Label(inputWindow, text="")
        lbl4.config(anchor=CENTER)
        lbl4.pack(side=TOP)

        btn = ttk.Button(inputWindow, text="submit", command=lambda: addEntry(
            websiteEntry, idEntry, nameEntry, passwordEntry))
        btn.pack(pady=10)

    window.geometry('900x550')
    window.resizable(height=None, width=None)
    # lbl = ttk.Label(window, text="Password Vault")
    # lbl.grid(column=1)

    btn = ttk.Button(window, text="+", command=popUpWindow)
    btn.grid(column=2, pady=(175, 20))

    bold_font = font.Font(family="Constantia", weight="bold")
    lbl = ttk.Label(window, text="Website", font=bold_font)
    lbl.grid(row=2, column=0, padx=50)
    lbl = ttk.Label(window, text="UserId", font=bold_font)
    lbl.grid(row=2, column=1, padx=50)
    lbl = ttk.Label(window, text="Username", font=bold_font)
    lbl.grid(row=2, column=2, padx=50)
    lbl = ttk.Label(window, text="Password", font=bold_font)
    lbl.grid(row=2, column=3, padx=50)
    lbl = ttk.Label(window, text="Operation", font=bold_font)
    lbl.grid(row=2, column=4, padx=50)
    ycord = 253
    cursor.execute('SELECT * FROM vault')
    if (cursor.fetchall() != None):
        i = 0
        while True:
            cursor.execute('SELECT * FROM vault')
            array = cursor.fetchall()

            if (len(array) == 0):
                break

            lbl1 = ttk.Label(window, text=(
                decrypt(array[i][1], encryptionKey)), font=("Helvetica", 12))
            lbl1.grid(column=0, row=(i+3))
            lbl2 = ttk.Label(window, text=(
                decrypt(array[i][2], encryptionKey)), font=("Helvetica", 12))
            lbl2.grid(column=1, row=(i+3))
            lbl3 = ttk.Label(window, text=(
                decrypt(array[i][3], encryptionKey)), font=("Helvetica", 12))
            lbl3.grid(column=2, row=(i+3))
            lbl4 = ttk.Label(window, text=(
                decrypt(array[i][4], encryptionKey)), font=("Helvetica", 12))
            lbl4.grid(column=3, row=(i+3))

            # delete button
            btn1 = ttk.Button(window, text="Delete",
                              command=partial(removeEntry, array[i][0]))
            btn1.grid(column=4, row=(i+3), pady=10)
            # print(array[i][0])
            # update ttk.Button
            btn2 = ttk.Button(window, text="Update",
                              command=partial(updateEntry, array[i][0]))
            # btn2.grid(column=5, row=(i+3))
            btn2.place(x=810, y=ycord)
            ycord += 45
            i = i + 1

            cursor.execute('SELECT * FROM vault')
            if (len(cursor.fetchall()) <= i):
                break

    window.mainloop()


cursor.execute('SELECT * FROM masterpassword')
if (cursor.fetchall()):
    loginScreen()
else:
    firstTimeScreen()
window.mainloop()
