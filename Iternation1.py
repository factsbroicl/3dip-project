import tkinter as tk
from tkinter import ttk
import json
from os import path
import bcrypt
from cryptography.fernet import Fernet
import copy

file_path = path.abspath(__file__)
dir_path = path.dirname(file_path)
data_path = path.join(dir_path, "data.json") #absolute filepath
login_path = path.join(dir_path, "login.json")

data = {} #Stores data
login = {}

class container(tk.Tk): #Container class for frames
    def __init__(self, *args, **kwargs):
        tk.Tk.__init__(self, *args, **kwargs)
        div = ttk.Frame(self)
        div.pack(side="top", fill="both", expand=True)
        div.grid_rowconfigure(0, weight=1)
        div.grid_columnconfigure(0, weight=1) #Creates frame for the programs

        self.frames = {}
        for F in (Login, Finance, Sign_up):
            page_name = F.__name__
            frame = F(parent=div, control=self)
            self.frames[page_name] = frame
            frame.grid(row=0, column=0, sticky="nsew") #Stores subsequent frames

        self.show("Login") #Shows first page
    
    def show(self, page): #Function to show frames
        frame = self.frames[page]
        self.refresh(page) #Updates the frame on change
        frame.tkraise()
    
    def refresh(self, page): #refresh page
        frame = self.frames[page]
        #WIP
        try:
            pass
        except:
            pass


class Login(tk.Frame): #Add page frame
    def __init__(self, parent, control):
        tk.Frame.__init__(self, parent) #Constructs frame from parent class
        self.control = control #Parent class call

        self.div_relative = ttk.LabelFrame(self, text="Login") #Adds a seperated Div
        self.div_relative.pack(fill="none", expand=True)

        self.username = ttk.Entry(self.div_relative)
        self.username.insert(0, "Username")
        self.username.bind("<FocusIn>", lambda e: self.username.delete('0', 'end'))
        self.username.grid(row=0, column=0, padx=5, pady=(0, 5), sticky="ew")

        self.password = ttk.Entry(self.div_relative)
        self.password.insert(0, "Password")
        self.password.bind("<FocusIn>", lambda e: self.password.delete('0', 'end'))
        self.password.grid(row=1, column=0, padx=5, pady=(0, 5), sticky="ew")

        enter = ttk.Button(self.div_relative, text="Enter", command=self.login_check) 
        enter.grid(row=2, column=0, padx=5, pady=5, sticky="nsew")

        change = ttk.Button(self.div_relative, text="No account? Sign up!", command=lambda : control.show("Sign_up")) 
        change.grid(row=3, column=0, padx=5, pady=5, sticky="nsew")
        #Calls show function to change
    
    def login_check(self):
        username = self.username.get()
        password = self.password.get()
        try:
            password_c = hash_bytes(copy.deepcopy(login[username]))
            password = bytes(password, "utf-8")
        except:
            warning = tk.Text(self.div_relative, width=16, height=4)
            warning.grid(row=4, column=0)
            warning.insert(tk.END, "Invalid username or password.")
        try:
            if bcrypt.checkpw(password, password_c): # Password check
                self.control.show("Finance")
                password_c = 0
            else:
                warning = tk.Text(self.div_relative, width=16, height=4)
                warning.grid(row=4, column=0)
                warning.insert(tk.END, "Invalid username or password.")
        except: # Except due to deepcopy of login, if incorrect username, it would return an error
            warning = tk.Text(self.div_relative, width=16, height=4)
            warning.grid(row=4, column=0)
            warning.insert(tk.END, "Invalid username or password.")

class Sign_up(tk.Frame):
    def __init__(self, parent, control):
        tk.Frame.__init__(self, parent)
        self.control = control

        self.div_relative = ttk.LabelFrame(self, text="Sign up")
        self.div_relative.pack(fill="none", expand=True)

        self.username = ttk.Entry(self.div_relative)
        self.username.insert(0, "Username")
        self.username.bind("<FocusIn>", lambda e: self.username.delete('0', 'end'))
        self.username.grid(row=0, column=0, padx=5, pady=(0, 5), sticky="ew")

        self.password = ttk.Entry(self.div_relative)
        self.password.insert(0, "Username")
        self.password.bind("<FocusIn>", lambda e: self.password.delete('0', 'end'))
        self.password.grid(row=1, column=0, padx=5, pady=(0, 5), sticky="ew")

        enter = ttk.Button(self.div_relative, text="Create", command=self.make_account) 
        enter.grid(row=2, column=0, padx=5, pady=5, sticky="nsew")

        change = ttk.Button(self.div_relative, text="Got an account? Sign in!", command=lambda : control.show("Login")) 
        change.grid(row=3, column=0, padx=5, pady=5, sticky="nsew")

    def make_account(self):
        temp_login_data = []
        username = self.username.get()
        try:
            if username in login.keys(): # Checks if username exists
                warning = tk.Text(self.div_relative, width=16, height=4)
                warning.grid(row=4, column=0)
                warning.insert(tk.END, "Username already exists")
            else:
                temp_login_data.append(username)
                password = True
        except:
            # Except because if the data is null, it crashes the program due to returning a null for login 
            temp_login_data.append(username)
            password = True
        try:
            while password:
                input_create_password = self.password.get()
                if numcheck(input_create_password) == False:
                    warning = tk.Text(self.div_relative, width=16, height=4)
                    warning.grid(row=4, column=0)
                    warning.insert(tk.END, "Your password needs to contain at least 1 number.")
                    break
                elif specialcheck(input_create_password) == False:
                    warning = tk.Text(self.div_relative, width=16, height=4)
                    warning.grid(row=4, column=0)
                    warning.insert(tk.END, "Your password needs at least 1 special character or has spaces.")
                    break
                else:
                    create = True
                    break
        except:
            pass

        try:
            if create == True:
                input_create_password = str(bcrypt.hashpw
                                            (bytes(input_create_password, "utf-8"), bcrypt.gensalt())
                                            ) # Encryption
                temp_login_data.append(input_create_password)
                login.update(dict([tupleconver(temp_login_data)])) # Tuple to be able to store
                updated(login, login_path)
                data.update(dict.fromkeys([temp_login_data[0]], [])) # Adds keys with empty values for future use
                updated(data, data_path)
                temp_login_data = []
                print("Account created.")
                self.control.show("Login")
        except:
            pass
class Finance(tk.Frame): #Add page frame
    def __init__(self, parent, control):
        tk.Frame.__init__(self, parent) #Constructs frame from parent class
        self.control = control #Parent class call#

        self.div_relative = ttk.LabelFrame(self, text="Finance") #Adds a seperated Div
        self.div_relative.grid(row=0, column=0, padx=20, pady=10)

        change = ttk.Button(self.div_relative, text="change pages", command=lambda : control.show("Login")) 
        change.grid(row=1, column=0, padx=5, pady=5, sticky="nsew")
        change.pack()

def updated(file, path): #Updates and syncs files
    """Saves and sync data"""
    with open(path, "w") as fp:
        json.dump(file, fp, indent=4)
    with open(path, "r") as fp:
        try:
            file = json.load(fp)
        except: 
            pass

def index_calculate(inputf,list): #Calculates index of item in list
    """Gets the index based on first item in 2d lists"""
    for i, j  in enumerate(list):
        if inputf == j[0]:
            index=i
    try:
        return index
    except:
        pass

def hash_bytes(input):
    """Converts to readable bytes"""
    password_c = input
    password_c = password_c[2:-1]
    password_c = password_c.encode("utf-8")
    return password_c

def numcheck(input): # Checks for any number in string
    return any(char.isdigit() for char in input)
def specialcheck(input): # Checks for any special character in string
    return any(not char.isalnum() for char in input)
def tupleconver(input): # Converts to tuple for data storage
    return tuple(input)

with open(data_path, "r") as fp: #Opens files with saved data
    try:
        data = json.load(fp)
    except:
        pass

with open(login_path, "r") as fp: #Opens files with saved data
    try:
        login = json.load(fp)
    except:
        pass
#Runtime
root = container()
root.minsize(400,400)
root.mainloop()
