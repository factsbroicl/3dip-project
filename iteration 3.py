import tkinter as tk
from tkinter import ttk, scrolledtext
import json
from os import path
import bcrypt
from cryptography.fernet import Fernet
import copy
import threading
import time
import enviroment
from PIL import ImageTk

file_path = path.abspath(__file__)
dir_path = path.dirname(file_path) # Absolute filepath
# Data path of the files
data_path = path.join(dir_path, "data.json") 
login_path = path.join(dir_path, "login.json")
log_path = path.join(dir_path, "logs.json")
setlist_path = path.join(dir_path, "setlist.json")

# Data initialize
data = {} 
login = {}
logs = {}
setlist_data = {}
user = 0
ENCRYPT = Fernet(enviroment.key) # Eviromental variable

class container(tk.Tk): 
    #Container class for frames
    def __init__(self, *args, **kwargs):
        tk.Tk.__init__(self, *args, **kwargs)
        div = ttk.Frame(self)
        div.pack(side="top", fill="both", expand=True)
        div.grid_rowconfigure(0, weight=1)
        div.grid_columnconfigure(0, weight=1) # Creates frame for the programs

        self.frames = {}
        for F in (Login, Sign_up, Budget, Setlist):
            page_name = F.__name__
            frame = F(parent=div, control=self)
            self.frames[page_name] = frame
            frame.grid(row=0, column=0, sticky="nsew") # Stores subsequent frames

        self.show("Login") # Shows first page
    
    def show(self, page): 
        # Function to show frames
        frame = self.frames[page]
        frame.tkraise()
        if page == "Budget": # Refreshes items on show
            self.refresh_box_budget()
            self.refresh_progressbar_budget()
            try: # Log refresh sometimes raises an error 
                self.refresh_log_budget()
            except:
                pass
        elif page == "Setlist":
            self.refresh_checkbox()
    
    def refresh_box_budget(self): 
        # Refreshes the combobox list
        frame = self.frames["Budget"]
        frame.update_idletasks()
        try:
            u_data = data_unencrypt()
            list = []
            for i,j in enumerate(u_data):
                list.append(j[1])
            # Makes the combo box 
            frame.select = ttk.Combobox(frame.div_relative, values=list)
            frame.select.config(height=5, width=15, state="readonly")
            frame.select.bind("<<ComboboxSelected>>", lambda e: frame.progress_update())
            frame.select.set(u_data[0][1])
            frame.select.grid(row=3, column=2, padx=5, pady=(0, 5), sticky="nsew")
        except: # Raises when no entries are exisiting, applies no values
            frame.select = ttk.Combobox(frame.div_relative, values=["Nothing"])
            frame.select.config(height=5, width=15, state="readonly")
            frame.select.bind("<<ComboboxSelected>>", lambda e: frame.progress_update())
            frame.select.grid(row=3, column=2, padx=5, pady=(0, 5), sticky="nsew")
    
    def refresh_progressbar_budget(self): 
        # Refresh function for the progress bar
        frame = self.frames["Budget"]
        frame.update_idletasks()
        try:
            u_data = data_unencrypt()
            # Makes the bar
            frame.progress = ttk.Progressbar(frame.div_relative, length=320)
            frame.progress.grid(row=4, column=0, padx=5, pady=(0, 5), sticky="ew", columnspan=4)
            # Calculates percentage
            percent = (float(u_data[index_calculate(frame.select.get(), u_data, 1)][3]) 
                       / float(u_data[index_calculate(frame.select.get(), u_data, 1)][2]) * 100)
            # Based on percent, change the text
            if percent >= 100:
                frame.nametext = tk.Label(frame.div_relative, text="Completed!", anchor="e", 
                                          justify="right", font=("arial", 10, "bold"))
                frame.nametext.grid(row=3, column=1, padx=5, pady=(0, 5), sticky="nsew")
                percent = 99.99
            else:
                frame.nametext = tk.Label(frame.div_relative, text="Goal:", anchor="e", 
                                          justify="right", font=("arial", 10, "bold"))
                frame.nametext.grid(row=3, column=1, padx=5, pady=(0, 5), sticky="nsew")
            # Applies progress to the bar
            frame.progress.step(percent)
        except:
            pass
    
    def refresh_log_budget(self, text): 
        # Refresh logs
        frame = self.frames["Budget"]
        frame.update_idletasks()
        printed_log = copy.deepcopy(text) # Deepcopy to maintain data intregrity 
        printed_log = printed_log[2:-1]
        printed_log = ENCRYPT.decrypt(printed_log)
        printed_log = printed_log.decode("utf-8")
        try: # Attempts to insert log, raises an error if empty
            frame.log.config(state="normal")
            frame.log.delete('1.0', tk.END)
            frame.log.insert(tk.INSERT, printed_log)
            frame.log.config(state="disabled")
        except:
            pass
    
    def refresh_checkbox(self):
        frame = self.frames["Setlist"]
        frame.update_idletasks()
        try:
            frame.set_list = frame.list_element(frame.div_relative, setlist_unencrypt())
            frame.set_list.grid(row=0, column=0, padx=5, pady=(0, 5), sticky="nsew", columnspan=3, rowspan=6)
        except:
            pass

    def warning(self, page, text): 
        # Warning message when a inout error is raised, fully based on multithreading
        frame = self.frames[page]
        frame.tkraise()
        if page == "Sign_up" or page == "Login": # Depending on the page, different warnings needs to be applied
            warning = tk.Text(frame.div_relative, width=16, height=4, wrap="word")
            warning.grid(row=4, column=0)
            warning.insert(tk.END, text)
        elif page == "Budget":
            warning = tk.Text(frame.div_relative, width=7, height=6, wrap="word")
            warning.grid(row=0, column=3, rowspan=3)
            warning.insert(tk.END, text)
        time.sleep(5) # Function only applicable when using multithreading
        try:
            warning.destroy()
        except:
            pass

    def thread(self, page, text): 
        # Starts a new thread to run warning to not freezze function
        t = threading.Thread(target=self.warning, args=[page, text])
        t.start()

class Login(tk.Frame): #Add page frame
    def __init__(self, parent, control):
        tk.Frame.__init__(self, parent) #Constructs frame from parent class
        self.control = control #Parent class call

        bg = ImageTk.PhotoImage(file=(dir_path + "/image/login_signup.png"))
        background = tk.Label(self, image=bg)
        background.image = bg
        background.place(x=0, y=0, relwidth=1, relheight=1)

        self.div_relative = ttk.LabelFrame(self, text="Login") #Adds a seperated Div
        self.div_relative.pack(fill="none", expand=True)

        # Entries
        self.username = ttk.Entry(self.div_relative)
        self.username.insert(0, "Username")
        # Deletes inside text when selected
        self.username.bind("<FocusIn>", lambda e: self.username.delete('0', 'end'))
        self.username.grid(row=0, column=0, padx=5, pady=(0, 5), sticky="ew")

        self.password = ttk.Entry(self.div_relative)
        self.password.insert(0, "Password")
        # Deletes inside text when selected
        self.password.bind("<FocusIn>", lambda e: self.password.delete('0', 'end'))
        self.password.grid(row=1, column=0, padx=5, pady=(0, 5), sticky="ew")

        # Login function call
        enter = ttk.Button(self.div_relative, text="Enter", command=self.login_check) 
        enter.grid(row=2, column=0, padx=5, pady=5, sticky="nsew")

        # Calls show function to change
        change = ttk.Button(self.div_relative, text="No account? Sign up!", command=lambda : control.show("Sign_up")) 
        change.grid(row=3, column=0, padx=5, pady=5, sticky="nsew")
    
    def login_check(self): 
        #Check password with saved password
        global user
        username = self.username.get()
        password = self.password.get()
        password_c = 0
        try:
            password_c = hash_bytes(copy.deepcopy(login[username])) # Deepcopy to maintain intregrity of the database
            password = bytes(password, "utf-8")
        except:
            self.control.thread("Login", "Invalid username or password.")
        try:
            if bcrypt.checkpw(password, password_c): # Password check
                user = copy.deepcopy(username) # Sets user
                self.control.refresh_log_budget(logs[user])
                password_c = 0
                self.control.show("Budget")
            else:
                self.control.thread("Login", "Invalid username or password.")
        except: # Except due to deepcopy of login, if incorrect username, it would return an error
            if password_c == 0: # This will return an error due to self.control.show handling multiple functions
                pass
            else:
                self.control.thread("Login", "Invalid username or password.")

class Sign_up(tk.Frame):
    def __init__(self, parent, control):
        tk.Frame.__init__(self, parent) # Constructs frame from parent class
        self.control = control # Parent class call

        bg = ImageTk.PhotoImage(file=(dir_path + "/image/login_signup.png"))
        background = tk.Label(self, image=bg)
        background.image = bg
        background.place(x=0, y=0, relwidth=1, relheight=1)

        self.div_relative = ttk.LabelFrame(self, text="Sign up") # Adds a seperate division
        self.div_relative.pack(fill="none", expand=True)

        # Entries
        self.username = ttk.Entry(self.div_relative)
        self.username.insert(0, "Username")
        # Deletes inside text when selected
        self.username.bind("<FocusIn>", lambda e: self.username.delete('0', 'end'))
        self.username.grid(row=0, column=0, padx=5, pady=(0, 5), sticky="ew")

        self.password = ttk.Entry(self.div_relative)
        self.password.insert(0, "Password")
        # Deletes inside text when selected
        self.password.bind("<FocusIn>", lambda e: self.password.delete('0', 'end'))
        self.password.grid(row=1, column=0, padx=5, pady=(0, 5), sticky="ew")

        # Entry button
        enter = ttk.Button(self.div_relative, text="Create", command=self.make_account) 
        enter.grid(row=2, column=0, padx=5, pady=5, sticky="nsew")

        # Change page button
        change = ttk.Button(self.div_relative, text="Got an account? Sign in!", command=lambda : control.show("Login")) 
        change.grid(row=3, column=0, padx=5, pady=5, sticky="nsew")

    def make_account(self):
        # Creates account and all relevant data entries
        temp_login_data = []
        username = self.username.get()
        try:
            if username in login.keys(): # Checks if username exists
                self.control.thread("Sign_up", "Username already exists.")
            else:
                temp_login_data.append(username)
                password = True
        except:
            # Except because if the data is null, it crashes the program due to returning a null for login 
            temp_login_data.append(username)
            password = True
        try: # Password checks for requirements
            while password:
                input_create_password = self.password.get()
                if numcheck(input_create_password) == False:
                    self.control.thread("Sign_up", "Your password needs to contain at least 1 number.")
                    break
                elif specialcheck(input_create_password) == False:
                    self.control.thread("Sign_up", "Your password needs at least 1 special character.")
                    break
                elif " " in input_create_password:
                    self.control.thread("Sign_up", "Your password cannot contain spaces.")
                    break
                else:
                    create = True
                    break
        except:
            pass

        # Seperate loop used to maintain data stucture intregrity and reduce code injection attempts
        try:
            if create == True:
                input_create_password = str(bcrypt.hashpw
                                            (bytes(input_create_password, "utf-8"), bcrypt.gensalt())
                                            ) # Encryption
                temp_login_data.append(input_create_password)
                login.update(dict([tupleconver(temp_login_data)])) # Tuple to be able to store
                updated(login, login_path)
                data.update(dict.fromkeys([temp_login_data[0]], [])) # Adds keys with empty values for future use
                logs.update(dict.fromkeys([temp_login_data[0]], str(ENCRYPT.encrypt(bytes("Logs: ", "utf-8")))))
                setlist_data.update(dict.fromkeys([temp_login_data[0]], []))
                updated(data, data_path)
                updated(logs, log_path)
                updated(setlist_data, setlist_path)
                temp_login_data = []
                self.control.show("Login")
        except:
            pass

class Budget(tk.Frame): #Add page frame
    def __init__(self, parent, control):
        tk.Frame.__init__(self, parent) #Constructs frame from parent class
        self.control = control #Parent class call#

        bg = ImageTk.PhotoImage(file=(dir_path + "/image/background.png"))
        background = tk.Label(self, image=bg)
        background.image = bg
        background.place(x=0, y=0, relwidth=1, relheight=1)

        self.div_relative = ttk.LabelFrame(self, text="Budget") #Adds a seperated Div
        self.div_relative.grid(row=0, column=0, padx=20, pady=10)

        # Adds all GUI widgets
        # Standard format used on entries: Construct, insert text, bind to delete on select, placement on grid
        # Standard format used on static: Construct, placement on grid
        self.goal = ttk.Entry(self.div_relative, width=10)
        self.goal.insert(0, "Amount in $")
        self.goal.bind("<FocusIn>", lambda e: self.goal.delete('0', 'end'))
        self.goal.grid(row=0, column=1, padx=5, pady=(0, 20), sticky="ew")

        self.name = ttk.Entry(self.div_relative, width=10)
        self.name.insert(0, "Item name")
        self.name.bind("<FocusIn>", lambda e: self.name.delete('0', 'end'))
        self.name.grid(row=0, column=2, padx=5, pady=(0, 20), sticky="ew")

        self.contribute = ttk.Entry(self.div_relative, width=10)
        self.contribute.insert(0, "Amount in $")
        self.contribute.bind("<FocusIn>", lambda e: self.contribute.delete('0', 'end'))
        self.contribute.grid(row=2, column=1, padx=5, pady=(0, 20), sticky="ew")

        self.c_name = ttk.Entry(self.div_relative, width=10)
        self.c_name.insert(0, "Contributor name")
        self.c_name.bind("<FocusIn>", lambda e: self.c_name.delete('0', 'end'))
        self.c_name.grid(row=2, column=2, padx=5, pady=(0, 20), sticky="ew")

        percent0 = tk.Label(self.div_relative, text="0%", anchor="w", justify="left", font=("arial", 10, "bold"))
        percent0.grid(row=5, column=0, padx=5, pady=(0, 5), sticky="nsew")

        percent100 = tk.Label(self.div_relative, text="100%", anchor="e", justify="right", font=("arial", 10, "bold"))
        percent100.grid(row=5, column=3, padx=5, pady=(0, 5), sticky="nsew")

        add = ttk.Button(self.div_relative, text="Add", command=lambda : self.contribute_money(self.select.get()))
        add.grid(row=2, column=0, padx=5, pady=(0, 20), sticky="nsew")

        set = ttk.Button(self.div_relative, text="Set", command=lambda : self.set_goal())
        set.grid(row=0, column=0, padx=5, pady=(0, 20), sticky="nsew", rowspan=2)

        nametext = tk.Label(self.div_relative, text="Goal:", anchor="e", justify="right", font=("arial", 10, "bold"))
        nametext.grid(row=3, column=1, padx=5, pady=(0, 5), sticky="nsew")

        logtext = tk.Label(self.div_relative, text="Logs", anchor="w", justify="left", font=("arial", 10, "bold"))
        logtext.grid(row=6, column=0, padx=5, pady=(0, 5), sticky="nsew")

        self.log = scrolledtext.ScrolledText(self.div_relative, wrap="word")
        self.log.config(state="disabled", width=40, height=7) # Disabled to not allow users to write
        self.log.grid(row=7, column=0, padx=5, pady=(0, 5), sticky="nsew", columnspan=4)

        change = ttk.Button(self.div_relative, text="View Setlist", command=lambda : control.show("Setlist")) 
        change.grid(row=8, column=0, padx=5, pady=5, sticky="nsew")
    
    def set_goal(self):
        # Adds goal to relevant databases with encryption 
        total = self.goal.get()
        name = self.name.get()
        if total[0] == "$": # In case user adds "$" when entering value
            total = total[1:]
        try:
            total = float(total) # Checks if value is valid and sets the variable to float for manipulation
        except:
            self.control.thread("Budget", "Invalid amount of money.")
            return 0
        
        if " " in name:
            self.control.thread("Budget", "Names cannot contain spaces")
            return 0
        # Prevents duplicate entries causing problems
        num = 0
        final_name = copy.deepcopy(name)
        u_data = data_unencrypt()
        for i,j in enumerate(u_data):
            if name in j[1]:
                num += 1
                final_name = name + " (" + str(num) + ")" # Adds (num) to differeniate
        # Encryption and saving
        encrypt_name = str(ENCRYPT.encrypt(bytes(final_name, "utf-8")))
        total = str(ENCRYPT.encrypt(bytes(str(total), "utf-8")))
        zero = str(ENCRYPT.encrypt(bytes("0", "utf-8")))
        data[user].append([len(data[user]), encrypt_name ,total, zero])
        updated(data, data_path)

        # Adds action to logs
        text = "\n" + "Added new goal: " + str(final_name)
        new_log = self.log_update(text)
        logs[user] = str(ENCRYPT.encrypt(bytes(new_log, "utf-8")))
        updated(logs, log_path)

        #Updates relevant widgets
        self.control.refresh_log_budget(logs[user])
        self.control.refresh_box_budget()
        self.control.refresh_progressbar_budget()

    
    def contribute_money(self, item):
        # Adds value to an existing goal
        # Note: u = Unencrypted e = Encrypted
        add = self.contribute.get()
        name = self.c_name.get()
        try:
            add = float(add) # Convert to float and checks if value is valid
        except:
            self.control.thread("Budget", "Invalid amount of money.")
            return 0
        u_data = data_unencrypt() # Unencrypted data 
        num = float(u_data[index_calculate(item, u_data, 1)][3]) # Calculates index of selected goal
        num += add
        e_num = str(ENCRYPT.encrypt(bytes(str(num), "utf-8"))) # Encryts data to be stored
        data[user][index_calculate(item, u_data, 1)][3] = e_num # Updates entry
        updated(data, data_path)
        # Logs the action to logs
        text = "\n" + str(name) + " added $" + str(add) + " to goal."
        new_log = self.log_update(text)
        logs[user] = str(ENCRYPT.encrypt(bytes(new_log, "utf-8")))
        updated(logs, log_path)
        # Refreshes relevant widgets
        self.control.refresh_log_budget(logs[user])
        self.control.refresh_progressbar_budget()
    
    def progress_update(self):
        # Refreshes progress on rare exceptions such as initial launch
        # Intregity of these 2 lines lies in the 2 interactions between this and parent class
        self.select.focus()
        self.control.refresh_progressbar_budget()
    
    def log_update(self, text):
        # Updates log used seperately from refresh logs, rather than deleting entire widget,
        # this merely changes the content, useful for non-initial updates of the logs
        new_log = copy.deepcopy(logs[user])
        new_log = new_log[2:-1]
        new_log = ENCRYPT.decrypt(new_log)
        new_log = new_log.decode("utf-8")
        new_log = new_log + text
        return new_log

class Setlist(tk.Frame): #Add page frame
    def __init__(self, parent, control):
        tk.Frame.__init__(self, parent) #Constructs frame from parent class
        self.control = control #Parent class call

        bg = ImageTk.PhotoImage(file=(dir_path + "/image/background.png"))
        background = tk.Label(self, image=bg)
        background.image = bg
        background.place(x=0, y=0, relwidth=1, relheight=1)

        self.div_relative = ttk.LabelFrame(self, text="Setlist") #Adds a seperated Div
        self.div_relative.grid(row=0, column=0, padx=20, pady=10)

        self.set_list = self.list_element(self.div_relative, [])
        self.set_list.grid(row=0, column=0, padx=5, pady=(0, 5), sticky="nsew", columnspan=3, rowspan=6)

        self.item = ttk.Entry(self.div_relative, width=20)
        self.item.insert(0, "Item name")
        self.item.bind("<FocusIn>", lambda e: self.item.delete('0', 'end'))
        self.item.grid(row=1, column=3, padx=5, pady=(0, 30), sticky="ew")

        add = ttk.Button(self.div_relative, text="Add", width=10, command=self.set_item) 
        add.grid(row=2, column=3, padx=5, pady=(0, 30), sticky="nsew")

        remove = ttk.Button(self.div_relative, text="Remove", width=10, command=self.remove_from_list) 
        remove.grid(row=3, column=3, padx=5, pady=(0, 30), sticky="nsew")

        clear = ttk.Button(self.div_relative, text="Clear", width=10, command=self.clearlist)
        clear.grid(row=4, column=3, padx=5, pady=(0, 30), sticky="nsew")

        save = ttk.Button(self.div_relative, text="Save", width=10, command=self.save_checks)
        save.grid(row=5, column=3, padx=5, pady=(0, 30), sticky="nsew")

        change = ttk.Button(self.div_relative, text="View Budget", command=lambda : control.show("Budget")) 
        change.grid(row=6, column=0, padx=5, pady=5, sticky="nsew")
    
    def clearlist(self):
        setlist_data[user].clear()
        updated(setlist_data, setlist_path)
        self.control.refresh_checkbox()
    
    def remove_from_list(self):
        item = self.item.get()
        u_data = setlist_unencrypt()
        setlist_data[user].pop(index_calculate(item, u_data, 0))
        print(index_calculate(item, u_data, 0))
        self.control.refresh_checkbox()

    def set_item(self):
        # Adds goal to relevant databases with encryption 
        item = self.item.get()
        # Prevents duplicate entries causing problems
        num = 0
        final_item = copy.deepcopy(item)
        u_data = setlist_unencrypt()
        for i,j in enumerate(u_data):
            if item in j[0]:
                num += 1
                final_item = item + " (" + str(num) + ")" # Adds (num) to differeniate
        # Encryption and saving
        encrypt_item = str(ENCRYPT.encrypt(bytes(final_item, "utf-8")))
        setlist_data[user].append([encrypt_item, "u"])
        updated(setlist_data, setlist_path)

        #Updates relevant widgets
        self.control.refresh_checkbox()
    
    def save_checks(self):
        for i,j in enumerate(self.set_list.in_list):
            if j.get():
                setlist_data[user][i][1] = "c"
            else:
                setlist_data[user][i][1] = "u"
        updated(setlist_data, setlist_path)


    class list_element(tk.Frame):
        def __init__(self, parent, list, **kwargs):
            tk.Frame.__init__(self, parent, **kwargs)

            self.div_relative = tk.Canvas(self) #Adds a seperated Div
            self.div_relative.config(width=160, height=300)

            self.frame = tk.Frame(self.div_relative)
            self.frame.bind(
                            "<Configure>",
                            lambda e: self.div_relative.configure(
                                scrollregion=self.div_relative.bbox("all")
                            )
                        )

            v = tk.Scrollbar(self, orient='vertical', command=self.div_relative.yview)

            self.div_relative.create_window((0,0), window=self.frame, anchor="nw")
            self.div_relative.configure(yscrollcommand=v.set)

            self.in_list = []
            for j in list:
                if j[1] == "u":
                    var = tk.IntVar(value=0)
                else:
                    var = tk.IntVar(value=1)
                self.in_list.append(var)
                f_list = tk.Checkbutton(self.frame, var=var, text=j[0],
                                        anchor="w", width=20)

                f_list.pack(side="top", fill="x", anchor="w")
            
            self.div_relative.pack(side="left", fill="both")
            v.pack(side="right", fill="y")

            self.div_relative.bind("<Enter>", self.enable_mouse_wheel)
            self.div_relative.bind("<Leave>", self.disable_mouse_wheel)
        
        def enable_mouse_wheel(self, event):
            self.div_relative.bind_all("<MouseWheel>", self.on_mouse_wheel)

        def disable_mouse_wheel(self, event):
            self.div_relative.unbind_all("<MouseWheel>")

        def on_mouse_wheel(self, event):
            if event.delta > 0:
                self.div_relative.yview_scroll(-1, "units")  # Scroll up
            elif event.delta < 0:
                self.div_relative.yview_scroll(1, "units")  # Scroll down

def updated(file, path): #Updates and syncs files
    """Saves and sync data"""
    with open(path, "w") as fp:
        json.dump(file, fp, indent=4)
    with open(path, "r") as fp:
        try:
            file = json.load(fp)
        except: 
            pass

def index_calculate(inputf,list,ind): #Calculates index of item in list
    """Gets the index based on selected item in 2d lists"""
    for i, j  in enumerate(list):
        if inputf == j[ind]:
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

def data_unencrypt():
    info = copy.deepcopy(data[user]) # Deepcopy to maintain data intregrity
    for i,j in enumerate(info): # Decrypts based on data.json structure
        j[1] = j[1][2:-1]
        j[1] = ENCRYPT.decrypt(j[1])
        j[1] = j[1].decode("utf-8")
        j[2] = j[2][2:-1]
        j[2] = ENCRYPT.decrypt(j[2])
        j[2] = j[2].decode("utf-8")
        j[3] = j[3][2:-1]
        j[3] = ENCRYPT.decrypt(j[3])
        j[3] = j[3].decode("utf-8")
    return info

def setlist_unencrypt():
    info = copy.deepcopy(setlist_data[user]) # Deepcopy to maintain data intregrity
    for i,j in enumerate(info): # Decrypts based on setlist.json structure
        j[0] = j[0][2:-1]
        j[0] = ENCRYPT.decrypt(j[0])
        j[0] = j[0].decode("utf-8")
        info[i] = [j[0], j[1]]
    return info

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

with open(log_path, "r") as fp: #Opens files with saved data
    try:
        logs = json.load(fp)
    except:
        pass

with open(setlist_path, "r") as fp: #Opens files with saved data
    try:
        setlist_data = json.load(fp)
    except:
        pass

#Runtime
root = container()
root.title("BandTied")
root.maxsize(400,400)
root.mainloop()
