import tkinter as tk
from tkinter import ttk
import json
from os import path

file_path = path.abspath(__file__)
dir_path = path.dirname(file_path)
data_path = path.join(dir_path, "data.json") #absolute filepath

data = [] #Stores data

class container(tk.Tk): #Container class for frames
    def __init__(self, *args, **kwargs):
        tk.Tk.__init__(self, *args, **kwargs)
        add_div = ttk.Frame(self)
        add_div.pack(side="top", fill="both", expand=True)
        add_div.grid_rowconfigure(0, weight=1)
        add_div.grid_columnconfigure(0, weight=1) #Creates frame for the programs

        self.frames = {}
        for F in ():
            page_name = F.__name__
            frame = F(parent=add_div, control=self)
            self.frames[page_name] = frame
            frame.grid(row=0, column=0, sticky="nsew") #Stores subsequent frames

        self.show("") #Shows first page
    
    def show(self, page): #Function to show frames
        frame = self.frames[page]
        self.refresh(page) #Updates the frame on change
        frame.tkraise()
    
    def refresh(self, page): #refresh page
        frame = self.frames[page]
        try:
            frame.entry.destroy()
            for i,j in enumerate(data):
                for n,m in enumerate(j):
                    frame.entry = tk.Entry(frame.add_div_relative)
                    frame.entry.grid(row=i+2, column=n+1)
                    frame.entry.insert(tk.END, m)
        except:
            for i,j in enumerate(data):
                for n,m in enumerate(j):
                    frame.entry = tk.Entry(frame.add_div_relative)
                    frame.entry.grid(row=i+2, column=n+1)
                    frame.entry.insert(tk.END, m)


class test(tk.Frame): #Add page frame
    def __init__(self, parent, control):
        tk.Frame.__init__(self, parent) #Constructs frame from parent class
        self.control = control #Parent class call

        self.add_div_relative = ttk.LabelFrame(self, text="Add Student") #Adds a seperated Div
        self.add_div_relative.grid(row=0, column=0, padx=20, pady=10)

        change = ttk.Button(self.add_div_relative, text="change pages", command=lambda : control.show("")) 
        change.grid(row=1, column=0, padx=5, pady=5, sticky="nsew")
        #Calls show function to change

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

with open(data_path, "r") as fp: #Opens files with saved data
    try:
        data = json.load(fp)
    except:
        pass

#Runtime
root = container()
root.mainloop()
