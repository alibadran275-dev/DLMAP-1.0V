import os
import sqlite3

def run_app():
    # Unsafe user-controlled source
    user_data = input("Enter username: ")
    
    # SQL database injection sink (CWE-89)
    conn = sqlite3.connect("users.db")
    conn.execute("SELECT * FROM users WHERE name = '" + user_data + "'")
    
    # OS Command injection sink (CWE-78)
    os.system("echo " + user_data)
    
    # Code injection sink (CWE-94)
    eval("print(" + user_data + ")")
