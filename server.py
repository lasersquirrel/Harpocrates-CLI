# Created by lasersquirrel on 29/02/2020.
# Licensed under MIT.
from encwork.server import Server
from encwork.encryption import *
from datetime import datetime
import binascii
import os
import sqlite3

# Track connections & pairs
connections = []
paired = {}
# Public keys of those connected (ip: key)
public_keys = {}
# Track how far into the connection process each client is (username setting, etc)
connection_process = {}
USERS_FILE = "harpocrates-users.db" # File to store various user data (token, username, signup date)
usernames = {}

# Set up users db
try:
    conn = sqlite3.connect(USERS_FILE)
    c = conn.cursor()
    # Check if users table exists
    exists = 0
    for table in c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users';"):
        exists += 1
    if exists < 1:
        # Ask to create 'users' table
        while True:
            ok = input(f"users table in {USERS_FILE} does not exist. Create it? [y/n]: ")
            if ok.lower() == "y":
                # Create 'users' table
                c.execute("""CREATE TABLE users
                             (token text, uname text, first_connection_date text)""")
                conn.commit()
                conn.close()
                break
            elif ok.lower() == "n":
                exit()

except sqlite3.DatabaseError:
    while True:
        ok = input(f"{USERS_FILE} is a corrupt or invalid SQLite3 database. Overwrite it? [y/n]: ")
        if ok.lower() == "y":
            # Delete file and create database
            os.remove(USERS_FILE)
            c.execute("""CREATE TABLE users
                        (token text, uname text, first_connection_date text)""")
            conn.commit()
            conn.close()
            break
        elif ok.lower() == "n":
            exit()


server = Server()
server.start()

# Loop
for status in server.statuses(2.5):
    # Log all statuses & data
    print(f"[{status['code']}] {status['data']}")

    if status["code"] == 11: # Public key received
        connections.append(status["data"])
        connection_process[status["data"]] = 0
    if status["code"] == 8: # Message received
        # Check connection progress of the client
        if connection_process[status["data"][1]] == 0: # Client username-getting
            # Client has provided a token
            if status["data"][0][:5] == "token":
                conn = sqlite3.connect(USERS_FILE)
                c = conn.cursor()
                # Check if the token exists
                if (status["data"][0][5:],) in c.execute("SELECT token FROM users"): # Valid token
                    # Tell the client the token is valid
                    server.send_msg("OK", status["data"][1])
                    # Map the username to the IP
                    for uname in c.execute("SELECT uname FROM users WHERE token=?", (status["data"][0][5:],)):
                        usernames[status["data"][1]] = uname
                    connection_process[status["data"][1]] += 1
                else: # Invalid token
                    # Tell the client to token is invalid
                    server.send_msg("NO", status["data"][1])
                conn.close()
            
            # Client has provided a new username
            if status["data"][0][:5] == "uname":
                conn = sqlite3.connect(USERS_FILE)
                c = conn.cursor()
                # Check if the username is taken
                if (status["data"][0][5:],) not in c.execute("SELECT uname FROM users"): # Untaken username
                    # Generate a new token
                    tk = binascii.b2a_hex(os.urandom(64)).decode("ascii")
                    # Save the token, username and date of account creation
                    c.execute("INSERT INTO users VALUES (?, ?, ?)", (tk, status["data"][0][5:], datetime.now().strftime("%Y-%m-%d-%H-%M-%S-%f")))
                    conn.commit()
                    conn.close()
                    # Tell the client the username is valid and provide a token for future use
                    server.send_msg("OK" + tk, status["data"][1])
                    # Map the username to the IP
                    usernames[status["data"][1]] = status["data"][0][5:]
                    connection_process[status["data"][1]] += 1
                else: # Taken username
                    # Tell the client the username has been taken
                    server.send_msg("NO", status["data"][1])
        
        elif connection_process[status["data"][1]] == 1: # Client key-getting
            # Test the key and send response
            try:
                encrypt(b"OK", status["data"][0].encode("ascii"))
                public_keys[status["data"][1]] = status["data"][0].encode("ascii")
                server.send_msg("OK", status["data"][1])
                connection_process[status["data"][1]] += 1
            except Exception as e:
                print(e)
                # Failed
                server.send_msg("NO", status["data"][1])
        
        elif connection_process[status["data"][1]] == 2: # Client target-getting
            paired[usernames[status["data"][1][0]]] = status["data"][0]
            print(paired)
            # See if their target has targeted them
            if status["data"][0] in paired: # Target has connected
                if paired[status["data"][0]] == usernames[status["data"][1]]: # Both clients tried to connect to each other
                    # Get the target's IP from the usernames dict
                    target_ip = list(usernames)[list(usernames.keys()).index(status["data"][0])]
                    # Send both clients each other's public keys
                    server.send_msg("CONNECTED" + public_keys[target_ip], status["data"][1])
                    server.send_msg("CONNECTED" + public_keys[status["data"][1]], target_ip)
                else: # Target connected to someone else
                    server.send_msg("FAILED", status["data"][1])
            # If their target isn't connected yet, don't respond and wait for them to