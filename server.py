# Created by lasersquirrel on 29/02/2020.
# Licensed under MIT.
from encwork.server import Server
from encwork.encryption import *
import binascii
import os
from json import loads, dumps
from json.decoder import JSONDecodeError

# Track connections & pairs
connections = []
paired = []
# Public keys of those connected (ip: key)
public_keys = {}
# Track how far into the connection process each client is (username setting, etc)
connection_process = {}
# Reserve usernames to IP's
USERNAMES_FILE = "harpocrates-usernames.json" # File to store usernames/IP's

# Load usernames
try:
    with open(USERNAMES_FILE, "r") as f:
        usernames = loads(f.read())
except FileNotFoundError: # Create file if it doesn't exist
    print("No usernames file, creating one...")
    with open(USERNAMES_FILE, "w") as f:
        f.writelines("{}")
    usernames = {}
    print("Done.")
except JSONDecodeError: # Invalid file
    while True:
        ok = input("Invalid usernames file, OK to overwrite? [y/n]: ")
        if ok.lower() == "y":
            with open(USERNAMES_FILE, "w") as f:
                f.writelines("{}")
            usernames = {}
            print("Done.")
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
                # Check if the token exists
                if status["data"][0][5:] in usernames: # Valid token
                    # Tell the client the token is valid
                    server.send_msg("OK", status["data"][1])
                    connection_process[status["data"][1]] += 1
                else: # Invalid token
                    # Tell the client to token is invalid
                    server.send_msg("NO", status["data"][1])
            
            # Client has provided a new username
            if status["data"][0][:5] == "uname":
                # Check if the username is taken
                if status["data"][0][5:] not in usernames.values(): # Untaken username
                    # Generate a new token
                    tk = binascii.b2a_hex(os.urandom(64)).decode("ascii")
                    # Save the token
                    usernames[tk] = status["data"][0][5:]
                    with open(USERNAMES_FILE, "w") as f:
                        f.write(dumps(usernames))
                    # Tell the client the username is valid and provide a token for future use
                    server.send_msg("OK" + tk, status["data"][1])
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
            pass