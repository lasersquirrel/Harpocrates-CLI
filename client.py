# Created by lasersquirrel on 29/02/2020.
# Licensed under MIT.
from encwork.client import Client
from encwork.encryption import *
from threading import Thread
from time import sleep

global ready_to_send
global states
global current_state
global target_uname
global pk
ready_to_send = -1 # Track whether or not the client is ready to send messages
states = {0: "", 1: "", 2: ""} # Track whether or not the server confirmed an initialization action
current_state = 0 # Avoid overwriting states dict

TOKEN_FILE = "harpocrates-tk.txt"
# Check for token file (used to reserve username)
try:
    with open(TOKEN_FILE, "r") as f:
        tk = f.read()
except FileNotFoundError:
    tk = None

# Main code
class StatusThread(Thread):
    def __init__(self, client):
        Thread.__init__(self)
        self._client = client
    
    def run(self):
        global ready_to_send
        global states
        global current_state
        global target_uname
        global pk
        for status in client.statuses(1):
            if status["code"] == 11: # Public key received
                ready_to_send += 1
            elif status["code"] == 15: # Public key sent
                ready_to_send += 1
            elif status["code"] == 8: # Message received
                # Check progress of connection
                if current_state == 0:
                    # Check the server's reply
                    states[0] = status["data"][0]
                    if status["data"][0][:2] == "OK":
                        current_state += 1

                elif current_state == 1:
                    # Check the server's reply
                    states[1] = status["data"][0]
                    if status["data"][0][:2] == "OK":
                        current_state += 1
                
                elif current_state == 2:
                    # Check the server's reply
                    states[2] = status["data"][0]
                    if status["data"][0][:9] == "CONNECTED":
                        current_state += 1
                
                elif current_state == 3:
                    # Print the client's latest message
                    print(f"[{target_uname}] {decrypt(status['data'][0], pk)}")
                
client = Client()
StatusThread(client).start()
target = input("Enter the server IP: ")
client.start(target)

# Wait for the key exchange
while ready_to_send < 1:
    pass

# Send token or username
while True:
    if tk is None:
        # Get username if there is no token saved
        uname = input("Username to use: ")
        client.send_msg("uname" + uname)
        method_used = "USERNAME" # Track whether a token or username was sent to server
    else:
        # Send token to server
        client.send_msg("token" + tk)
        method_used = "TOKEN"

    # Wait for server reply
    while states[0] == "":
        pass
    # Check if the username/token was confirmed
    if states[0][:2] == "OK": # Username free/token is fine
        if method_used == "USERNAME":
            # Save new token to file
            with open(TOKEN_FILE, "w") as f:
                f.writelines(states[0][2:])
        break
    else:
        if method_used == "TOKEN":
            print(f"Invalid username token in {TOKEN_FILE}.")
            exit()
        elif method_used == "USERNAME":
            print("Username is taken.")

# Send custom public key
pk = gen_private_key()
while True:
    client.send_msg(get_public_key_text(get_public_key(pk)).decode("ascii"))
    # Wait for server reply
    while states[1] == "":
        pass
    # Check if the public key was confirmed
    if states[1][:2] == "OK":
        print("Custom public key confirmed.")
        break
    else:
        print("Public key was rejected by server.")
        exit()

# Send target user
target_uname = input("Enter the username to connect to: ")
client.send_msg(target_uname)

# Check response
while states[2] == "":
    pass
if states[2][:9] == "CONNECTED":
    # Save public key and try to encrypt
    client_pub = states[2][9:].encode("ascii")
    encrypt("test string", client_pub)
else:
    print("Key exchange with client failed.")
    sleep(3)
    exit()

# Send messages
while True:
    msg = input("Enter a message to send:\n")
    client.send_msg(encrypt(msg, get_public_key_text(get_public_key(pk))))
