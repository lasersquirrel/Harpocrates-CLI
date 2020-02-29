# Harpocrates CLI
Continuously re-encrypting chat service that pairs clients and can handle multiple at a time.

## Requirements
**Python v3.6+** - Download standard Python [here](https://www.python.org/downloads/).  
**encwork>=1.0.4** - Download with `python` or `python3 -m pip install "encwork>=1.0.4"`.  

## How does it work?
### Client
The client will generate its own private/public RSA key pair (separate from [Encwork](https://github.com/MysteryBlokHed/Encwork)'s) that will be handed to the other client via the server. This is done so that the server cannot see unencrypted messages of all clients connected. The clients will also have a kind of cookie that's handed to the server and is used to reserve usernames (this is done so that when a client asks to connect to a username, nobody can steal that username).
### Server
The server will get the client's target from the client. If two clients target each other (`ClientA` asks for `ClientB`, `ClientB` asks for `ClientA`), each client will be notified and will be ready to talk. The server will store the pair of IP's to know where messages should be sent. With an **unmodified** server, it is impossible to see the clients' messages, since the clients encrypt it with their own separate key. **However,** with a modified server, it is possible to give the clients the wrong key and see all traffic. **You must trust the server.**