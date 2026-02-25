import socket
import threading
import json
from crypto_utils import generate_rsa_keypair, encrypt_message

class Sender:
    def __init__(self, server_host='127.0.0.1', server_port=9999):
        self.server_addr = (server_host, server_port)
        self.sock = None
        self.username = None
        self.private_key, self.public_key = generate_rsa_keypair()
        self.public_key_pem = self.public_key.decode('utf-8')   # string for JSON

    def connect(self):
        """Connect to server and register."""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect(self.server_addr)
        # Register
        self.send_message({
            'type': 'register',
            'username': self.username,
            'public_key': self.public_key_pem
        })
        resp = self.recv_message()
        if resp and resp.get('type') == 'registered':
            print(f"Registered as {self.username}")
        else:
            raise Exception("Registration failed")

    def send_message(self, msg):
        """Send a JSON message (length‑prefixed)."""
        data = json.dumps(msg).encode('utf-8')
        self.sock.send(len(data).to_bytes(4, 'big'))
        self.sock.send(data)

    def recv_message(self):
        """Receive a JSON message."""
        raw_len = self.sock.recv(4)
        if not raw_len:
            return None
        msg_len = int.from_bytes(raw_len, 'big')
        data = b''
        while len(data) < msg_len:
            chunk = self.sock.recv(msg_len - len(data))
            if not chunk:
                return None
            data += chunk
        return json.loads(data.decode('utf-8'))

    def get_public_key(self, target):
        """Request public key of target user from server."""
        self.send_message({'type': 'get_key', 'username': target})
        resp = self.recv_message()
        if resp and resp.get('type') == 'key_response':
            return resp['public_key']
        elif resp and resp.get('type') == 'error':
            print(f"Error: {resp['message']}")
            return None
        return None

    def send_encrypted_message(self, target, plaintext):
        """Fetch target's public key, encrypt message, and send via server."""
        pubkey = self.get_public_key(target)
        if not pubkey:
            return
        # Encrypt
        encrypted_b64 = encrypt_message(pubkey.encode('utf-8'), plaintext)
        # Send to server for forwarding
        self.send_message({
            'type': 'send_msg',
            'to': target,
            'data': encrypted_b64
        })
        print("Message sent.")

    def run(self):
        self.username = input("Enter your username: ")
        self.connect()
        target = input("Enter recipient username: ")
        message = input("Enter your message: ")
        self.send_encrypted_message(target, message)
        self.sock.close()

if __name__ == '__main__':
    Sender().run()