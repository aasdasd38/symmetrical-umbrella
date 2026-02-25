import socket
import threading
import json
from crypto_utils import generate_rsa_keypair, decrypt_message

class Receiver:
    def __init__(self, server_host='127.0.0.1', server_port=9999):
        self.server_addr = (server_host, server_port)
        self.sock = None
        self.username = None
        self.private_key, self.public_key = generate_rsa_keypair()
        self.private_key_pem = self.private_key.decode('utf-8')   # string for internal use
        self.public_key_pem = self.public_key.decode('utf-8')

    def connect(self):
        """Connect to server and register."""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect(self.server_addr)
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
        data = json.dumps(msg).encode('utf-8')
        self.sock.send(len(data).to_bytes(4, 'big'))
        self.sock.send(data)

    def recv_message(self):
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

    def listen_for_messages(self):
        """Continuously listen for forwarded messages and decrypt them."""
        while True:
            try:
                msg = self.recv_message()
                if not msg:
                    break
                if msg.get('type') == 'forward_msg':
                    sender = msg['from']
                    encrypted_b64 = msg['data']
                    # Decrypt using our private key
                    plaintext = decrypt_message(self.private_key_pem, encrypted_b64)
                    print(f"\n[Message from {sender}]: {plaintext}")
                elif msg.get('type') == 'error':
                    print(f"Server error: {msg['message']}")
            except Exception as e:
                print(f"Error receiving: {e}")
                break

    def run(self):
        self.username = input("Enter your username: ")
        self.connect()
        print("Waiting for messages...")
        try:
            self.listen_for_messages()
        except KeyboardInterrupt:
            pass
        finally:
            self.sock.close()

if __name__ == '__main__':
    Receiver().run()