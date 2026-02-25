import socket
import threading
import json

class Server:
    def __init__(self, host='0.0.0.0', port=9999):
        self.host = host
        self.port = port
        self.clients = {}          # username -> (socket, public_key)
        self.lock = threading.Lock()

    def handle_client(self, conn, addr):
        """Handle a single client connection."""
        print(f"New connection from {addr}")
        username = None
        try:
            # 1. Registration: receive username and public key
            data = self.recv_message(conn)
            if not data or data['type'] != 'register':
                return
            username = data['username']
            public_key = data['public_key']
            with self.lock:
                self.clients[username] = (conn, public_key)
            print(f"Registered {username}")

            # 2. Notify client that registration succeeded
            self.send_message(conn, {'type': 'registered', 'username': username})

            # 3. Main loop: handle requests
            while True:
                msg = self.recv_message(conn)
                if not msg:
                    break
                self.process_request(username, msg)

        except Exception as e:
            print(f"Error with {addr}: {e}")
        finally:
            with self.lock:
                if username and username in self.clients:
                    del self.clients[username]
            conn.close()
            print(f"Connection closed for {addr}")

    def process_request(self, sender, msg):
        """Process client requests."""
        msg_type = msg.get('type')
        if msg_type == 'get_key':
            # Client wants the public key of another user
            target = msg['username']
            with self.lock:
                if target in self.clients:
                    pubkey = self.clients[target][1]
                    self.send_message(self.clients[sender][0],
                                      {'type': 'key_response', 'public_key': pubkey})
                else:
                    self.send_message(self.clients[sender][0],
                                      {'type': 'error', 'message': 'User not found'})

        elif msg_type == 'send_msg':
            # Client wants to send an encrypted message to another user
            target = msg['to']
            encrypted = msg['data']   # bytes (already base64 encoded in JSON)
            with self.lock:
                if target in self.clients:
                    # Forward the encrypted blob
                    self.send_message(self.clients[target][0],
                                      {'type': 'forward_msg', 'from': sender, 'data': encrypted})
                else:
                    self.send_message(self.clients[sender][0],
                                      {'type': 'error', 'message': 'Recipient not online'})

    def recv_message(self, conn):
        """Receive a length‑prefixed JSON message."""
        try:
            raw_len = conn.recv(4)
            if not raw_len:
                return None
            msg_len = int.from_bytes(raw_len, 'big')
            data = b''
            while len(data) < msg_len:
                chunk = conn.recv(msg_len - len(data))
                if not chunk:
                    return None
                data += chunk
            return json.loads(data.decode('utf-8'))
        except:
            return None

    def send_message(self, conn, msg):
        """Send a length‑prefixed JSON message."""
        try:
            data = json.dumps(msg).encode('utf-8')
            conn.send(len(data).to_bytes(4, 'big'))
            conn.send(data)
        except:
            pass

    def start(self):
        """Start the server."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.host, self.port))
            s.listen()
            print(f"Server listening on {self.host}:{self.port}")
            while True:
                conn, addr = s.accept()
                threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True).start()

if __name__ == '__main__':
    Server().start()