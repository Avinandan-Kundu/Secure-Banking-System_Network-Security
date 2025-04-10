import socket
from generateMAC import MAC

class ATMClient:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sock = None
        self.username = None  # Will be set during login

    def connect_and_authenticate(self, username, password):
        self.username = username
        print(f"[ATMClient-{self.username}] Connecting to bank server...")
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((self.host, self.port))
            self.sock.sendall(self.username.encode())

            challenge = self.sock.recv(1024).decode()
            nonce = challenge.split("||")[0]
            response = f"1234||{nonce}"
            self.sock.sendall(response.encode())

            self.sock.recv(1024)  # NA echo
            self.sock.recv(1024)  # KA
            self.sock.sendall(b"ACK")
            self.sock.recv(1024)  # Encrypted master share

            self.gen_MAC = MAC(b'b92135480b05ae68de59acfa95cd6c57')
            self.mac_key = self.gen_MAC.MACKey
            self.sym_key = self.gen_MAC.symKey

            credentials = f"{self.username}:{password}"
            self.sock.sendall(credentials.encode())

            enc_data = self.sock.recv(1024)
            split_msg = enc_data.split(b'||')
            decrypted = self.gen_MAC.decrypt(split_msg[0], split_msg[1])
            response = decrypted.split(b'||')[0].decode()
            print(f"[ATMClient-{self.username}] Login response: {response}")
            return "success" in response.lower()

        except Exception as e:
            print(f"[ATMClient-{self.username}] Error:", e)
            return False

    def send_transaction(self, action, amount=""):
        try:
            msg = f"{action}:{amount}" if action in ["deposit", "withdraw"] and amount else action
            msg_bytes = msg.encode() + b'||' + b'dummy'
            ct, tag = self.gen_MAC.encrypt(msg_bytes)
            self.sock.sendall(ct + b'||' + tag)

            response = self.sock.recv(1024)
            split_msg = response.split(b'||')
            decrypted = self.gen_MAC.decrypt(split_msg[0], split_msg[1])
            return decrypted.split(b'||')[0].decode()

        except Exception as e:
            print(f"[ATMClient-{self.username}] Transaction error:", e)
            return "Transaction failed"
