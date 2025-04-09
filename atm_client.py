import socket
from generateMAC import MAC

class ATMClient:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sock = None
        self.username = None

    def connect_and_authenticate(self, username, password):
        print("------ ATMClient: connect_and_authenticate() ------")
        print(f"[CLIENT] Attempting to connect to {self.host}:{self.port}")

        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((self.host, self.port))
            print("[CLIENT] Connected to bank server")
        except Exception as e:
            print("[CLIENT ERROR] Could not connect to KDC server:", e)
            return False

        try:
            # Step 1: Send client identity
            self.sock.sendall(username.encode())
            print("[CLIENT] Sent client ID")

            # Step 2: Receive challenge
            challenge = self.sock.recv(1024).decode()
            print("[CLIENT] Challenge received:", challenge)
            parts = challenge.split("||")
            nonce = parts[0]

            # Step 3: Send challenge response (dummy logic for now)
            dummy_NA = "1234"
            response = f"{dummy_NA}||{nonce}"
            self.sock.sendall(response.encode())
            print("[CLIENT] Sent challenge response:", response)

            # Step 4: Key exchange
            self.sock.recv(1024)  # NA echo
            self.sock.recv(1024)  # KA
            self.sock.sendall(b"ACK")  # Acknowledge
            self.sock.recv(1024)  # Encrypted master share
            print("[CLIENT] Key exchange complete")

            # Step 5: Set up MAC keys (same master secret as KDC)
            self.gen_MAC = MAC(b'b92135480b05ae68de59acfa95cd6c57')
            self.mac_key = self.gen_MAC.MACKey
            self.sym_key = self.gen_MAC.symKey

            # Step 6: Send login credentials
            credentials = f"{username}:{password}"
            self.sock.sendall(credentials.encode())
            print("[CLIENT] Sent login credentials")

            # Step 7: Receive encrypted login result
            enc_data = self.sock.recv(1024)
            split_msg = enc_data.split(b'||')
            if len(split_msg) < 2:
                print("[CLIENT ERROR] Malformed encrypted message from server.")
                return False

            decrypted = self.gen_MAC.decrypt(split_msg[0], split_msg[1])
            response = decrypted.split(b'||')[0].decode()
            print("[CLIENT] Server response:", response)

            if "success" in response.lower():
                print("[CLIENT] Login SUCCESSFUL\n")
                self.username = username
                return True
            else:
                print("[CLIENT] Login FAILED\n")
                return False

        except Exception as e:
            print("[CLIENT ERROR] Exception during authentication:", e)
            return False

    def send_transaction(self, action, amount=""):
        try:
            if action in ["deposit", "withdraw"] and amount:
                message = f"{action}:{amount}"
            else:
                message = action

            print(f"[CLIENT] Sending encrypted transaction: {message}")

            # Encrypt and MAC the message
            msg_bytes = message.encode() + b'||' + b'random_nonce'  # Add dummy nonce
            ciphertext, tag = self.gen_MAC.encrypt(msg_bytes)

            self.sock.sendall(ciphertext + b'||' + tag)

            # Receive encrypted response
            response = self.sock.recv(1024)
            split_msg = response.split(b'||')
            if len(split_msg) < 2:
                print("[CLIENT ERROR] Invalid encrypted format from server.")
                return "Transaction failed"

            decrypted = self.gen_MAC.decrypt(split_msg[0], split_msg[1])
            result = decrypted.split(b'||')[0].decode()
            print("[CLIENT] Decrypted server response:", result)
            return result

        except Exception as e:
            print("[CLIENT ERROR] Transaction error:", e)
            return "Transaction failed"
