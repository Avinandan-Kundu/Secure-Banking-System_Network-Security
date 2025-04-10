import socket
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import struct
from generateMAC import MAC
import sys
from threading import Thread
from datetime import datetime
from transaction_logger import transaction_log


HOST = "127.0.0.1"
PORT = 6000
MAX_CLIENTS = 1


class Server:
    def __init__(self, HOST, PORT, identity):
        self.host = HOST
        self.port = PORT
        self.id = identity
        self.clients = []
        self.socket_init = False
        self.session_keys = {}
        self.Master_Secret = 'b92135480b05ae68de59acfa95cd6c57'
        self.MACKey = None
        self.symKey = None

        self.USERS = {
            "Client-A": {"pswd": "ClientA", "balance": 1000},
            "Client-B": {"pswd": "ClientB", "balance": 1000},
            "Client-C": {"pswd": "ClientC", "balance": 1000},
            "Client-D": {"pswd": "ClientD", "balance": 1000}
        }

    def new_client(self, conn, addr):
        try:
            print(f"Connected by {addr}")
            while True:
                client_Identity = conn.recv(1024)
                if client_Identity:
                    break
            print("ID: ", client_Identity.decode())

            Nk1 = get_random_bytes(16).hex()
            challenge = Nk1 + "||" + self.id
            print("[NK1||IDK]:\n", challenge)
            conn.send(challenge.encode())

            while True:
                challenge_resp = conn.recv(1024)
                if challenge_resp:
                    break
            print("D(PRK, [NA||NK1]): \n", challenge_resp.decode())
            NA, Nk1_check = challenge_resp.decode().split("||")
            if Nk1_check != Nk1:
                print("Incorrect Nonce")
                conn.close()
                print("Disconnected")
                return

            conn.send(NA.encode())

            KA = get_random_bytes(16)
            final_message = KA.hex()
            print("Signature: \n", final_message)
            conn.send(final_message.encode())
            conn.recv(1024)

            master_share = self.encrypt(KA, self.Master_Secret)
            conn.send(master_share)

            self.gen_MAC = MAC(self.Master_Secret.encode())
            self.gen_MAC.generateMAC_KEY()
            self.MACKey, self.symKey = self.gen_MAC.symKey, self.gen_MAC.MACKey

            print("MAC: ", self.MACKey.hex())
            print("New Symmetric Key: ", self.symKey.hex())

        except KeyboardInterrupt:
            conn.close()
            print("Disconnected")

    def send_msg(self, conn, msg):
        assert self.gen_MAC is not None
        msg_byte = msg.encode() + b'||' + get_random_bytes(16)
        message, tag = self.gen_MAC.encrypt(msg_byte)
        print('Encrypted Message:', message)
        conn.send(message + b'||' + tag)

    def receive_msg(self, conn):
        received = conn.recv(1024)
        if received:
            print('[KDC] Encrypted Message Received:', received)
            try:
                split_message = received.split(b'||')
                plaintext = self.gen_MAC.decrypt(split_message[0], split_message[1])
                msg = plaintext.split(b'||')[0].decode()
                print("[KDC] Decrypted message:", msg)
                return received, msg
            except Exception as e:
                print("[KDC ERROR] Failed to decrypt message:", e)
                conn.close()
                return None, None
        return None, None

    def login(self, username, password):
        try:
            if self.USERS[username]["pswd"] == password:
                print(f"{username} has successfully logged in.\n")
                return True
            else:
                print("Password is incorrect.")
        except KeyError:
            print("Username not found.")
        return False

    def handle_transactions(self, conn, connections):
        try:
            raw_msg = conn.recv(1024)
            try:
                print("[KDC] Attempting to decrypt received login...")
                split_message = raw_msg.split(b'||')
                plaintext = self.gen_MAC.decrypt(split_message[0], split_message[1])
                msg = plaintext.split(b'||')[0].decode()
                print("[KDC] Decrypted login message:", msg)
            except Exception as e:
                print("[KDC] Failed to decrypt. Fallback to plaintext. Reason:", e)
                msg = raw_msg.decode()
                print("[KDC] Plaintext login received:", msg)

            username, password = msg.split(':')
            while not self.login(username, password):
                self.send_msg(conn, "failed")
                _, msg = self.receive_msg(conn)
                username, password = msg.split(':')

            self.send_msg(conn, "success")
            transaction_log(self.symKey, username=username, action="logged in")

            while True:
                received, msg = self.receive_msg(conn)
                if not msg:
                    break
                parts = msg.split(":")
                action_str = msg

                if len(parts) > 1:
                    action, amount = parts
                    try:
                        amount = int(amount)
                        if amount < 0:
                            self.send_msg(conn, "Amount should never be negative.")
                            continue
                    except ValueError:
                        self.send_msg(conn, "Invalid amount format.")
                        continue

                    if action == "deposit":
                        self.USERS[username]["balance"] += amount
                        self.send_msg(conn, f"You successfully deposited: ${amount}")
                    elif action == "withdraw":
                        if self.USERS[username]["balance"] >= amount:
                            self.USERS[username]["balance"] -= amount
                            self.send_msg(conn, f"You successfully withdrew: ${amount}")
                        else:
                            self.send_msg(conn, "Insufficient funds.")
                    else:
                        self.send_msg(conn, "Unknown action.")
                else:
                    action = parts[0]
                    if action == "balance":
                        current = self.USERS[username]["balance"]
                        self.send_msg(conn, f"Your current balance is: ${current}")
                    else:
                        self.send_msg(conn, "Invalid request.")

                transaction_log(self.symKey, username=username, action=action_str)


        except Exception as main_err:
            print("[KDC ERROR] Transaction handling failed:", main_err)
            conn.close()

    def distribute_protocol(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.bind((self.host, self.port))
        self.socket_init = True
        connections = []
        print("Waiting for Client...")
        self.s.listen()

        for _ in range(MAX_CLIENTS):
            conn, addr = self.s.accept()
            connections.append(conn)
            try:
                self.clients.append(Thread(target=self.new_client, args=(conn, addr)))
                self.clients[-1].start()
                self.clients[-1].join()
            except KeyboardInterrupt:
                conn.close()
                print("Disconnected")

        for conn in connections:
            Thread(target=self.handle_transactions, args=(conn, connections)).start()

    def encrypt(self, Key, msg):
        cipher = AES.new(Key, AES.MODE_ECB)
        return cipher.encrypt(pad(msg.encode(), AES.block_size))


def main():
    KDC = Server(HOST, int(sys.argv[1]), "KDC")
    KDC.distribute_protocol()


if __name__ == "__main__":
    main()