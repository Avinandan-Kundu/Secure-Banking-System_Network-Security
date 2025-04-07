import socket
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from generateMAC import MAC
import sys
from threading import Thread
from datetime import datetime
import os
import base64

HOST = "127.0.0.1"  # Standard loopback interface address (localhost)
PORT = 6000  # Port to listen on (non-privileged ports are > 1023)
LOG_FILE = "bank_transactions.log"
MAX_CLIENTS = 3  # Number of ATM clients that can connect to the bank server
USERS = {
    "Avinandan": {"pswd": "Avinandan", "balance": 1000},
    "Samiul": {"pswd": "Samiul", "balance": 1000},
    "Raiyan": {"pswd": "Raiyan", "balance": 1000},
    "Roy": {"pswd": "Roy", "balance": 1000}
}


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

    def new_client(self, conn, addr):

        try:
            print(f"Connected by {addr}")
            # Recieve client id
            while True:
                client_Identity = conn.recv(1024)
                if client_Identity:
                    break
            print("ID: ", client_Identity.decode())

            Nk1 = get_random_bytes(16).hex()
            challenge = Nk1 + "||" + self.id
            print("[NK1||IDK]:\n", challenge)
            conn.send(challenge.encode())

            # Message 2, challenge response
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

            # Challenge response
            conn.send(NA.encode())

            # Key transfer
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

    def broadcast(self, conn, connections, message):
        for c in connections:
            c.send(message)
        return
    
    def log_transaction(self, d_msg, e_msg=None):
        today = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(LOG_FILE, 'a') as f:
            if e_msg:
                f.write(f"{today} - {e_msg}\n")
            f.write(f"{today} - {d_msg}\n")
    
    def send_msg(self, conn, msg):
        msg_byte = msg.encode() + '||'.encode() + get_random_bytes(16)
        message, tag = self.gen_MAC.encrypt(msg_byte)
        print('Encrypted Message:' + str(message))
        conn.send(message + '||'.encode() + tag)
    
    def receive_msg(self, conn):
        received = conn.recv(1024)

        if received:
            print('Encrypted Message Received:', received)
            split_message = received.split('||'.encode())
            plaintext = self.gen_MAC.decrypt(split_message[0], split_message[1])
            msg = plaintext.split(
                '||'.encode())[0].decode().split('||')[0]
            
            return received, msg
        
        return False
    
    def login(self, username, password):
        try:
            if USERS[username]["pswd"] == password:
                print(f"{username} has successfully logged in.\n")
                return True
            else:
                print("Password is incorrect.")
        except KeyError:
            print("Username not found.")
            
        return False

    def handle_transactions(self, conn, connections):
        _, msg = self.receive_msg(conn)
        username, password = str(msg).split(':')
        while not self.login(username, password):
            self.send_msg(conn, "failed")
            _, msg = self.receive_msg(conn)
            username, password = str(msg[0]).split(':')

        self.send_msg(conn, "success")
        self.log_transaction(d_msg=f"{username} has successfully logged in.")

        while (True):
            received, msg = self.receive_msg(conn)
            if received:
                # Log the message
                self.log_transaction(msg, str(received))
                msg_tuple = msg.split(":")
                if len(msg_tuple) > 1:
                    action, amount = msg_tuple
                    try:
                        amount = int(amount)
                        if amount < 0:
                            self.send_msg(conn, "Amount should never be negative. Action failed.")
                            self.log_transaction("Invalid Transaction\n", None)
                            continue
                    except ValueError:
                        raise ValueError("Amount received is not integer. This error should never occur~")
                    if action == "deposit":
                        USERS[username]["balance"] += amount
                        self.send_msg(conn, f"You successfully deposited {amount}")
                    elif action == "withdraw":
                        if USERS[username]["balance"] - amount >= 0:
                            USERS[username]["balance"] -= amount
                            self.send_msg(conn, f"You successfully withdrew {amount}")
                        else:
                            self.send_msg(conn, f"Insufficient funds.")
                            self.log_transaction("Isufficient funds\n", None)

                            continue
                    else:
                        raise Exception("This action should never be received! (msg_tuple > 1)")
                else:
                    action = msg_tuple[0]
                    if action == "balance":
                        self.send_msg(conn, f"Your current balance is: " + str(USERS[username]["balance"]))
                    else:
                        raise Exception("This action should never be received! (msg_tuple <= 1)")
                    

            

    def distribute_protocol(self):
        self.nonces_Seen = set()
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
                self.clients.append(
                    Thread(target=self.new_client, args=(conn, addr)))
                self.clients[-1].start()
                self.clients[-1].join()

            except KeyboardInterrupt:
                conn.close()
                print("Disconnected")
        for conn in connections:
            Thread(target=self.handle_transactions,
                   args=(conn, connections)).start()

    def encrypt(self, Key, msg):
        cipher = AES.new(Key, AES.MODE_ECB)
        ciphertext = cipher.encrypt(pad(msg.encode(), AES.block_size))
        return ciphertext


def main():
    KDC = Server(HOST, int(sys.argv[1]), "KDC")
    KDC.distribute_protocol()


if __name__ == "__main__":

    main()
