from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from generateMAC import MAC
import os

MASTER_SECRET = 'b92135480b05ae68de59acfa95cd6c57'
BLOCK_SIZE = 16
LOG_FILE = "bank_transactions.log"

def decrypt_log_file():
    mac = MAC(MASTER_SECRET.encode())
    mac.generateMAC_KEY()
    sym_key = mac.symKey

    if not os.path.exists(LOG_FILE):
        print(" Log File not found")
        return

    print("\nDecrypted Audit Log\n" + "-" * 40)

    with open(LOG_FILE, 'rb') as f:
        lines = f.read().split(b'\n')  # Read entries separated by newlines

    entry_num = 1
    for line in lines:
        if not line.strip():
            continue
        try:
            cipher = AES.new(sym_key, AES.MODE_ECB)
            decrypted = unpad(cipher.decrypt(line.strip()), BLOCK_SIZE)
            print(f"{entry_num:02d}. {decrypted.decode()}")
            entry_num += 1
        except Exception as e:
            print(f"[ERROR decrypting entry {entry_num}]:", e)
            entry_num += 1

if __name__ == "__main__":
    decrypt_log_file()
