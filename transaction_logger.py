import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from datetime import datetime

def transaction_log(sym_key, username=None, action=None, raw=None):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if username and action:
        log_line = f"{username} | {action} | {timestamp}"
    elif raw:
        log_line = f"{raw} | {timestamp}"
    else:
        log_line = f"UNKNOWN | {timestamp}"

    #encrypt using AES
    cipher = AES.new(sym_key, AES.MODE_ECB)
    padded = pad(log_line.encode(), AES.block_size)
    encrypted = cipher.encrypt(padded)
    encoded = base64.b64encode(encrypted).decode()

    #print encrypted and decrypted logs
    print(f"[ENCRYPTED LOG] {encoded}")
    print(f"[DECRYPTED LOG] {log_line}")

    #write to logs.txt on local file
    with open("logs.txt", 'a') as f:
        f.write(encoded + "\n")
        f.write(log_line + "\n")
