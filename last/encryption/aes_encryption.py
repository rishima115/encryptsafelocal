from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

BLOCK_SIZE = 16  # AES block size

def encrypt_password(password, key):
    """
    Encrypts the password using AES encryption and a provided key.
    """
    # Ensure the key is exactly BLOCK_SIZE (16 bytes)
    key = key.ljust(BLOCK_SIZE)[:BLOCK_SIZE].encode("utf-8")
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    encrypted_bytes = cipher.encrypt(pad(password.encode("utf-8"), BLOCK_SIZE))
    # Combine IV and encrypted bytes, and encode as Base64
    encrypted_data = base64.b64encode(iv + encrypted_bytes).decode("utf-8")
    return encrypted_data

def decrypt_password(encrypted_password, key):
    """
    Decrypts the password using AES encryption and the provided key.
    """
    try:
        # Ensure the key is exactly BLOCK_SIZE (16 bytes)
        key = key.ljust(BLOCK_SIZE)[:BLOCK_SIZE].encode("utf-8")
        encrypted_data = base64.b64decode(encrypted_password)
        iv = encrypted_data[:BLOCK_SIZE]
        encrypted_bytes = encrypted_data[BLOCK_SIZE:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_bytes = unpad(cipher.decrypt(encrypted_bytes), BLOCK_SIZE)
        return decrypted_bytes.decode("utf-8")
    except (ValueError, KeyError):
        # Error occurs if the key is wrong or data is corrupted
        raise ValueError("Decryption failed. Incorrect key or corrupted data.")
