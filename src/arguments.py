import hashlib
import json
from Conversion import bytes_to_hex, hex_to_bytes
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# AES-CBC-256 uses 32 byte keys
AES_key_bytes = 32

# Encrypts a string using a key provided in hex.
# Returns the IV and ciphertext in hex.
def encryAES(Plain_text: str, key_hex: str):
    # converts the hex key into bytes
    AES_key_bytes: bytes = hex_to_bytes(key_hex)
    # Creates the new cipher object
    cipher = AES.new(AES_key_bytes, AES.MODE_CBC)
    # Encrypts the plaintext
    encrypted_bytes = cipher.encrypt(pad(Plain_text.encode('utf-8'), AES.block_size))
    # Convert encrypted bytes to hex string
    encrypted_hex = bytes_to_hex(encrypted_bytes)
    # Converts the generated IV to hex string
    iv_hex = bytes_to_hex(cipher.iv)
    # Returns tuple with iv and encrypted hex
    return (iv_hex, encrypted_hex)


# Dencrypts a string using a key and IV provided in hex.
# Returns the Plain_text.
def decryAES(encrypted_hex: str, key_hex: str, iv_hex: str) -> str:
    encrypted_bytes = hex_to_bytes(encrypted_hex)
    AES_key_bytes = hex_to_bytes(key_hex)
    iv_bytes = hex_to_bytes(iv_hex)
    cipher = AES.new(AES_key_bytes, AES.MODE_CBC, iv_bytes)
    return unpad(cipher.decrypt(encrypted_bytes), AES.block_size)

# Encrypts a string using SHA256
# Returns the digest as
def encrySHA256(Plain_text: str) -> str:
    Plain_text_bytes = Plain_text.encode('utf-8')
    sha = hashlib.sha256()
    sha.update(Plain_text_bytes)
    digest_bytes = sha.digest()
    return bytes_to_hex(digest_bytes)


# Generates length number of bytes and returns it as a hex string
def key_generation(length: int):
    random_bytes = get_random_bytes(32)
    return bytes_to_hex(random_bytes)




class Index:
    #Maping through the Dict 
    data = {}

    def __init__(self, dataJson: str = None):
        if dataJson != None:
            self.data = json.loads(dataJson)

    def serialize(self) -> str:
        return json.dumps(self.data)

    #token is encrypted word
    #value is file name
    def addEntry(self, token, value):
        if (token in self.data):
            self.data[token].append(value)
        else:
            self.data[token] = [value]

    #Returns a list of files that the word can be found in for the search function
    def search(self, token) -> list:
        return self.data[token]
