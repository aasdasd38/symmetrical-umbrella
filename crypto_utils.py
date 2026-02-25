from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
import base64

def generate_rsa_keypair():
    """Generate a new RSA key pair (private + public)."""
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def encrypt_message(public_key_pem, plaintext):
    """
    Encrypt a message using hybrid encryption:
    - Generate a random AES key and nonce.
    - Encrypt plaintext with AES-GCM.
    - Encrypt the AES key with the recipient's RSA public key.
    Returns a base64 string containing all components.
    """
    # Import recipient's public key
    recipient_key = RSA.import_key(public_key_pem)
    # Generate AES key and nonce
    aes_key = get_random_bytes(32)          # 256-bit key
    nonce = get_random_bytes(12)             # GCM recommended nonce length
    cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher_aes.encrypt_and_digest(plaintext.encode('utf-8'))

    # Encrypt AES key with RSA
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_aes_key = cipher_rsa.encrypt(aes_key)

    # Package: enc_aes_key + nonce + tag + ciphertext
    # Convert all to bytes and then to base64 for easy JSON transport
    package = enc_aes_key + nonce + tag + ciphertext
    return base64.b64encode(package).decode('utf-8')

def decrypt_message(private_key_pem, encrypted_b64):
    """
    Decrypt a message using the private RSA key.
    Returns the plaintext string.
    """
    package = base64.b64decode(encrypted_b64)
    # Import private key
    private_key = RSA.import_key(private_key_pem)

    # Extract components
    rsa_key_size = private_key.size_in_bytes()
    enc_aes_key = package[:rsa_key_size]
    nonce = package[rsa_key_size:rsa_key_size+12]
    tag = package[rsa_key_size+12:rsa_key_size+12+16]
    ciphertext = package[rsa_key_size+12+16:]

    # Decrypt AES key
    cipher_rsa = PKCS1_OAEP.new(private_key)
    aes_key = cipher_rsa.decrypt(enc_aes_key)

    # Decrypt message
    cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher_aes.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode('utf-8')