import os
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from base64 import b64encode
from django.core.cache import cache
from django.utils import timezone

def generate_aes_key():
    return os.urandom(32)  # 256-bit key

def encrypt_file(file, aes_key):
    cipher = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(file.read())
    return cipher.nonce + tag + ciphertext  # combine all parts

def encrypt_aes_key_with_rsa(aes_key, public_key_pem):
    public_key = RSA.import_key(public_key_pem)
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_key = cipher_rsa.encrypt(aes_key)
    return encrypted_key


# Rate limit settings
MAX_ATTEMPTS_PER_IP = 7   # Number of allowed failed attempts
BLOCK_TIME_MINUTES = 1       # Duration to block the IP

def get_client_ip(request):
    """Get the client IP address from request headers."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

def is_ip_blocked(ip):
    """Check if the IP is blocked."""
    block_info = cache.get(f'blocked_{ip}')
    if block_info:
        return True
    return False

def register_failed_attempt(ip):
    """Register a failed login attempt for the given IP."""
    attempts = cache.get(ip, 0) + 1
    cache.set(ip, attempts, timeout=BLOCK_TIME_MINUTES * 60)  # Reset after BLOCK_TIME_MINUTES
    if attempts >= MAX_ATTEMPTS_PER_IP:
        cache.set(f'blocked_{ip}', True, timeout=BLOCK_TIME_MINUTES * 60)
        return True  # IP blocked
    return False

def reset_ip_attempts(ip):
    """Reset failed attempts for the IP after successful login."""
    cache.delete(ip)
    cache.delete(f'blocked_{ip}')

