# HKDF Key Derivation Function

import hmac
import hashlib

def hkdf(key, length, info=b'', salt=b'', hash_name='sha256'):
    if not salt:
        hash_obj = hashlib.new(hash_name)
        salt = b'\0' * hash_obj.digest_size
    
    # Extract
    prk = hmac.new(salt, key, getattr(hashlib, hash_name)).digest()
    
    # Expand
    blocks = []
    block = b''
    
    i = 0
    while len(b''.join(blocks)) < length:
        i += 1
        block = hmac.new(
            prk,
            block + info + bytes([i]),
            getattr(hashlib, hash_name)
        ).digest()
        blocks.append(block)
    
    return b''.join(blocks)[:length]


# Donwload Media
import requests

def download_file(url, debug=None):
    if debug is None:
        debug = {}
    
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        
        debug['http_code'] = response.status_code
        debug['downloaded_size'] = len(response.content)
        
        return response.content
    except requests.exceptions.RequestException as e:
        debug['error'] = str(e)
        return False

# Decrypt Function
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def try_decrypt(encrypted, cipher_key, iv, debug=None):
    if debug is None:
        debug = {}
        
    trunc_lengths = [0, 10, 16, 32]
    
    for length in trunc_lengths:
        try:
            cut = encrypted[:-length] if length > 0 else encrypted
            cipher = AES.new(cipher_key, AES.MODE_CBC, iv)
            decrypted = cipher.decrypt(cut)
            
            # Try to unpad - if this fails, the decryption was likely incorrect
            try:
                decrypted = unpad(decrypted, AES.block_size)
            except Exception:
                # If unpadding fails, try the next truncation
                continue
                
            debug['decrypted_size'] = len(decrypted)
            debug['truncate_bytes'] = length
            return decrypted
            
        except Exception:
            continue
            
    debug['decrypt_error'] = "Decryption failed for all truncation attempts"
    return False

# Usage Example
import base64
import requests

payload = {
    "payload": {
        "imageMessage": {
            "url": "https://mmg.whatsapp.net/d/f/example-image-url.enc",
            "mediaKey": "ExAmPleB@s364+EnC0d3dM3dIaK3y="
        }
    }
}

debug = {}

def download_file(url, debug):
    try:
        resp = requests.get(url)
        resp.raise_for_status()
        return resp.content
    except Exception as e:
        debug['error'] = str(e)
        return False

def decrypt_media(encrypted_data, media_key, debug, media_type):
    # You need to implement this based on WhatsApp's media decryption spec
    # Placeholder function
    debug['decrypt_error'] = 'decryptMedia not implemented'
    return False

url = payload['payload']['imageMessage']['url']
media_key = payload['payload']['imageMessage']['mediaKey']
encrypted = download_file(url, debug)

if encrypted:
    decrypted = decrypt_media(encrypted, media_key, debug, 'Image')

    if decrypted:
        base64_data = base64.b64encode(decrypted).decode('utf-8')
        data_uri = f'data:image/jpeg;base64,{base64_data}'
        print(f"Decryption successful! Data URI length: {len(data_uri)}")
    else:
        print("Decryption failed:", debug.get('decrypt_error', 'Unknown error'))
else:
    print("Download failed:", debug.get('error', 'Unknown error'))
