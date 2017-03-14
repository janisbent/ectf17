"""
Some helper function to make AES and signing easier to use
"""

from Crypto.Cipher import AES  # pip install pycrypto
from hashlib import sha256
from hmac import HMAC
from ecdsa import SigningKey

def numtohex(n):
    """
    Converts a python large integer to the format used in nano-ecc
    """
    rn = hex(n)[2:-1].rjust(48,'0').decode('hex')
    rn = rn[::-1].encode('hex')
    return rn

def pk_to_necc(vk):
    """
    Converts a ecdsa public key into the format used in nano-ecc
    """
    pkx = numtohex(vk.pubkey.point.x())
    pky = numtohex(vk.pubkey.point.y())
    return (pkx + pky)


def sign(hsh, keys):
    """
    Given a hash, signs data and returns signature in a format for nano-ecc
    """
    sig_hsh = int(hsh[:24][::-1].encode('hex'), 16)
    key = SigningKey.from_pem(str(keys['sign_key']))
    sig = key.sign_number(sig_hsh)

    r_str = numtohex(sig[0])
    s_str = numtohex(sig[1])

    return (r_str + s_str).decode('hex')

def standalone_sign(data, keys):
    """ Encrypts the given data and prepends it with a signature

    The output is the following:
    [sign(sha256(data)) 48 bytes][hmac(sha256(data)) 32 bytes]
    """
    hsh = sha256(data).digest()
    hmac = HMAC(keys['hmac_key'], hsh, sha256).digest()
    sig = sign(hsh, keys)
    print 'HASH:', hsh.encode('hex')
    print 'HMAC:', hmac.encode('hex')
    print 'SIGN:', sig.encode('hex')
    return sig + hmac

def enc_and_sign(data, keys):
    """ Encrypts the given data and prepends it with a signature

    The output is the following:
    [sign(sha256(data)) 48 bytes][hmac(sha256(data)) 32 bytes][AES(data) .... ]
    """
    ctxt = aes_encrypt(data, (keys['firm_key']), (keys['firm_iv']))
    hsh = sha256(ctxt).digest()
    hmac = HMAC(keys['hmac_key'], hsh, sha256).digest()
    sig = sign(hsh, keys)
    print 'HASH:', hsh.encode('hex')
    print 'HMAC:', hmac.encode('hex')
    print 'CTXT:', ctxt.encode('hex')
    print 'SIGN:', sig.encode('hex')
    return sig + hmac + ctxt

def hmac_sign(data, keys):
    hsh = sha256(data).digest()
    sig = HMAC(keys['hmac_key'], hsh, sha256).digest()
    print 'HASH:', hsh.encode('hex')
    print 'SIGN:', sig.encode('hex')
    return sig


def aes_encrypt(data, key, iv):
    return AES.new(key, AES.MODE_CBC, iv).encrypt(_pad(data))


def aes_decrypt(data, key, iv):
    return AES.new(key, AES.MODE_CBC, iv).decrypt(data)


def _pad(s):
    s = str(s)
    return s + ((AES.block_size - len(s) % AES.block_size) % AES.block_size) * '\x00'
