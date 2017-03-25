#!/usr/bin/env python2
"""
Python-Norx interface via norx.so
"""

import os
import sys
from ctypes import *
from binascii import unhexlify, hexlify

FILE_DIR = os.path.abspath(os.path.dirname(__file__))
norxlib = CDLL(os.path.join(FILE_DIR, 'norx', 'norx.so'))

norxlib.norx_aead_decrypt.argtypes = [POINTER(c_char), POINTER(c_size_t),
                                      POINTER(c_char), c_size_t,
                                      POINTER(c_char), c_size_t,
                                      POINTER(c_char), c_size_t,
                                      POINTER(c_char), POINTER(c_char)]

norxlib.norx_aead_encrypt.argtypes = [POINTER(c_char), POINTER(c_size_t),
                                      POINTER(c_char), c_size_t,
                                      POINTER(c_char), c_size_t,
                                      POINTER(c_char), c_size_t,
                                      POINTER(c_char), POINTER(c_char)]

def aead_decrypt(hdr, msg, ftr, nce, key):
    c_out = (c_char * len(msg))()
    c_outlen = c_size_t()

    ret = norxlib.norx_aead_decrypt(c_out, byref(c_outlen),
                                    hdr, len(hdr),
                                    msg, len(msg),
                                    ftr, len(ftr),
                                    nce, key);

    if ret != 0:
        raise Exception("Failed decryption!")

    return c_out[:c_outlen.value]

def aead_encrypt(hdr, msg, ftr, nce, key):
    # Tag size is at most 10 * wordsize = +80 bytes
    c_out = (c_char * (len(msg) + 80))()
    c_outlen = c_size_t()

    norxlib.norx_aead_encrypt(c_out, byref(c_outlen),
                              hdr, len(hdr),
                              msg, len(msg),
                              ftr, len(ftr),
                              nce, key);


    return c_out[:c_outlen.value]
