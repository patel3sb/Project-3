# -*- coding: utf-8 -*-
"""
Created on Mon Oct  7 13:06:56 2019

@author: Jsmit_1n8uqvk
"""
#conversion function
def bytes_to_hex(data: bytes, byte_order = 'big') -> str:
    integer = int.from_bytes(data, byte_order)
    return hex(integer)[2:]

def hex_to_bytes(data: str, byte_order = 'big') -> bytes:
    return bytearray.fromhex(data)
