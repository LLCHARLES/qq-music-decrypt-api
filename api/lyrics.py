# api/lyrics.py - 与C#代码完全一致的版本

from flask import Flask, request, jsonify, make_response
import urllib.request
import urllib.parse
import json
import zlib
import re
import xml.etree.ElementTree as ET
from enum import Enum

app = Flask(__name__)

# 全局设置JSON确保不使用ASCII编码
app.json.ensure_ascii = False

# ================ CORS 支持 ================
@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response

# ================ 辅助函数：返回JSON响应 ================
def json_response(data, status_code=200):
    """返回JSON响应，确保中文字符不被转义"""
    response = make_response(
        json.dumps(data, ensure_ascii=False, indent=None)
    )
    response.headers['Content-Type'] = 'application/json; charset=utf-8'
    response.status_code = status_code
    return response

# ================ DES算法实现 ================
class DESMode(Enum):
    DES_ENCRYPT = 1
    DES_DECRYPT = 0

# ================ DES 算法实现 ================
class DESMode(Enum):
    DES_ENCRYPT = 1
    DES_DECRYPT = 0

def bit_num(a, b, c):
    """对应 C# 中的 BITNUM 函数"""
    byte_index = (b // 32) * 4 + 3 - (b % 32) // 8
    bit_position = 7 - (b % 8)
    extracted_bit = (a[byte_index] >> bit_position) & 0x01
    return extracted_bit << c

def bit_num_int_r(a, b, c):
    """对应 C# 中的 BITNUMINTR 函数"""
    extracted_bit = (a >> (31 - b)) & 0x00000001
    return extracted_bit << c

def bit_num_int_l(a, b, c):
    """对应 C# 中的 BITNUMINTL 函数"""
    extracted_bit = (a << b) & 0x80000000
    return extracted_bit >> c

def s_box_bit(a):
    """对应 C# 中的 SBOXBIT 函数"""
    return (a & 0x20) | ((a & 0x1f) >> 1) | ((a & 0x01) << 4)

# S-box 表
s_box1 = [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
          0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
          4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
          15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]

s_box2 = [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
          3, 13, 4, 7, 15, 2, 8, 15, 12, 0, 1, 10, 6, 9, 11, 5,
          0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
          13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]

s_box3 = [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
          13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
          13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
          1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]

s_box4 = [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
          13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
          10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
          3, 15, 0, 6, 10, 10, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]

s_box5 = [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
          14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
          4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
          11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]

s_box6 = [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
          10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
          9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
          4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]

s_box7 = [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
          13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
          1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
          6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]

s_box8 = [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
          1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
          7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
          2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]

def ip(state, input_bytes):
    """Initial Permutation"""
    state[0] = (bit_num(input_bytes, 57, 31) | bit_num(input_bytes, 49, 30) | 
                bit_num(input_bytes, 41, 29) | bit_num(input_bytes, 33, 28) |
                bit_num(input_bytes, 25, 27) | bit_num(input_bytes, 17, 26) |
                bit_num(input_bytes, 9, 25) | bit_num(input_bytes, 1, 24) |
                bit_num(input_bytes, 59, 23) | bit_num(input_bytes, 51, 22) |
                bit_num(input_bytes, 43, 21) | bit_num(input_bytes, 35, 20) |
                bit_num(input_bytes, 27, 19) | bit_num(input_bytes, 19, 18) |
                bit_num(input_bytes, 11, 17) | bit_num(input_bytes, 3, 16) |
                bit_num(input_bytes, 61, 15) | bit_num(input_bytes, 53, 14) |
                bit_num(input_bytes, 45, 13) | bit_num(input_bytes, 37, 12) |
                bit_num(input_bytes, 29, 11) | bit_num(input_bytes, 21, 10) |
                bit_num(input_bytes, 13, 9) | bit_num(input_bytes, 5, 8) |
                bit_num(input_bytes, 63, 7) | bit_num(input_bytes, 55, 6) |
                bit_num(input_bytes, 47, 5) | bit_num(input_bytes, 39, 4) |
                bit_num(input_bytes, 31, 3) | bit_num(input_bytes, 23, 2) |
                bit_num(input_bytes, 15, 1) | bit_num(input_bytes, 7, 0))

    state[1] = (bit_num(input_bytes, 56, 31) | bit_num(input_bytes, 48, 30) |
                bit_num(input_bytes, 40, 29) | bit_num(input_bytes, 32, 28) |
                bit_num(input_bytes, 24, 27) | bit_num(input_bytes, 16, 26) |
                bit_num(input_bytes, 8, 25) | bit_num(input_bytes, 0, 24) |
                bit_num(input_bytes, 58, 23) | bit_num(input_bytes, 50, 22) |
                bit_num(input_bytes, 42, 21) | bit_num(input_bytes, 34, 20) |
                bit_num(input_bytes, 26, 19) | bit_num(input_bytes, 18, 18) |
                bit_num(input_bytes, 10, 17) | bit_num(input_bytes, 2, 16) |
                bit_num(input_bytes, 60, 15) | bit_num(input_bytes, 52, 14) |
                bit_num(input_bytes, 44, 13) | bit_num(input_bytes, 36, 12) |
                bit_num(input_bytes, 28, 11) | bit_num(input_bytes, 20, 10) |
                bit_num(input_bytes, 12, 9) | bit_num(input_bytes, 4, 8) |
                bit_num(input_bytes, 62, 7) | bit_num(input_bytes, 54, 6) |
                bit_num(input_bytes, 46, 5) | bit_num(input_bytes, 38, 4) |
                bit_num(input_bytes, 30, 3) | bit_num(input_bytes, 22, 2) |
                bit_num(input_bytes, 14, 1) | bit_num(input_bytes, 6, 0))
    return state

def inv_ip(state, output_bytes):
    """Inverse Initial Permutation"""
    output_bytes[3] = (bit_num_int_r(state[1], 7, 7) | bit_num_int_r(state[0], 7, 6) |
                       bit_num_int_r(state[1], 15, 5) | bit_num_int_r(state[0], 15, 4) |
                       bit_num_int_r(state[1], 23, 3) | bit_num_int_r(state[0], 23, 2) |
                       bit_num_int_r(state[1], 31, 1) | bit_num_int_r(state[0], 31, 0))

    output_bytes[2] = (bit_num_int_r(state[1], 6, 7) | bit_num_int_r(state[0], 6, 6) |
                       bit_num_int_r(state[1], 14, 5) | bit_num_int_r(state[0], 14, 4) |
                       bit_num_int_r(state[1], 22, 3) | bit_num_int_r(state[0], 22, 2) |
                       bit_num_int_r(state[1], 30, 1) | bit_num_int_r(state[0], 30, 0))

    output_bytes[1] = (bit_num_int_r(state[1], 5, 7) | bit_num_int_r(state[0], 5, 6) |
                       bit_num_int_r(state[1], 13, 5) | bit_num_int_r(state[0], 13, 4) |
                       bit_num_int_r(state[1], 21, 3) | bit_num_int_r(state[0], 21, 2) |
                       bit_num_int_r(state[1], 29, 1) | bit_num_int_r(state[0], 29, 0))

    output_bytes[0] = (bit_num_int_r(state[1], 4, 7) | bit_num_int_r(state[0], 4, 6) |
                       bit_num_int_r(state[1], 12, 5) | bit_num_int_r(state[0], 12, 4) |
                       bit_num_int_r(state[1], 20, 3) | bit_num_int_r(state[0], 20, 2) |
                       bit_num_int_r(state[1], 28, 1) | bit_num_int_r(state[0], 28, 0))

    output_bytes[7] = (bit_num_int_r(state[1], 3, 7) | bit_num_int_r(state[0], 3, 6) |
                       bit_num_int_r(state[1], 11, 5) | bit_num_int_r(state[0], 11, 4) |
                       bit_num_int_r(state[1], 19, 3) | bit_num_int_r(state[0], 19, 2) |
                       bit_num_int_r(state[1], 27, 1) | bit_num_int_r(state[0], 27, 0))

    output_bytes[6] = (bit_num_int_r(state[1], 2, 7) | bit_num_int_r(state[0], 2, 6) |
                       bit_num_int_r(state[1], 10, 5) | bit_num_int_r(state[0], 10, 4) |
                       bit_num_int_r(state[1], 18, 3) | bit_num_int_r(state[0], 18, 2) |
                       bit_num_int_r(state[1], 26, 1) | bit_num_int_r(state[0], 26, 0))

    output_bytes[5] = (bit_num_int_r(state[1], 1, 7) | bit_num_int_r(state[0], 1, 6) |
                       bit_num_int_r(state[1], 9, 5) | bit_num_int_r(state[0], 9, 4) |
                       bit_num_int_r(state[1], 17, 3) | bit_num_int_r(state[0], 17, 2) |
                       bit_num_int_r(state[1], 25, 1) | bit_num_int_r(state[0], 25, 0))

    output_bytes[4] = (bit_num_int_r(state[1], 0, 7) | bit_num_int_r(state[0], 0, 6) |
                       bit_num_int_r(state[1], 8, 5) | bit_num_int_r(state[0], 8, 4) |
                       bit_num_int_r(state[1], 16, 3) | bit_num_int_r(state[0], 16, 2) |
                       bit_num_int_r(state[1], 24, 1) | bit_num_int_r(state[0], 24, 0))
    return output_bytes

def f_func(state, key):
    """DES F function"""
    lrgstate = bytearray(6)
    
    # Expansion
    t1 = (bit_num_int_l(state, 31, 0) | ((state & 0xf0000000) >> 1) | bit_num_int_l(state, 4, 5) |
          bit_num_int_l(state, 3, 6) | ((state & 0x0f000000) >> 3) | bit_num_int_l(state, 8, 11) |
          bit_num_int_l(state, 7, 12) | ((state & 0x00f00000) >> 5) | bit_num_int_l(state, 12, 17) |
          bit_num_int_l(state, 11, 18) | ((state & 0x000f0000) >> 7) | bit_num_int_l(state, 16, 23))

    t2 = (bit_num_int_l(state, 15, 0) | ((state & 0x0000f000) << 15) | bit_num_int_l(state, 20, 5) |
          bit_num_int_l(state, 19, 6) | ((state & 0x00000f00) << 13) | bit_num_int_l(state, 24, 11) |
          bit_num_int_l(state, 23, 12) | ((state & 0x000000f0) << 11) | bit_num_int_l(state, 28, 17) |
          bit_num_int_l(state, 27, 18) | ((state & 0x0000000f) << 9) | bit_num_int_l(state, 0, 23))

    lrgstate[0] = (t1 >> 24) & 0x000000ff
    lrgstate[1] = (t1 >> 16) & 0x000000ff
    lrgstate[2] = (t1 >> 8) & 0x000000ff
    lrgstate[3] = (t2 >> 24) & 0x000000ff
    lrgstate[4] = (t2 >> 16) & 0x000000ff
    lrgstate[5] = (t2 >> 8) & 0x000000ff

    # XOR with key
    lrgstate[0] ^= key[0]
    lrgstate[1] ^= key[1]
    lrgstate[2] ^= key[2]
    lrgstate[3] ^= key[3]
    lrgstate[4] ^= key[4]
    lrgstate[5] ^= key[5]

    # S-box substitution
    state = ((s_box1[s_box_bit(lrgstate[0] >> 2)] << 28) |
             (s_box2[s_box_bit(((lrgstate[0] & 0x03) << 4) | (lrgstate[1] >> 4))] << 24) |
             (s_box3[s_box_bit(((lrgstate[1] & 0x0f) << 2) | (lrgstate[2] >> 6))] << 20) |
             (s_box4[s_box_bit(lrgstate[2] & 0x3f)] << 16) |
             (s_box5[s_box_bit(lrgstate[3] >> 2)] << 12) |
             (s_box6[s_box_bit(((lrgstate[3] & 0x03) << 4) | (lrgstate[4] >> 4))] << 8) |
             (s_box7[s_box_bit(((lrgstate[4] & 0x0f) << 2) | (lrgstate[5] >> 6))] << 4) |
             s_box8[s_box_bit(lrgstate[5] & 0x3f)])

    # P-box permutation
    state = (bit_num_int_l(state, 15, 0) | bit_num_int_l(state, 6, 1) | bit_num_int_l(state, 19, 2) |
             bit_num_int_l(state, 20, 3) | bit_num_int_l(state, 28, 4) | bit_num_int_l(state, 11, 5) |
             bit_num_int_l(state, 27, 6) | bit_num_int_l(state, 16, 7) | bit_num_int_l(state, 0, 8) |
             bit_num_int_l(state, 14, 9) | bit_num_int_l(state, 22, 10) | bit_num_int_l(state, 25, 11) |
             bit_num_int_l(state, 4, 12) | bit_num_int_l(state, 17, 13) | bit_num_int_l(state, 30, 14) |
             bit_num_int_l(state, 9, 15) | bit_num_int_l(state, 1, 16) | bit_num_int_l(state, 7, 17) |
             bit_num_int_l(state, 23, 18) | bit_num_int_l(state, 13, 19) | bit_num_int_l(state, 31, 20) |
             bit_num_int_l(state, 26, 21) | bit_num_int_l(state, 2, 22) | bit_num_int_l(state, 8, 23) |
             bit_num_int_l(state, 18, 24) | bit_num_int_l(state, 12, 25) | bit_num_int_l(state, 29, 26) |
             bit_num_int_l(state, 5, 27) | bit_num_int_l(state, 21, 28) | bit_num_int_l(state, 10, 29) |
             bit_num_int_l(state, 3, 30) | bit_num_int_l(state, 24, 31))

    return state

def des_key_schedule(key, schedule, mode):
    """DES key schedule"""
    key_rnd_shift = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
    key_perm_c = [56, 48, 40, 32, 24, 16, 8, 0, 57, 49, 41, 33, 25, 17,
                  9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35]
    key_perm_d = [62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21,
                  13, 5, 60, 52, 44, 36, 28, 20, 12, 4, 27, 19, 11, 3]
    key_compression = [13, 16, 10, 23, 0, 4, 2, 27, 14, 5, 20, 9,
                       22, 18, 11, 3, 25, 7, 15, 6, 26, 19, 12, 1,
                       40, 51, 30, 36, 46, 54, 29, 39, 50, 44, 32, 47,
                       43, 48, 38, 55, 33, 52, 45, 41, 49, 35, 28, 31]

    # Initial key permutation
    c = 0
    d = 0
    for i in range(28):
        c |= bit_num(key, key_perm_c[i], 31 - i)
        d |= bit_num(key, key_perm_d[i], 31 - i)

    # Generate 16 subkeys
    for i in range(16):
        c = ((c << key_rnd_shift[i]) | (c >> (28 - key_rnd_shift[i]))) & 0xfffffff0
        d = ((d << key_rnd_shift[i]) | (d >> (28 - key_rnd_shift[i]))) & 0xfffffff0

        if mode == DESMode.DES_DECRYPT:
            to_gen = 15 - i
        else:
            to_gen = i

        # Initialize subkey
        schedule[to_gen] = [0] * 6
        
        # Fill subkey
        for j in range(24):
            schedule[to_gen][j // 8] |= bit_num_int_r(c, key_compression[j], 7 - (j % 8))
        
        for j in range(24, 48):
            schedule[to_gen][j // 8] |= bit_num_int_r(d, key_compression[j] - 27, 7 - (j % 8))

def des_crypt(input_bytes, key_schedule):
    """DES encryption/decryption"""
    state = [0, 0]
    
    # Initial permutation
    ip(state, input_bytes)
    
    # 16 rounds
    for idx in range(15):
        t = state[1]
        state[1] = f_func(state[1], key_schedule[idx]) ^ state[0]
        state[0] = t
    
    # Final round (no swap)
    state[0] = f_func(state[1], key_schedule[15]) ^ state[0]
    
    # Inverse initial permutation
    output_bytes = bytearray(8)
    inv_ip(state, output_bytes)
    
    return output_bytes

def triple_des_key_setup(key, schedule, mode):
    """Triple DES key setup"""
    if mode == DESMode.DES_ENCRYPT:
        des_key_schedule(key[0:8], schedule[0], DESMode.DES_ENCRYPT)
        des_key_schedule(key[8:16], schedule[1], DESMode.DES_DECRYPT)
        des_key_schedule(key[16:24], schedule[2], DESMode.DES_ENCRYPT)
    else:  # DECRYPT
        des_key_schedule(key[0:8], schedule[2], DESMode.DES_DECRYPT)
        des_key_schedule(key[8:16], schedule[1], DESMode.DES_ENCRYPT)
        des_key_schedule(key[16:24], schedule[0], DESMode.DES_DECRYPT)

def triple_des_crypt(input_bytes, schedule):
    """Triple DES encryption/decryption"""
    # Create mutable bytearray
    if isinstance(input_bytes, bytes):
        data = bytearray(input_bytes)
    else:
        data = bytearray(input_bytes)
    
    # Ensure length is multiple of 8
    if len(data) % 8 != 0:
        padding = 8 - (len(data) % 8)
        data.extend([0] * padding)
    
    output = bytearray(len(data))
    
    # Process in 8-byte blocks
    for i in range(0, len(data), 8):
        block = data[i:i+8]
        
        # First DES
        temp = des_crypt(block, schedule[0])
        
        # Second DES
        temp = des_crypt(temp, schedule[1])
        
        # Third DES
        temp = des_crypt(temp, schedule[2])
        
        # Copy to output
        output[i:i+8] = temp
    
    return output

# ================ QQ 音乐解密核心 ================
# QQ Music 密钥
QQ_KEY = b'!@#)(*$%123ZXC!@!@#)(NHL'

def decrypt_qq_lyric(encrypted_hex):
    """解密QQ音乐歌词 - 对应C#的Decrypter.DecryptLyrics"""
    try:
        # 1. Hex字符串转字节
        encrypted_bytes = bytes.fromhex(encrypted_hex)
        
        # 2. 准备3DES密钥调度
        schedule = [[[0] * 6 for _ in range(16)] for _ in range(3)]
        
        # 3. 设置密钥
        triple_des_key_setup(QQ_KEY, schedule, DESMode.DES_DECRYPT)
        
        # 4. 解密
        decrypted_data = triple_des_crypt(encrypted_bytes, schedule)
        
        # 5. Zlib解压
        decompressed = zlib.decompress(decrypted_data)
        
        # 6. 返回UTF-8字符串（与C#完全一致，不做任何格式化）
        return decompressed.decode('utf-8')
        
    except Exception as e:
        raise Exception(f"解密失败: {str(e)}")

def remove_illegal_xml_content(content):
    """移除XML中的非法内容 - 对应C#的XmlUtils.RemoveIllegalContent"""
    i = 0
    while i < len(content):
        if content[i] == '<':
            left = i
        if i > 0 and content[i] == '>' and content[i-1] == '/':
            part = content[left:i+1]
            if '=' in part and part.find('=') == part.rfind('='):
                part1 = content[left:left + part.find('=')]
                if ' ' not in part1.strip():
                    content = content[:left] + content[i+1:]
                    i = 0
                    continue
        i += 1
    return content.strip()

def parse_xml_content(xml_content):
    """解析XML内容并提取歌词 - 与C#的Helper.GetLyricsAsync完全一致"""
    # 移除注释（与C#一致）
    xml_content = xml_content.replace('<!--', '').replace('-->', '')
    
    # 移除非法内容（与C#一致）
    xml_content = remove_illegal_xml_content(xml_content)
    
    try:
        # 修复&符号（与C#的ReplaceAmp一致）
        xml_content = re.sub(r'&(?![a-zA-Z]{2,6};|#[0-9]{2,4};)', '&amp;', xml_content)
        
        # 解析XML
        root = ET.fromstring(xml_content)
        
        # 查找歌词节点（与C#的VerbatimXmlMappingDict映射一致）
        result = {'lyrics': '', 'trans': ''}
        
        # 递归查找节点（简化版，与C#的XmlUtils.RecursionFindElement逻辑一致）
        def find_nodes(node, tag_name):
            """递归查找指定标签的节点"""
            if node.tag == tag_name:
                return node
            for child in node:
                found = find_nodes(child, tag_name)
                if found is not None:
                    return found
            return None
        
        # 查找content标签（原文歌词）
        content_node = find_nodes(root, 'content')
        if content_node is not None and content_node.text:
            try:
                result['lyrics'] = decrypt_qq_lyric(content_node.text.strip())
            except Exception as e:
                print(f"解密原文歌词失败: {e}")
                result['lyrics'] = ''
        
        # 查找contentts标签（翻译歌词）
        contentts_node = find_nodes(root, 'contentts')
        if contentts_node is not None and contentts_node.text:
            try:
                result['trans'] = decrypt_qq_lyric(contentts_node.text.strip())
            except Exception as e:
                print(f"解密翻译歌词失败: {e}")
                result['trans'] = ''
        
        return result
        
    except Exception as e:
        # XML解析失败，尝试使用正则表达式提取（降级处理）
        print(f"XML解析失败，尝试正则匹配: {e}")
        return extract_content_with_regex(xml_content)

def extract_content_with_regex(xml_content):
    """使用正则表达式从XML中提取内容（降级处理）"""
    result = {'lyrics': '', 'trans': ''}
    
    # 匹配<content>标签
    content_match = re.search(r'<content>(.*?)</content>', xml_content, re.DOTALL)
    if content_match:
        encrypted = content_match.group(1).strip()
        if encrypted:
            try:
                result['lyrics'] = decrypt_qq_lyric(encrypted)
            except Exception as e:
                print(f"解密原文歌词失败（正则）: {e}")
    
    # 匹配<contentts>标签
    contentts_match = re.search(r'<contentts>(.*?)</contentts>', xml_content, re.DOTALL)
    if contentts_match:
        encrypted = contentts_match.group(1).strip()
        if encrypted:
            try:
                result['trans'] = decrypt_qq_lyric(encrypted)
            except Exception as e:
                print(f"解密翻译歌词失败（正则）: {e}")
    
    return result

def get_song_by_mid(mid):
    """通过mid获取歌曲信息 - 对应C#的GetSong方法"""
    callback = 'getOneSongInfoCallback'
    params = {
        'songmid': mid,
        'tpl': 'yqq_song_detail',
        'format': 'jsonp',
        'callback': callback,
        'g_tk': '5381',
        'jsonpCallback': callback,
        'loginUin': '0',
        'hostUin': '0',
        'outCharset': 'utf8',
        'notice': '0',
        'platform': 'yqq',
        'needNewCode': '0'
    }
    
    url = 'https://c.y.qq.com/v8/fcg-bin/fcg_play_single_song.fcg?' + urllib.parse.urlencode(params)
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36',
        'Referer': 'https://c.y.qq.com/',
        'Cookie': 'os=pc;osver=Microsoft-Windows-10-Professional-build-16299.125-64bit;appver=2.0.3.131777;channel=netease;__remember_me=true'
    }
    
    req = urllib.request.Request(url, headers=headers)
    
    with urllib.request.urlopen(req, timeout=10) as response:
        data = response.read().decode('utf-8')
        
        # 移除JSONP包装（与C#一致）
        if data.startswith(callback + '('):
            data = data[len(callback) + 1:-2]
        
        return json.loads(data)

def get_lyrics_by_musicid(musicid):
    """通过musicid获取歌词 - 对应C#的GetLyricsAsync方法"""
    params = {
        'version': '15',
        'miniversion': '82',
        'lrctype': '4',
        'musicid': musicid
    }
    
    url = 'https://c.y.qq.com/qqmusic/fcgi-bin/lyric_download.fcg'
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36',
        'Referer': 'https://c.y.qq.com/',
        'Cookie': 'os=pc;osver=Microsoft-Windows-10-Professional-build-16299.125-64bit;appver=2.0.3.131777;channel=netease;__remember_me=true',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    
    data = urllib.parse.urlencode(params).encode('utf-8')
    req = urllib.request.Request(url, data=data, headers=headers)
    
    with urllib.request.urlopen(req, timeout=10) as response:
        xml_content = response.read().decode('utf-8')
        
        # 解析XML并解密歌词（与C#完全一致）
        return parse_xml_content(xml_content)

# ================ Flask 路由 ================
@app.route('/')
def index():
    return json_response({
        'name': 'QQ音乐歌词解密API',
        'version': '2.0.0',
        'description': '与C#代码完全一致的实现',
        'endpoints': {
            '/api/lyrics?musicid=<musicid>': '通过musicid获取歌词',
            '/api/lyrics/mid?mid=<mid>': '通过mid获取歌词',
            '/api/test': '测试接口',
            '/api/debug?hex=<hex>': '调试接口（直接解密）'
        },
        'example': '/api/lyrics?musicid=213836590'
    })

@app.route('/api/lyrics', methods=['GET'])
def get_lyrics_by_id():
    """通过musicid获取歌词"""
    musicid = request.args.get('musicid')
    
    if not musicid:
        return json_response({
            'success': False,
            'error': '缺少musicid参数',
            'example': '/api/lyrics?musicid=213836590'
        }, 400)
    
    try:
        # 调用函数获取歌词
        result = get_lyrics_by_musicid(musicid)
        
        if not result.get('lyrics') and not result.get('trans'):
            return json_response({
                'success': False,
                'error': '未找到歌词',
                'musicid': musicid
            }, 404)
        
        # 获取歌词文本（与C#完全一致，不做任何格式化）
        lyrics = result.get('lyrics', '')
        translation = result.get('trans', '')
        
        # 注意：C#代码没有处理BOM字符，但Python需要处理
        # 为了完全一致，我们也不处理BOM字符
        # if lyrics and lyrics.startswith('\ufeff'):
        #     lyrics = lyrics[1:]
        # if translation and translation.startswith('\ufeff'):
        #     translation = translation[1:]
        
        return json_response({
            'success': True,
            'musicid': musicid,
            'lyrics': lyrics,
            'translation': translation,
            'has_lyrics': bool(lyrics),
            'has_translation': bool(translation),
            'note': '逐字歌词格式保持原样，与C#代码完全一致'
        })
        
    except Exception as e:
        import traceback
        return json_response({
            'success': False,
            'error': '服务器内部错误',
            'message': str(e),
            'traceback': traceback.format_exc() if app.debug else None,
            'musicid': musicid
        }, 500)

@app.route('/api/lyrics/mid', methods=['GET'])
def get_lyrics_by_mid():
    """通过mid获取歌词"""
    mid = request.args.get('mid')
    
    if not mid:
        return json_response({
            'success': False,
            'error': '缺少mid参数',
            'example': '/api/lyrics/mid?mid=003F1P942q4lEs'
        }, 400)
    
    try:
        # 1. 通过mid获取歌曲信息
        song_data = get_song_by_mid(mid)
        
        if not song_data or 'data' not in song_data or not song_data['data']:
            return json_response({
                'success': False,
                'error': '未找到歌曲信息',
                'mid': mid
            }, 404)
        
        # 2. 获取musicid
        song_info = song_data['data'][0]
        musicid = song_info.get('id') or song_info.get('songid')
        if not musicid:
            return json_response({
                'success': False,
                'error': '未找到歌曲ID',
                'mid': mid
            }, 404)
        
        # 3. 通过musicid获取歌词
        result = get_lyrics_by_musicid(musicid)
        
        # 获取歌词文本（与C#完全一致，不做任何格式化）
        lyrics = result.get('lyrics', '')
        translation = result.get('trans', '')
        
        return json_response({
            'success': True,
            'mid': mid,
            'musicid': musicid,
            'lyrics': lyrics,
            'translation': translation,
            'has_lyrics': bool(lyrics),
            'has_translation': bool(translation),
            'song_info': {
                'id': musicid,
                'mid': mid,
                'name': song_info.get('name', ''),
                'title': song_info.get('title', ''),
                'singer': song_info.get('singer', [{}])[0].get('name', '') if song_info.get('singer') else ''
            },
            'note': '逐字歌词格式保持原样，与C#代码完全一致'
        })
        
    except Exception as e:
        import traceback
        return json_response({
            'success': False,
            'error': '服务器内部错误',
            'message': str(e),
            'traceback': traceback.format_exc() if app.debug else None,
            'mid': mid
        }, 500)

@app.route('/api/test', methods=['GET'])
def test():
    """测试接口"""
    return json_response({
        'success': True,
        'message': 'API运行正常',
        'timestamp': '2023-01-01T00:00:00Z',
        'endpoints': [
            {'path': '/api/lyrics?musicid=<id>', 'method': 'GET', 'description': '通过musicid获取歌词'},
            {'path': '/api/lyrics/mid?mid=<mid>', 'method': 'GET', 'description': '通过mid获取歌词'},
            {'path': '/api/test', 'method': 'GET', 'description': '测试接口'},
            {'path': '/api/debug?hex=<hex>', 'method': 'GET', 'description': '调试接口（直接解密）'}
        ]
    })

@app.route('/api/debug', methods=['GET'])
def debug():
    """调试接口：直接测试解密"""
    hex_str = request.args.get('hex')
    if not hex_str:
        return json_response({
            'success': False,
            'error': '缺少hex参数',
            'example': '/api/debug?hex=加密的16进制字符串'
        }, 400)
    
    try:
        decrypted = decrypt_qq_lyric(hex_str)
        return json_response({
            'success': True,
            'original_length': len(hex_str),
            'decrypted_length': len(decrypted),
            'decrypted': decrypted[:500] + '...' if len(decrypted) > 500 else decrypted,
            'is_xml': '<?xml' in decrypted[:20],
            'note': '直接解密，不做任何格式化'
        })
    except Exception as e:
        import traceback
        return json_response({
            'success': False,
            'error': str(e),
            'traceback': traceback.format_exc() if app.debug else None
        }, 500)

# 用于Vercel
application = app

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=3000)
