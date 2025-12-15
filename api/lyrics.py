# api/lyrics.py - 修复QRC歌词完整过滤
from flask import Flask, request, jsonify, make_response
import urllib.request
import urllib.parse
import json
import zlib
import re
import xml.etree.ElementTree as ET
from enum import Enum
import base64
import time
import html  # 添加html模块用于解码HTML实体

app = Flask(__name__)
app.json.ensure_ascii = False

# ================ CORS 支持 ================
@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response

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

def bit_num(a, b, c):
    byte_index = (b // 32) * 4 + 3 - (b % 32) // 8
    bit_position = 7 - (b % 8)
    extracted_bit = (a[byte_index] >> bit_position) & 0x01
    return extracted_bit << c

def bit_num_int_r(a, b, c):
    extracted_bit = (a >> (31 - b)) & 0x00000001
    return extracted_bit << c

def bit_num_int_l(a, b, c):
    extracted_bit = (a << b) & 0x80000000
    return extracted_bit >> c

def s_box_bit(a):
    return (a & 0x20) | ((a & 0x1f) >> 1) | ((a & 0x01) << 4)

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
    lrgstate = bytearray(6)
    
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

    lrgstate[0] ^= key[0]
    lrgstate[1] ^= key[1]
    lrgstate[2] ^= key[2]
    lrgstate[3] ^= key[3]
    lrgstate[4] ^= key[4]
    lrgstate[5] ^= key[5]

    state = ((s_box1[s_box_bit(lrgstate[0] >> 2)] << 28) |
             (s_box2[s_box_bit(((lrgstate[0] & 0x03) << 4) | (lrgstate[1] >> 4))] << 24) |
             (s_box3[s_box_bit(((lrgstate[1] & 0x0f) << 2) | (lrgstate[2] >> 6))] << 20) |
             (s_box4[s_box_bit(lrgstate[2] & 0x3f)] << 16) |
             (s_box5[s_box_bit(lrgstate[3] >> 2)] << 12) |
             (s_box6[s_box_bit(((lrgstate[3] & 0x03) << 4) | (lrgstate[4] >> 4))] << 8) |
             (s_box7[s_box_bit(((lrgstate[4] & 0x0f) << 2) | (lrgstate[5] >> 6))] << 4) |
             s_box8[s_box_bit(lrgstate[5] & 0x3f)])

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
    key_rnd_shift = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
    key_perm_c = [56, 48, 40, 32, 24, 16, 8, 0, 57, 49, 41, 33, 25, 17,
                  9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35]
    key_perm_d = [62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21,
                  13, 5, 60, 52, 44, 36, 28, 20, 12, 4, 27, 19, 11, 3]
    key_compression = [13, 16, 10, 23, 0, 4, 2, 27, 14, 5, 20, 9,
                       22, 18, 11, 3, 25, 7, 15, 6, 26, 19, 12, 1,
                       40, 51, 30, 36, 46, 54, 29, 39, 50, 44, 32, 47,
                       43, 48, 38, 55, 33, 52, 45, 41, 49, 35, 28, 31]

    c = 0
    d = 0
    for i in range(28):
        c |= bit_num(key, key_perm_c[i], 31 - i)
        d |= bit_num(key, key_perm_d[i], 31 - i)

    for i in range(16):
        c = ((c << key_rnd_shift[i]) | (c >> (28 - key_rnd_shift[i]))) & 0xfffffff0
        d = ((d << key_rnd_shift[i]) | (d >> (28 - key_rnd_shift[i]))) & 0xfffffff0

        if mode == DESMode.DES_DECRYPT:
            to_gen = 15 - i
        else:
            to_gen = i

        schedule[to_gen] = [0] * 6
        
        for j in range(24):
            schedule[to_gen][j // 8] |= bit_num_int_r(c, key_compression[j], 7 - (j % 8))
        
        for j in range(24, 48):
            schedule[to_gen][j // 8] |= bit_num_int_r(d, key_compression[j] - 27, 7 - (j % 8))

def des_crypt(input_bytes, key_schedule):
    state = [0, 0]
    
    ip(state, input_bytes)
    
    for idx in range(15):
        t = state[1]
        state[1] = f_func(state[1], key_schedule[idx]) ^ state[0]
        state[0] = t
    
    state[0] = f_func(state[1], key_schedule[15]) ^ state[0]
    
    output_bytes = bytearray(8)
    inv_ip(state, output_bytes)
    
    return output_bytes

def triple_des_key_setup(key, schedule, mode):
    if mode == DESMode.DES_ENCRYPT:
        des_key_schedule(key[0:8], schedule[0], DESMode.DES_ENCRYPT)
        des_key_schedule(key[8:16], schedule[1], DESMode.DES_DECRYPT)
        des_key_schedule(key[16:24], schedule[2], DESMode.DES_ENCRYPT)
    else:
        des_key_schedule(key[0:8], schedule[2], DESMode.DES_DECRYPT)
        des_key_schedule(key[8:16], schedule[1], DESMode.DES_ENCRYPT)
        des_key_schedule(key[16:24], schedule[0], DESMode.DES_DECRYPT)

def triple_des_crypt(input_bytes, schedule):
    if isinstance(input_bytes, bytes):
        data = bytearray(input_bytes)
    else:
        data = bytearray(input_bytes)
    
    if len(data) % 8 != 0:
        padding = 8 - (len(data) % 8)
        data.extend([0] * padding)
    
    output = bytearray(len(data))
    
    for i in range(0, len(data), 8):
        block = data[i:i+8]
        temp = des_crypt(block, schedule[0])
        temp = des_crypt(temp, schedule[1])
        temp = des_crypt(temp, schedule[2])
        output[i:i+8] = temp
    
    return output

# ================ 统一歌词过滤系统（修复QRC处理） ================
def contains_colon(text):
    """检查是否包含冒号（中英文冒号）"""
    if not text:
        return False
    return ':' in text or '：' in text

def contains_bracket_tag(text):
    """检查是否包含括号标签"""
    if not text:
        return False
    has_half_pair = '[' in text and ']' in text
    has_full_pair = '【' in text and '】' in text
    return has_half_pair or has_full_pair

def contains_paren_pair(text):
    """检查是否包含圆括号对"""
    if not text:
        return False
    has_half_pair = '(' in text and ')' in text
    has_full_pair = '（' in text and '）' in text
    return has_half_pair or has_full_pair

def is_license_warning_line(text):
    """检查是否是版权警告行"""
    if not text:
        return False
    
    special_keywords = ['文曲大模型', '享有本翻译作品的著作权']
    for keyword in special_keywords:
        if keyword in text:
            return True
    
    tokens = ['未经', '许可', '授权', '不得', '请勿', '使用', '版权', '翻唱']
    count = 0
    for token in tokens:
        if token in text:
            count += 1
    return count >= 3

def extract_plain_text_from_yrc(yrc_content):
    """从YRC内容中提取纯文本（移除时间标记）"""
    if not yrc_content:
        return ''
    
    plain_text = ''
    current_pos = 0
    
    while current_pos < len(yrc_content):
        paren_index = yrc_content.find('(', current_pos)
        
        if paren_index == -1:
            plain_text += yrc_content[current_pos:]
            break
        
        plain_text += yrc_content[current_pos:paren_index]
        
        close_paren_index = yrc_content.find(')', paren_index)
        if close_paren_index == -1:
            break
        
        current_pos = close_paren_index + 1
    
    return plain_text.strip()

def preprocess_lyric_lines(lyric_content, lyric_type='lrc'):
    """预处理歌词行（LRC和QRC/YRC）"""
    if not lyric_content:
        return []
    
    lines = lyric_content.replace('\r\n', '\n').split('\n')
    
    # 移除元数据标签行
    filtered_lines = []
    for line in lines:
        trimmed = line.strip()
        if not re.match(r'^\[(ti|ar|al|by|offset|t_time|kana|lang|total):.*\]$', trimmed, re.IGNORECASE):
            filtered_lines.append(line)
    
    parsed_lines = []
    
    if lyric_type == 'lrc':
        # 解析LRC格式行
        for line in filtered_lines:
            match = re.match(r'^(\[[0-9:.]+\])(.*)$', line)
            if match:
                plain_text = match.group(2).strip()
                plain_text = re.sub(r'\[.*?\]', '', plain_text)
                
                parsed_lines.append({
                    'raw': line,
                    'timestamp': match.group(1),
                    'text': match.group(2).strip(),
                    'plainText': plain_text.strip(),
                    'type': 'lrc'
                })
            elif line.strip():
                # 纯文本行
                parsed_lines.append({
                    'raw': line,
                    'timestamp': '',
                    'text': line.strip(),
                    'plainText': line.strip(),
                    'type': 'text'
                })
    
    elif lyric_type == 'qrc':
        # 解析QRC/YRC格式行 - 只匹配YRC格式
        for line in filtered_lines:
            # 匹配YRC格式：[开始时间,持续时间]内容
            match = re.match(r'^\[(\d+),(\d+)\](.*)$', line)
            if match:
                start_time = int(match.group(1))
                duration = int(match.group(2))
                content = match.group(3).strip()
                plain_text = extract_plain_text_from_yrc(content)
                
                parsed_lines.append({
                    'raw': line,
                    'startTime': start_time,
                    'duration': duration,
                    'content': content,
                    'plainText': plain_text,
                    'type': 'qrc'
                })
            elif line.strip():
                # QRC中不应该有LRC格式行，但如果有其他内容，作为纯文本处理
                parsed_lines.append({
                    'raw': line,
                    'timestamp': '',
                    'text': line.strip(),
                    'plainText': line.strip(),
                    'type': 'text'
                })
    
    return parsed_lines

def filter_lyric_lines(parsed_lines, lyric_type='lrc'):
    """通用的歌词行过滤函数（LRC和QRC/YRC共用）"""
    if not parsed_lines:
        return []
    
    filtered = parsed_lines.copy()
    
    # 1) 前三行内：含 '-' 的行直接删除（标题行）
    i = 0
    scan_limit = min(3, len(filtered))
    while i < scan_limit:
        text = filtered[i]['plainText']
        if '-' in text:
            filtered.pop(i)
            scan_limit = min(3, len(filtered))
            continue
        else:
            i += 1
    
    # 2) 前三行内：含冒号的行直接删除
    removed_a2_colon = False
    i = 0
    scan_limit = min(3, len(filtered))
    while i < scan_limit:
        text = filtered[i]['plainText']
        if contains_colon(text):
            filtered.pop(i)
            removed_a2_colon = True
            scan_limit = min(3, len(filtered))
            continue
        else:
            i += 1
    
    # 3) 处理"开头连续冒号行"
    leading = 0
    while leading < len(filtered):
        text = filtered[leading]['plainText']
        if contains_colon(text):
            leading += 1
        else:
            break
    
    if removed_a2_colon:
        if leading >= 1:
            filtered = filtered[leading:]
    else:
        if leading >= 2:
            filtered = filtered[leading:]
    
    # 4) 制作行（全局）：删除任意位置出现的"连续 ≥2 行均含冒号"的区间
    new_filtered = []
    i = 0
    while i < len(filtered):
        text = filtered[i]['plainText']
        if contains_colon(text):
            j = i
            while j < len(filtered):
                tj = filtered[j]['plainText']
                if contains_colon(tj):
                    j += 1
                else:
                    break
            run_len = j - i
            if run_len >= 2:
                i = j
            else:
                new_filtered.append(filtered[i])
                i = j
        else:
            new_filtered.append(filtered[i])
            i += 1
    filtered = new_filtered
    
    # 5) 全局删除：凡包含【】或 [] 的行一律删除
    # 对于QRC/YRC格式，时间标签 [数字,数字] 需要保留
    new_filtered = []
    for line in filtered:
        text = line['plainText']
        
        # 对于QRC/YRC格式，[数字,数字] 是时间标签，不是要过滤的标签
        if line['type'] == 'qrc' and re.match(r'^\[\d+,\d+\]', line['raw']):
            # 检查纯文本部分是否包含标签
            if contains_bracket_tag(text):
                continue
            else:
                new_filtered.append(line)
        else:
            # 对于其他格式，检查是否包含标签
            if not contains_bracket_tag(text):
                new_filtered.append(line)
    filtered = new_filtered
    
    # 6) 处理开头两行的"圆括号标签"
    i = 0
    scan_limit = min(2, len(filtered))
    while i < scan_limit:
        text = filtered[i]['plainText']
        if contains_paren_pair(text):
            filtered.pop(i)
            scan_limit = min(2, len(filtered))
            continue
        else:
            i += 1
    
    # 7) 全局删除：版权/授权/禁止类提示语
    filtered = [line for line in filtered if not is_license_warning_line(line['plainText'])]
    
    # 8) 额外的清理步骤
    new_filtered = []
    for line in filtered:
        text = line['plainText']
        
        # 移除空行
        if text == '':
            continue
        
        # 移除只包含"//"的行
        if text == '//':
            continue
        
        # 对于LRC格式，移除只包含时间轴后面只有"//"的行
        if line['type'] == 'lrc':
            if 'timestamp' in line and line['timestamp']:
                if re.match(r'^\/\/\s*$', text):
                    continue
                
                if re.match(r'^\[\d+:\d+(\.\d+)?\]\s*\/\/\s*$', line['raw']):
                    continue
                
                if re.match(r'^\[\d+:\d+(\.\d+)?\]\s*$', line['raw']):
                    continue
        
        # 对于QRC/YRC格式，检查是否只有时间标签没有内容
        if line['type'] == 'qrc' and text == '':
            # 如果只有时间标签没有实际歌词内容，跳过
            continue
        
        new_filtered.append(line)
    
    return new_filtered

def unified_filter_lyrics(lyric_content, lyric_type='lrc'):
    """统一的歌词过滤函数 - 处理LRC和QRC/YRC格式"""
    if not lyric_content:
        return ''
    
    # 基础预处理：分割行和移除元数据
    parsed_lines = preprocess_lyric_lines(lyric_content, lyric_type)
    
    # 使用通用的过滤逻辑
    filtered = filter_lyric_lines(parsed_lines, lyric_type)
    
    # 重新组合成对应格式
    result_lines = []
    for line in filtered:
        result_lines.append(line['raw'])
    
    result = '\n'.join(result_lines)
    return result

# ================ QQ 音乐解密核心 ================
QQ_KEY = b'!@#)(*$%123ZXC!@!@#)(NHL'

def decrypt_qq_lyric(encrypted_hex):
    """解密QQ音乐歌词，并解码HTML实体"""
    try:
        encrypted_bytes = bytes.fromhex(encrypted_hex)
        schedule = [[[0] * 6 for _ in range(16)] for _ in range(3)]
        triple_des_key_setup(QQ_KEY, schedule, DESMode.DES_DECRYPT)
        decrypted_data = triple_des_crypt(encrypted_bytes, schedule)
        
        try:
            decompressed = zlib.decompress(decrypted_data)
        except zlib.error as e1:
            try:
                decompressed = zlib.decompress(decrypted_data, -15)
            except zlib.error as e2:
                try:
                    if decrypted_data.startswith(b'\xef\xbb\xbf'):
                        decompressed = decrypted_data[3:]
                    else:
                        decompressed = decrypted_data
                    # 解码HTML实体
                    decoded_text = decompressed.decode('utf-8')
                    return html.unescape(decoded_text)
                except UnicodeDecodeError as e3:
                    raise Exception(f"解密和解压失败: 标准zlib错误: {e1}, 原始deflate错误: {e2}, UTF-8解码错误: {e3}")
        
        # 解码HTML实体
        decoded_text = decompressed.decode('utf-8')
        return html.unescape(decoded_text)
        
    except Exception as e:
        if "incorrect header check" in str(e):
            try:
                # 解码HTML实体
                decoded_text = decrypted_data.decode('utf-8', errors='ignore')
                return html.unescape(decoded_text)
            except:
                pass
        raise Exception(f"解密失败: {str(e)}")

def extract_lyric_content_from_xml(xml_string):
    """从XML中提取歌词内容，并解码HTML实体"""
    pattern1 = r'LyricContent=(["\'])(.*?)\1'
    match = re.search(pattern1, xml_string, re.DOTALL)
    
    if match:
        lyric_content = match.group(2)
        # 解码HTML实体
        lyric_content = html.unescape(lyric_content)
        return lyric_content
    
    try:
        root = ET.fromstring(xml_string)
        lyric_node = root.find('.//Lyric_1')
        if lyric_node is not None:
            lyric_content = lyric_node.get('LyricContent')
            if lyric_content is not None:
                # 解码HTML实体
                lyric_content = html.unescape(lyric_content)
                return lyric_content
    except Exception as e:
        print(f"XML解析失败: {e}")
    
    return xml_string

def remove_illegal_xml_content(content):
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
    """解析XML内容，提取歌词、翻译和罗马音"""
    xml_content = xml_content.replace('<!--', '').replace('-->', '')
    xml_content = remove_illegal_xml_content(xml_content)
    original_xml = xml_content[:500] if len(xml_content) > 500 else xml_content
    
    try:
        xml_content = re.sub(r'&(?![a-zA-Z]{2,6};|#[0-9]{2,4};)', '&amp;', xml_content)
        root = ET.fromstring(xml_content)
        
        result = {'lyrics': '', 'trans': '', 'roma': ''}
        
        def find_all_nodes(node, tag_name):
            nodes = []
            if node.tag == tag_name:
                nodes.append(node)
            for child in node:
                nodes.extend(find_all_nodes(child, tag_name))
            return nodes
        
        content_nodes = find_all_nodes(root, 'content')
        for content_node in content_nodes:
            if content_node.text:
                try:
                    decrypted_text = decrypt_qq_lyric(content_node.text.strip())
                    if decrypted_text and decrypted_text.strip().startswith('<?xml'):
                        result['lyrics'] = extract_lyric_content_from_xml(decrypted_text)
                    else:
                        result['lyrics'] = decrypted_text
                    if result['lyrics']:
                        break
                except Exception as e:
                    print(f"解密原文歌词失败: {e}")
        
        contentts_nodes = find_all_nodes(root, 'contentts')
        for contentts_node in contentts_nodes:
            if contentts_node.text:
                try:
                    decrypted_text = decrypt_qq_lyric(contentts_node.text.strip())
                    result['trans'] = decrypted_text
                    if result['trans']:
                        break
                except Exception as e:
                    print(f"解密翻译歌词失败: {e}")
        
        contentroma_nodes = find_all_nodes(root, 'contentroma')
        for contentroma_node in contentroma_nodes:
            if contentroma_node.text:
                try:
                    decrypted_text = decrypt_qq_lyric(contentroma_node.text.strip())
                    # 罗马音字段是完整的XML格式，直接返回
                    result['roma'] = decrypted_text
                    if result['roma']:
                        break
                except Exception as e:
                    print(f"解密罗马音失败: {e}")
        
        return result
        
    except Exception as e:
        print(f"XML解析失败: {e}")
        print(f"原始XML内容（前500字符）: {original_xml}")
        return extract_content_with_regex(xml_content)

def extract_content_with_regex(xml_content):
    """使用正则表达式提取XML内容"""
    result = {'lyrics': '', 'trans': '', 'roma': ''}
    
    content_matches = re.findall(r'<content>(.*?)</content>', xml_content, re.DOTALL)
    for encrypted in content_matches:
        encrypted = encrypted.strip()
        if encrypted:
            try:
                decrypted_text = decrypt_qq_lyric(encrypted)
                if decrypted_text and decrypted_text.strip().startswith('<?xml'):
                    result['lyrics'] = extract_lyric_content_from_xml(decrypted_text)
                else:
                    result['lyrics'] = decrypted_text
                if result['lyrics']:
                    break
            except Exception as e:
                print(f"解密原文歌词失败（正则）: {e}")
    
    contentts_matches = re.findall(r'<contentts>(.*?)</contentts>', xml_content, re.DOTALL)
    for encrypted in contentts_matches:
        encrypted = encrypted.strip()
        if encrypted:
            try:
                result['trans'] = decrypt_qq_lyric(encrypted)
                if result['trans']:
                    break
            except Exception as e:
                print(f"解密翻译歌词失败（正则）: {e}")
    
    contentroma_matches = re.findall(r'<contentroma>(.*?)</contentroma>', xml_content, re.DOTALL)
    for encrypted in contentroma_matches:
        encrypted = encrypted.strip()
        if encrypted:
            try:
                # 罗马音字段是完整的XML格式，直接返回
                result['roma'] = decrypt_qq_lyric(encrypted)
                if result['roma']:
                    break
            except Exception as e:
                print(f"解密罗马音失败（正则）: {e}")
    
    return result

def extract_roma_text_from_xml(roma_xml):
    """从罗马音XML中提取纯文本罗马音"""
    if not roma_xml:
        return ''
    
    try:
        # 尝试解析XML
        root = ET.fromstring(roma_xml)
        
        # 查找LyricInfo标签
        lyric_info = root.find('.//LyricInfo')
        if lyric_info is not None and lyric_info.text:
            # 返回LyricInfo标签内的文本内容
            return lyric_info.text.strip()
        else:
            # 如果没有找到LyricInfo标签，返回整个XML
            return roma_xml
    except Exception as e:
        print(f"解析罗马音XML失败: {e}")
        # 如果解析失败，返回原始XML
        return roma_xml

# ================ 歌曲信息获取 ================
def get_song_by_mid(mid):
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
    
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            data = response.read().decode('utf-8')
            print(f"歌曲API原始响应（前500字符）: {data[:500]}")
            
            if data.startswith(callback + '(') and data.endswith(')'):
                data = data[len(callback) + 1:-1]
            elif data.startswith(callback + '('):
                start_index = data.find('(')
                end_index = data.rfind(')')
                if start_index != -1 and end_index != -1 and end_index > start_index:
                    data = data[start_index + 1:end_index]
            
            data = data.strip()
            if data.startswith('(') and data.endswith(')'):
                data = data[1:-1]
            
            print(f"处理后的JSON数据（前200字符）: {data[:200]}")
            return json.loads(data)
    except Exception as e:
        print(f"获取歌曲信息失败: {e}")
        import traceback
        traceback.print_exc()
        return None

def get_song_by_id(id):
    if id.isdigit():
        param_key = 'songid'
    else:
        param_key = 'songmid'
    
    callback = 'getOneSongInfoCallback'
    params = {
        param_key: id,
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
    
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            data = response.read().decode('utf-8')
            print(f"歌曲API原始响应（前500字符）: {data[:500]}")
            
            if data.startswith(callback + '(') and data.endswith(')'):
                data = data[len(callback) + 1:-1]
            elif data.startswith(callback + '('):
                start_index = data.find('(')
                end_index = data.rfind(')')
                if start_index != -1 and end_index != -1 and end_index > start_index:
                    data = data[start_index + 1:end_index]
            
            data = data.strip()
            if data.startswith('(') and data.endswith(')'):
                data = data[1:-1]
            
            print(f"处理后的JSON数据（前200字符）: {data[:200]}")
            return json.loads(data)
    except Exception as e:
        print(f"获取歌曲信息失败: {e}")
        import traceback
        traceback.print_exc()
        return None

def get_lrc_by_mid(mid):
    """获取LRC歌词（包含过滤）"""
    current_millis = int(time.time() * 1000)
    callback = 'MusicJsonCallback_lrc'
    params = {
        'callback': callback,
        'pcachetime': str(current_millis),
        'songmid': mid,
        'g_tk': '5381',
        'jsonpCallback': callback,
        'loginUin': '0',
        'hostUin': '0',
        'format': 'jsonp',
        'inCharset': 'utf8',
        'outCharset': 'utf8',
        'notice': '0',
        'platform': 'yqq',
        'needNewCode': '0'
    }
    
    url = 'https://c.y.qq.com/lyric/fcgi-bin/fcg_query_lyric_new.fcg?' + urllib.parse.urlencode(params)
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36',
        'Referer': 'https://c.y.qq.com/',
        'Cookie': 'os=pc;osver=Microsoft-Windows-10-Professional-build-16299.125-64bit;appver=2.0.3.131777;channel=netease;__remember_me=true'
    }
    
    req = urllib.request.Request(url, headers=headers)
    
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            data = response.read().decode('utf-8')
            
            # 移除JSONP包装
            if data.startswith(callback):
                data = data.replace(callback + '(', '').rsplit(')', 1)[0]
            
            lyric_data = json.loads(data)
            result = {'lyric': '', 'trans': ''}
            
            if lyric_data.get('lyric'):
                try:
                    decoded_lyric = base64.b64decode(lyric_data['lyric']).decode('utf-8')
                    # 解码HTML实体
                    decoded_lyric = html.unescape(decoded_lyric)
                    # 使用统一过滤函数
                    result['lyric'] = unified_filter_lyrics(decoded_lyric, 'lrc')
                    print(f"LRC歌词过滤后长度: {len(result['lyric'])}")
                except Exception as e:
                    print(f"解码LRC歌词失败: {e}")
                    result['lyric'] = lyric_data['lyric']
            
            if lyric_data.get('trans'):
                try:
                    decoded_trans = base64.b64decode(lyric_data['trans']).decode('utf-8')
                    # 解码HTML实体
                    decoded_trans = html.unescape(decoded_trans)
                    # 使用统一过滤函数
                    result['trans'] = unified_filter_lyrics(decoded_trans, 'lrc')
                    print(f"LRC翻译过滤后长度: {len(result['trans'])}")
                except Exception as e:
                    print(f"解码LRC翻译失败: {e}")
                    result['trans'] = lyric_data['trans']
            
            return result
            
    except Exception as e:
        print(f"获取LRC歌词失败: {e}")
        import traceback
        traceback.print_exc()
        return {'lyric': '', 'trans': ''}

def get_qrc_by_id(musicid):
    """获取QRC逐字歌词（应用统一过滤）"""
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
    
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            xml_content = response.read().decode('utf-8')
            
            print(f"获取到原始XML，长度: {len(xml_content)}")
            print(f"前200个字符: {xml_content[:200] if len(xml_content) > 200 else xml_content}")
            
            # 解析XML并解密歌词
            result = parse_xml_content(xml_content)
            
            # 对QRC歌词应用统一过滤（使用qrc类型）
            if result['lyrics']:
                result['lyrics'] = unified_filter_lyrics(result['lyrics'], 'qrc')
                print(f"QRC歌词过滤后长度: {len(result['lyrics'])}")
            
            if result['trans']:
                # QRC的翻译可能是LRC格式，所以使用lrc类型过滤
                result['trans'] = unified_filter_lyrics(result['trans'], 'lrc')
                print(f"QRC翻译过滤后长度: {len(result['trans'])}")
            
            # 罗马音字段是完整的XML格式，不进行过滤
            if result['roma']:
                print(f"QRC罗马音长度: {len(result['roma'])}")
                # 可以选择提取罗马音文本，或者返回完整XML
                # 这里返回完整XML，让前端解析
                # 如果需要提取文本，可以调用 extract_roma_text_from_xml
                # result['roma'] = extract_roma_text_from_xml(result['roma'])
            
            return result
    except Exception as e:
        print(f"获取QRC歌词失败: {e}")
        import traceback
        traceback.print_exc()
        return {'lyrics': '', 'trans': '', 'roma': ''}

# ================ Flask 路由 ================
@app.route('/')
def index():
    return json_response({
        'name': 'QQ音乐歌词解密API - 修复版',
        'version': '4.2.0',
        'description': '完整支持LRC和QRC歌词过滤，使用统一的过滤系统',
        'endpoints': {
            '/api/lyrics?id=<musicid>': '通过musicid获取所有歌词',
            '/api/lyrics?mid=<songmid>': '通过songmid获取所有歌词',
            '/api/test': '测试接口',
            '/api/debug?hex=<hex>': '调试接口（直接解密）'
        },
        'note': 'id和mid参数二选一，id优先',
        'example_id': '/api/lyrics?id=213836590',
        'example_mid': '/api/lyrics?mid=0009vzel3OWyod'
    })

@app.route('/api/lyrics', methods=['GET'])
def get_lyrics():
    """获取所有歌词（LRC逐行歌词 + QRC逐字歌词 + 罗马音）"""
    musicid = request.args.get('id')
    mid = request.args.get('mid')
    
    if not musicid and not mid:
        return json_response({
            'success': False,
            'error': '缺少参数，请提供id或mid',
            'example_id': '/api/lyrics?id=213836590',
            'example_mid': '/api/lyrics?mid=0009vzel3OWyod'
        }, 400)
    
    try:
        song_info = None
        final_mid = None
        final_musicid = None
        
        # 优先使用id
        if musicid:
            song_info = get_song_by_id(musicid)
            if song_info and 'data' in song_info and song_info['data']:
                song_data = song_info['data'][0]
                final_musicid = musicid
                final_mid = song_data.get('mid') or song_data.get('songmid')
                if not final_mid and not musicid.isdigit():
                    final_mid = musicid
        elif mid:
            song_info = get_song_by_mid(mid)
            if song_info and 'data' in song_info and song_info['data']:
                song_data = song_info['data'][0]
                final_mid = mid
                final_musicid = song_data.get('id') or song_data.get('songid')
                if not final_musicid:
                    final_musicid = mid
        
        if not song_info or not song_info.get('data'):
            return json_response({
                'success': False,
                'error': '未找到歌曲信息',
                'id': musicid,
                'mid': mid
            }, 404)
        
        song_data = song_info['data'][0]
        song_name = song_data.get('name', '')
        singer_name = ''
        if song_data.get('singer') and len(song_data['singer']) > 0:
            singer_name = song_data['singer'][0].get('name', '')
        
        # 获取LRC歌词（需要mid）
        lrc_result = {'lyric': '', 'trans': ''}
        if final_mid:
            print(f"获取LRC歌词，mid: {final_mid}")
            lrc_result = get_lrc_by_mid(final_mid)
        else:
            print("没有mid，跳过LRC歌词获取")
        
        # 获取QRC歌词（需要musicid）
        qrc_result = {'lyrics': '', 'trans': '', 'roma': ''}
        if final_musicid:
            print(f"获取QRC歌词，musicid: {final_musicid}")
            qrc_result = get_qrc_by_id(final_musicid)
        else:
            print("没有musicid，跳过QRC歌词获取")
        
        # 如果都没有歌词，返回404
        if (not lrc_result.get('lyric') and not lrc_result.get('trans') and
            not qrc_result.get('lyrics') and not qrc_result.get('roma')):
            return json_response({
                'success': False,
                'error': '未找到歌词或歌词解析失败',
                'id': final_musicid,
                'mid': final_mid,
                'note': '可能是歌曲没有歌词，或者歌词格式不支持'
            }, 404)
        
        # 清理文本
        def clean_lyric_text(text):
            if not text:
                return ''
            text = re.sub(r'[ \t]+', ' ', text)
            return text
        
        lrc_lyric = clean_lyric_text(lrc_result.get('lyric', ''))
        lrc_trans = clean_lyric_text(lrc_result.get('trans', ''))
        qrc_lyric = clean_lyric_text(qrc_result.get('lyrics', ''))
        qrc_trans = clean_lyric_text(qrc_result.get('trans', ''))
        
        # 罗马音字段特殊处理：如果是XML格式，提取LyricInfo内容
        qrc_roma = qrc_result.get('roma', '')
        if qrc_roma:
            # 尝试提取罗马音文本内容
            extracted_roma = extract_roma_text_from_xml(qrc_roma)
            if extracted_roma and extracted_roma != qrc_roma:
                # 如果成功提取到文本，使用提取的文本
                qrc_roma = extracted_roma
            # 清理文本
            qrc_roma = clean_lyric_text(qrc_roma)
        
        # 优先使用LRC的翻译，如果没有则使用QRC的翻译
        trans = lrc_trans if lrc_trans else qrc_trans
        
        response_data = {
            'success': True,
            'id': final_musicid,
            'mid': final_mid,
            'song_info': {
                'name': song_name,
                'singer': singer_name
            },
            'lyric': {
                'lrc': lrc_lyric,       # LRC逐行歌词
                'qrc': qrc_lyric,      # QRC逐字歌词（对应 get.js 的 yrcLyrics）
                'trans': trans,        # 翻译歌词（优先LRC翻译）
                'roma': qrc_roma       # 罗马音（从XML中提取的文本）
            },
            'has_lrc': bool(lrc_lyric or lrc_trans),
            'has_qrc': bool(qrc_lyric or qrc_roma)
        }
        
        return json_response(response_data)
        
    except Exception as e:
        import traceback
        error_traceback = traceback.format_exc()
        print(f"服务器内部错误: {e}")
        print(f"错误堆栈: {error_traceback}")
        
        return json_response({
            'success': False,
            'error': '服务器内部错误',
            'message': str(e),
            'traceback': error_traceback,
            'id': musicid,
            'mid': mid
        }, 500)

@app.route('/api/test', methods=['GET'])
def test():
    """测试接口"""
    return json_response({
        'success': True,
        'message': 'API运行正常',
        'version': '4.2.0',
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'endpoints': [
            {'path': '/api/lyrics?id=<musicid>', 'method': 'GET', 'description': '通过musicid获取所有歌词'},
            {'path': '/api/lyrics?mid=<mid>', 'method': 'GET', 'description': '通过mid获取所有歌词'},
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
            'traceback': traceback.format_exc()
        }, 500)

# 用于Vercel
application = app

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=3000)