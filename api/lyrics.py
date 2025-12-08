from flask import Flask, request, jsonify
import urllib.request
import json
import zlib
from enum import Enum
import time

app = Flask(__name__)

# ================ CORS 支持 ================
@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response

# ================ DES 算法实现 ================
class DESMode(Enum):
    DES_ENCRYPT = 'DES_ENCRYPT'
    DES_DECRYPT = 'DES_DECRYPT'

def bit_num(a: bytearray, b: int, c: int):
    byte_index = (b // 32) * 4 + 3 - (b % 32) // 8
    bit_position = 7 - (b % 8)
    extracted_bit = (a[byte_index] >> bit_position) & 0x01
    return extracted_bit << c

def bit_num_int_r(a: int, b: int, c: int) -> int:
    extracted_bit = (a >> (31 - b)) & 0x00000001
    return extracted_bit << c

def bit_num_int_l(a: int, b: int, c: int) -> int:
    extracted_bit = (a << b) & 0x80000000
    return extracted_bit >> c

def s_box_bit(a: int) -> int:
    part1 = (a & 0x20)
    part2 = ((a & 0x1f) >> 1)
    part3 = ((a & 0x01) << 4)
    return part1 | part2 | part3

s_box1 = [
    14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
    0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
    4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
    15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13
]

s_box2 = [
    15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
    3, 13, 4, 7, 15, 2, 8, 15, 12, 0, 1, 10, 6, 9, 11, 5,
    0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
    13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9
]

s_box3 = [
    10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
    13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
    13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
    1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12
]

s_box4 = [
    7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
    13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
    10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
    3, 15, 0, 6, 10, 10, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14
]

s_box5 = [
    2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
    14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
    4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
    11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3
]

s_box6 = [
    12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
    10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
    9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
    4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13
]

s_box7 = [
    4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
    13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
    1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
    6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12
]

s_box8 = [
    13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
    1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
    7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
    2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11
]

def ip(state: list, in_bytes: bytearray):
    state[0] = (
        bit_num(in_bytes, 57, 31) | bit_num(in_bytes, 49, 30) | bit_num(in_bytes, 41, 29) |
        bit_num(in_bytes, 33, 28) | bit_num(in_bytes, 25, 27) | bit_num(in_bytes, 17, 26) |
        bit_num(in_bytes, 9, 25) | bit_num(in_bytes, 1, 24) | bit_num(in_bytes, 59, 23) |
        bit_num(in_bytes, 51, 22) | bit_num(in_bytes, 43, 21) | bit_num(in_bytes, 35, 20) |
        bit_num(in_bytes, 27, 19) | bit_num(in_bytes, 19, 18) | bit_num(in_bytes, 11, 17) |
        bit_num(in_bytes, 3, 16) | bit_num(in_bytes, 61, 15) | bit_num(in_bytes, 53, 14) |
        bit_num(in_bytes, 45, 13) | bit_num(in_bytes, 37, 12) | bit_num(in_bytes, 29, 11) |
        bit_num(in_bytes, 21, 10) | bit_num(in_bytes, 13, 9) | bit_num(in_bytes, 5, 8) |
        bit_num(in_bytes, 63, 7) | bit_num(in_bytes, 55, 6) | bit_num(in_bytes, 47, 5) |
        bit_num(in_bytes, 39, 4) | bit_num(in_bytes, 31, 3) | bit_num(in_bytes, 23, 2) |
        bit_num(in_bytes, 15, 1) | bit_num(in_bytes, 7, 0)
    )
    state[1] = (
        bit_num(in_bytes, 56, 31) | bit_num(in_bytes, 48, 30) | bit_num(in_bytes, 40, 29) |
        bit_num(in_bytes, 32, 28) | bit_num(in_bytes, 24, 27) | bit_num(in_bytes, 16, 26) |
        bit_num(in_bytes, 8, 25) | bit_num(in_bytes, 0, 24) | bit_num(in_bytes, 58, 23) |
        bit_num(in_bytes, 50, 22) | bit_num(in_bytes, 42, 21) | bit_num(in_bytes, 34, 20) |
        bit_num(in_bytes, 26, 19) | bit_num(in_bytes, 18, 18) | bit_num(in_bytes, 10, 17) |
        bit_num(in_bytes, 2, 16) | bit_num(in_bytes, 60, 15) | bit_num(in_bytes, 52, 14) |
        bit_num(in_bytes, 44, 13) | bit_num(in_bytes, 36, 12) | bit_num(in_bytes, 28, 11) |
        bit_num(in_bytes, 20, 10) | bit_num(in_bytes, 12, 9) | bit_num(in_bytes, 4, 8) |
        bit_num(in_bytes, 62, 7) | bit_num(in_bytes, 54, 6) | bit_num(in_bytes, 46, 5) |
        bit_num(in_bytes, 38, 4) | bit_num(in_bytes, 30, 3) | bit_num(in_bytes, 22, 2) |
        bit_num(in_bytes, 14, 1) | bit_num(in_bytes, 6, 0)
    )
    return state

def inv_ip(state: list, in_bytes: bytearray):
    in_bytes[3] = (
        bit_num_int_r(state[1], 7, 7) | bit_num_int_r(state[0], 7, 6) |
        bit_num_int_r(state[1], 15, 5) | bit_num_int_r(state[0], 15, 4) |
        bit_num_int_r(state[1], 23, 3) | bit_num_int_r(state[0], 23, 2) |
        bit_num_int_r(state[1], 31, 1) | bit_num_int_r(state[0], 31, 0)
    )
    in_bytes[2] = (
        bit_num_int_r(state[1], 6, 7) | bit_num_int_r(state[0], 6, 6) |
        bit_num_int_r(state[1], 14, 5) | bit_num_int_r(state[0], 14, 4) |
        bit_num_int_r(state[1], 22, 3) | bit_num_int_r(state[0], 22, 2) |
        bit_num_int_r(state[1], 30, 1) | bit_num_int_r(state[0], 30, 0)
    )
    in_bytes[1] = (
        bit_num_int_r(state[1], 5, 7) | bit_num_int_r(state[0], 5, 6) |
        bit_num_int_r(state[1], 13, 5) | bit_num_int_r(state[0], 13, 4) |
        bit_num_int_r(state[1], 21, 3) | bit_num_int_r(state[0], 21, 2) |
        bit_num_int_r(state[1], 29, 1) | bit_num_int_r(state[0], 29, 0)
    )
    in_bytes[0] = (
        bit_num_int_r(state[1], 4, 7) | bit_num_int_r(state[0], 4, 6) |
        bit_num_int_r(state[1], 12, 5) | bit_num_int_r(state[0], 12, 4) |
        bit_num_int_r(state[1], 20, 3) | bit_num_int_r(state[0], 20, 2) |
        bit_num_int_r(state[1], 28, 1) | bit_num_int_r(state[0], 28, 0)
    )
    in_bytes[7] = (
        bit_num_int_r(state[1], 3, 7) | bit_num_int_r(state[0], 3, 6) |
        bit_num_int_r(state[1], 11, 5) | bit_num_int_r(state[0], 11, 4) |
        bit_num_int_r(state[1], 19, 3) | bit_num_int_r(state[0], 19, 2) |
        bit_num_int_r(state[1], 27, 1) | bit_num_int_r(state[0], 27, 0)
    )
    in_bytes[6] = (
        bit_num_int_r(state[1], 2, 7) | bit_num_int_r(state[0], 2, 6) |
        bit_num_int_r(state[1], 10, 5) | bit_num_int_r(state[0], 10, 4) |
        bit_num_int_r(state[1], 18, 3) | bit_num_int_r(state[0], 18, 2) |
        bit_num_int_r(state[1], 26, 1) | bit_num_int_r(state[0], 26, 0)
    )
    in_bytes[5] = (
        bit_num_int_r(state[1], 1, 7) | bit_num_int_r(state[0], 1, 6) |
        bit_num_int_r(state[1], 9, 5) | bit_num_int_r(state[0], 9, 4) |
        bit_num_int_r(state[1], 17, 3) | bit_num_int_r(state[0], 17, 2) |
        bit_num_int_r(state[1], 25, 1) | bit_num_int_r(state[0], 25, 0)
    )
    in_bytes[4] = (
        bit_num_int_r(state[1], 0, 7) | bit_num_int_r(state[0], 0, 6) |
        bit_num_int_r(state[1], 8, 5) | bit_num_int_r(state[0], 8, 4) |
        bit_num_int_r(state[1], 16, 3) | bit_num_int_r(state[0], 16, 2) |
        bit_num_int_r(state[1], 24, 1) | bit_num_int_r(state[0], 24, 0)
    )
    return in_bytes

def f(state: int, key: list) -> int:
    lrgstate = [0] * 6

    # Expansion Permutation
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

    # Key XOR
    for i in range(6):
        lrgstate[i] ^= key[i]

    # S-Box Permutation
    state = (s_box1[s_box_bit(lrgstate[0] >> 2)] << 28) | \
            (s_box2[s_box_bit(((lrgstate[0] & 0x03) << 4) | (lrgstate[1] >> 4))] << 24) | \
            (s_box3[s_box_bit(((lrgstate[1] & 0x0f) << 2) | (lrgstate[2] >> 6))] << 20) | \
            (s_box4[s_box_bit(lrgstate[2] & 0x3f)] << 16) | \
            (s_box5[s_box_bit(lrgstate[3] >> 2)] << 12) | \
            (s_box6[s_box_bit(((lrgstate[3] & 0x03) << 4) | (lrgstate[4] >> 4))] << 8) | \
            (s_box7[s_box_bit(((lrgstate[4] & 0x0f) << 2) | (lrgstate[5] >> 6))] << 4) | \
            s_box8[s_box_bit(lrgstate[5] & 0x3f)]

    # P-Box Permutation
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

def des_key_setup(key: bytearray, schedule: list, mode: DESMode):
    key_rnd_shift = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
    key_perm_c = [56, 48, 40, 32, 24, 16, 8, 0, 57, 49, 41, 33, 25, 17,
                  9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35]
    key_perm_d = [62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21,
                  13, 5, 60, 52, 44, 36, 28, 20, 12, 4, 27, 19, 11, 3]
    key_compression = [13, 16, 10, 23, 0, 4, 2, 27, 14, 5, 20, 9,
                       22, 18, 11, 3, 25, 7, 15, 6, 26, 19, 12, 1,
                       40, 51, 30, 36, 46, 54, 29, 39, 50, 44, 32, 47,
                       43, 48, 38, 55, 33, 52, 45, 41, 49, 35, 28, 31]

    # Permutated Choice #1
    c = 0
    d = 0
    for i in range(28):
        c |= bit_num(key, key_perm_c[i], 31 - i)
        d |= bit_num(key, key_perm_d[i], 31 - i)

    # Generate the 16 subkeys
    for i in range(16):
        c = ((c << key_rnd_shift[i]) | (c >> (28 - key_rnd_shift[i]))) & 0xfffffff0
        d = ((d << key_rnd_shift[i]) | (d >> (28 - key_rnd_shift[i]))) & 0xfffffff0

        # Decryption subkeys are reverse order of encryption subkeys
        to_gen = 15 - i if mode == DESMode.DES_DECRYPT else i

        # Initialize the array
        schedule[to_gen] = [0] * 6
        for j in range(24):
            schedule[to_gen][j // 8] |= bit_num_int_r(c, key_compression[j], 7 - (j % 8))
        for j in range(24, 48):
            schedule[to_gen][j // 8] |= bit_num_int_r(d, key_compression[j] - 27, 7 - (j % 8))

def des_crypt(input_bytes: bytearray, key_schedule: list):
    state = [0, 0]

    # Initial Permutation
    ip(state, input_bytes)

    for idx in range(15):
        t = state[1]
        i = f(state[1], key_schedule[idx])
        state[1] = i ^ state[0]
        state[0] = t

    # Perform the final loop manually as it doesn't switch sides
    state[0] = f(state[1], key_schedule[15]) ^ state[0]

    # Inverse Initial Permutation
    inv_ip(state, input_bytes)
    return input_bytes

# 密钥定义
KEY1 = b"!@#)(NHLiuy*$%^&"
KEY2 = b"123ZXC!@#)(*$%^&"
KEY3 = b"!@#)(*$%^&abcDEF"

def func_des(buff: bytearray, key: bytes, length: int) -> bytearray:
    schedule = [[0] * 6 for _ in range(16)]
    des_key_setup(bytearray(key), schedule, DESMode.DES_ENCRYPT)
    output = bytearray()
    for i in range(0, length, 8):
        output += des_crypt(buff[i:i + 8], schedule)
    return output

def func_ddes(buff: bytearray, key: bytes, length: int) -> bytearray:
    schedule = [[0] * 6 for _ in range(16)]
    des_key_setup(bytearray(key), schedule, DESMode.DES_DECRYPT)
    output = bytearray()
    for i in range(0, length, 8):
        output += des_crypt(buff[i:i + 8], schedule)
    return output

def lyric_decode(content: bytearray, length: int) -> bytearray:
    content = func_ddes(content, KEY1, length)
    content = func_des(content, KEY2, length)
    content = func_ddes(content, KEY3, length)
    return content

def decrypt_qq_lyric(encrypted_hex: str) -> str:
    """解密QQ音乐歌词的完整函数"""
    try:
        encrypted_data = bytearray.fromhex(encrypted_hex)
        decrypted_data = lyric_decode(encrypted_data, len(encrypted_data))
        decompressed_data = zlib.decompress(decrypted_data)
        return decompressed_data.decode('utf-8')
    except Exception as e:
        raise Exception(f"解密失败: {str(e)}")

# ================ 辅助函数 ================
def parse_qq_response(response_data: str):
    """解析QQ音乐API的响应，处理JSONP格式"""
    # 尝试去除可能的空白字符
    response_data = response_data.strip()
    
    # 处理JSONP格式 (callback({...}))
    if response_data.startswith('callback(') and response_data.endswith(')'):
        response_data = response_data[9:-1]
    elif response_data.startswith('MusicJsonCallback(') and response_data.endswith(')'):
        response_data = response_data[18:-1]
    elif response_data.startswith('jsonCallback(') and response_data.endswith(')'):
        response_data = response_data[13:-1]
    
    # 尝试解析JSON
    try:
        return json.loads(response_data)
    except json.JSONDecodeError as e:
        # 如果解析失败，尝试修复常见的JSON格式问题
        try:
            # 尝试处理可能的多余字符
            if response_data.startswith('{') and response_data.endswith('}'):
                return json.loads(response_data)
            else:
                # 尝试查找第一个 { 和最后一个 }
                start = response_data.find('{')
                end = response_data.rfind('}')
                if start != -1 and end != -1 and end > start:
                    return json.loads(response_data[start:end+1])
                else:
                    raise e
        except Exception:
            raise ValueError(f"无法解析QQ音乐响应: {response_data[:200]}...")

# ================ Flask 路由 ================
@app.route('/')
def index():
    return jsonify({
        'name': 'QQ音乐歌词解密API',
        'version': '1.1.0',
        'usage': 'GET /api/lyrics?musicid=歌曲ID',
        'example': '/api/lyrics?musicid=213836590',
        'timestamp': int(time.time())
    })

@app.route('/api/lyrics', methods=['GET', 'OPTIONS'])
def get_lyrics():
    """获取并解密歌词"""
    if request.method == 'OPTIONS':
        return '', 200
    
    musicid = request.args.get('musicid')
    
    if not musicid:
        return jsonify({
            'success': False,
            'error': '缺少 musicid 参数',
            'usage': 'GET /api/lyrics?musicid=歌曲ID'
        }), 400
    
    try:
        # 构建 QQ 音乐 API 请求 URL - 使用更可靠的接口
        api_url = 'https://c.y.qq.com/lyric/fcgi-bin/fcg_query_lyric_new.fcg'
        params = {
            'songmid': musicid,  # 注意：这里用的是songmid，不是musicid
            'format': 'json',
            'inCharset': 'utf8',
            'outCharset': 'utf-8',
            'platform': 'yqq',
            'hostUin': 0,
            'needNewCode': 0
        }
        
        import urllib.parse
        url_with_params = f"{api_url}?{urllib.parse.urlencode(params)}"
        
        # 设置更完整的请求头，模拟浏览器
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Referer': 'https://y.qq.com/',
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Host': 'c.y.qq.com',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-site',
            'Pragma': 'no-cache',
            'Cache-Control': 'no-cache',
            'DNT': '1',
            'Sec-Ch-Ua': '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
            'Sec-Ch-Ua-Mobile': '?0',
            'Sec-Ch-Ua-Platform': '"Windows"'
        }
        
        # 发送请求到 QQ 音乐 API
        req = urllib.request.Request(url_with_params, headers=headers)
        
        with urllib.request.urlopen(req, timeout=15) as response:
            # 解析响应
            response_data = response.read().decode('utf-8', errors='ignore')
            
            # 如果响应为空
            if not response_data:
                return jsonify({
                    'success': False,
                    'error': 'QQ音乐API返回空响应',
                    'musicid': musicid
                }), 404
            
            # 解析响应数据
            try:
                data = parse_qq_response(response_data)
            except Exception as parse_error:
                # 返回原始响应前200字符用于调试
                return jsonify({
                    'success': False,
                    'error': '解析QQ音乐响应失败',
                    'message': str(parse_error),
                    'musicid': musicid,
                    'raw_response': response_data[:500] if len(response_data) > 500 else response_data
                }), 500
            
            # 检查是否获取到歌词
            if 'lyric' not in data or not data.get('lyric'):
                # 尝试不同的字段名
                lyric_key = None
                for key in ['lyric', 'content', 'lyricBase64', 'lyric_utf8']:
                    if key in data and data[key]:
                        lyric_key = key
                        break
                
                if not lyric_key:
                    return jsonify({
                        'success': False,
                        'error': '未找到歌词',
                        'musicid': musicid,
                        'response_keys': list(data.keys()) if isinstance(data, dict) else []
                    }), 404
                
                lyric_data = data[lyric_key]
            else:
                lyric_data = data['lyric']
            
            try:
                # 歌词可能是base64编码的
                import base64
                try:
                    # 尝试base64解码
                    if lyric_data.startswith('LyricContent='):
                        lyric_data = lyric_data[13:]
                    
                    # 尝试base64解码
                    try:
                        lyric_hex = base64.b64decode(lyric_data).hex()
                    except:
                        # 如果不是base64，直接使用
                        lyric_hex = lyric_data
                    
                    # 解密歌词
                    decrypted_lyric = decrypt_qq_lyric(lyric_hex)
                    
                except Exception as decode_error:
                    # 如果解密失败，尝试直接返回原始歌词（可能是明文的）
                    return jsonify({
                        'success': True,
                        'musicid': musicid,
                        'lyric': lyric_data,
                        'translation': data.get('trans', '') or data.get('tran', ''),
                        'source': 'qq',
                        'info': {
                            'song_name': data.get('songname', '') or data.get('name', ''),
                            'singer': data.get('singer', '') or data.get('singer_name', '')
                        },
                        'note': '歌词未加密，直接返回'
                    })
                
                # 构建响应
                result = {
                    'success': True,
                    'musicid': musicid,
                    'lyric': decrypted_lyric,
                    'translation': data.get('trans', '') or data.get('tran', ''),
                    'source': 'qq',
                    'info': {
                        'song_name': data.get('songname', '') or data.get('name', ''),
                        'singer': data.get('singer', '') or data.get('singer_name', '')
                    }
                }
                
                return jsonify(result)
                
            except Exception as decrypt_error:
                return jsonify({
                    'success': False,
                    'error': '歌词解密失败',
                    'message': str(decrypt_error),
                    'musicid': musicid,
                    'raw_lyric': lyric_data[:200] + '...' if len(lyric_data) > 200 else lyric_data
                }), 500
                
    except urllib.error.HTTPError as http_err:
        return jsonify({
            'success': False,
            'error': f'HTTP 错误: {http_err.code}',
            'message': str(http_err.reason),
            'musicid': musicid
        }), http_err.code if http_err.code >= 400 else 500
        
    except urllib.error.URLError as url_err:
        return jsonify({
            'success': False,
            'error': '网络请求失败',
            'message': str(url_err.reason),
            'musicid': musicid
        }), 500
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': '服务器内部错误',
            'message': str(e),
            'musicid': musicid,
            'traceback': str(type(e).__name__)
        }), 500

@app.route('/api/test', methods=['GET'])
def test():
    """测试接口"""
    return jsonify({
        'success': True,
        'message': 'API 运行正常',
        'timestamp': int(time.time()),
        'endpoints': {
            'get_lyrics': '/api/lyrics?musicid=歌曲ID',
            'test': '/api/test',
            'home': '/'
        }
    })

@app.route('/api/debug/<musicid>', methods=['GET'])
def debug_lyric(musicid):
    """调试接口，返回原始响应"""
    try:
        # 使用旧的接口尝试
        api_url = 'https://c.y.qq.com/qqmusic/fcgi-bin/lyric_download.fcg'
        params = {
            'musicid': musicid,
            'version': '15',
            'miniversion': '82',
            'lrctype': '4'
        }
        
        import urllib.parse
        url_with_params = f"{api_url}?{urllib.parse.urlencode(params)}"
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Referer': 'https://y.qq.com/'
        }
        
        req = urllib.request.Request(url_with_params, headers=headers)
        
        with urllib.request.urlopen(req, timeout=10) as response:
            response_data = response.read().decode('utf-8', errors='ignore')
            
            return jsonify({
                'success': True,
                'musicid': musicid,
                'url': url_with_params,
                'response_length': len(response_data),
                'response_preview': response_data[:1000] if len(response_data) > 1000 else response_data,
                'is_json': response_data.strip().startswith('{') or response_data.strip().startswith('callback(')
            })
            
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'musicid': musicid
        }), 500

# Vercel 需要这个变量
application = app

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=3000)
