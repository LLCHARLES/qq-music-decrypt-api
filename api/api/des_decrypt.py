# des_decrypt.py
import zlib
from enum import Enum
import array

# 使用 Python 内置 array 替代 numpy
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


# 使用 Python list 代替 numpy array
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


# 其他 DES 函数保持不变 (ip, inv_ip, f, des_key_setup, des_crypt, etc.)
# ... [这里包含原代码中的所有其他函数，只是把 numpy array 替换为 list]

def ip(state: list, in_bytes: bytearray):
    # ... [原代码中的 ip 函数]
    pass

def inv_ip(state: list, in_bytes: bytearray):
    # ... [原代码中的 inv_ip 函数]
    pass

def f(state: int, key: list) -> int:
    # ... [原代码中的 f 函数，把 numpy array 访问改为 list 访问]
    # 例如：s_box1[value] 而不是 s_box1[value]
    pass

def des_key_setup(key: bytearray, schedule: list, mode: DESMode):
    # ... [原代码中的 des_key_setup 函数]
    pass

def des_crypt(input_bytes: bytearray, key_schedule: list):
    # ... [原代码中的 des_crypt 函数]
    pass

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
    """三重DES解密歌词"""
    content = func_ddes(content, KEY1, length)
    content = func_des(content, KEY2, length)
    content = func_ddes(content, KEY3, length)
    return content


def decrypt_qq_lyric(encrypted_hex: str) -> str:
    """解密QQ音乐歌词的完整函数"""
    encrypted_data = bytearray.fromhex(encrypted_hex)
    decrypted_data = lyric_decode(encrypted_data, len(encrypted_data))
    decompressed_data = zlib.decompress(decrypted_data)
    return decompressed_data.decode('utf-8')
