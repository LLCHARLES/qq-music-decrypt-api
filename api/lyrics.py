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

# ... [DES算法实现部分保持不变，与之前完全一样] ...

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
