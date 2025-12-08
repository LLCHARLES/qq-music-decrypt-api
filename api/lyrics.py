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

# ================ DES 算法实现 ================
# ... [保持原有的DES算法实现部分不变] ...

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
        
        # 6. 返回UTF-8字符串
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

def extract_lyric_from_xml(decrypted_text):
    """从XML中提取歌词内容 - 修复版，保留换行符"""
    if not decrypted_text or '<?xml' not in decrypted_text:
        return decrypted_text
    
    try:
        # 方法1: 使用正则表达式直接提取LyricContent属性值（保留换行符）
        # 匹配 LyricContent="..." 的内容
        pattern = r'LyricContent="([^"]*)"'
        match = re.search(pattern, decrypted_text, re.DOTALL)
        if match:
            lyric_content = match.group(1)
            # 还原XML转义字符
            lyric_content = lyric_content.replace('&quot;', '"')
            lyric_content = lyric_content.replace('&amp;', '&')
            lyric_content = lyric_content.replace('&lt;', '<')
            lyric_content = lyric_content.replace('&gt;', '>')
            return lyric_content
        
        # 方法2: 如果正则失败，尝试使用ElementTree
        # 移除可能的BOM字符
        if decrypted_text.startswith('\ufeff'):
            decrypted_text = decrypted_text[1:]
        
        # 修复XML中的非法内容
        decrypted_text = remove_illegal_xml_content(decrypted_text)
        
        # 解析XML
        root = ET.fromstring(decrypted_text)
        
        # 查找Lyric_1节点
        for elem in root.iter():
            if elem.tag == 'Lyric_1':
                lyric_content = elem.get('LyricContent')
                if lyric_content:
                    # 注意：ElementTree的get()方法会去掉换行符
                    # 所以我们回退到方法1
                    return lyric_content
        
        # 如果都没有找到，返回原始文本
        return decrypted_text
        
    except Exception as e:
        print(f"解析XML失败: {e}")
        # 解析失败，尝试使用更简单的方法
        # 查找包含LyricContent的文本
        lines = decrypted_text.split('\n')
        for line in lines:
            if 'LyricContent=' in line:
                # 提取引号内的内容
                start = line.find('LyricContent="')
                if start != -1:
                    start += len('LyricContent="')
                    end = line.find('"', start)
                    if end != -1:
                        lyric_content = line[start:end]
                        # 还原XML转义字符
                        lyric_content = lyric_content.replace('&quot;', '"')
                        lyric_content = lyric_content.replace('&amp;', '&')
                        lyric_content = lyric_content.replace('&lt;', '<')
                        lyric_content = lyric_content.replace('&gt;', '>')
                        return lyric_content
        
        # 如果所有方法都失败，返回原始文本
        return decrypted_text

def parse_xml_content(xml_content):
    """解析XML内容并提取歌词"""
    # 移除注释
    xml_content = xml_content.replace('<!--', '').replace('-->', '')
    
    # 移除非法内容
    xml_content = remove_illegal_xml_content(xml_content)
    
    try:
        # 修复&符号
        xml_content = re.sub(r'&(?![a-zA-Z]{2,6};|#[0-9]{2,4};)', '&amp;', xml_content)
        
        # 解析XML
        root = ET.fromstring(xml_content)
        
        # 查找歌词节点
        result = {'lyrics': '', 'trans': ''}
        
        # 查找content标签（原文歌词）
        for elem in root.iter():
            if elem.tag == 'content' and elem.text:
                try:
                    decrypted_text = decrypt_qq_lyric(elem.text.strip())
                    # 从XML中提取歌词内容
                    result['lyrics'] = extract_lyric_from_xml(decrypted_text)
                    break
                except Exception as e:
                    print(f"解密原文歌词失败: {e}")
        
        # 查找contentts标签（翻译歌词）
        for elem in root.iter():
            if elem.tag == 'contentts' and elem.text:
                try:
                    decrypted_text = decrypt_qq_lyric(elem.text.strip())
                    result['trans'] = decrypted_text
                    break
                except Exception as e:
                    print(f"解密翻译歌词失败: {e}")
        
        return result
        
    except Exception as e:
        # XML解析失败，尝试使用正则表达式提取
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
                decrypted_text = decrypt_qq_lyric(encrypted)
                result['lyrics'] = extract_lyric_from_xml(decrypted_text)
            except Exception as e:
                print(f"解密原文歌词失败（正则）: {e}")
    
    # 匹配<contentts>标签
    contentts_match = re.search(r'<contentts>(.*?)</contentts>', xml_content, re.DOTALL)
    if contentts_match:
        encrypted = contentts_match.group(1).strip()
        if encrypted:
            try:
                decrypted_text = decrypt_qq_lyric(encrypted)
                result['trans'] = decrypted_text
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
        
        # 移除JSONP包装
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
        
        # 解析XML并解密歌词
        return parse_xml_content(xml_content)

# ================ Flask 路由 ================
@app.route('/')
def index():
    return json_response({
        'name': 'QQ音乐歌词解密API',
        'version': '2.0.1',
        'description': '修复了XML解析问题，正确提取LyricContent并保留换行符',
        'endpoints': {
            '/api/lyrics?musicid=<musicid>': '通过musicid获取歌词',
            '/api/lyrics/mid?mid=<mid>': '通过mid获取歌词',
            '/api/test': '测试接口',
            '/api/debug?hex=<hex>': '调试接口（直接解密）'
        },
        'example': '/api/lyrics?musicid=559981893'
    })

@app.route('/api/lyrics', methods=['GET'])
def get_lyrics_by_id():
    """通过musicid获取歌词"""
    musicid = request.args.get('musicid')
    
    if not musicid:
        return json_response({
            'success': False,
            'error': '缺少musicid参数',
            'example': '/api/lyrics?musicid=559981893'
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
        
        # 获取歌词文本
        lyrics = result.get('lyrics', '')
        translation = result.get('trans', '')
        
        # 处理BOM字符
        if lyrics and lyrics.startswith('\ufeff'):
            lyrics = lyrics[1:]
        if translation and translation.startswith('\ufeff'):
            translation = translation[1:]
        
        # 检查歌词是否包含换行符
        has_newlines_in_lyrics = '\n' in lyrics
        has_newlines_in_trans = '\n' in translation
        
        return json_response({
            'success': True,
            'musicid': musicid,
            'lyrics': lyrics,
            'translation': translation,
            'has_lyrics': bool(lyrics),
            'has_translation': bool(translation),
            'format_info': {
                'lyrics_has_newlines': has_newlines_in_lyrics,
                'translation_has_newlines': has_newlines_in_trans,
                'lyrics_is_xml_format': '<?xml' in lyrics[:100] if lyrics else False,
                'translation_is_xml_format': '<?xml' in translation[:100] if translation else False
            },
            'note': '逐字歌词已从XML中正确提取，换行符已保留'
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
        
        lyrics = result.get('lyrics', '')
        translation = result.get('trans', '')
        
        # 处理BOM字符
        if lyrics and lyrics.startswith('\ufeff'):
            lyrics = lyrics[1:]
        if translation and translation.startswith('\ufeff'):
            translation = translation[1:]
        
        # 检查歌词是否包含换行符
        has_newlines_in_lyrics = '\n' in lyrics
        has_newlines_in_trans = '\n' in translation
        
        return json_response({
            'success': True,
            'mid': mid,
            'musicid': musicid,
            'lyrics': lyrics,
            'translation': translation,
            'has_lyrics': bool(lyrics),
            'has_translation': bool(translation),
            'format_info': {
                'lyrics_has_newlines': has_newlines_in_lyrics,
                'translation_has_newlines': has_newlines_in_trans,
                'lyrics_is_xml_format': '<?xml' in lyrics[:100] if lyrics else False,
                'translation_is_xml_format': '<?xml' in translation[:100] if translation else False
            },
            'song_info': {
                'id': musicid,
                'mid': mid,
                'name': song_info.get('name', ''),
                'title': song_info.get('title', ''),
                'singer': song_info.get('singer', [{}])[0].get('name', '') if song_info.get('singer') else ''
            },
            'note': '逐字歌词已从XML中正确提取，换行符已保留'
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
    """调试接口：直接测试解密和XML提取"""
    hex_str = request.args.get('hex')
    if not hex_str:
        return json_response({
            'success': False,
            'error': '缺少hex参数',
            'example': '/api/debug?hex=加密的16进制字符串'
        }, 400)
    
    try:
        # 1. 解密
        decrypted = decrypt_qq_lyric(hex_str)
        
        # 2. 提取
        extracted = extract_lyric_from_xml(decrypted)
        
        # 3. 分析
        result = {
            'success': True,
            'stats': {
                'original_hex_length': len(hex_str),
                'decrypted_length': len(decrypted),
                'extracted_length': len(extracted),
                'decrypted_newline_count': decrypted.count('\n'),
                'extracted_newline_count': extracted.count('\n'),
                'decrypted_has_xml': '<?xml' in decrypted[:100],
                'was_extracted': extracted != decrypted
            },
            'previews': {
                'decrypted_preview': decrypted[:500] + '...' if len(decrypted) > 500 else decrypted,
                'extracted_preview': extracted[:500] + '...' if len(extracted) > 500 else extracted
            },
            'note': '检查decrypted_newline_count和extracted_newline_count是否相等'
        }
        
        return json_response(result)
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
