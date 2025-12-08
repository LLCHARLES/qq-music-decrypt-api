# api/lyrics.py
from http.server import BaseHTTPRequestHandler
import json
import urllib.parse
import urllib.request
import urllib.error
from .des_decrypt import decrypt_qq_lyric


class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        # 设置 CORS 头
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        
        # 处理 OPTIONS 预检请求
        if self.path.startswith('/api/lyrics') and self.command == 'OPTIONS':
            self.send_response(204)
            self.end_headers()
            return
        
        # 解析查询参数
        parsed_path = urllib.parse.urlparse(self.path)
        query_params = urllib.parse.parse_qs(parsed_path.query)
        
        # 获取 musicid 参数
        musicid = query_params.get('musicid', [None])[0]
        
        if not musicid:
            self.send_response(400)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            response = json.dumps({
                'success': False,
                'error': '缺少 musicid 参数',
                'usage': 'GET /api/lyrics?musicid=歌曲ID'
            }, ensure_ascii=False)
            self.wfile.write(response.encode('utf-8'))
            return
        
        try:
            # 构建 QQ 音乐 API 请求 URL
            api_url = 'https://c.y.qq.com/qqmusic/fcgi-bin/lyric_download.fcg'
            params = {
                'musicid': musicid,
                'version': '15',
                'miniversion': '82',
                'lrctype': '4'
            }
            
            url_with_params = f"{api_url}?{urllib.parse.urlencode(params)}"
            
            # 设置请求头
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Referer': 'https://y.qq.com/',
                'Accept': 'application/json, text/plain, */*'
            }
            
            # 发送请求到 QQ 音乐 API
            req = urllib.request.Request(url_with_params, headers=headers)
            
            with urllib.request.urlopen(req, timeout=10) as response:
                # 解析响应
                response_data = response.read().decode('utf-8')
                
                # QQ 音乐 API 返回的是 JSONP 格式，需要提取 JSON
                if response_data.startswith('callback('):
                    json_str = response_data[9:-2]  # 移除 callback() 包装
                else:
                    json_str = response_data
                
                data = json.loads(json_str)
                
                # 检查是否获取到歌词
                if 'lyric' not in data or not data['lyric']:
                    self.send_response(404)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    response = json.dumps({
                        'success': False,
                        'error': '未找到歌词',
                        'musicid': musicid
                    }, ensure_ascii=False)
                    self.wfile.write(response.encode('utf-8'))
                    return
                
                try:
                    # 解密歌词
                    decrypted_lyric = decrypt_qq_lyric(data['lyric'])
                    
                    # 构建响应
                    result = {
                        'success': True,
                        'musicid': musicid,
                        'lyric': decrypted_lyric,
                        'translation': data.get('trans', ''),
                        'source': 'qq',
                        'info': {
                            'song_name': data.get('songname', ''),
                            'singer': data.get('singer', '')
                        }
                    }
                    
                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    response = json.dumps(result, ensure_ascii=False)
                    self.wfile.write(response.encode('utf-8'))
                    
                except Exception as decrypt_error:
                    self.send_response(500)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    response = json.dumps({
                        'success': False,
                        'error': '歌词解密失败',
                        'message': str(decrypt_error),
                        'musicid': musicid,
                        'raw_lyric': data['lyric'][:100] + '...' if len(data['lyric']) > 100 else data['lyric']
                    }, ensure_ascii=False)
                    self.wfile.write(response.encode('utf-8'))
                    
        except urllib.error.HTTPError as http_err:
            self.send_response(http_err.code)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            response = json.dumps({
                'success': False,
                'error': f'HTTP 错误: {http_err.code}',
                'message': str(http_err.reason),
                'musicid': musicid
            }, ensure_ascii=False)
            self.wfile.write(response.encode('utf-8'))
            
        except urllib.error.URLError as url_err:
            self.send_response(500)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            response = json.dumps({
                'success': False,
                'error': '网络请求失败',
                'message': str(url_err.reason),
                'musicid': musicid
            }, ensure_ascii=False)
            self.wfile.write(response.encode('utf-8'))
            
        except Exception as e:
            self.send_response(500)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            response = json.dumps({
                'success': False,
                'error': '服务器内部错误',
                'message': str(e),
                'musicid': musicid
            }, ensure_ascii=False)
            self.wfile.write(response.encode('utf-8'))
    
    def do_OPTIONS(self):
        # 处理 OPTIONS 预检请求
        self.send_response(204)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()


# 为了在 Vercel 中正确运行，添加以下代码
if __name__ == '__main__':
    from http.server import HTTPServer
    server = HTTPServer(('localhost', 3000), handler)
    print('Starting server on http://localhost:3000')
    server.serve_forever()
