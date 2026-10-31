import urllib.request, json, http.cookiejar

cj = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

boundary = '----WebKitFormBoundary7MA4YWxkTrZu0gW'
with open('ml/data/sample_network_flows.csv', 'rb') as f:
    csv_bytes = f.read()

def upload(filename):
    parts = [
        f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{filename}"\r\nContent-Type: text/csv\r\n\r\n'.encode('utf-8'),
        csv_bytes,
        f'\r\n--{boundary}--\r\n'.encode('utf-8')
    ]
    body = b''.join(parts)
    req = urllib.request.Request(
        'http://127.0.0.1:5000/api/analyze',
        data=body,
        headers={'Content-Type': f'multipart/form-data; boundary={boundary}'}
    )
    with opener.open(req) as resp:
        return json.loads(resp.read().decode())

res1 = upload('file1.csv')
print('Upload 1 status:', res1.get('investigation', {}).get('status'))
res2 = upload('file2.csv')
print('Upload 2 status:', res2.get('investigation', {}).get('status'))
print('Upload 2 reason:', res2.get('investigation', {}).get('reason'))
