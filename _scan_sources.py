import sys, json, requests
sys.path.insert(0, '.')
import fine_clash as fc
rules = fc.load_rules()
src = json.load(open('data/sources.json', encoding='utf-8'))
print('sources in json:', len(src))
sess = requests.Session()
sess.headers.update({'User-Agent': 'Fine-Clash/1.0'})
total_nodes = 0
alive_sources = []
for s in src:
    url = s.get('url')
    if not url:
        continue
    try:
        r = sess.get(url, timeout=25, allow_redirects=True)
        nodes = fc.parse_subscription(r.text) if r.status_code == 200 else []
        n = len(nodes)
        total_nodes += n
        flag = 'OK' if n >= 2 else 'EMPTY'
        if n >= 2:
            alive_sources.append((s.get('repo'), url, n))
        print(f"{flag:6} http={r.status_code} nodes={n:4}  {s.get('repo')}  {s.get('path')}")
    except Exception as e:
        print(f"ERR    {type(e).__name__:10}  {s.get('repo')}  {s.get('path')}")
print('--- total candidate nodes across sources:', total_nodes)
print('--- alive sources (>=2 nodes):', len(alive_sources))
json.dump(alive_sources, open('data/alive_sources.json','w'), ensure_ascii=False, indent=2)
