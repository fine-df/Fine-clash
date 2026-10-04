import sys, base64
sys.path.insert(0, '.')
import fine_clash as fc
rules = fc.load_rules()
raw = open('sub_local.txt', encoding='utf-8').read().strip()
dec = base64.b64decode(raw.replace('\n','').strip() + '='*(-len(raw.replace('\n','').strip())%4)).decode('utf-8','ignore')
nodes = fc.parse_subscription(dec)
print('curated nodes parsed:', len(nodes))
import shutil
binary = shutil.which('mihomo') or r'D:/Program Files/mihomo/mihomo.exe'
print('mihomo binary:', binary)
if not binary or not __import__('os').path.exists(binary):
    print('NO MIHOMO BINARY'); sys.exit(1)
tester_cfg = {**rules['nodes'], 'challenge_markers': rules['checks']['challenge_markers'], 'success_statuses': rules['checks']['success_statuses']}
print('--- testing each curated node (google204/gemini/play) ---')
for item in fc.test_nodes_parallel(binary, nodes, tester_cfg, rules['checks']):
    n = item['node']
    g = (item.get('google') or {}).get('ok')
    print(f"{str(n.get('name',''))[:42]:42} type={n.get('type'):8} google={g} gemini={item['gemini']} play={item['google_play']} server={n.get('server')}")
