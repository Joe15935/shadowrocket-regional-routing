"""Small, strict Shadowrocket domain-rule reader and ordered routing simulator."""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit
import ipaddress
import json
import re

ROOT = Path(__file__).resolve().parents[1]
UK, JP, US, HK, DIRECT = '英国家宽', '日本家宽', '美国家宽', '香港家宽', 'DIRECT'
POLICIES = {UK, JP, US, HK, DIRECT}
TLD_POLICY = {'uk': UK, 'jp': JP, 'hk': HK, 'cn': DIRECT}
LAN = [('DOMAIN', 'localhost'), ('DOMAIN-SUFFIX', 'localhost'),
       ('DOMAIN-SUFFIX', 'local'), ('DOMAIN-SUFFIX', 'localdomain'),
       ('DOMAIN-SUFFIX', 'home.arpa'),
       ('IP-CIDR', '10.0.0.0/8'), ('IP-CIDR', '172.16.0.0/12'),
       ('IP-CIDR', '192.168.0.0/16'), ('IP-CIDR', '127.0.0.0/8'),
       ('IP-CIDR', '169.254.0.0/16'), ('IP-CIDR', '100.64.0.0/10'),
       ('IP-CIDR6', '::1/128'), ('IP-CIDR6', 'fc00::/7'), ('IP-CIDR6', 'fe80::/10')]

def read_json(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))

def write_json(path, obj):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True) + '\n', encoding='utf-8')

def domain(value):
    value = value.lower().rstrip('.').encode('idna').decode('ascii')
    if len(value) > 253 or any(not re.fullmatch(r'[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?', x) for x in value.split('.')):
        raise ValueError('Invalid domain rule value')
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise ValueError('Address in domain rule')

def list_rules(text):
    if '<html' in text.lower() or '<!doctype' in text.lower() or '\x00' in text:
        raise ValueError('Expected UTF-8 rule text, received another format')
    rows=[]
    for number, raw in enumerate(text.splitlines(), 1):
        raw=raw.strip()
        if not raw or raw.startswith('#'):
            continue
        parts=[p.strip() for p in raw.split(',')]
        if len(parts)!=2 or parts[0] not in {'DOMAIN','DOMAIN-SUFFIX'}:
            raise ValueError(f'Unsupported generated rule at line {number}')
        rows.append((parts[0],domain(parts[1])))
    return rows

@dataclass(frozen=True)
class Rule:
    kind: str
    value: str
    policy: str
    source: str = ''
    category: str = ''
    manual: bool = False

    def text(self):
        return f'FINAL,{self.policy}' if self.kind=='FINAL' else f'{self.kind},{self.value},{self.policy}'

def covers(a, b):
    """Whether all hostnames matched by b are also matched by a."""
    ak, av = a[:2] if isinstance(a, tuple) else (a.kind, a.value)
    bk, bv = b[:2] if isinstance(b, tuple) else (b.kind, b.value)
    if ak == 'DOMAIN-SUFFIX':
        return bv == av or bv.endswith('.' + av)
    return ak == bk == 'DOMAIN' and av == bv

def overlap(a, b):
    return covers(a,b) or covers(b,a)

def assembled(root=ROOT):
    policy=read_json(root/'policy.json')
    rows=[Rule(k,v,DIRECT,'LAN','LAN',True) for k,v in LAN]
    for layer in policy['layers']:
        p=root/layer['path']
        if p.exists():
            rows += [Rule(k,v,layer['policy'],layer['path'],layer['category'],layer['manual']) for k,v in list_rules(p.read_text())]
    rows += [Rule('DOMAIN-SUFFIX',t,p,'TLD','Country fallback',True) for t,p in TLD_POLICY.items()]
    rows += [Rule('GEOIP','CN',DIRECT,'GEOIP','Country fallback',True), Rule('FINAL','',US,'FINAL','Final',True)]
    return rows

class Simulator:
    """Indexes candidates, then chooses the smallest expanded config line index."""
    def __init__(self, rows):
        self.rows=rows
        self.exact={}
        self.suffix={}
        self.keywords=[]
        self.ip=[]
        self.geo=[]
        self.final=[]
        for i,r in enumerate(rows):
            if r.policy not in POLICIES:
                raise ValueError('Unknown policy label')
            if r.kind=='DOMAIN':self.exact.setdefault(r.value,[]).append(i)
            elif r.kind=='DOMAIN-SUFFIX':self.suffix.setdefault(r.value,[]).append(i)
            elif r.kind=='DOMAIN-KEYWORD':self.keywords.append((i,r.value))
            elif r.kind in {'IP-CIDR','IP-CIDR6'}:self.ip.append((i,ipaddress.ip_network(r.value)))
            elif r.kind=='GEOIP':self.geo.append((i,r.value))
            elif r.kind=='FINAL':self.final.append(i)
            else:raise ValueError('Unsupported simulator rule type')
        if not self.final:raise ValueError('FINAL missing')

    def match(self, host, geoip=None, destination_ip=None):
        host=host.lower().rstrip('.')
        if '/' in host:raise ValueError('Use hostnames, not URL paths')
        candidates=self.final.copy()
        candidates.extend(self.exact.get(host,[]))
        parts=host.split('.')
        for j in range(len(parts)):
            candidates.extend(self.suffix.get('.'.join(parts[j:]),[]))
        candidates.extend(i for i,keyword in self.keywords if keyword in host)
        try:address=ipaddress.ip_address(destination_ip or host)
        except ValueError:address=None
        if address is not None:
            candidates.extend(i for i,net in self.ip if address.version==net.version and address in net)
        if geoip:
            candidates.extend(i for i,country in self.geo if country==geoip.upper())
        return self.rows[min(candidates)]

def parse_config(root=ROOT):
    """Expand exactly the files referenced by the real configuration, in order."""
    text=(root/'shadowrocket-ultimate.conf').read_text()
    section=None
    rows=[]
    general={}
    urls=[]
    policy=read_json(root/'policy.json')
    metadata={x['path']:x for x in policy['layers']}
    for line in text.splitlines():
        line=line.strip()
        if not line or line.startswith('#'):continue
        if line.startswith('['):
            if line not in {'[General]','[Rule]'}:raise ValueError('Forbidden configuration section')
            section=line
            continue
        if section=='[General]':
            key,value=[p.strip() for p in line.split('=',1)]
            if key in general:raise ValueError('Repeated General option')
            general[key]=value
            continue
        if section!='[Rule]':raise ValueError('Content outside supported sections')
        parts=[p.strip() for p in line.split(',')]
        kind=parts[0]
        if kind=='RULE-SET':
            if len(parts)!=3:raise ValueError('Invalid RULE-SET syntax')
            url,pol=parts[1:]
            u=urlsplit(url)
            prefix='/'+policy['repository']+'/'
            if u.scheme!='https' or u.netloc!='raw.githubusercontent.com' or not u.path.startswith(prefix) or u.query or u.fragment:
                raise ValueError('Unapproved rule URL')
            ref,rel=u.path[len(prefix):].split('/',1)
            if not re.fullmatch(r'rules-[0-9a-f]{16}',ref):raise ValueError('Rules must be pinned to a release snapshot')
            if rel not in metadata or pol!=metadata[rel]['policy']:raise ValueError('Rule URL or policy not in reviewed manifest')
            layer=metadata[rel]
            rows += [Rule(k,v,pol,rel,layer['category'],layer['manual']) for k,v in list_rules((root/rel).read_text())]
            urls.append(url)
        elif kind=='FINAL':
            if len(parts)!=2:raise ValueError('Invalid FINAL')
            rows.append(Rule('FINAL','',parts[1],'FINAL','Final',True))
        elif kind in {'DOMAIN','DOMAIN-SUFFIX','IP-CIDR','IP-CIDR6','GEOIP'}:
            if len(parts) not in {3,4}:raise ValueError('Invalid inline rule')
            if len(parts)==4 and parts[3]!='no-resolve':raise ValueError('Unapproved rule option')
            rows.append(Rule(kind,parts[1],parts[2],kind,'Inline',True))
        else:raise ValueError('Unapproved rule kind')
    if general!={'udp-policy-not-supported-behaviour':'REJECT'}:raise ValueError('General safety contract violated')
    if len([r for r in rows if r.kind=='FINAL'])!=1 or rows[-1].text()!='FINAL,美国家宽':raise ValueError('FINAL contract violated')
    if [(r.value,r.policy) for r in rows if r.kind=='GEOIP']!=[('CN',DIRECT)]:raise ValueError('Country GEOIP contract violated')
    expected=assembled(root)
    if [(r.kind,r.value,r.policy) for r in rows]!=[(r.kind,r.value,r.policy) for r in expected]:
        raise ValueError('Expanded configuration differs from authoritative layer order')
    return rows,urls

def check_cases(rows, cases):
    sim=Simulator(rows)
    results=[]
    for case in cases:
        r=sim.match(case['host'],case.get('geoip'),case.get('destination_ip'))
        results.append({'HOST':case['host'],'MATCHED_RULE':r.text(),'SOURCE':r.source,
                        'POLICY':r.policy,'EXPECTED':case['expected'],'RESULT':'PASS' if r.policy==case['expected'] else 'FAIL',
                        **({'GEOIP_FIXTURE':case['geoip']} if 'geoip' in case else {})})
    return results
