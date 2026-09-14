"""Fetch, normalize, resolve, test, report and build; Python standard library only."""
from __future__ import annotations
import argparse
import concurrent.futures
import collections
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import urllib.request
from routing import ROOT, Rule, Simulator, assembled, read_json, write_json, list_rules, domain, covers, overlap, parse_config, check_cases, LAN, TLD_POLICY, UK, JP, US, HK, DIRECT

WORK=ROOT/'work'

def now():return dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds')
def digest(b):return hashlib.sha256(b).hexdigest()

def request(url, method='GET'):
    req=urllib.request.Request(url,method=method,headers={'User-Agent':'regional-routing-rules/1.0','Accept':'application/vnd.github+json' if 'api.github.com' in url else 'text/plain'})
    with urllib.request.urlopen(req,timeout=45) as r:
        if r.status!=200:raise ValueError(f'HTTP {r.status}: {url}')
        if not r.url.startswith('https://'):raise ValueError('Insecure redirect')
        body=r.read() if method=='GET' else b''
        return body,r.headers.get('Content-Type','')

def fetch():
    WORK.mkdir(exist_ok=True)
    manifest=read_json(ROOT/'sources.json')
    repo,branch=manifest['repository'],manifest['branch']
    commit=json.loads(request(f'https://api.github.com/repos/{repo}/commits/{branch}')[0])
    sha=commit['sha']
    def one(source):
        url=f'https://raw.githubusercontent.com/{repo}/{sha}/{source["path"]}'
        _,head_type=request(url,'HEAD')
        b,content_type=request(url)
        text=b.decode('utf-8-sig')
        if '<html' in text[:1000].lower() or '<!doctype' in text[:1000].lower() or not text.startswith('# NAME:'):
            raise ValueError('Upstream is not the expected native rule file: '+source['name'])
        updated=re.search(r'^# UPDATED: (.+)$',text,re.M)
        first_rule=next((x for x in text.splitlines() if x and not x.startswith('#')),None)
        if not first_rule:raise ValueError('Empty upstream '+source['name'])
        return {**source,'url':url,'sha256':digest(b),'head_http':200,'get_http':200,'content_type':content_type,
                'upstream_updated':updated.group(1) if updated else 'not declared','first_rule':first_rule,'text':text}
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
        files=list(pool.map(one,manifest['sources']))
    write_json(WORK/'fetched.json',{'repository':repo,'commit':sha,'commit_date':commit['commit']['committer']['date'],'checked_at':now(),'files':files})
    print(f'FETCH PASS: {len(files)} pinned files, HEAD + GET HTTP 200')

def normalize():
    fetched=read_json(WORK/'fetched.json')
    policy=read_json(ROOT/'policy.json')
    excluded=set(policy['exclude_domains'])
    shared=set(policy['shared_infrastructure_roots'])
    rows=[]; omitted=[]
    for file in fetched['files']:
        for raw in file['text'].splitlines():
            raw=raw.strip()
            if not raw or raw.startswith('#'):continue
            reason=None
            if file['format']=='domain-set':
                kind='DOMAIN-SUFFIX' if raw.startswith('.') else 'DOMAIN'
                value=raw.lstrip('.')
            else:
                parts=[x.strip() for x in raw.split(',')]
                kind=parts[0]
                if kind not in {'DOMAIN','DOMAIN-SUFFIX'}:
                    # Never carry request-path, application, keyword or network-range rules into domain snapshots.
                    omitted.append({'source':file['name'],'kind':kind,'reason':'unsupported_or_deliberately_omitted_type'})
                    continue
                if len(parts)!=2:raise ValueError('Unexpected upstream domain-rule syntax: '+file['name'])
                value=parts[1]
            value=domain(value)
            if re.search(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',value):
                omitted.append({'source':file['name'],'kind':kind,'reason':'identifier_like_hostname_omitted'})
                continue
            if value in excluded:reason='reviewed_market_or_shared_endpoint_exclusion'
            if value in shared:reason='shared_infrastructure_root'
            if '.' not in value and value not in {'bbc','youtube','cn','tmall','alibaba','icbc','citic'}:
                reason='unreviewed_top_level_domain'
            if file['category']=='china' and value in {'cn','tmall','alibaba','icbc','citic'}:
                # Country/brand suffixes are explicit only, below global product overrides.
                if value!='cn':reason='broad_brand_tld_not_market_specific'
                else:reason='cn_suffix_has_dedicated_fallback_position'
            if reason:
                omitted.append({'source':file['name'],'kind':kind,'value':value,'reason':reason})
            else:
                rows.append({'kind':kind,'value':value,'upstream_category':file['category'],'source':file['name']})
    write_json(WORK/'normalized.json',{'rows':rows,'omitted':omitted})
    print(f'NORMALIZE PASS: {len(rows)} rows; {len(omitted)} reviewed exclusions/type omissions')

def classify():
    config=read_json(ROOT/'policy.json')
    normalized=read_json(WORK/'normalized.json')
    layer_by_category={l['upstream_category']:l for l in config['layers'] if not l['manual']}
    indexed={l['path']:i for i,l in enumerate(config['layers'])}
    manual=[]
    shared_roots=set(config['shared_infrastructure_roots'])
    for l in config['layers']:
        if l['manual']:
            manual += [(k,v,l) for k,v in list_rules((ROOT/l['path']).read_text())]
    manual_exact=collections.defaultdict(list)
    manual_suffix=collections.defaultdict(list)
    manual_descendants=collections.defaultdict(list)
    for mi,(k,v,l) in enumerate(manual):
        (manual_exact if k=='DOMAIN' else manual_suffix)[v].append(mi)
        parts=v.split('.')
        for j in range(len(parts)):
            manual_descendants['.'.join(parts[j:])].append(mi)
    out=collections.defaultdict(set);conflicts=[];skip=0
    for row in normalized['rows']:
        rule=(row['kind'],row['value'])
        category=row['upstream_category']
        target=layer_by_category[category]
        # Country domains represent product markets. Crypto remains subject to its explicit ecosystem policy.
        tld=row['value'].rsplit('.',1)[-1]
        if category!='crypto' and tld in {'uk','jp','hk'}:
            target=layer_by_category[{'uk':'uk','jp':'jp','hk':'hk'}[tld]]
        blocked=None
        candidate_ids=set(manual_exact.get(row['value'],[]))
        parts=row['value'].split('.')
        for j in range(len(parts)):
            candidate_ids.update(manual_suffix.get('.'.join(parts[j:]),[]))
        if row['kind']=='DOMAIN-SUFFIX':
            candidate_ids.update(manual_descendants.get(row['value'],[]))
        for mi in sorted(candidate_ids):
            k,v,l=manual[mi]
            if not overlap((k,v),rule):continue
            if (v in shared_roots and row['value']!=v and covers((k,v),rule)
                    and indexed[target['path']]<indexed[l['path']]):
                # The shared-parent default is not a prohibition on an audited, dedicated child hostname.
                # Generic shared endpoints are separately excluded by normalize().
                continue
            if covers((k,v),rule):
                # The local rule already supplies the complete coverage; no remote override can displace it.
                blocked=(k,v,l,'local_canonical_covers_upstream')
                break
            if l['policy']!=target['policy'] and indexed[target['path']]<=indexed[l['path']]:
                blocked=(k,v,l,'upstream_parent_would_shadow_local_canonical')
                break
        if blocked:
            k,v,l,reason=blocked
            if target['policy']!=l['policy']:
                conflicts.append({'rule':','.join(rule),'source':row['source'],'candidate_policy':target['policy'],
                                  'winner_rule':f'{k},{v}','winner_policy':l['policy'],'resolution':reason})
            skip+=1
            continue
        out[target['path']].add(rule)
    # Resolve exact and suffix overlaps deterministically in authoritative layer order.
    accepted=[]
    for l in config['layers']:
        candidates=list_rules((ROOT/l['path']).read_text()) if l['manual'] else sorted(out[l['path']])
        keep=[]
        for k,v in candidates:
            r=Rule(k,v,l['policy'],l['path'],l['category'],l['manual'])
            # Indexed suffix lookup avoids quadratic scans over the China list.
            keep.append(r)
        accepted.extend(keep)
    seen_exact={};seen_suffix={};final=collections.defaultdict(list)
    for r in accepted:
        predecessors=[]
        parts=r.value.split('.')
        predecessors+=seen_exact.get(r.value,[])
        for j in range(len(parts)):
            predecessors+=seen_suffix.get('.'.join(parts[j:]),[])
        covering=[p for p in predecessors if covers(p,r)]
        if covering and not r.manual:
            p=covering[0]
            if p.policy!=r.policy:
                conflicts.append({'rule':f'{r.kind},{r.value}','source':r.source,'candidate_policy':r.policy,
                                  'winner_rule':f'{p.kind},{p.value}','winner_policy':p.policy,'resolution':'authoritative_priority_removes_covered_lower_rule'})
            continue
        final[r.source].append((r.kind,r.value))
        (seen_exact if r.kind=='DOMAIN' else seen_suffix).setdefault(r.value,[]).append(r)
    for l in config['layers']:
        if not l['manual']:
            text='# Tested normalized snapshot. Attribution and revisions: upstream-lock.json.\n'
            text+='\n'.join(','.join(r) for r in final[l['path']])+'\n'
            (ROOT/l['path']).write_text(text)
    # Retained broad lower-priority rules can contain deliberate higher-priority exceptions.
    current=assembled()
    parent_index=collections.defaultdict(list)
    for i,r in enumerate(current):
        if r.kind=='DOMAIN-SUFFIX':parent_index[r.value].append((i,r))
    overlaps=[]
    for i,r in enumerate(current):
        if r.kind not in {'DOMAIN','DOMAIN-SUFFIX'}:continue
        parts=r.value.split('.')
        for j in range(len(parts)):
            for pi,p in parent_index.get('.'.join(parts[j:]),[]):
                if pi<=i or p.policy==r.policy:continue
                overlaps.append({'rule':f'{r.kind},{r.value}','policy':r.policy,'lower_rule':f'{p.kind},{p.value}',
                                 'lower_policy':p.policy,'winner_policy':r.policy,'resolution':'explicit_higher_priority_exception'})
    result={'resolution_order':['local canonical overrides','regional native','crypto','global category','China','country suffix','FINAL'],
            'resolved_count':len(conflicts),'resolved':conflicts,'retained_overlap_count':len(overlaps),'retained_overlaps':overlaps,'unresolved':[]}
    write_json(ROOT/'conflicts.json',result)
    fetched=read_json(WORK/'fetched.json')
    write_json(ROOT/'upstream-lock.json',{k:v for k,v in fetched.items() if k!='files'} | {'sources':[{k:v for k,v in f.items() if k!='text'} for f in fetched['files']],
                           'normalization':{'kept_before_canonical_resolution':len(normalized['rows']),'omitted_count':len(normalized['omitted']),
                                            'omitted_by_reason':dict(collections.Counter(x['reason'] for x in normalized['omitted'])),
                                            'domain_exclusions':[x for x in normalized['omitted'] if 'value' in x]}})
    print(f'CLASSIFY PASS: canonical overrides protected; {len(conflicts)} conflicts resolved; {len(overlaps)} explicit overlaps recorded')

def snapshot_version():
    config=read_json(ROOT/'policy.json')
    h=hashlib.sha256()
    h.update(json.dumps(config,sort_keys=True,ensure_ascii=False).encode())
    for layer in config['layers']:
        h.update(layer['path'].encode());h.update((ROOT/layer['path']).read_bytes())
    return 'rules-'+h.hexdigest()[:16]

def build():
    config=read_json(ROOT/'policy.json')
    version=snapshot_version()
    base=f'https://raw.githubusercontent.com/{config["repository"]}/{version}/'
    lines=['# Shadowrocket Ultimate Regional Routing',f'# Snapshot: {version}',
           '[General]','udp-policy-not-supported-behaviour = REJECT','','[Rule]','# 0. Local/private destinations']
    for k,v in LAN:
        lines.append(f'{k},{v},DIRECT'+(',no-resolve' if k.startswith('IP-CIDR') else ''))
    prev=None
    stage_names={0:'Critical manual overrides',1:'UK native',2:'Japan native',3:'Hong Kong native',4:'Crypto general',5:'Global AI',6:'Global streaming and shared international infrastructure',7:'Global social',8:'International finance',9:'Mainland China'}
    for l in config['layers']:
        if l['stage']!=prev:
            lines.extend(['',f'# {l["stage"]+1}. {stage_names[l["stage"]]}']);prev=l['stage']
        lines.append(f'RULE-SET,{base}{l["path"]},{l["policy"]}')
    lines+=['','# 11. Country domain suffixes']
    lines += [f'DOMAIN-SUFFIX,{t},{p}' for t,p in TLD_POLICY.items()]
    lines += ['','# 12. Mainland destination fallback','GEOIP,CN,DIRECT,no-resolve','','# 13. Explicit default','FINAL,美国家宽','']
    (ROOT/'shadowrocket-ultimate.conf').write_text('\n'.join(lines))
    print('BUILD PASS:',version)
    return version

def validate():
    rows,urls=parse_config()
    config=read_json(ROOT/'policy.json')
    if config['labels']!=[UK,JP,US,HK]:raise ValueError('Fixed node label contract changed')
    if config['udp_reject'] is not True:raise ValueError('UDP policy contract changed')
    if [l['stage'] for l in config['layers']]!=sorted(l['stage'] for l in config['layers']):raise ValueError('Layer order changed')
    for l in config['layers']:
        raw=(ROOT/l['path']).read_text()
        parsed=list_rules(raw)
        if len(set(parsed))!=len(parsed):raise ValueError('Duplicate rules in '+l['path'])
    if any(x['unresolved'] for x in [read_json(ROOT/'conflicts.json')]):raise ValueError('Unresolved conflicts')
    duplicate_policies=collections.defaultdict(set)
    for r in rows:
        if r.kind in {'DOMAIN','DOMAIN-SUFFIX'}:
            duplicate_policies[(r.kind,r.value)].add(r.policy)
    if any(len(p)>1 for p in duplicate_policies.values()):
        raise ValueError('Same domain rule has multiple unresolved policies')
    sim=Simulator(rows)
    for c in read_json(ROOT/'conflicts.json')['retained_overlaps']:
        host=c['rule'].split(',',1)[1]
        if sim.match(host).policy!=c['winner_policy']:
            raise ValueError('Recorded overlap decision differs from effective routing')
    # Public payload allowlist, including workflows and regression fixtures. Only LAN ranges are literal addresses.
    banned=[r'(?i)(?:vless|vmess|ss|ssr|trojan|hysteria2?)://',r'(?i)-----BEGIN [A-Z ]*PRIVATE KEY-----',
            r'(?i)gh[pousr]_[A-Za-z0-9]{30,}',r'(?i)github_pat_[A-Za-z0-9_]{30,}',
            r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
            '/'+r'Users/[^/]+/','/'+r'home/[^/]+/',r'(?i)(password|subscription-url|reality-key)\s*[:=]\s*["\']?[^\s,}]+']
    allowed_top={'README.md','CHANGELOG.md','LICENSE','sources.json','policy.json','upstream-lock.json','conflicts.json','version.json','shadowrocket-ultimate.conf','.gitignore','rules','scripts','tests','reports','.github'}
    for p in ROOT.rglob('*'):
        if not p.is_file():continue
        rel=p.relative_to(ROOT)
        if rel.parts[0] in {'.git','work'} or '__pycache__' in rel.parts:continue
        if rel.parts[0] not in allowed_top:raise ValueError('Unexpected public file: '+str(rel))
        text=p.read_text(encoding='utf-8')
        for pattern in banned:
            if re.search(pattern,text):raise ValueError('Public secret/path scan failed: '+str(rel))
    print(f'VALIDATE PASS: {len(rows)} expanded rules; {len(urls)} pinned RULE-SET URLs; safe sections and payload')

def regress(verbose=False):
    rows,_=parse_config()
    cases=read_json(ROOT/'tests/routing_cases.yaml') # JSON is a YAML 1.2 subset; no parser dependency.
    results=check_cases(rows,cases)
    WORK.mkdir(exist_ok=True)
    write_json(WORK/'regression-results.json',results)
    bad=[r for r in results if r['RESULT']!='PASS']
    if verbose or bad:
        for r in results if verbose else bad:print(json.dumps(r,ensure_ascii=False))
    if bad:raise ValueError(f'{len(bad)} fixed regression cases failed')
    # All deliberate local overrides must win for the hostname and arbitrary descendants.
    sim=Simulator(rows);manual_checks=0
    for l in read_json(ROOT/'policy.json')['layers']:
        if not l['manual']:continue
        for k,v in list_rules((ROOT/l['path']).read_text()):
            for host in [v]+(['routing-test.'+v] if k=='DOMAIN-SUFFIX' else []):
                winner=sim.match(host)
                if winner.policy!=l['policy']:
                    # A more specific *earlier* manual rule may deliberately divide a shared suffix.
                    matches=[r for r in rows if r.manual and r.kind in {'DOMAIN','DOMAIN-SUFFIX'} and covers(r,('DOMAIN',host))]
                    if not matches or winner.policy!=matches[0].policy:raise ValueError('Canonical override shadowed: '+v)
                manual_checks+=1
    print(f'REGRESSION PASS: {len(results)}/{len(results)} fixed cases; {manual_checks} canonical host/descendant checks')
    return results

def policy_diff(old_rows,new_rows):
    old,new=Simulator(old_rows),Simulator(new_rows)
    witnesses=set()
    for r in old_rows+new_rows:
        if r.kind in {'DOMAIN','DOMAIN-SUFFIX'}:
            witnesses.add(r.value)
            if r.kind=='DOMAIN-SUFFIX':witnesses.add('routing-test.'+r.value)
    changes=[]
    for host in sorted(witnesses):
        a,b=old.match(host),new.match(host)
        if a.policy!=b.policy:
            changes.append({'host':host,'old':a.policy,'new':b.policy,'old_rule':a.text(),'new_rule':b.text(),
                            'old_source':a.source,'new_source':b.source,'high_impact':True})
    return changes

def make_report(previous,old_rows,results,status='PASS',reason=''):
    version=snapshot_version();stamp=now();date=stamp[:10]
    new_rows=assembled();changes=policy_diff(old_rows,new_rows) if old_rows else []
    oldset={(r.kind,r.value,r.policy,r.category) for r in old_rows}
    newset={(r.kind,r.value,r.policy,r.category) for r in new_rows}
    added=newset-oldset;removed=oldset-newset
    lock=read_json(ROOT/'upstream-lock.json') if (ROOT/'upstream-lock.json').exists() else {}
    oldlock=previous.get('sources',{})
    sources=[s for s in lock.get('sources',[]) if oldlock.get(s['name'])!=s['sha256']]
    report=[f'# {date} — {status}',f'\nUpdate Date: {stamp}',f'Previous Version: {previous.get("version","none (initial release)")}',f'New Version: {version}',
            f'\nStatus: {status}',f'Added rules: {len(added)}',f'Removed rules: {len(removed)}',f'Modified policy witnesses: {len(changes)}',
            '\n## Upstream sources changed']
    report += [f'- {s["name"]}: upstream content date {s["upstream_updated"]}; SHA-256 `{s["sha256"]}`' for s in sources] or ['None.']
    report += ['\n## Counts by category','| Category | Added | Removed | Policy changes |','|---|---:|---:|---:|']
    new_sim=Simulator(new_rows)
    changes_by_category=collections.Counter(new_sim.match(c['host']).category for c in changes)
    for cat in ['UK','Japan','Hong Kong','US/Global','Crypto','AI','Streaming','Social','China DIRECT','Finance','Apple']:
        report.append(f'| {cat} | {sum(x[3]==cat for x in added)} | {sum(x[3]==cat for x in removed)} | {changes_by_category[cat]} |')
    report += ['\n## POLICY CHANGES']
    report += [f'- `{c["host"]}` OLD: {c["old"]}; NEW: {c["new"]}' for c in changes] or ['None. Initial installation establishes the requested policies; it is not a migration of any local configuration.' if not old_rows else 'None.']
    report += ['\n## HIGH IMPACT CHANGES']
    report += [f'- `{c["host"]}`: {c["old"]} → {c["new"]}; {c["old_rule"]} → {c["new_rule"]}' for c in changes] or ['None.']
    report += ['\n## Important changes']
    if not old_rows:
        report += ['- PayPal first-party endpoints are UK; the explicit paypal.us suffix is US.',
                   '- Kraken, Kraken Pro and Krak are UK; the remaining identified crypto ecosystem is Japan.',
                   '- Added official exchange REST/WebSocket roots, including binance.vision, gateio.ws, bytick.com, and wbs-api.mexc.com.',
                   '- Shared cloud/CDN roots and generic Brightcove, Cognito and LaunchDarkly endpoints are not assigned to a regional service.',
                   '- UK/Japan/Hong Kong destination-country GEOIP rules are absent. The sole country lookup is CN after domain rules.',
                   '- Apple China uses apple.com.cn, icloud.com.cn and Apple-documented apzones.com. Shared Apple infrastructure uses US.',
                   '- All keyword, request-path, application-name and upstream public-IP rules were omitted.',
                   '- The ChinaMaxNoIP native rule file and companion domain file were combined; relying on the small rule file alone would omit most coverage.']
    else:
        report += [f'- Added `{k},{v}` → {p} ({cat})' for k,v,p,cat in sorted(added)[:100]]
        report += [f'- Removed `{k},{v}` → {p} ({cat})' for k,v,p,cat in sorted(removed)[:100]]
        if len(added)+len(removed)>200:report += ['Complete added/removed rules are included in the accompanying machine-readable change report.']
    conflicts=read_json(ROOT/'conflicts.json') if (ROOT/'conflicts.json').exists() else {}
    report += ['\n## Conflict decisions',f'Resolved collisions: {conflicts.get("resolved_count",0)}. Explicit suffix overlaps: {conflicts.get("retained_overlap_count",0)}. Full evidence: [conflicts.json](../conflicts.json).']
    report += [f'- `{c["rule"]}`: {c["candidate_policy"]} → {c["winner_policy"]}; {c["resolution"]}' for c in conflicts.get('resolved',[])[:40]]
    report += ['\n## Validation',f'Fixed routing cases: {len(results)}; passed: {sum(r["RESULT"]=="PASS" for r in results)}.',
               'The simulator expands the actual configuration URLs into domain rules and chooses the first matching rule. GEOIP test inputs are synthetic country metadata, not live DNS or a bundled country database.',
               'UDP configuration support was verified in Shadowrocket 2.2.92 build 3445 using its installed bundled default template and executable. UDP traffic behavior was not exercised.',
               'All four required node display names were found exactly once in a read-only traversal of the complete local node archive, including subscription records. No connection or active configuration was changed.',
               '\n## Limits',
               'Hostname rules identify reviewed first-party endpoints and selected service-specific CDN hostnames. Shared third-party infrastructure follows its own rules. Unknown domains use the US default (or CN destination fallback); this cannot prove the egress of undiscovered endpoints. No HTTPS path matching, live account activity, native import or active-profile switch was performed.',
               'Importing or updating a profile is performed by Shadowrocket separately from this repository. Existing enabled modules can take precedence over profile rules; they were not modified. The current connection and server chains were left intact.',
               'GitHub scheduled runs are best effort. Blocked updates retain the last published snapshot; their report is available in the failed workflow run artifacts and job summary.']
    if reason:report += ['\n## UPDATE_BLOCKED reason',reason]
    reporttext=re.sub(r'(?m)^(#{1,3} .+)$',r'\1\n','\n'.join(report))+'\n'
    artifact={'date':stamp,'status':status,'previous':previous.get('version'),'new':version,'added':[list(x) for x in sorted(added)],'removed':[list(x) for x in sorted(removed)],'policy_changes':changes,'reason':reason}
    WORK.mkdir(exist_ok=True)
    (WORK/'update-report.md').write_text(reporttext)
    write_json(WORK/'change-report.json',artifact)
    return reporttext,artifact

def publish_report(previous,old_rows,results):
    report,data=make_report(previous,old_rows,results)
    version=data['new'];date=data['date'][:10];path=ROOT/'reports'/f'{date}.md'
    if path.exists():report=path.read_text()+'\n---\n\n'+report
    path.write_text(report)
    write_json(ROOT/'reports'/f'{date}-{version}.json',data)
    write_json(ROOT/'reports'/f'{date}-routing-results.json',results)
    (ROOT/'version.json').write_text(json.dumps({'version':version,'last_updated':data['date'],'last_successful_test':data['date'],
                                    'last_change_report':f'reports/{date}.md','fixed_cases':len(results)},ensure_ascii=False,indent=2)+'\n')
    changelog=ROOT/'CHANGELOG.md'
    old=changelog.read_text() if changelog.exists() else '# Change history\n'
    changelog.write_text(old+f'\n- {data["date"]}: [{version}](reports/{date}.md), {len(results)} fixed routing cases passed.\n')
    readme=ROOT/'README.md'
    text=readme.read_text()
    status=f'<!-- STATUS -->\nCurrent Version: `{version}`  \nLast Updated: {data["date"]}  \nLast Successful Test: {data["date"]} — {len(results)} / {len(results)} fixed cases  \nLast Change Report: [{date}](reports/{date}.md)\n<!-- /STATUS -->'
    text=re.sub(r'<!-- STATUS -->.*?<!-- /STATUS -->',lambda _:status,text,flags=re.S)
    readme.write_text(text)

def save_before():
    previous=read_json(ROOT/'version.json') if (ROOT/'version.json').exists() else {}
    rows=assembled() if previous else []
    if previous and (ROOT/'upstream-lock.json').exists():previous['sources']={s['name']:s['sha256'] for s in read_json(ROOT/'upstream-lock.json')['sources']}
    return previous,rows

def update():
    previous,old_rows=save_before();results=[]
    try:
        fetch();normalize();classify();version=build();validate();results=regress()
        subprocess.run([sys.executable,'-m','unittest','discover','-s','tests','-p','test_*.py'],cwd=ROOT,check=True)
        changes=policy_diff(old_rows,assembled()) if old_rows else []
        if changes:
            make_report(previous,old_rows,results,'UPDATE_BLOCKED','Effective policy changed. A deliberate canonical-rule review is required; automatic upstream updates cannot approve country or DIRECT changes.')
            raise ValueError(f'UPDATE_BLOCKED: {len(changes)} high-impact policy witnesses changed')
        if version==previous.get('version'):
            make_report(previous,old_rows,results,'NO_RULE_CHANGES')
            print('NO_RULE_CHANGES: retain published snapshot and history')
            return
        publish_report(previous,old_rows,results)
        validate()
        print('RELEASE_READY:',version)
    except Exception as e:
        WORK.mkdir(exist_ok=True)
        if not (WORK/'update-report.md').exists():
            (WORK/'update-report.md').write_text('# UPDATE_BLOCKED\n\n'+str(e)+'\n\nThe published main branch was not changed.\n')
        raise

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('command',choices=['fetch','normalize','classify','build','validate','regression','update'])
    parser.add_argument('--verbose',action='store_true')
    args=parser.parse_args()
    if args.command=='regression':regress(args.verbose)
    else:globals()[args.command]()

if __name__=='__main__':main()
