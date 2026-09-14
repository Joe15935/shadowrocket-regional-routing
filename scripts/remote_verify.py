"""Anonymous curl HEAD and GET checks of the public configuration and every snapshot URL."""
from pathlib import Path
import argparse
import concurrent.futures
import hashlib
import re
import subprocess
from urllib.parse import urlsplit
from routing import ROOT, read_json, parse_config, write_json

def verify(ref='main'):
    if ref!='main' and not re.fullmatch(r'rules-[0-9a-f]{16}',ref):
        raise ValueError('Expected main or a content-addressed snapshot tag')
    _,urls=parse_config()
    repo=read_json(ROOT/'policy.json')['repository']
    main=f'https://raw.githubusercontent.com/{repo}/{ref}/shadowrocket-ultimate.conf'
    targets=[(main,'shadowrocket-ultimate.conf')]+[(u,u.split('/rules-',1)[1].split('/',1)[1]) for u in urls]
    work=ROOT/'work'/'remote-checks';work.mkdir(parents=True,exist_ok=True)
    def one(pair):
        url,rel=pair
        key=hashlib.sha256(url.encode()).hexdigest()[:16]
        header=work/(key+'.headers');body=work/(key+'.body')
        # -q prevents a personal curl configuration from adding authentication or changing behavior.
        common=['curl','-q','--fail','--silent','--show-error','--location','--proto','=https','--max-time','45','--retry','3','--retry-all-errors','--retry-delay','2']
        h=subprocess.run(common+['--head','--output',str(header),'--write-out','%{http_code}',url],capture_output=True,text=True,check=True)
        g=subprocess.run(common+['--output',str(body),'--write-out','%{http_code}',url],capture_output=True,text=True,check=True)
        if h.stdout!='200' or g.stdout!='200':raise ValueError('Public URL did not return HTTP 200')
        data=body.read_bytes()
        if data!=(ROOT/rel).read_bytes():raise ValueError('Public content mismatch: '+rel)
        text=data.decode('utf-8')
        if '<html' in text.lower() or '<!doctype' in text.lower():raise ValueError('HTML instead of raw text')
        return {'path':rel,'url':url,'head_http':200,'get_http':200,'sha256':hashlib.sha256(data).hexdigest(),'matches_local':True,
                'first_line':text.splitlines()[0]}
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:results=list(pool.map(one,targets))
    write_json(work/'results.json',results)
    print(f'REMOTE PASS: {len(results)} anonymous raw HTTPS resources; curl HEAD/GET HTTP 200; exact byte equality')

if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--ref',default='main')
    verify(parser.parse_args().ref)
