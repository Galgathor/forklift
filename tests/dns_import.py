#!/usr/bin/env python3
"""Reviewed record-set imports through real native REST/DNS, including durable retries."""
import json
import time
from fixture import Stack,run

with Stack() as s:
    s.setup();r=s.request;zone='example.test.';path='/api/dns/zones/'+zone
    r('/api/dns/zones','POST',dict(name=zone,kind='forward',nameserver='ns1.example.test.',nameserver_address='192.168.1.2',ttl=300))
    def record(name,kind,value,ttl=300):return dict(name=name,type=kind,ttl=ttl,records=[dict(content=v,disabled=False) for v in value])
    def draft(sets,**extra):return dict(data=dict(format=1,zone=zone,rrsets=sets),mode='merge')|extra
    def preview(body):return r(path+'/import/preview','POST',body)
    def commit(body,p,**extra):
        return r(path+'/import','POST',body|dict(expected_revision=p['expected_revision'],plan_hash=p['plan_hash'],confirm_name=zone,acknowledge=True)|extra)
    def dig(name,kind,value):
        text=run(['docker','run','--rm','--network','host','--entrypoint','dig','forklift-dns:latest','@127.0.0.1','-p',s.env['FORKLIFT_DNS_PORT'],name,kind,'+time=1','+tries=1']).stdout.decode()
        assert 'status: NOERROR' in text and value in text,text
        return text
    file=draft([record('server','A',['192.168.1.50']),record('server','AAAA',['fd00::50']),record('alias','CNAME',['server.example.test.']),record('@','MX',['10 mail.example.test.']),record('@','TXT',['"imported value"']),record('_service._tcp','SRV',['0 5 443 server.example.test.']),record('delegated','NS',['ns1.example.test.'])])
    r(path+'/import/preview','POST',file,authenticated=False,expect=401)
    r(path+'/import/preview','POST',file,use_csrf=False,expect=403)
    p=preview(file);assert len(p['changes'])==7
    assert not any(v['name']=='server.example.test.' for v in r(path)['rrsets'])
    r(path+'/import','POST',file|dict(expected_revision=p['expected_revision'],plan_hash=p['plan_hash'],confirm_name=zone,acknowledge=False),expect=400)
    assert commit(file,p)['status']=='completed'
    for name,kind,value in [('server','A','192.168.1.50'),('server','AAAA','fd00::50'),('alias','CNAME','server.example.test.'),('@','MX','10 mail.example.test.'),('@','TXT','"imported value"'),('_service._tcp','SRV','0 5 443 server.example.test.'),('delegated','NS','ns1.example.test.')]:
        dig((name+'.' if name!='@' else '')+zone,kind,value)
    merged=draft([record('server','A',['192.168.1.51'],ttl=900)])
    p=preview(merged);assert p['changes'][0]['after']['ttl']==300 and len(p['changes'][0]['after']['records'])==2
    commit(merged,p)
    text=dig('server.'+zone,'A','192.168.1.51');assert '192.168.1.50' in text
    replaced=draft([record('server','A',['192.168.1.52'],ttl=600)],mode='replace')
    p=preview(replaced);commit(replaced,p)
    text=dig('server.'+zone,'A','192.168.1.52');assert '192.168.1.50' not in text and '192.168.1.51' not in text
    # Disabled records stay disabled during merge; reverse JSON uses the actual reverse owner.
    disabled=record('disabled','TXT',['"kept disabled"']);disabled['records'][0]['disabled']=True
    body=draft([disabled]);commit(body,preview(body))
    merge_disabled=draft([record('disabled','TXT',['"kept disabled"','"active"'],ttl=900)])
    check=preview(merge_disabled)['changes'][0]['after']
    assert check['ttl']==300 and next(v for v in check['records'] if v['content']=='"kept disabled"')['disabled']
    commit(merge_disabled,preview(merge_disabled))
    assert 'kept disabled' not in dig('disabled.'+zone,'TXT','"active"')
    reverse='1.168.192.in-addr.arpa.';reverse_path='/api/dns/zones/'+reverse
    r('/api/dns/zones','POST',dict(name='192.168.1.0/24',kind='reverse4',nameserver='ns1.example.test.',ttl=300))
    body=dict(data=dict(format=1,zone=reverse,rrsets=[record('52','PTR',['server.example.test.'])]),mode='merge')
    check=r(reverse_path+'/import/preview','POST',body)
    assert r(reverse_path+'/import','POST',body|dict(expected_revision=check['expected_revision'],plan_hash=check['plan_hash'],confirm_name=reverse,acknowledge=True))['status']=='completed'
    dig('52.'+reverse,'PTR','server.example.test.')
    # A stale preview or modified file cannot apply against a newer zone.
    next_file=draft([record('fresh','A',['192.168.1.53'])]);stale=preview(next_file)
    other=draft([record('other','A',['192.168.1.54'])]);commit(other,preview(other))
    r(path+'/import','POST',next_file|dict(expected_revision=stale['expected_revision'],plan_hash=stale['plan_hash'],confirm_name=zone,acknowledge=True),expect=409)
    fresh=preview(next_file)
    r(path+'/import','POST',next_file|dict(expected_revision=fresh['expected_revision'],plan_hash='changed',confirm_name=zone,acknowledge=True),expect=409)
    for sets in [[record('alias','A',['192.168.1.50'])],[record('outside.invalid.','A',['192.168.1.50'])],[record('x','A',['192.168.1.50','192.168.1.50'])],[record('bad','LUA',['arbitrary'])],[record('@','CNAME',['server.example.test.'])]]:
        r(path+'/import/preview','POST',draft(sets),expect=400)
    # Export round-trips through this import format; native PowerDNS JSON is accepted too.
    exported,_=r(path+'/export-json',raw=True);document=json.loads(exported)
    assert document['format']==1 and 'api-key' not in exported.decode()
    roundtrip=preview(dict(data=document,mode='merge'));assert not roundtrip['changes']
    native_style=dict(name=zone,kind='Slave',masters=['ignored.invalid'],rrsets=[record('native-json','A',['192.168.1.55'])])
    body=dict(data=native_style,mode='merge');commit(body,preview(body))
    assert r(path)['kind']=='Native'
    dig('native-json.'+zone,'A','192.168.1.55')
    # Changed host-owned sets release ownership, preserving manual/imported values on deletion.
    host=r('/api/hosts','POST',dict(name='Managed',hostname='managed.example.test',endpoints=['ldaps://ldap.example.test'],allowed_groups=[],dns=dict(zone=zone,fqdn='managed',ipv4='192.168.1.56',ipv6=None,reverse=False)))
    body=draft([record('managed','A',['192.168.1.57'])]);commit(body,preview(body))
    host=next(h for h in r('/api/hosts') if h['id']==host['id']);assert host['dns_status']['state']=='needs_review'
    r('/api/hosts/'+host['id']+'?dns=delete&revision='+str(host['revision']),'DELETE')
    text=dig('managed.'+zone,'A','192.168.1.57');assert '192.168.1.56' in text
    # Rebuild a real interrupted import: one DNS set remains applied, another is absent.
    body=draft([record('recover-one','A',['192.168.1.58']),record('recover-two','A',['192.168.1.59'])])
    applied=commit(body,preview(body));operation=applied['id']
    code="import http.client,json;from pathlib import Path;c=http.client.HTTPConnection('127.0.0.1',8081);c.request('PATCH','/api/v1/servers/localhost/zones/example.test.',body=json.dumps(dict(rrsets=[dict(name='recover-two.example.test.',type='A',changetype='DELETE')])),headers={'X-API-Key':Path('/run/dns-secrets/api-key').read_text().strip(),'Content-Type':'application/json'});assert c.getresponse().status==204"
    s.compose('exec','-T','dns','python3','-c',code)
    s.compose('exec','-T','maintenance','python3','-c',"import sqlite3,sys;d=sqlite3.connect('/metadata/forklift.db');d.execute(\"UPDATE dns_changes SET status='pending' WHERE id=?\",(sys.argv[1],));d.commit()",operation)
    s.compose('restart','manager');s.wait()
    assert r('/api/dns/changes/'+operation+'/retry','POST',{})['status']=='completed'
    dig('recover-one.'+zone,'A','192.168.1.58');dig('recover-two.'+zone,'A','192.168.1.59')
    unavailable=draft([record('offline','A',['192.168.1.60'])]);p=preview(unavailable)
    s.compose('stop','dns')
    r(path+'/import','POST',unavailable|dict(expected_revision=p['expected_revision'],plan_hash=p['plan_hash'],confirm_name=zone,acknowledge=True),expect=503)
    s.bind('admin')
    print('PASS: real DNS imports and read-only preview, all supported types, merge/replace/TTL, validation, stale/file guards, JSON round-trip, host ownership, interrupted-plan retry and LDAP isolation.',flush=True)
