"""Real DNS forwarding, network ACLs, authoritative negatives and persistence."""
import json
import time
from fixture import Stack, run, port

with Stack(dns_bind='0.0.0.0') as upstream, Stack(dns_bind='0.0.0.0') as source:
    upstream.setup(); source.setup()
    def zone(stack, name):
        stack.request('/api/dns/zones','POST',dict(name=name,kind='forward',nameserver='ns1.'+name,nameserver_address='192.168.1.2',ttl=300))
    def record(stack, name, address):
        stack.request('/api/dns/zones/'+name+'/records','POST',dict(name='answer',type='A',values=[address],ttl=300,auto_ptr=False))
    zone(upstream,'outside.test.'); record(upstream,'outside.test.','192.168.1.80')
    zone(source,'inside.test.'); record(source,'inside.test.','192.168.1.90')
    path='/api/dns/forwarding'
    source.request(path,authenticated=False,expect=401)
    config=source.request(path)['settings']
    assert config['enabled'] is False
    # Include only the private bridge used by this disposable source fixture.
    network=json.loads(run(['docker','network','inspect',source.project+'_default']).stdout)[0]
    allowed=network['IPAM']['Config'][0]['Subnet']
    value=dict(enabled=True,upstreams=[dict(address=upstream.net['address'],port=int(upstream.env['FORKLIFT_DNS_PORT']))],allowed_clients=[allowed,'127.0.0.0/8',source.net['address']+'/32'])
    source.request(path,'PUT',value,authenticated=False,expect=401)
    source.request(path,'PUT',value,use_csrf=False,expect=403)
    source.request(path,'PUT',dict(value,allowed_clients=['0.0.0.0/0']),expect=400)
    source.request(path,'PUT',dict(value,upstreams=[dict(address=source.net['address'],port=int(source.env['FORKLIFT_DNS_PORT']))]),expect=400)
    source.request(path,'PUT',value)
    def query(name,tcp=False,rcode='NOERROR',content=None):
        args=['docker','run','--rm','--network','host','--entrypoint','dig','forklift-dns:latest','@127.0.0.1','-p',source.env['FORKLIFT_DNS_PORT'],name,'A','+time=2','+tries=1']
        if tcp:args.append('+tcp')
        result=run(args).stdout.decode()
        assert 'status: '+rcode in result,result
        if content:assert content in result,result
        return result
    query('answer.outside.test.',content='192.168.1.80')
    query('answer.outside.test.',tcp=True,content='192.168.1.80')
    query('answer.inside.test.',content='192.168.1.90')
    def eventually(**options):
        for attempt in range(12):
            try:
                return query('answer.outside.test.',**options)
            except (AssertionError,RuntimeError):
                if attempt == 11:raise
                time.sleep(1)
    upstream.compose('stop','dns')
    eventually(rcode='SERVFAIL')
    query('answer.inside.test.',content='192.168.1.90')
    upstream.compose('start','dns')
    eventually(content='192.168.1.80')
    source.request(path,'PUT',dict(value,upstreams=[dict(address=upstream.net['address'],port=port()),*value['upstreams']]))
    eventually(content='192.168.1.80')
    source.request(path,'PUT',value)
    # A missing managed name stays authoritative and is not answered upstream.
    zone(upstream,'inside.test.')
    upstream.request('/api/dns/zones/inside.test./records','POST',dict(name='missing',type='A',values=['192.168.1.99'],ttl=300,auto_ptr=False))
    answer=query('missing.inside.test.',rcode='NXDOMAIN')
    assert 'aa' in answer.split('flags:',1)[1].split(';',1)[0].split(),answer
    source.request(path,'PUT',dict(value,allowed_clients=['192.168.254.0/24']))
    query('answer.outside.test.',rcode='REFUSED')
    query('answer.inside.test.',content='192.168.1.90')
    source.request(path,'PUT',value)
    source.compose('up','-d','--no-build','--force-recreate','--no-deps','--wait','dns')
    assert source.request(path)['settings']==value
    query('answer.outside.test.',content='192.168.1.80')
    # Newly managed zones take precedence immediately, even with overlapping upstream data.
    zone(source,'outside.test.'); record(source,'outside.test.','192.168.1.81')
    query('answer.outside.test.',content='192.168.1.81')
    zone_data=source.request('/api/dns/zones/outside.test.')
    source.request('/api/dns/zones/outside.test.','DELETE',dict(acknowledge=True,confirm_name='outside.test.',expected_revision=zone_data['revision']))
    query('answer.outside.test.',content='192.168.1.80')
    source.compose('stop','manager')
    query('answer.outside.test.',content='192.168.1.80')
    source.compose('start','manager'); source.wait()
    source.request(path,'PUT',dict(value,enabled=False))
    query('answer.outside.test.',rcode='REFUSED')
    query('answer.inside.test.',content='192.168.1.90')
    source.compose('stop','dns')
    source.request(path,'PUT',value,expect=503)
    assert source.request('/api/overview')['users']
    assert any(e['action']=='DNS failed forwarding' for e in source.request('/api/dns')['errors'])
    source.compose('start','dns')
    print('PASS: real UDP/TCP forwarding, authorization/CSRF, private client ACLs, local NXDOMAIN, immediate zone routing, persistent settings, disabling forwarding and manager-independent DNS.',flush=True)
