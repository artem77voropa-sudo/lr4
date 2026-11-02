"""Local LR04 HTTP evidence. Credentials/cookies never printed; created fixtures cleaned in finally."""
import os,json,uuid,urllib.request,urllib.error,http.cookiejar,subprocess
from pathlib import Path
base='http://localhost:5080'
out=Path(__file__).resolve().parents[2]/'docs/evidence/lr04'
assert 'Database=securelab_lr04;' in os.environ.get('ConnectionStrings__SecureLab',''), 'Load Use-Lab04.ps1 first.'
created=[]
def client():return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
def req(c,method,path,body=None):
 data=None if body is None else json.dumps(body).encode()
 r=urllib.request.Request(base+path,data=data,method=method,headers={'Accept':'application/json','Content-Type':'application/json'})
 try: response=c.open(r)
 except urllib.error.HTTPError as e:response=e
 with response:
  raw=response.read().decode()
  return {'status':response.status,'mediaType':response.headers.get_content_type(),'body':json.loads(raw) if raw else None}
def save(name,result):
 (out/(name+'.json')).write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
 print(name+': saved (safe response/state only)')
def create(c):
 r=req(c,'POST','/api/incidents',{'title':'LR04-evidence-'+uuid.uuid4().hex,'description':'Synthetic evidence incident.','severity':'Low','occurredAtUtc':'2026-09-01T10:00:00Z'})
 assert r['status']==201
 id=str(uuid.UUID(r['body']['id']));created.append(id);return '/api/incidents/'+id
out.mkdir(parents=True,exist_ok=True)
a,b,m=client(),client(),client()
for name,c in [('alice',a),('bob',b),('morgan',m)]:
 assert req(c,'POST','/api/auth/login',{'userName':name,'password':os.environ['SeedUsers__Password']})['status']==204
 save('profile-'+name,req(c,'GET','/api/me'))
alice='/api/incidents/20000000-0000-0000-0000-000000000001'
bob='/api/incidents/20000000-0000-0000-0000-000000000002'
try:
 anon=req(client(),'GET',alice);assert anon['status']==401;save('A01-anonymous',anon)
 own=req(a,'GET',alice);assert own['status']==200;save('A02-owner',own)
 foreign=req(a,'GET',bob);unknown=req(a,'GET','/api/incidents/'+str(uuid.uuid4()))
 assert foreign['status']==unknown['status']==404
 assert {k:v for k,v in foreign['body'].items() if k!='traceId'}=={k:v for k,v in unknown['body'].items() if k!='traceId'}
 save('A03-A10-foreign-unknown',{'foreign':foreign,'unknown':unknown})
 before=req(b,'GET',bob);update=req(a,'PUT',bob,{'title':before['body']['title'],'description':'LOCAL LR04 PoC: unauthorized synthetic modification.'});delete=req(a,'DELETE',bob);after=req(b,'GET',bob)
 assert update['status']==delete['status']==404 and before==after
 save('A04-update-delete',{'before':before,'update':update,'delete':delete,'after':after,'unchanged':before==after})
 listing=req(a,'GET','/api/incidents');assert all(x['id']!='20000000-0000-0000-0000-000000000002' for x in listing['body']);save('A05-list',listing)
 path=create(a);before=req(a,'GET',path)
 denied=req(a,'POST',path+'/triage',{'role':'Analyst','status':'Triaged','ownerUserId':'10000000-0000-0000-0000-000000000003'})
 after=req(a,'GET',path);assert denied['status']==403 and before==after
 save('A06-A09-denied-triage',{'before':before,'response':denied,'after':after,'unchanged':True})
 allowed=req(m,'POST',path+'/triage');after=req(a,'GET',path);again=req(m,'POST',path+'/triage')
 assert allowed['status']==204 and after['body']['status']=='Triaged' and again['status']==403
 save('A07-analyst-triage',{'response':allowed,'after':after,'repeat':again})
 path=create(a);before=req(a,'GET',path)
 result=req(a,'PUT',path,{'title':before['body']['title'],'description':'Updated permitted content.','ownerUserId':'10000000-0000-0000-0000-000000000002','role':'Administrator','status':'Closed','severity':'Critical'})
 after=req(a,'GET',path);assert result['status']==204 and after['body']['status']=='New' and after['body']['severity']=='Low' and after['body']['ownerDisplayName']==before['body']['ownerDisplayName']
 save('A08a-overposting',{'response':result,'before':before,'after':after})
 internal='/api/incident-comments/30000000-0000-0000-0000-000000000003'
 child=req(a,'GET','/api/incident-comments/30000000-0000-0000-0000-000000000002');hidden=req(a,'GET',internal);visible=req(m,'GET',internal);analysis=req(m,'GET',alice)
 assert child['status']==hidden['status']==404 and visible['status']==analysis['status']==200
 save('A12-comments',{'foreignComment':child,'reporterInternal':hidden,'analystInternal':visible,'analystDetails':analysis})
 trace=denied['body']['traceId']
 log=Path(r'C:\dev\lr04-local\fixed-server.log').read_bytes()
 log=log.decode('utf-16' if log.startswith((b'\xff\xfe',b'\xfe\xff')) else 'utf-8-sig')
 matches=[line.strip() for line in log.splitlines() if 'authorization.denied' in line and trace in line]
 assert len(matches)==1, 'Audit evidence unavailable: start API using Start-Lab04.ps1.'
 (out/'A09-audit.txt').write_text('Response traceId: '+trace+'\nAudit:\n'+matches[0]+'\nMatch: True\n',encoding='utf-8')
 print('PASS: all live LR04 checks matched the contract; audit trace matches.')
finally:
 # Only IDs returned by this run, parsed as UUID above; fixed local training database.
 for id in created:
  subprocess.run(['docker','exec','secure-lab-postgres-1','psql','-U','securelab','-d','securelab_lr04','-v','ON_ERROR_STOP=1','-c',"DELETE FROM incidents WHERE id='"+id+"';"],check=True,stdout=subprocess.DEVNULL)
