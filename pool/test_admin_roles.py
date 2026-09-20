"""Actual Linux process-UID separation and packaged configuration integration.
The coordinator uses a disposable chain fixture. No production nodes or keys.
"""
import http.client,json,os,pathlib,pwd,socket,ssl,subprocess,sys,tempfile,time,unittest
from pool.admin import password_record
from pool.protocol import encode
from pool.test_install import module,InstallTests


@unittest.skipUnless(os.name=='posix' and os.geteuid()==0,'requires disposable Linux root to test real separate UIDs')
class AdminRoleTests(unittest.TestCase):
    def test_installed_admin_cannot_read_keys_and_gateway_cannot_reach_control_socket(self):
        core,gateway,admin=61241,61242,61243
        for uid in (core,gateway,admin):
            try:pwd.getpwuid(uid)
            except KeyError:pass
            else:self.fail('qualification UID is already assigned; select a different unused fixture range')
        configure,provision=module('configure'),module('provision')
        source=pathlib.Path(__file__).resolve().parents[1]
        def user(uid):
            def drop():os.setgroups([]);os.setgid(uid);os.setuid(uid)
            return drop
        with tempfile.TemporaryDirectory(prefix='veld-admin-roles-') as directory:
            root=pathlib.Path(directory);root.chmod(0o755);config=root/'config';state=root/'state';config.mkdir()
            with socket.socket() as probe:probe.bind(('127.0.0.1',0));port=probe.getsockname()[1]
            values=dict(InstallTests().values(),prefix=str(root/'version'),config=str(config),state=str(state),admin_uid=admin,admin_port=port)
            configs=configure.render(values)
            for name,data in configs.items():(config/(name+'.json')).write_bytes(encode(data))
            provision.layout(config,state,core,core,gateway,gateway,admin,admin)
            secret=config/'private/pool.seed';secret.write_bytes(b'fixture-not-a-real-key');os.chown(secret,core,core);secret.chmod(0o600)
            password='separate-role-disposable-panel-passphrase'
            access=config/'admin/access.json';access.write_bytes(encode(password_record(password)))
            subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=localhost',
                '-addext','subjectAltName=IP:127.0.0.1','-keyout',str(config/'admin/private-key.pem'),
                '-out',str(config/'admin/certificate.pem')],check=True,capture_output=True)
            provision.layout(config,state,core,core,gateway,gateway,admin,admin)
            env=dict(os.environ,PYTHONPATH=str(source),PYTHONDONTWRITEBYTECODE='1')
            code='''import pathlib,signal,threading,sys,time
# Exercise startup ordering instead of relying on which process imports first.
time.sleep(.25)
from pool.test_operator import fixture
from pool.service import Server
p,o,j=fixture(pathlib.Path(sys.argv[1]))
with Server(sys.argv[2],p,int(sys.argv[3])) as s:
 signal.signal(signal.SIGTERM,lambda *_:threading.Thread(target=s.shutdown,daemon=True).start())
 s.serve_forever(poll_interval=.1)
p.journal.close();j.close()
'''
            processes=[];logs=[]
            try:
                for name,argv,uid in [('core',[sys.executable,'-c',code,str(state/'core'),configs['admin']['operator_socket'],str(admin)],core),
                    ('admin',[sys.executable,'-m','pool.admin','--config',str(config/'admin.json')],admin)]:
                    log=(root/(name+'.log')).open('wb');logs.append(log)
                    processes.append(subprocess.Popen(argv,cwd=source,env=env,preexec_fn=user(uid),stdout=log,stderr=subprocess.STDOUT))
                    if name=='core':
                        deadline=time.monotonic()+10
                        while True:
                            self.assertIsNone(processes[-1].poll(),'private core exited during startup')
                            try:
                                with socket.socket(socket.AF_UNIX) as probe:
                                    probe.settimeout(.2);probe.connect(configs['admin']['operator_socket'])
                                break
                            except OSError:
                                if time.monotonic()>deadline:self.fail('private core IPC readiness deadline')
                                time.sleep(.02)
                context=ssl.create_default_context(cafile=str(config/'admin/certificate.pem'));origin='https://127.0.0.1:'+str(port)
                deadline=time.monotonic()+10
                while True:
                    try:
                        c=http.client.HTTPSConnection('127.0.0.1',port,context=context,timeout=1)
                        c.request('POST','/api/login',encode({'password':password}),{'Origin':origin,'Content-Type':'application/json'})
                        r=c.getresponse();body=json.loads(r.read());cookie=r.getheader('Set-Cookie').split(';')[0];c.close();break
                    except OSError:
                        if time.monotonic()>deadline:raise
                        time.sleep(.05)
                self.assertEqual(r.status,200)
                value=dict(request_id='a'*32,revision='0',reason='Separate process role integration',settings=dict(
                    minimum_units='200000000',batch_seconds='86400',fee_ppm='0',payments_paused=True,comining_paused=True))
                c=http.client.HTTPSConnection('127.0.0.1',port,context=context,timeout=5)
                c.request('POST','/api/settings',encode(value),{'Origin':origin,'Content-Type':'application/json','Cookie':cookie,'X-CSRF-Token':body['result']['csrf']})
                r=c.getresponse();reply=json.loads(r.read());c.close();self.assertEqual(r.status,200);self.assertEqual(reply['result']['status'],'applied')
                for uid,path in ((admin,secret),(gateway,secret),(gateway,access),(admin,state/'core/work/events.jsonl')):
                    check=subprocess.run([sys.executable,'-c','import pathlib,sys;pathlib.Path(sys.argv[1]).read_bytes()',str(path)],
                                         preexec_fn=user(uid),capture_output=True)
                    self.assertNotEqual(check.returncode,0);self.assertIn(b'PermissionError',check.stderr)
                check=subprocess.run([sys.executable,'-c','import socket,sys;s=socket.socket(socket.AF_UNIX);s.connect(sys.argv[1])',
                                      configs['admin']['operator_socket']],preexec_fn=user(gateway),capture_output=True)
                self.assertNotEqual(check.returncode,0);self.assertIn(b'PermissionError',check.stderr)
                self.assertTrue(all(p.poll() is None for p in processes))
            finally:
                for process in reversed(processes):
                    if process.poll() is None:process.terminate()
                    try:process.wait(timeout=10)
                    except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
                for log in logs:log.close()
                for name in ('core','admin'):
                    text=(root/(name+'.log')).read_text()
                    self.assertNotIn('Traceback',text,text)


if __name__=='__main__':unittest.main(verbosity=2)
