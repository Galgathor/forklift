#!/usr/bin/env python3
"""Exercise publishing semantics against an actual local HTTP fixture without registry credentials."""
import importlib.util
import os
import runpy
import subprocess
import sys
from pathlib import Path
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('ci_common',Path(__file__).resolve().parents[1]/'scripts/ci_common.py')
ci=importlib.util.module_from_spec(spec);spec.loader.exec_module(ci)

class Packages(unittest.TestCase):
    def test_ref_and_origin_guards(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest=Path(directory)/'Cargo.toml';manifest.write_text('[package]\nversion = "0.5.0"\n')
            env=dict(CI_SHA='a'*40,CI_REF='refs/heads/main',CI_SERVER_URL='https://git.example.test',CI_OWNER='Owner')
            with patch.dict(os.environ,env,clear=True):
                self.assertEqual(ci.metadata(manifest)['tags'],['sha-'+'a'*40])
                os.environ['CI_REF']='refs/tags/v0.5.0';self.assertEqual(ci.metadata(manifest)['version'],'0.5.0')
                for ref in ['refs/heads/other','refs/pull/1/head','refs/tags/v0.6.0','refs/tags/v0.5.0;echo unsafe']:
                    os.environ['CI_REF']=ref
                    with self.assertRaises(ValueError):ci.metadata(manifest)
                os.environ['CI_REF']='refs/heads/main';os.environ['CI_SERVER_URL']='http://git.example.test'
                with self.assertRaises(ValueError):ci.metadata(manifest)

    def test_upload_rerun_mismatch_and_redirect(self):
        state=dict(data=None,redirect=False,gets=0)
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_PUT(self):
                self.server.test.assertTrue(self.headers['Authorization'].startswith('Basic '))
                if state['redirect']:
                    self.send_response(307);self.send_header('Location','/unexpected');self.end_headers();return
                body=self.rfile.read(int(self.headers['Content-Length']))
                if state['data'] is None:state['data']=body;code=201
                else:code=409
                self.send_response(code);self.end_headers()
            def do_GET(self):
                state['gets']+=1;self.send_response(200);self.end_headers();self.wfile.write(state['data'])
        server=ThreadingHTTPServer(('127.0.0.1',0),Handler);server.test=self
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            with tempfile.TemporaryDirectory() as directory,patch.dict(os.environ,dict(PACKAGES_TOKEN='fixture-only',CI_OWNER='Owner')):
                file=Path(directory)/'artifact';file.write_bytes(b'first build')
                meta=dict(server='http://127.0.0.1:'+str(server.server_port),owner='Owner',version='test')
                ci.upload(meta,'fixture',file);ci.upload(meta,'fixture',file)
                file.write_bytes(b'different build')
                with self.assertRaises(RuntimeError):ci.upload(meta,'fixture',file)
                state['redirect']=True;before=state['gets']
                with self.assertRaises(RuntimeError):ci.upload(meta,'fixture',file)
                self.assertEqual(before,state['gets'])
        finally:server.shutdown();server.server_close();thread.join()

class Images(unittest.TestCase):
    def test_changed_image_is_never_pushed_over_existing_tag(self):
        script=Path(__file__).resolve().parents[1]/'scripts/ci_images.py'
        calls=[]
        def command(args,**kwargs):
            calls.append(args)
            if 'login' in args:
                self.assertEqual(kwargs['input'],b'fixture-only')
                self.assertNotIn('fixture-only',args)
                return subprocess.CompletedProcess(args,0)
            return subprocess.CompletedProcess(args,0,stdout='{"config":{"digest":"sha256:other"}}',stderr='')
        with tempfile.TemporaryDirectory() as directory:
            previous=os.getcwd()
            try:
                os.chdir(directory);Path('backend').mkdir();Path('backend/Cargo.toml').write_text('[package]\nversion = "0.5.0"\n')
                env=dict(CI_SHA='a'*40,CI_REF='refs/heads/main',CI_SERVER_URL='https://git.example.test',CI_OWNER='Owner',PACKAGES_TOKEN='fixture-only')
                with patch.dict(os.environ,env,clear=True),patch.dict(sys.modules,{'ci_common':ci}),patch.object(sys,'argv',[str(script),'publish']),patch('subprocess.run',side_effect=command),patch('subprocess.check_output',return_value='sha256:local'):
                    with self.assertRaisesRegex(RuntimeError,'refusing to overwrite'):runpy.run_path(str(script),run_name='__main__')
                self.assertFalse(any('push' in args for args in calls))
            finally:os.chdir(previous)

if __name__=='__main__':unittest.main()
