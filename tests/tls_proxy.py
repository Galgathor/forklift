"""Disposable HTTPS reverse proxy for integration tests; never logs requests."""
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ssl

class Proxy(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass
    def forward(self):
        body=self.rfile.read(int(self.headers.get('Content-Length','0')))
        conn=http.client.HTTPConnection('manager',8080,timeout=45)
        headers={k:v for k,v in self.headers.items() if k.lower() not in ['host','connection','content-length']}
        headers['Content-Length']=str(len(body))
        conn.request(self.command,self.path,body,headers)
        response=conn.getresponse();data=response.read()
        self.send_response(response.status)
        for key,value in response.getheaders():
            if key.lower() not in ['connection','content-length','transfer-encoding','server','date']:
                self.send_header(key,value)
        self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data);conn.close()
    do_GET=forward
    do_POST=forward
    do_PUT=forward
    do_DELETE=forward

server=ThreadingHTTPServer(('0.0.0.0',8443),Proxy)
context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.minimum_version=ssl.TLSVersion.TLSv1_2
context.load_cert_chain('/fixture/server.crt','/fixture/server.key')
server.socket=context.wrap_socket(server.socket,server_side=True)
server.serve_forever()
