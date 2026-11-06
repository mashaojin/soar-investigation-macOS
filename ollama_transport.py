"""Bounded Ollama HTTP or Windows-loopback stdio transport; no exposed listener."""
import http.client
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
from urllib.parse import urlsplit

PATHS={'/api/version','/api/tags','/api/show','/api/ps','/api/chat','/api/generate'}


class OllamaHTTPError(ValueError):
    def __init__(self,status,raw):
        self.status=status
        try:self.detail=str(json.loads(raw).get('error',''))[:1000]
        except (ValueError,AttributeError):self.detail=''
        super().__init__('Ollama returned HTTP '+str(status)+(': '+self.detail if self.detail else ''))


def request_json(config,path,body=None,*,timeout=120,max_bytes=65536):
    if path not in PATHS:raise ValueError('Unsupported fixed Ollama API operation')
    if not 0<timeout<=120 or not 1<=max_bytes<=1048576:raise ValueError('Invalid Ollama request bound')
    endpoint=config.get('endpoint','http://127.0.0.1:11434');url=urlsplit(endpoint)
    if url.scheme not in ('http','https') or not url.hostname or url.username or url.password or url.path not in ('','/') or url.query or url.fragment:
        raise ValueError('Ollama endpoint must be an origin without credentials')
    encoded=json.dumps(body).encode() if body is not None else None
    if encoded is not None and len(encoded)>131072:raise ValueError('Oversized Ollama request')
    if config.get('transport','http')=='windows-stdio':
        if url.hostname not in ('127.0.0.1','localhost','::1'):raise ValueError('Windows stdio transport permits loopback only')
        executable=config.get('windows_curl') or shutil.which('curl.exe')
        if not executable:raise ValueError('Windows curl.exe is required for loopback stdio transport')
        argv=[executable,'--silent','--show-error','--noproxy','*','--proto','=http,https',
              '--connect-timeout',str(min(3,timeout)),'--max-time',str(timeout),
              '--max-filesize',str(max_bytes),'--write-out','\n%{http_code}']
        if encoded is not None:argv+=['--header','Content-Type: application/json','--data-binary','@-']
        argv+=[endpoint.rstrip('/')+path]
        with tempfile.TemporaryFile() as output,tempfile.TemporaryFile() as errors:
            with subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=output,stderr=errors) as child:
                try:child.communicate(input=encoded,timeout=timeout)
                except subprocess.TimeoutExpired:
                    child.kill();child.wait()
                    raise TimeoutError('Ollama exceeded wall-clock request budget') from None
                output.seek(0);raw=output.read(max_bytes+6)
                if child.returncode:
                    errors.seek(0)
                    raise ValueError('Windows Ollama transport failed: '+errors.read(1000).decode(errors='replace'))
        try:raw,status=raw.rsplit(b'\n',1);status=int(status)
        except (ValueError,TypeError):raise ValueError('Missing bounded Ollama HTTP status') from None
        if len(raw)>max_bytes:raise ValueError('Oversized Ollama response')
        if status!=200:raise OllamaHTTPError(status,raw)
    elif config.get('transport','http')=='http':
        started=time.monotonic();deadline=started+timeout
        kind=http.client.HTTPSConnection if url.scheme=='https' else http.client.HTTPConnection
        connection=kind(url.hostname,url.port or (443 if url.scheme=='https' else 80),timeout=timeout)
        try:
            connection.connect();sock=connection.sock
            sock.settimeout(max(0.001,deadline-time.monotonic()))
            connection.request('POST' if encoded is not None else 'GET',path,encoded,{'Content-Type':'application/json'})
            sock.settimeout(max(0.001,deadline-time.monotonic()));response=connection.getresponse()
            chunks=[];size=0
            while not response.isclosed():
                remaining=deadline-time.monotonic()
                if remaining<=0:raise TimeoutError('Ollama exceeded wall-clock request budget')
                sock.settimeout(remaining);block=response.read1(min(4096,max_bytes+1-size))
                if not block:break
                chunks.append(block);size+=len(block)
                if size>max_bytes:raise ValueError('Oversized Ollama response')
            raw=b''.join(chunks)
            if response.status!=200:raise OllamaHTTPError(response.status,raw)
        finally:connection.close()
    else:raise ValueError('Unsupported Ollama transport')
    result=json.loads(raw)
    if not isinstance(result,dict):raise ValueError('Ollama response must be an object')
    return result
