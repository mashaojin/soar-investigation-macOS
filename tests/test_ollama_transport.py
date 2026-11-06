import json
import unittest
from unittest.mock import MagicMock,patch
from ollama_transport import request_json,OllamaHTTPError


class TransportTests(unittest.TestCase):
    def test_windows_transport_is_loopback_and_operation_scoped(self):
        with patch('ollama_transport.subprocess.Popen') as spawn:
            for path,endpoint in [('/api/pull','http://127.0.0.1:11434'),('/api/chat','http://172.18.240.1:11434')]:
                with self.assertRaises(ValueError):request_json({'transport':'windows-stdio','endpoint':endpoint},path)
            spawn.assert_not_called()

    def test_windows_stdin_is_data_and_proxy_is_disabled(self):
        child=MagicMock();child.returncode=0;child.__enter__.return_value=child
        def spawn(argv,**kwargs):
            self.assertIn('--noproxy',argv);self.assertIn('--max-filesize',argv)
            self.assertIn('@-',argv);self.assertNotIn('untrusted $(command)',argv)
            kwargs['stdout'].write(b'{"model":"gemma3:1b"}\n200')
            return child
        with patch('ollama_transport.subprocess.Popen',side_effect=spawn):
            result=request_json({'transport':'windows-stdio','windows_curl':'curl.exe'},'/api/chat',{'prompt':'untrusted $(command)'})
        self.assertEqual(result['model'],'gemma3:1b')
        self.assertEqual(json.loads(child.communicate.call_args.kwargs['input'])['prompt'],'untrusted $(command)')

    def test_windows_http_error_preserves_bounded_context_error(self):
        child=MagicMock();child.returncode=0;child.__enter__.return_value=child
        def spawn(argv,**kwargs):kwargs['stdout'].write(b'{"error":"input exceeds context length"}\n400');return child
        with patch('ollama_transport.subprocess.Popen',side_effect=spawn),self.assertRaises(OllamaHTTPError) as caught:
            request_json({'transport':'windows-stdio','windows_curl':'curl.exe'},'/api/chat',{})
        self.assertEqual(caught.exception.status,400)
        self.assertIn('context',caught.exception.detail)

    def test_windows_missing_status_and_oversize_are_rejected(self):
        for raw in [b'{}',b'x'*65+b'\n200']:
            child=MagicMock();child.returncode=0;child.__enter__.return_value=child
            def spawn(argv,**kwargs):kwargs['stdout'].write(raw);return child
            with patch('ollama_transport.subprocess.Popen',side_effect=spawn),self.assertRaises(ValueError):
                request_json({'transport':'windows-stdio','windows_curl':'curl.exe'},'/api/chat',{},max_bytes=64)
