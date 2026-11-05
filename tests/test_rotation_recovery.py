import base64,hashlib,json,unittest
from recover_compressed_rotation import recovery_batch

class RecoveryTests(unittest.TestCase):
    def proof(self,tail=b'{"event_type":"flow"}\n'):
        old={'identity':'1:2','offset':99,'anchor':'old-anchor'}
        return old,{'old_cursor':old,'anchor_verified':True,'gzip_eof_verified':True,
                    'tail_base64':base64.b64encode(tail).decode(),'tail_sha256':hashlib.sha256(tail).hexdigest(),
                    'cursor':{'identity':'1:2','offset':0,'anchor':hashlib.sha256(b'').hexdigest()}}
    def test_complete_tail_preserved_no_baseline_skip(self):
        old,proof=self.proof();batch,tail=recovery_batch(proof,old)
        self.assertEqual(base64.b64decode(batch['lines'][0]),tail)
        self.assertEqual(batch['baseline_skipped_bytes'],0)
        self.assertTrue(batch['has_more'])
    def test_wrong_anchor_digest_or_destination_rejected(self):
        for change in [{'anchor_verified':False},{'gzip_eof_verified':False},
                       {'tail_sha256':'wrong'},{'cursor':{'identity':'wrong','offset':0}}]:
            old,proof=self.proof()
            with self.subTest(change=change),self.assertRaises(ValueError):recovery_batch(dict(proof,**change),old)
    def test_partial_invalid_or_oversized_tail_rejected(self):
        for tail in [b'{"event_type":"flow"}',b'not-json\n',b'[]\n',b'x'*1048577]:
            old,proof=self.proof(tail)
            with self.subTest(size=len(tail)),self.assertRaises(ValueError):recovery_batch(proof,old)
