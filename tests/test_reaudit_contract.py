from cryptography.hazmat.primitives.asymmetric import padding
import unittest,json,sys,subprocess,copy,base64,hashlib,datetime
from crl_revocation_review import audit
from crl_revocation_review.common import ReviewError,load
import test_review as fixtures
def reject(test,d):
    with test.assertRaises(ReviewError):audit(d)
    p=subprocess.run([sys.executable,'-m','crl_revocation_review','-'],input=json.dumps(d).encode(),capture_output=True,timeout=10)
    out=json.loads(p.stdout);test.assertEqual(p.returncode,1);test.assertEqual(out['status'],'FAIL');test.assertFalse(out['complete']);test.assertFalse(out.get('verified',False))
class FiniteInputTests(unittest.TestCase):
    def test_exponent_overflow_rejected_api_and_cli(self):
        for raw in (b'{"x":1e999}',b'{"x":[-1e999]}'):
            with self.assertRaises(ReviewError):load(raw)
            p=subprocess.run([sys.executable,'-m','crl_revocation_review','-'],input=raw,capture_output=True,timeout=10);out=json.loads(p.stdout)
            self.assertEqual(p.returncode,1);self.assertFalse(out['complete']);self.assertEqual(out['status'],'FAIL')
        self.assertEqual(load(b'{"x":1.25}'),{'x':1.25})
    def test_unknown_fields_error_does_not_echo_canary(self):
        canary='SYNTHETIC-PRIVATE-CANARY-cc94e6f3'
        with self.assertRaises(ReviewError) as e:audit({canary:canary})
        self.assertNotIn(canary,str(e.exception))
        p=subprocess.run([sys.executable,'-m','crl_revocation_review','-'],input=json.dumps({canary:canary}).encode(),capture_output=True,timeout=10)
        self.assertEqual(p.returncode,1);self.assertNotIn(canary,p.stdout.decode()+p.stderr.decode())
class RevocationTimeTests(unittest.TestCase):
    def request(self,offset,target=True):
        t=fixtures.CrlTests();t.setUp();issued=t.now-datetime.timedelta(minutes=1)
        revoked=fixtures.x509.RevokedCertificateBuilder().serial_number(t.leaf.serial_number if target else 11).revocation_date(issued+datetime.timedelta(seconds=offset)).build()
        crl=fixtures.x509.CertificateRevocationListBuilder().issuer_name(t.issuer.subject).last_update(issued).next_update(t.now+datetime.timedelta(hours=1)).add_extension(fixtures.x509.CRLNumber(1),False).add_revoked_certificate(revoked).sign(t.key,fixtures.hashes.SHA256())
        t.issuer.public_key().verify(crl.signature,crl.tbs_certlist_bytes,padding.PKCS1v15(),crl.signature_hash_algorithm)
        return {**t.d,'crl_der':fixtures.enc(crl.public_bytes(fixtures.serialization.Encoding.DER))}
    def test_revocation_cannot_follow_crl_issuance_api_cli(self):
        for target in (False,True):reject(self,self.request(1,target))
    def test_equal_and_earlier_revocation_keep_complete_status(self):
        for offset in (0,-1):
            for target in (False,True):
                d=self.request(offset,target);r=audit(d);self.assertTrue(r['verified']);self.assertTrue(r['complete']);self.assertEqual(r['status'],'FAIL' if target else 'PASS')

class FilePlatformCapabilityTests(unittest.TestCase):
    def test_missing_or_unusable_file_flags_fail_closed(self):
        from unittest import mock
        from crl_revocation_review.common import read
        from crl_revocation_review import common
        for flag in ('O_NOFOLLOW','O_NONBLOCK'):
            for value in (None,0,'unusable'):
                with mock.patch.object(common.os,flag,value,create=True):
                    with self.assertRaisesRegex(ReviewError,'flags unavailable'):read('synthetic-nonexistent-file')
            with mock.patch.object(common.os,flag,1,create=True):
                delattr(common.os,flag)
                with self.assertRaisesRegex(ReviewError,'flags unavailable'):read('synthetic-nonexistent-file')
