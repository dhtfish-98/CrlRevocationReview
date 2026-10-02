from .common import *
from .crypto import *
def audit(d):
    fields(d,['issuer_pem','issuer_sha256','certificate_pem','crl_der','now'])
    now=instant(d['now']);issuer=certificate(d['issuer_pem']);leaf=certificate(d['certificate_pem'])
    need(issuer.fingerprint(hashes.SHA256()).hex()==string(d['issuer_sha256'],64),"pinned issuer certificate mismatch");issuer_pair(leaf,issuer,now)
    need(issuer.extensions.get_extension_for_class(x509.KeyUsage).value.crl_sign,"issuer not permitted to sign CRLs")
    raw=b64(d['crl_der'],limit=1048576);signed_der(raw,'crl')
    try:crl=x509.load_der_x509_crl(raw)
    except ValueError:raise ReviewError("invalid CRL") from None
    need(crl.issuer==issuer.subject,"CRL issuer mismatch");need(crl.last_update_utc<=now and crl.next_update_utc is not None and now<crl.next_update_utc,"CRL stale, future, or missing nextUpdate")
    for ext in crl.extensions:
        need(isinstance(ext.value,(x509.AuthorityKeyIdentifier,x509.CRLNumber)),"partial, delta, indirect or unknown CRL extension unsupported")
        if isinstance(ext.value,x509.AuthorityKeyIdentifier):
            aki=ext.value
            if aki.key_identifier is not None:
                try:expected=issuer.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
                except x509.ExtensionNotFound:expected=x509.SubjectKeyIdentifier.from_public_key(issuer.public_key()).digest
                need(aki.key_identifier==expected,"CRL authority key identifier mismatch")
            if aki.authority_cert_serial_number is not None:need(aki.authority_cert_serial_number==issuer.serial_number,"CRL authority serial mismatch")
            if aki.authority_cert_issuer is not None:need(any(isinstance(n,x509.DirectoryName) and n.value==issuer.issuer for n in aki.authority_cert_issuer),"CRL authority issuer mismatch")
    verify_x509(issuer.public_key(),crl.signature,crl.tbs_certlist_bytes,crl.signature_hash_algorithm,crl.signature_algorithm_oid)
    need(len(crl)<=4096,"CRL entry limit");serials=set();revoked=None
    for entry in crl:
        need(entry.serial_number not in serials,"duplicate revoked serial");serials.add(entry.serial_number)
        need(entry.revocation_date_utc<=crl.last_update_utc,"CRL revocation time exceeds CRL issuance time")
        for ext in entry.extensions:
            need(isinstance(ext.value,(x509.CRLReason,x509.InvalidityDate)),"indirect or unknown revocation entry extension unsupported")
            if isinstance(ext.value,x509.InvalidityDate):need(ext.value.invalidity_date_utc<=now,"future invalidity date unsupported")
            if isinstance(ext.value,x509.CRLReason):need(ext.value.reason!=x509.ReasonFlags.remove_from_crl,"delta CRL removal semantics unsupported")
        if entry.serial_number==leaf.serial_number:revoked=entry.revocation_date_utc.isoformat()
    return {**report(verified=True,issuer_sha256=issuer.fingerprint(hashes.SHA256()).hex(),target_sha256=leaf.fingerprint(hashes.SHA256()).hex(),certificate_status='revoked' if revoked else 'not_listed',revocation_time=revoked,full_root_chain_verified=False),'status':'FAIL' if revoked else 'PASS'}
