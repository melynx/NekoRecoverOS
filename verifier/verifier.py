import struct
import hashlib
import binascii
from M2Crypto import BIO, EVP, SMIME, X509, m2

FOOTER_SIZE = 6
EOCD_HEADER_SIZE = 22

def verify_file(path):
    with open(path, 'rb') as ota_file:
        ota_file.seek(0, 2)
        length = ota_file.tell()
        ota_file.seek(-FOOTER_SIZE, 2)
        footer = bytearray(ota_file.read())
        if (footer[2] != 0xff or footer[3] != 0xff):
            print("This zip is not signed!")
            return False
        comment_size = footer[4] + (footer[5] << 8)
        signature_start = footer[0] + (footer[1] << 8)
        print("Comment is %d bytes; signature %d bytes from end." % (comment_size, signature_start))

        eocd_size = comment_size + EOCD_HEADER_SIZE
        ota_file.seek(-eocd_size, 2)
        signed_len = ota_file.tell() + EOCD_HEADER_SIZE - 2
        eocd = bytearray(ota_file.read(eocd_size))

        if (eocd[0] != 0x50 or eocd[1] != 0x4b or eocd[2] != 0x05 or eocd[3] != 0x06):
            print("Signature length doesn't match EOCD marker.")
            return False

        for i in range(4, eocd_size-3):
            if (eocd[i] == 0x50 and eocd[i+1] == 0x4b and eocd[i+2] == 0x05 and eocd[i+3] == 0x06):
                print("EOCD marker occurs after start of EOCD")
                return False
        
        ota_file.seek(0,0)
        zip_content = bytearray(ota_file.read(signed_len))
        sha1 = hashlib.sha1()
        sha1.update(zip_content)

        signature_size = signature_start - FOOTER_SIZE
        signature = eocd[eocd_size-signature_start:signature_size]
        print("Signature (offset: %x, length: %d):" % (length-signature_start, signature_size)) 

	s = SMIME.SMIME()
	# Load the signer's cert.
	x509 = X509.load_cert('certificate.pem')
	sk = X509.X509_Stack()
	sk.push(x509)
	s.set_x509_stack(sk)
	
	# Load the signer's CA cert. In this case, because the signer's
	# cert is self-signed, it is the signer's cert itself.
	st = X509.X509_Store()
	st.load_info('certificate.pem')
	s.set_x509_store(st)
	
	# Load the data, verify it.
        # signature is a buffer containing the signature in pkcs#7 DER format
        p7bio = BIO.MemoryBuffer(signature)
        contentbio = BIO.MemoryBuffer(zip_content)
        contentbio = BIO.openfile('ota-unsign.zip')
        p7 = SMIME.PKCS7(m2.pkcs7_read_bio_der(p7bio._ptr()))
        md = EVP.MessageDigest('sha1')
        md.update(zip_content)
        print binascii.b2a_hex(md.digest())
	v = s.verify(p7)
	v = s.verify(p7, contentbio)
	print v


verify_file('ota-signed.zip')
