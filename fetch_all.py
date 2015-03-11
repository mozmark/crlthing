from OpenSSL import SSL, crypto
from StringIO import StringIO
import sys
import ldap

from urlparse import urlparse
import urllib

from pyasn1.codec.der import decoder
from pyasn1.codec.der import encoder
from pyasn1_modules import rfc2459

from base64 import b64encode

from ldif import LDIFRecordList
import pycurl

asn1Spec = rfc2459.Extension()
crlType = rfc2459.CertificateList()

context = SSL.Context(SSL.TLSv1_METHOD) # Use TLS Method
context.set_options(SSL.OP_NO_SSLv2) # Don't accept SSLv2
#context.set_options(SSL.OP_NO_SSLv3) # Don't accept SSLv2
# we don't need to verify (yet)
#context.set_verify(SSL.VERIFY_NONE, callback)
#context.load_verify_locations(ca_file, ca_path)

from socket import socket
from binascii import unhexlify


"""
Get a byte array for an ASN1 integer
"""
def getASNIntegerBytes(asnInt):
    hexstr = "%X" % (int(asnInt))
    if len(hexstr) % 2 == 1:
        return unhexlify('0'+hexstr)
    return unhexlify(hexstr)

def extract_URIs(extension):
    # TODO: extract the URI properly from ASN.1
    urls = []
    for line in str(extension).split('\n'):
        if 'URI:' in line:
            urls.append(line.split(':',1)[1])
    return urls

def get_chain(host, port):
    sock = socket()
    ssl_sock = SSL.Connection(context, sock)
    ssl_sock.connect((host, port))
    ssl_sock.do_handshake()
    return ssl_sock.get_peer_cert_chain()

def fetchCRL(crlURI):
    crlLocation = urlparse(crlURI)
    if 'ldap' == crlLocation.scheme:
        buffer = StringIO()
        c = pycurl.Curl()
        c.setopt(c.URL, crlURI)
        c.setopt(c.WRITEDATA, buffer)
        c.perform()
        c.close()
        body = buffer.getvalue()

        buffer = StringIO(body)
        parser = LDIFRecordList(buffer)
        parser.parse()
        dn, entry = parser.all_records[0]
        crl = entry[entry.keys()[-1]][0]
        return crl
    else:
        return urllib.urlopen(crlURI).read()

def parseCRL(crlData):
    try:
        if None != crlData:
            stuff = decoder.decode(crlData,asn1Spec=crlType)
            for crl in stuff:
                #print crl.prettyPrint()
                return stuff
    except Exception as e:
        print 'parsing failed',e

def getRevokedSerials(crl):
    serials = []
    issuer = ''
    if None != crl[0]['tbsCertList'] and None != crl[0]['tbsCertList']['revokedCertificates']:
        issuer = b64encode(encoder.encode(crl[0]['tbsCertList']['issuer']))
        for cert in crl[0]['tbsCertList']['revokedCertificates']:
            #serials.append(b64encode(encoder.encode(cert['userCertificate'])))
            # serial = b64encode(''.join(["%x"%(ord(pos)) for pos in encoder.encode(cert['userCertificate'])[2:]]))
            serial = b64encode(getASNIntegerBytes(cert['userCertificate']))
            serials.append(serial)
    return issuer, serials

if __name__ == '__main__':
    for line in sys.stdin.readlines():
        url = urlparse(line.rstrip())
        host = url.hostname
        port = 443
        print host
        try:
            port = int(url.port)
        except:
            pass
        try:
        #if True:
            #for cert in get_chain(host, port):
            chain = get_chain(host, port)
            if len(chain) > 1:
                cert = chain[1]
                if True:
                    count = cert.get_extension_count()
                    for index in range(0,count):
                        extension = cert.get_extension(index)
                        if 'crlDistributionPoints' == extension.get_short_name():
                            for crlURI in extract_URIs(extension):
                                issuer, serials = getRevokedSerials(parseCRL(fetchCRL(crlURI)))
                                for serial in serials:
                                    print serial
        except:
            print 'problem getting cert for '+line
