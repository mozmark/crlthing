from OpenSSL import SSL, crypto
import StringIO
import sys
import ldap

from urlparse import urlparse
import urllib

from pyasn1.codec.der import decoder
from pyasn1_modules import rfc2459

asn1Spec = rfc2459.Extension()
crlType = rfc2459.CertificateList()

context = SSL.Context(SSL.TLSv1_METHOD) # Use TLS Method
context.set_options(SSL.OP_NO_SSLv2) # Don't accept SSLv2
# we don't need to verify (yet)
#context.set_verify(SSL.VERIFY_NONE, callback)
#context.load_verify_locations(ca_file, ca_path)

from socket import socket

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
        print '       ', 'will fetch via LDAP', crlURI
        l = ldap.initialize("%s://%s"%(crlLocation.scheme, crlLocation.netloc))
        filters = []
        attrs = []
        for item in crlLocation.query.split('?'):
            if '=' in item:
                filters.append(item)
            else:
                attrs.append(item)
        # print filters, attrs
        result = l.search_s(crlLocation.path[1:],ldap.SCOPE_SUBTREE,filters[0],attrs)
        crlData = result[0][1]['certificaterevocationlist'][0]
        return crlData
    else:
        print '       ', 'will fetch via usual channel',crlURI
        return urllib.urlopen(crlURI).read()

def parseCRL(crlData):
    if None != crlData:
        stuff = decoder.decode(crlData,asn1Spec=crlType)
        for crl in stuff:
            #print crl.prettyPrint()
            return stuff

def getRevokedSerials(crl):
    serials = []
    if None != crl[0]['tbsCertList'] and None != crl[0]['tbsCertList']['revokedCertificates']:
        for cert in crl[0]['tbsCertList']['revokedCertificates']:
            serials.append(str(cert['userCertificate']))
    return serials

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
            cert = get_chain(host, port)[1]
            if True:
                print ' ',cert.get_subject().commonName
                count = cert.get_extension_count()
                for index in range(0,count):
                    extension = cert.get_extension(index)
                    if 'crlDistributionPoints' == extension.get_short_name():
                        for crlURI in extract_URIs(extension):
                            print '  ',crlURI
                            print getRevokedSerials(parseCRL(fetchCRL(crlURI)))
        except:
            print 'problem getting cert for '+host
