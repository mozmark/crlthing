from fetch_all import fetchCRL, parseCRL, getRevokedSerials

crlURI = 'http://crl.pki.fraunhofer.de/fhg-root-ca-2007.crl'
issuer, serials = getRevokedSerials(parseCRL(fetchCRL(crlURI)))
print issuer
for serial in serials:
    print serial
