package main

import (
  "crypto/x509"
  "crypto/x509/pkix"
  "encoding/asn1"
  "encoding/base64"
  "encoding/pem"
  "flag"
  "fmt"
  "io/ioutil"
  "time"
)

func check(e error) {
  if e != nil {
    panic(e)
  }
}

func loadCertPool(filename string) (*x509.CertPool, []*x509.Certificate) {
  dat, err := ioutil.ReadFile(filename)
  check(err)
  pool := x509.NewCertPool()
  // annoyingly, we have to parse the PEM ourselves since we need each cert
  // outside of the cert pool
  var certs []*x509.Certificate

  for len(dat) > 0 {
    var block *pem.Block
    block, dat = pem.Decode(dat)
    if block == nil {
      break
    }
    if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
      continue
    }
    cert, err := x509.ParseCertificate(block.Bytes)
    if err != nil {
      continue
    }

    certs = append(certs, cert)
    pool.AddCert(cert)
  }
  return pool, certs
}

func findSigningCert(certs []*x509.Certificate, crl *pkix.CertificateList) *x509.Certificate{
  for _, cert := range certs {
    if nil == cert.CheckCRLSignature(crl) {
      return cert
    }
  }
  return nil
}

func main() {
  interPEMPtr := flag.String("inter", "", "a PEM file containing intermediates")
  rootPEMPtr := flag.String("roots", "", "a PEM file containing roots")
  crlPtr := flag.String("crl", "", "a CRL file")

  flag.Parse()

  var rootPool, intermediatePool *x509.CertPool
  var roots, intermediates []*x509.Certificate

  if nil != rootPEMPtr && len(*rootPEMPtr) > 0 {
    rootPool, roots = loadCertPool(*rootPEMPtr)
  }
  if nil != interPEMPtr && len(*interPEMPtr) > 0 {
    intermediatePool, intermediates = loadCertPool(*interPEMPtr)
  }

  var crlData []byte
  if nil != crlPtr && len(*crlPtr) > 0 {
    // Get the crl from the args
    var err error
    crlData, err = ioutil.ReadFile(*crlPtr)
    check(err)
  }

  if len(crlData) > 0{
    // Maybe it's PEM; try to parse as PEM, if that fails, just use the bytes
    block, _ := pem.Decode(crlData)
    if block != nil {
      crlData = block.Bytes
    }

    crl, err := x509.ParseCRL(crlData)
    if err != nil {
      panic("could not parse CRL")
    }

    // check the CRL is still current
    if crl.HasExpired(time.Now()) {
      fmt.Printf("crl has expired\n");
    }

    var signer *x509.Certificate
    if (nil != roots) {
      signer = findSigningCert(roots, crl)
      if nil == signer {
        fmt.Printf("Not signed by a root; trying known intermediates\n");
        if nil != intermediates {
          signer = findSigningCert(intermediates, crl)
        }
      }
    }

    if nil != signer {
      fmt.Printf("found signer! %v\n", signer.Subject)
      opts := x509.VerifyOptions{
        Roots: rootPool,
        Intermediates: intermediatePool,
      }

      if _,err := signer.Verify(opts); err != nil {
        fmt.Println("Warning! Can't verify signer!")
      }
    }

    issuerData, err := asn1.Marshal(crl.TBSCertList.Issuer)
    if nil == err {
      issuerString := base64.StdEncoding.EncodeToString(issuerData)
      fmt.Printf("%v\n", issuerString);
    }
    for revoked := range crl.TBSCertList.RevokedCertificates {
      cert := crl.TBSCertList.RevokedCertificates[revoked]
      fmt.Printf(" %v\n",
                 base64.StdEncoding.EncodeToString(cert.SerialNumber.Bytes()))
    }
  }
}
