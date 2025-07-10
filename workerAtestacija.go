package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"time"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/client"
)

var nsCommentOID = asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 1, 13}
var attestationOID = asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6, 7, 8, 1}

func decodeNonceFromAcceptableCAs(acceptableCAs [][]byte) ([]byte, error) {
	if len(acceptableCAs) == 0 {
		return nil, fmt.Errorf("no AcceptableCAs")
	}
	var rdnSeq pkix.RDNSequence
	_, err := asn1.Unmarshal(acceptableCAs[0], &rdnSeq)
	if err != nil {
		return nil, err
	}
	oidCommonName := asn1.ObjectIdentifier{2, 5, 4, 3}
	for _, rdnSet := range rdnSeq {
		for _, rdn := range rdnSet {
			if rdn.Type.Equal(oidCommonName) {
				if s, ok := rdn.Value.(string); ok {
					decoded, err := base64.StdEncoding.DecodeString(s)
					if err != nil {
						return nil, err
					}
					fmt.Printf("[KLIJENT]  Raw CN (Base64): %s\n", s)
					fmt.Printf("[KLIJENT]  Decoded nonce: %x\n", decoded)
					return decoded, nil
				}
			}
		}
	}
	return nil, fmt.Errorf("CN not found")
}
func AddAttestation(nonce []byte) ([]byte, error) {

	if len(nonce) != abi.ReportDataSize {
		return nil, fmt.Errorf("nonce mora imati tacno %d bajta", abi.ReportDataSize)
	}

	var fixedNonceLength [abi.ReportDataSize]byte
	copy(fixedNonceLength[:], nonce)

	provider, err := client.GetQuoteProvider()
	if err != nil {
		return nil, fmt.Errorf("nije moguce dobiti quote provider: %v", err)
	}

	report, err := provider.GetRawQuote(fixedNonceLength)
	if err != nil {
		return nil, fmt.Errorf("nije moguce dobiti attestation report: %v", err)
	}

	fmt.Printf("Raw quote data (hex): %x\n", report[:80])
	fmt.Printf(" repo rtData poslato proveri: %x\n", fixedNonceLength)

	err = os.WriteFile("attestation.bin", report, 0o644)
	if err != nil {
		return nil, fmt.Errorf("greska pri pisanju fajla: %v", err)
	}

	fmt.Println("Attestation sacuvan u 'attestation.bin'")
	return report, nil
}

func main() {

	//addr := "127.0.0.1:4433"
	addr := "147.91.12.238:2300"
	var savedKey *rsa.PrivateKey
	//handskaje
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true, // jer proveru radimo rucno
		GetClientCertificate: func(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			nonce, err := decodeNonceFromAcceptableCAs(cri.AcceptableCAs)
			if err != nil {
				return nil, fmt.Errorf("nije moguce dobiti nonce: %v", err)
			}
			fmt.Printf("[KLIJENT] Nonce koji se koristi: %x\n", nonce)

			//dodavanje atestacije

			report, err := AddAttestation(nonce)
			//atestacija kraj

			key, err := rsa.GenerateKey(rand.Reader, 2048)
			check(err)
			keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
			err = os.WriteFile("head.key", keyPEM, 0600)
			check(err)

			// userData := sha256.Sum256([]byte("fixed-user-data"))

			// att := AttestationDoc{
			//      UserData: userData[:],
			//      Nonce:    nonce,
			// }
			// extVal, err := json.Marshal(att)
			// if err != nil {
			//      return nil, err
			// }

			// encodedReport, err := asn1.Marshal(report)
			// if err != nil {
			// 	return nil, fmt.Errorf("ASN.1 marshal failed: %v", err)
			// }

			// pureReport:=report[:1184]
			//
			//	encodedReport, err := asn1.Marshal(pureReport)
			encodedReport, err := asn1.Marshal(asn1.RawValue{
				Class:      0,
				Tag:        16,
				IsCompound: true,
				Bytes:      report, // ovde ide  raw atestation report (1184 bajta)
			})
			if err != nil {
				return nil, fmt.Errorf("ASN.1 marshal failed: %v", err)
			}

			tmpl := &x509.Certificate{
				SerialNumber: big.NewInt(time.Now().UnixNano()),
				Subject:      pkix.Name{CommonName: "Client"},
				NotBefore:    time.Now(),
				NotAfter:     time.Now().Add(time.Hour),

				ExtraExtensions: []pkix.Extension{
					{
						Id:       attestationOID,
						Critical: false,

						Value: encodedReport,
					},
				},
			}
			//		fmt.Printf(" report koji se ubacuje u sertifikat (hex): %x\n", report[:64])
			certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
			if err != nil {
				return nil, err
			}
			savedKey = key

			return &tls.Certificate{
				Certificate: [][]byte{certDER},
				PrivateKey:  key,
			}, nil
		},
	}
	//kraj

	// 2. CSR
	subj := pkix.Name{
		Country:            []string{"US"},
		Province:           []string{"California"},
		Locality:           []string{"San Fransisco"},
		Organization:       []string{"ray"},
		OrganizationalUnit: []string{"ray"},
		CommonName:         "*.ray.io",
	}

	// 3. TLS konekcija
	conn, err := tls.Dial("tcp", addr, tlsConfig)
	check(err)
	defer conn.Close()
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:     subj,
		DNSNames:    []string{"localhost", "service-ray-head.default.svc.cluster.local"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("192.168.100.3")},
	}, savedKey)
	check(err)

	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	_, err = conn.Write(csrPEM)
	check(err)
	conn.CloseWrite()

	// 4. citanje head.crt, ca.crt, ca.key
	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(conn)
	check(err)

	received := buf.Bytes()

	block, rest := pem.Decode(received)
	if block == nil || block.Type != "CERTIFICATE" {
		log.Fatal(" Nevalidan head.crt")
	}
	os.WriteFile("head.crt", pem.EncodeToMemory(block), 0644)

	block, rest2 := pem.Decode(rest)
	if block == nil || block.Type != "CERTIFICATE" {
		log.Fatal(" Nevalidan ca.crt")
	}
	os.WriteFile("ca.crt", pem.EncodeToMemory(block), 0644)

	block, _ = pem.Decode(rest2)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		log.Fatal(" Nevalidan ca.key")
	}
	os.WriteFile("ca.key", pem.EncodeToMemory(block), 0600)

	log.Println(" head.crt, ca.crt i ca.key uspešno sačuvani.")
}

func check(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
