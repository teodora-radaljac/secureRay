package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"net"
	"os"
)

func main() {
	//	addr := "127.0.0.1:4444"
	addr := "147.91.12.238:2301"
	// Kljuc
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	check(err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	err = os.WriteFile("head.key", keyPEM, 0600)
	check(err)

	//  CSR
	subj := pkix.Name{
		Country:            []string{"US"},
		Province:           []string{"California"},
		Locality:           []string{"San Fransisco"},
		Organization:       []string{"ray"},
		OrganizationalUnit: []string{"ray"},
		CommonName:         "*.ray.io",
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:     subj,
		DNSNames:    []string{"localhost", "service-ray-head.default.svc.cluster.local"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("192.168.100.2")},
	}, key)
	check(err)

	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	// TLS konekcija
	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
	check(err)
	defer conn.Close()

	_, err = conn.Write(csrPEM)
	check(err)
	conn.CloseWrite()

	// Citanje head.crt, ca.crt, ca.key
	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(conn)
	check(err)

	received := buf.Bytes()

	block, rest := pem.Decode(received)
	if block == nil || block.Type != "CERTIFICATE" {
		log.Fatal("Nevalidan head.crt")
	}
	os.WriteFile("head.crt", pem.EncodeToMemory(block), 0644)

	block, rest2 := pem.Decode(rest)
	if block == nil || block.Type != "CERTIFICATE" {
		log.Fatal("Nevalidan ca.crt")
	}
	os.WriteFile("ca.crt", pem.EncodeToMemory(block), 0644)

	block, _ = pem.Decode(rest2)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		log.Fatal("Nevalidan ca.key")
	}
	os.WriteFile("ca.key", pem.EncodeToMemory(block), 0600)

	log.Println(" head.crt, ca.crt i ca.key uspesno sacuvani")
}

func check(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
