package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"
	"time"

	"github.com/google/go-sev-guest/abi"
	checkpb "github.com/google/go-sev-guest/proto/check"
	"github.com/google/go-sev-guest/proto/sevsnp"
	spb "github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/go-sev-guest/validate"
	"github.com/google/go-sev-guest/verify"
	"github.com/google/go-sev-guest/verify/trust"
	"google.golang.org/protobuf/encoding/protojson"

	cpb "github.com/google/go-sev-guest/proto/check"
)

var nsCommentOID = asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 1, 13}
var (
	timeout     = time.Minute * 2
	maxTryDelay = time.Second * 30
)
var attestationOID = asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6, 7, 8, 1} // proizvoljan OID za "atestacija"
var (
	config = &checkpb.Config{
		RootOfTrust: &checkpb.RootOfTrust{},
		Policy:      &checkpb.Policy{},
	}
	product = &spb.SevProduct{}
)

const (
	cocosDirectory      = ".cocos"
	caBundleName        = "ask_ark.pem"
	Nonce               = 64
	sevProductNameMilan = "Milan"
	sevProductNameGenoa = "Genoa"
)

func loadPolicyFromJSON(path string) (*cpb.Config, error) {
	data, err := os.ReadFile(path)

	if err != nil {
		return nil, err
	}
	var policy cpb.Config

	if err := protojson.Unmarshal(data, &policy); err != nil {
		return nil, err
	}

	return &policy, nil
}
func LoadValidationOptions(policyPath string, nonce []byte) (*validate.Options, *cpb.Config, error) {
	// Ucitavanje policy fajla
	config, err := loadPolicyFromJSON(policyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("neuspesno ucitavanje policy fajla: %v", err)
	}

	// Umetanje nonce-a u ReportData polje
	config.Policy.ReportData = nonce

	// Konverzija policy -> options
	opts, err := validate.PolicyToOptions(config.Policy)
	if err != nil {
		return nil, nil, fmt.Errorf("greska pri konverziji policy u options: %v", err)
	}

	opts.TrustedAuthorKeys = nil
	opts.CertTableOptions = nil

	return opts, config, nil
}
func loadCertBytes(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("PEM decode nije uspeo: %s", path)
	}
	return block.Bytes, nil
}
func extractRawReportFromCert(cert *x509.Certificate) ([]byte, error) {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(attestationOID) {
			var raw asn1.RawValue
			_, err := asn1.Unmarshal(ext.Value, &raw)
			if err != nil {
				return nil, fmt.Errorf("ASN.1 unmarshal nije uspeo: %v", err)
			}
			return raw.Bytes, nil
		}
	}
	return nil, errors.New("atestacioni report nije pronadjen u ekstenzijama sertifikata")
}

func GetProductName(product string) sevsnp.SevProduct_SevProductName {
	switch product {
	case sevProductNameMilan:
		return sevsnp.SevProduct_SEV_PRODUCT_MILAN
	case sevProductNameGenoa:
		return sevsnp.SevProduct_SEV_PRODUCT_GENOA
	default:
		return sevsnp.SevProduct_SEV_PRODUCT_UNKNOWN
	}
}

// BuildAttestationFromCert izvlaci raw atestaciju iz sertifikata, parsira je i dodaje lanac sertifikata.
func BuildAttestationFromCert(cert *x509.Certificate, arkBytes, askBytes, vcekBytes []byte) (*spb.Attestation, error) {

	// Ekstrakcija raw reporta iz ASN.1 sertifikata
	rawReport, err := extractRawReportFromCert(cert)
	if err != nil {
		return nil, fmt.Errorf("dohvatanje atestacije nije uspelo: %v", err)
	}

	// Parsiranje u Protobuf strukturu
	protoReport, err := abi.ReportToProto(rawReport)
	if err != nil {
		return nil, fmt.Errorf("neuspešan parsing reporta u protobuf: %v", err)
	}

	// Formiranje kompletne atestacije
	attestation := &spb.Attestation{
		Report: protoReport,
		CertificateChain: &spb.CertificateChain{
			ArkCert:  arkBytes,
			AskCert:  askBytes,
			VcekCert: vcekBytes,
		},
	}

	return attestation, nil
}
func verifyReport(attestationPB *spb.Attestation, cfg *cpb.Config) error {
	sopts, err := verify.RootOfTrustToOptions(cfg.RootOfTrust)
	if err != nil {
		return fmt.Errorf("failed to get root of trust options: %v", err)
	}
	if cfg.Policy.Product == nil {
		productName := GetProductName(cfg.RootOfTrust.ProductLine)
		if productName == sevsnp.SevProduct_SEV_PRODUCT_UNKNOWN {
			return fmt.Errorf("failed to get product: %v", err)
		}

		sopts.Product = &sevsnp.SevProduct{
			Name: productName,
		}
	} else {
		sopts.Product = cfg.Policy.Product
	}
	sopts.Getter = &trust.RetryHTTPSGetter{
		Timeout:       timeout,
		MaxRetryDelay: maxTryDelay,
		Getter:        &trust.SimpleHTTPSGetter{},
	}

	if err := verify.SnpAttestation(attestationPB, sopts); err != nil {
		return fmt.Errorf("failed to verify attestation: %v", err)
	}

	return nil
}
func verification(rawCerts [][]byte, nonce []byte) error {

	//Dohvatanje sertifikata
	arkBytes, err := loadCertBytes("/root/certs/ark.pem")
	check(err)
	askBytes, err := loadCertBytes("/root/certs/ask.pem")
	check(err)
	vcekBytes, err := loadCertBytes("/root/certs/vcek.pem")
	check(err)

	//Proveravanje sertifikata dobijenig preko TLS-a
	if len(rawCerts) == 0 {
		return errors.New("nije pronadjen nijedan sertifikat")
	}

	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("neuspesno parsiranje sertifikata: %v", err)
	}

	// var attestationReport []byte
	// for _, ext := range cert.Extensions {
	// 	if ext.Id.Equal(attestationOID) {
	// 		//			attestationReport = ext.Value
	// 		if len(ext.Value) == 0x4a0 {
	// 			// direktno raw report
	// 			attestationReport = ext.Value
	// 		} else {
	// 			var raw asn1.RawValue
	// 			_, err := asn1.Unmarshal(ext.Value, &raw)
	// 			if err != nil {
	// 				return fmt.Errorf(" ASN.1 unmarshal nije uspeo: %v", err)
	// 			}
	// 			attestationReport = raw.Bytes
	// 		}
	// 	}
	// 	break
	// }

	// if attestationReport == nil {
	// 	return errors.New("atestaciona ekstenzija nije pronadjena u sertifikatu")
	// }

	//	 SEV-SNP ReportData se nalazi na offsetu 576, dužine 64 bajta
	// const reportDataOffset = 576
	// const reportDataSize = 64

	// if len(attestationReport) < reportDataOffset+reportDataSize {
	// 	return fmt.Errorf("atestacioni report je prekratak: ima %d bajta", len(attestationReport))
	// }
	// err0 := os.WriteFile("received_attestation_report.bin", attestationReport, 0o644)
	// if err0 != nil {
	// 	fmt.Printf(" Greska pri čuvanju atestacionog reporta: %v\n", err)
	// } else {
	// 	fmt.Println(" Atestacioni report sacuvan u 'received_attestation_report.bin'")
	// }

	// fmt.Printf(" attestationReport (ekstenzija): %x\n", attestationReport[:80])
	// reportData := attestationReport[84:148]
	// fmt.Printf(" direktni reportData: %x\n", reportData)

	// fmt.Printf(" expectedNonce: %x\n", nonce)
	// fmt.Printf(" reportData iz atestacije: %x\n", reportData)
	// if !bytes.Equal(reportData, nonce) {
	// 	return errors.New(" nonce iz atestacije se ne poklapa sa očekivanim")
	// }

	//Isprbavanje validacije

	//	config.Policy.ReportData = nonce

	//Kreiranje konfiguracija
	opts, config, err := LoadValidationOptions("./policy.json", nonce)
	if err != nil {
		log.Fatalf("Greška prilikom kreiranja opcija za validaciju: %v", err)
	}

	//Dohvatanje atestacije
	attestation, err := BuildAttestationFromCert(cert, arkBytes, askBytes, vcekBytes)
	if err != nil {
		log.Fatalf("Greska prilikom gradjenja atestacije: %v", err)
	}
	// Validacija
	err = validate.SnpAttestation(attestation, opts)
	if err != nil {
		return fmt.Errorf("validacija atestacije nije uspela: %v", err)
	}

	// Verifikacija
	err = verifyReport(attestation, config)
	if err != nil {
		return fmt.Errorf("Verifikacija atestacije nije uspela: %v", err)
	}

	log.Println("[SERVER]  Uspesna atestacija")
	return nil

}
func encodeNonceToCertPool(nonce []byte, privKey *rsa.PrivateKey) (*x509.CertPool, error) {
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: base64.StdEncoding.EncodeToString(nonce),
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(5 * time.Minute),
	}
	signedCert, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, fmt.Errorf("create cert: %w", err)
	}
	parsed, err := x509.ParseCertificate(signedCert)
	if err != nil {
		return nil, fmt.Errorf("parse cert: %w", err)
	}
	log.Printf("[SERVER]  Nonce embedded in CA: %x", nonce)
	pool := x509.NewCertPool()
	pool.AddCert(parsed)
	return pool, nil
}
func main() {
	// === 1. Generisi CA kljuc i sertifikat ===
	caPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	check(err)

	caTemplate := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			Country:            []string{"US"},
			Province:           []string{"California"},
			Locality:           []string{"San Fransisco"},
			Organization:       []string{"ray"},
			OrganizationalUnit: []string{"ray"},
			CommonName:         "ray CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(5, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          generateSubjectKeyID(&caPriv.PublicKey),
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caPriv.PublicKey, caPriv)
	check(err)

	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})
	caKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(caPriv)})

	tlsCert := tls.Certificate{
		Certificate: [][]byte{caCertDER},
		PrivateKey:  caPriv,
	}
	go workerHandle(tlsCert, caPriv, caPEM, caKeyPEM)
	go headHandle(tlsCert, caPriv, caPEM, caKeyPEM)
	select {}
}
func workerHandle(cert tls.Certificate, caKey *rsa.PrivateKey, caPEM, caKeyPEM []byte) {
	mainConfig := &tls.Config{

		GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			nonce := make([]byte, 64)
			_, err := rand.Read(nonce)
			if err != nil {
				return nil, err
			}
			pool, err := encodeNonceToCertPool(nonce, caKey)
			if err != nil {
				return nil, err
			}
			return &tls.Config{
				Certificates: []tls.Certificate{cert},
				ClientAuth:   tls.RequireAnyClientCert,
				ClientCAs:    pool,
				VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
					return verification(rawCerts, nonce)

				},
			}, nil
		},
	}
	ln, err := tls.Listen("tcp", ":4433", mainConfig)
	check(err)
	defer ln.Close()

	log.Println("[SERVER]  Spreman da primi CSR i posalje head.crt + ca.crt + ca.key na :4433")

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println("[SERVER] Greška pri prihvatanju konekcije:", err)
			continue
		}

		go handleClient(conn.(*tls.Conn), caKey, cert, caPEM, caKeyPEM)
	}

}
func headHandle(cert tls.Certificate, caKey *rsa.PrivateKey, caPEM, caKeyPEM []byte) {
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	ln, err := tls.Listen("tcp", ":4444", tlsConfig)
	check(err)
	defer ln.Close()

	log.Println("[SERVER]  Spreman da primi CSR i posalje head.crt + ca.crt + ca.key na :4444")

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println("[SERVER] Greska pri prihvatanju konekcije:", err)
			continue
		}

		go handleClient(conn.(*tls.Conn), caKey, cert, caPEM, caKeyPEM)
	}
}

func handleClient(conn *tls.Conn, caKey *rsa.PrivateKey, tlsCert tls.Certificate, caPEM, caKeyPEM []byte) {
	defer conn.Close()

	if err := conn.Handshake(); err != nil {
		log.Println("[SERVER]  Handshake greska:", err)
		return
	}
	log.Printf("[SERVER]  Konekcija uspostavljena sa: %s", conn.RemoteAddr())

	pemData, err := io.ReadAll(conn)
	check(err)

	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		log.Println("[SERVER]  Nevalidan PEM blok CSR-a")
		return
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	check(err)

	if err := csr.CheckSignature(); err != nil {
		log.Println("[SERVER]  Nevalidan potpis CSR-a:", err)
		return
	}
	log.Println("[SERVER]  CSR uspesno primljen i verifikovan")

	caCert, err := x509.ParseCertificate(tlsCert.Certificate[0])
	check(err)

	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      csr.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     csr.DNSNames,
		IPAddresses:  csr.IPAddresses,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, certTemplate, caCert, csr.PublicKey, caKey)
	check(err)

	headCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	_, err = conn.Write(headCertPEM)
	check(err)

	_, err = conn.Write(caPEM)
	check(err)

	_, err = conn.Write(caKeyPEM)
	check(err)

	log.Println("[SERVER]  Sertifikati i kljuc poslati.")
}

func check(err error) {
	if err != nil {
		log.Fatal(err)
	}
	abi.ValidateReportFormat([]byte{})

}

func generateSubjectKeyID(pub *rsa.PublicKey) []byte {
	pubASN1, err := x509.MarshalPKIXPublicKey(pub)
	check(err)
	sum := sha1.Sum(pubASN1)
	return sum[:]
}
