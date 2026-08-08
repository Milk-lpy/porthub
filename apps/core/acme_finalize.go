package main

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"time"
)

func finalizeACMEOrder(session *acmeOrderSession, cert certificateItem, deploy bool) (acmeIssueResult, error) {
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: cert.Domains}, session.CertificateKey)
	if err != nil {
		return acmeIssueResult{}, err
	}
	chainDER, _, err := session.Client.CreateOrderCert(session.Context, session.Order.FinalizeURL, csrDER, true)
	if err != nil {
		return acmeIssueResult{}, errors.New("ACME certificate issuance failed: " + err.Error())
	}
	if len(chainDER) == 0 {
		return acmeIssueResult{}, errors.New("ACME certificate issuance returned an empty chain")
	}
	certificatePEM := []byte{}
	for _, der := range chainDER {
		certificatePEM = append(certificatePEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	leaf, err := validateImportedCertificate(cert.Domains, certificatePEM, session.KeyPEM, time.Now())
	if err != nil {
		return acmeIssueResult{}, err
	}
	certPath, managedKeyPath := managedCertificatePaths(cert)
	if err := atomicPrivateWrite(certPath, certificatePEM, 0640); err != nil {
		return acmeIssueResult{}, err
	}
	if err := atomicPrivateWrite(managedKeyPath, session.KeyPEM, 0600); err != nil {
		return acmeIssueResult{}, err
	}
	issuer := leaf.Issuer.CommonName
	if issuer == "" {
		issuer = "ACME"
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := db.Exec("update certificates set issuer=?,status='issued',expires_at=?,key_ref=?,updated_at=? where id=?", issuer, leaf.NotAfter.UTC().Format(time.RFC3339), managedKeyPath, now, cert.ID); err != nil {
		return acmeIssueResult{}, err
	}
	_, _ = db.Exec("insert into acme_orders(certificate_id,ts,status,directory_url,error) values(?,?,?,?,?)", cert.ID, now, "issued", acmeDirectoryURL, "")
	if deploy {
		if err := deployCertificateToEdge(cert.ID); err != nil {
			return acmeIssueResult{}, errors.New("certificate issued but Edge deploy failed: " + err.Error())
		}
	}
	return acmeIssueResult{OK: true, CertificateID: cert.ID, Domains: cert.Domains, ExpiresAt: leaf.NotAfter.UTC(), Deployed: deploy, Issuer: issuer}, nil
}
