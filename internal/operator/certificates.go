package operator

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	mcpv1alpha1 "github.com/samuelsupe/supek8smcp/api/v1alpha1"
)

const rootCASecretName = "supek8smcp-serving-ca"

type certificateAuthority struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte
	keyPEM  []byte
}

type servingCertificateMaterial struct {
	caBundle []byte
	revision string
}

func (r *KubernetesMCPServerReconciler) ensureRootCA(ctx context.Context) (*certificateAuthority, error) {
	key := types.NamespacedName{Namespace: r.OperatorNamespace, Name: rootCASecretName}
	secret := &corev1.Secret{}
	if err := r.Get(ctx, key, secret); err == nil {
		return parseCA(secret.Data["ca.crt"], secret.Data["ca.key"])
	} else if !apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("get root CA: %w", err)
	}

	ca, err := newCA()
	if err != nil {
		return nil, err
	}
	secret = &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: key.Namespace, Name: key.Name},
		Type:       corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"ca.crt": ca.certPEM,
			"ca.key": ca.keyPEM,
		},
	}
	if err := r.Create(ctx, secret); err != nil {
		if apierrors.IsAlreadyExists(err) {
			if err := r.Get(ctx, key, secret); err != nil {
				return nil, fmt.Errorf("get concurrently-created root CA: %w", err)
			}
			return parseCA(secret.Data["ca.crt"], secret.Data["ca.key"])
		}
		return nil, fmt.Errorf("create root CA: %w", err)
	}
	return ca, nil
}

func (r *KubernetesMCPServerReconciler) ensureServingCertificate(
	ctx context.Context,
	server *mcpv1alpha1.KubernetesMCPServer,
	ca *certificateAuthority,
) (servingCertificateMaterial, error) {
	name := server.TLSSecretName()
	key := types.NamespacedName{Namespace: server.Namespace, Name: name}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: key.Namespace, Name: key.Name}}
	if server.Spec.TLS.SecretName != "" {
		if err := r.Get(ctx, key, secret); err != nil {
			return servingCertificateMaterial{}, fmt.Errorf("get configured TLS Secret: %w", err)
		}
		if secret.Type != corev1.SecretTypeTLS {
			return servingCertificateMaterial{}, fmt.Errorf("TLS Secret %s must have type %s", name, corev1.SecretTypeTLS)
		}
		if len(secret.Data[corev1.TLSCertKey]) == 0 || len(secret.Data[corev1.TLSPrivateKeyKey]) == 0 || len(secret.Data["ca.crt"]) == 0 {
			return servingCertificateMaterial{}, fmt.Errorf("TLS Secret %s must contain tls.crt, tls.key, and ca.crt", name)
		}
		if err := validateConfiguredTLS(secret, server); err != nil {
			return servingCertificateMaterial{}, fmt.Errorf("validate TLS Secret %s: %w", name, err)
		}
		return materialForSecret(secret, secret.Data["ca.crt"]), nil
	}
	if ca == nil {
		return servingCertificateMaterial{}, fmt.Errorf("operator CA is required for a managed serving certificate")
	}

	err := r.Get(ctx, key, secret)
	if err == nil {
		if err := requireControllerOwnership(server, secret); err != nil {
			return servingCertificateMaterial{}, fmt.Errorf("validate managed serving certificate ownership: %w", err)
		}
	}
	if err == nil && servingCertificateValid(secret, server, ca.certPEM, 30*24*time.Hour) {
		if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, secret, func() error {
			if err := requireControllerOwnership(server, secret); err != nil {
				return err
			}
			secret.Labels = server.ServerLabels()
			return controllerutil.SetControllerReference(server, secret, r.Scheme)
		}); err != nil {
			return servingCertificateMaterial{}, fmt.Errorf("reconcile serving certificate metadata: %w", err)
		}
		return materialForSecret(secret, ca.certPEM), nil
	}
	if err != nil && !apierrors.IsNotFound(err) {
		return servingCertificateMaterial{}, fmt.Errorf("get serving certificate: %w", err)
	}

	certPEM, keyPEM, err := ca.signServer(server)
	if err != nil {
		return servingCertificateMaterial{}, err
	}
	_, err = controllerutil.CreateOrUpdate(ctx, r.Client, secret, func() error {
		if err := requireControllerOwnership(server, secret); err != nil {
			return err
		}
		secret.Namespace = server.Namespace
		secret.Name = name
		secret.Labels = server.ServerLabels()
		secret.Type = corev1.SecretTypeTLS
		secret.Data = map[string][]byte{
			corev1.TLSCertKey:       certPEM,
			corev1.TLSPrivateKeyKey: keyPEM,
			"ca.crt":                ca.certPEM,
		}
		return controllerutil.SetControllerReference(server, secret, r.Scheme)
	})
	if err != nil {
		return servingCertificateMaterial{}, fmt.Errorf("reconcile serving certificate: %w", err)
	}
	return materialForSecret(secret, ca.certPEM), nil
}

func materialForSecret(secret *corev1.Secret, caBundle []byte) servingCertificateMaterial {
	return servingCertificateMaterial{
		caBundle: caBundle,
		revision: digestParts(
			secret.Data[corev1.TLSCertKey],
			secret.Data[corev1.TLSPrivateKeyKey],
			[]byte(secret.ResourceVersion),
		),
	}
}

func validateConfiguredTLS(secret *corev1.Secret, server *mcpv1alpha1.KubernetesMCPServer) error {
	return validateServingTLS(secret, server, secret.Data["ca.crt"])
}

func validateServingTLS(secret *corev1.Secret, server *mcpv1alpha1.KubernetesMCPServer, caBundle []byte) error {
	pair, err := tls.X509KeyPair(secret.Data[corev1.TLSCertKey], secret.Data[corev1.TLSPrivateKeyKey])
	if err != nil {
		return fmt.Errorf("parse certificate and private key: %w", err)
	}
	if len(pair.Certificate) == 0 {
		return fmt.Errorf("tls.crt contains no certificate")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return fmt.Errorf("parse serving certificate: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caBundle) {
		return fmt.Errorf("ca.crt contains no certificate")
	}
	intermediates := x509.NewCertPool()
	for _, der := range pair.Certificate[1:] {
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			return fmt.Errorf("parse certificate chain: %w", err)
		}
		intermediates.AddCert(certificate)
	}
	serviceName := fmt.Sprintf("%s.%s.svc", server.Name, server.Namespace)
	if _, err := leaf.Verify(x509.VerifyOptions{
		DNSName: serviceName, Roots: roots, Intermediates: intermediates,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		return fmt.Errorf("verify certificate for %s: %w", serviceName, err)
	}
	return nil
}

func newCA() (*certificateAuthority, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate CA key: %w", err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber:          randomSerial(),
		Subject:               pkix.Name{CommonName: "SupeK8sMCP Serving CA"},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(5 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create CA certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal CA key: %w", err)
	}
	return &certificateAuthority{
		cert:    template,
		key:     key,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		keyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	}, nil
}

func parseCA(certPEM, keyPEM []byte) (*certificateAuthority, error) {
	certBlock, _ := pem.Decode(certPEM)
	keyBlock, _ := pem.Decode(keyPEM)
	if certBlock == nil || keyBlock == nil {
		return nil, fmt.Errorf("operator CA Secret contains invalid PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA certificate: %w", err)
	}
	parsedKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA key: %w", err)
	}
	key, ok := parsedKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("operator CA key is not ECDSA")
	}
	publicKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !publicKey.Equal(&key.PublicKey) {
		return nil, fmt.Errorf("operator CA certificate and key do not match")
	}
	if !cert.IsCA || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, fmt.Errorf("operator CA certificate is not valid for certificate signing")
	}
	now := time.Now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return nil, fmt.Errorf("operator CA certificate is not currently valid")
	}
	return &certificateAuthority{cert: cert, key: key, certPEM: certPEM, keyPEM: keyPEM}, nil
}

func (ca *certificateAuthority) signServer(server *mcpv1alpha1.KubernetesMCPServer) ([]byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate serving key: %w", err)
	}
	now := time.Now().UTC()
	short := fmt.Sprintf("%s.%s.svc", server.Name, server.Namespace)
	template := &x509.Certificate{
		SerialNumber: randomSerial(),
		Subject:      pkix.Name{CommonName: short},
		DNSNames: []string{
			server.Name,
			server.Name + "." + server.Namespace,
			short,
			short + ".cluster.local",
		},
		NotBefore:   now.Add(-5 * time.Minute),
		NotAfter:    now.Add(90 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return nil, nil, fmt.Errorf("sign serving certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal serving key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), nil
}

func servingCertificateValid(secret *corev1.Secret, server *mcpv1alpha1.KubernetesMCPServer, caBundle []byte, remaining time.Duration) bool {
	if secret.Type != corev1.SecretTypeTLS || validateServingTLS(secret, server, caBundle) != nil {
		return false
	}
	pair, err := tls.X509KeyPair(secret.Data[corev1.TLSCertKey], secret.Data[corev1.TLSPrivateKeyKey])
	if err != nil || len(pair.Certificate) == 0 {
		return false
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil || time.Until(cert.NotAfter) < remaining {
		return false
	}
	return true
}

func randomSerial() *big.Int {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return big.NewInt(time.Now().UnixNano())
	}
	return serial
}
