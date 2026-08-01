package operator

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	mcpv1alpha1 "github.com/samuelsupe/supek8smcp/api/v1alpha1"
)

func TestSignServerCertificateHasServiceDNSNames(t *testing.T) {
	t.Parallel()

	ca, err := newCA()
	if err != nil {
		t.Fatalf("newCA() error = %v", err)
	}
	server := &mcpv1alpha1.KubernetesMCPServer{ObjectMeta: metav1.ObjectMeta{Name: "demo", Namespace: "mcp-system"}}
	certPEM, _, err := ca.signServer(server)
	if err != nil {
		t.Fatalf("signServer() error = %v", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("signed certificate is not PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate() error = %v", err)
	}
	wantNames := []string{"demo", "demo.mcp-system", "demo.mcp-system.svc", "demo.mcp-system.svc.cluster.local"}
	for _, name := range wantNames {
		if err := cert.VerifyHostname(name); err != nil {
			t.Errorf("VerifyHostname(%q) error = %v; DNSNames = %#v", name, err, cert.DNSNames)
		}
	}
	caBlock, _ := pem.Decode(ca.certPEM)
	if caBlock == nil {
		t.Fatal("generated CA certificate is not PEM")
	}
	parsedCA, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate(CA) error = %v", err)
	}
	if err := cert.CheckSignatureFrom(parsedCA); err != nil {
		t.Fatalf("serving certificate is not signed by generated CA: %v", err)
	}
	if cert.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Fatalf("ExtKeyUsage = %#v, want ServerAuth", cert.ExtKeyUsage)
	}
}

func TestEnsureServingCertificateRejectsNonTLSExternalSecret(t *testing.T) {
	t.Parallel()

	server := &mcpv1alpha1.KubernetesMCPServer{ObjectMeta: metav1.ObjectMeta{Name: "demo", Namespace: "mcp-system"}, Spec: mcpv1alpha1.KubernetesMCPServerSpec{TLS: mcpv1alpha1.TLSSpec{SecretName: "external-tls"}}}
	client := fake.NewClientBuilder().WithScheme(testOperatorScheme()).WithObjects(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "external-tls", Namespace: "mcp-system"},
		Type:       corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			corev1.TLSCertKey:       []byte("cert"),
			corev1.TLSPrivateKeyKey: []byte("key"),
			"ca.crt":                []byte("ca"),
		},
	}).Build()
	r := &KubernetesMCPServerReconciler{Client: client}
	ca, err := newCA()
	if err != nil {
		t.Fatalf("newCA() error = %v", err)
	}
	_, err = r.ensureServingCertificate(context.Background(), server, ca)
	if err == nil || !strings.Contains(err.Error(), "must have type") {
		t.Fatalf("ensureServingCertificate() error = %v, want external Secret type error", err)
	}
}

func TestEnsureServingCertificateValidatesExternalSAN(t *testing.T) {
	t.Parallel()

	ca, err := newCA()
	if err != nil {
		t.Fatalf("newCA() error = %v", err)
	}
	target := &mcpv1alpha1.KubernetesMCPServer{
		ObjectMeta: metav1.ObjectMeta{Name: "demo", Namespace: "mcp-system"},
		Spec:       mcpv1alpha1.KubernetesMCPServerSpec{TLS: mcpv1alpha1.TLSSpec{SecretName: "external-tls"}},
	}
	wrongTarget := &mcpv1alpha1.KubernetesMCPServer{ObjectMeta: metav1.ObjectMeta{Name: "other", Namespace: "mcp-system"}}

	for _, tt := range []struct {
		name              string
		certificateServer *mcpv1alpha1.KubernetesMCPServer
		wantErr           bool
	}{
		{name: "wrong SAN", certificateServer: wrongTarget, wantErr: true},
		{name: "matching SAN", certificateServer: target, wantErr: false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			certPEM, keyPEM, err := ca.signServer(tt.certificateServer)
			if err != nil {
				t.Fatalf("signServer() error = %v", err)
			}
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "external-tls", Namespace: "mcp-system"},
				Type:       corev1.SecretTypeTLS,
				Data: map[string][]byte{
					corev1.TLSCertKey: certPEM, corev1.TLSPrivateKeyKey: keyPEM, "ca.crt": ca.certPEM,
				},
			}
			r := &KubernetesMCPServerReconciler{Client: fake.NewClientBuilder().WithScheme(testOperatorScheme()).WithObjects(secret).Build()}
			caBundle, err := r.ensureServingCertificate(context.Background(), target, ca)
			if tt.wantErr {
				if err == nil || !strings.Contains(err.Error(), "verify certificate") {
					t.Fatalf("ensureServingCertificate() error = %v, want SAN verification error", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ensureServingCertificate() error = %v", err)
			}
			if string(caBundle) != string(ca.certPEM) {
				t.Fatalf("returned CA bundle differs from configured ca.crt")
			}
		})
	}
}

func testOperatorScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = mcpv1alpha1.AddToScheme(scheme)
	return scheme
}
