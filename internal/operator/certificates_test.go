package operator

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	mcpv1alpha1 "github.com/samuelsupe/supek8smcp/api/v1alpha1"
)

func TestSignServerCertificateHasServiceDNSNames(t *testing.T) {
	t.Parallel()

	ca, err := newCA()
	if err != nil {
		t.Fatalf("newCA() error = %v", err)
	}
	server := &mcpv1alpha1.KubernetesMCPServer{ObjectMeta: metav1.ObjectMeta{Name: "demo", Namespace: "mcp-system", UID: types.UID("server-uid")}}
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
			material, err := r.ensureServingCertificate(context.Background(), target, ca)
			if tt.wantErr {
				if err == nil || !strings.Contains(err.Error(), "verify certificate") {
					t.Fatalf("ensureServingCertificate() error = %v, want SAN verification error", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ensureServingCertificate() error = %v", err)
			}
			if string(material.caBundle) != string(ca.certPEM) {
				t.Fatalf("returned CA bundle differs from configured ca.crt")
			}
		})
	}
}

func TestEnsureServingCertificateReplacesManagedSecretSignedByDifferentCA(t *testing.T) {
	t.Parallel()

	operatorCA, err := newCA()
	if err != nil {
		t.Fatalf("newCA() operator CA error = %v", err)
	}
	otherCA, err := newCA()
	if err != nil {
		t.Fatalf("newCA() other CA error = %v", err)
	}
	server := &mcpv1alpha1.KubernetesMCPServer{ObjectMeta: metav1.ObjectMeta{Name: "demo", Namespace: "mcp-system", UID: types.UID("server-uid")}}
	oldCertPEM, oldKeyPEM, err := otherCA.signServer(server)
	if err != nil {
		t.Fatalf("signServer() old certificate error = %v", err)
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: server.TLSSecretName(), Namespace: server.Namespace},
		Type:       corev1.SecretTypeTLS,
		Data: map[string][]byte{
			corev1.TLSCertKey: oldCertPEM, corev1.TLSPrivateKeyKey: oldKeyPEM, "ca.crt": otherCA.certPEM,
		},
	}
	if err := controllerutil.SetControllerReference(server, secret, testOperatorScheme()); err != nil {
		t.Fatalf("set serving Secret controller reference: %v", err)
	}
	client := fake.NewClientBuilder().WithScheme(testOperatorScheme()).WithObjects(secret).Build()
	r := &KubernetesMCPServerReconciler{Client: client, Scheme: testOperatorScheme()}

	material, err := r.ensureServingCertificate(context.Background(), server, operatorCA)
	if err != nil {
		t.Fatalf("ensureServingCertificate() error = %v", err)
	}
	if !bytes.Equal(material.caBundle, operatorCA.certPEM) {
		t.Fatalf("returned CA bundle does not use operator CA")
	}

	got := &corev1.Secret{}
	if err := client.Get(context.Background(), types.NamespacedName{Namespace: server.Namespace, Name: server.TLSSecretName()}, got); err != nil {
		t.Fatalf("get reconciled serving Secret: %v", err)
	}
	for key, want := range server.ServerLabels() {
		if got.Labels[key] != want {
			t.Fatalf("reconciled serving Secret label %q = %q, want %q", key, got.Labels[key], want)
		}
	}
	if !bytes.Equal(got.Data["ca.crt"], operatorCA.certPEM) {
		t.Fatalf("reconciled ca.crt does not use operator CA")
	}
	wantRevision := digestParts(got.Data[corev1.TLSCertKey], got.Data[corev1.TLSPrivateKeyKey], []byte(got.ResourceVersion))
	if material.revision == "" || material.revision != wantRevision {
		t.Fatalf("returned revision = %q, want final Secret digest %q", material.revision, wantRevision)
	}
	if bytes.Equal(got.Data[corev1.TLSCertKey], oldCertPEM) {
		t.Fatal("reconciled tls.crt was not replaced")
	}
	if err := validateServingTLS(got, server, operatorCA.certPEM); err != nil {
		t.Fatalf("reconciled Secret does not validate against operator CA: %v", err)
	}
	pair, err := tls.X509KeyPair(got.Data[corev1.TLSCertKey], got.Data[corev1.TLSPrivateKeyKey])
	if err != nil {
		t.Fatalf("parse reconciled serving key pair: %v", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatalf("parse reconciled serving certificate: %v", err)
	}
	caBlock, _ := pem.Decode(operatorCA.certPEM)
	if caBlock == nil {
		t.Fatal("operator CA certificate is not PEM")
	}
	operatorCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		t.Fatalf("parse operator CA certificate: %v", err)
	}
	if err := leaf.CheckSignatureFrom(operatorCert); err != nil {
		t.Fatalf("reconciled serving certificate is not signed by operator CA: %v", err)
	}
}

func TestEnsureServingCertificateRepairsValidSecretMetadataWithoutRotation(t *testing.T) {
	t.Parallel()

	ca, err := newCA()
	if err != nil {
		t.Fatalf("newCA() error = %v", err)
	}
	server := &mcpv1alpha1.KubernetesMCPServer{ObjectMeta: metav1.ObjectMeta{
		Name: "demo", Namespace: "mcp-system", UID: types.UID("server-uid"),
	}}
	certPEM, keyPEM, err := ca.signServer(server)
	if err != nil {
		t.Fatalf("signServer() error = %v", err)
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: server.TLSSecretName(), Namespace: server.Namespace},
		Type:       corev1.SecretTypeTLS,
		Data: map[string][]byte{
			corev1.TLSCertKey: certPEM, corev1.TLSPrivateKeyKey: keyPEM, "ca.crt": ca.certPEM,
		},
	}
	if err := controllerutil.SetControllerReference(server, secret, testOperatorScheme()); err != nil {
		t.Fatalf("set serving Secret controller reference: %v", err)
	}
	client := fake.NewClientBuilder().WithScheme(testOperatorScheme()).WithObjects(secret).Build()
	reconciler := &KubernetesMCPServerReconciler{Client: client, Scheme: testOperatorScheme()}

	if _, err := reconciler.ensureServingCertificate(context.Background(), server, ca); err != nil {
		t.Fatalf("ensureServingCertificate() error = %v", err)
	}
	got := &corev1.Secret{}
	if err := client.Get(context.Background(), types.NamespacedName{Namespace: server.Namespace, Name: server.TLSSecretName()}, got); err != nil {
		t.Fatalf("get repaired serving Secret: %v", err)
	}
	if !bytes.Equal(got.Data[corev1.TLSCertKey], certPEM) || !bytes.Equal(got.Data[corev1.TLSPrivateKeyKey], keyPEM) {
		t.Fatal("valid serving Secret certificate or key was rotated while repairing metadata")
	}
	for key, want := range server.ServerLabels() {
		if got.Labels[key] != want {
			t.Fatalf("repaired serving Secret label %q = %q, want %q", key, got.Labels[key], want)
		}
	}
	controllerRef := metav1.GetControllerOf(got)
	if controllerRef == nil {
		t.Fatal("repaired serving Secret has no controller owner reference")
	}
	if controllerRef.Kind != "KubernetesMCPServer" || controllerRef.Name != server.Name || controllerRef.UID != server.UID {
		t.Fatalf("controller owner reference = %#v, want KubernetesMCPServer %s/%s UID %s", controllerRef, server.Namespace, server.Name, server.UID)
	}
}

func TestEnsureServingCertificateRejectsUnownedManagedSecret(t *testing.T) {
	t.Parallel()

	ca, err := newCA()
	if err != nil {
		t.Fatalf("newCA() error = %v", err)
	}
	server := &mcpv1alpha1.KubernetesMCPServer{ObjectMeta: metav1.ObjectMeta{
		Name: "demo", Namespace: "mcp-system", UID: types.UID("server-uid"),
	}}
	foreign := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
		Name: server.TLSSecretName(), Namespace: server.Namespace, UID: types.UID("foreign-secret"), ResourceVersion: "11",
		Labels: map[string]string{"owner": "another-controller"},
	}, Type: corev1.SecretTypeOpaque, Data: map[string][]byte{"marker": []byte("keep")}}
	client := fake.NewClientBuilder().WithScheme(testOperatorScheme()).WithObjects(foreign).Build()
	reconciler := &KubernetesMCPServerReconciler{Client: client, Scheme: testOperatorScheme()}

	if _, err := reconciler.ensureServingCertificate(context.Background(), server, ca); err == nil || !strings.Contains(err.Error(), "not controlled") {
		t.Fatalf("ensureServingCertificate() error = %v, want unowned managed Secret rejection", err)
	}
	got := &corev1.Secret{}
	if err := client.Get(context.Background(), types.NamespacedName{Namespace: server.Namespace, Name: server.TLSSecretName()}, got); err != nil {
		t.Fatalf("get foreign managed Secret after rejection: %v", err)
	}
	if got.UID != types.UID("foreign-secret") || got.Labels["owner"] != "another-controller" || len(got.OwnerReferences) != 0 || string(got.Data["marker"]) != "keep" {
		t.Fatalf("foreign managed Secret changed: UID=%q labels=%#v ownerRefs=%#v data=%#v", got.UID, got.Labels, got.OwnerReferences, got.Data)
	}
}

func TestMaterialForSecretRevisionTracksResourceVersion(t *testing.T) {
	t.Parallel()

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{ResourceVersion: "7"},
		Data: map[string][]byte{
			corev1.TLSCertKey:       []byte("cert"),
			corev1.TLSPrivateKeyKey: []byte("key"),
		},
	}
	first := materialForSecret(secret, []byte("ca"))
	secret.ResourceVersion = "8"
	second := materialForSecret(secret, []byte("ca"))

	if first.revision == second.revision {
		t.Fatalf("serving revision stayed %q after Secret resourceVersion changed", first.revision)
	}
	if first.revision != digestParts(secret.Data[corev1.TLSCertKey], secret.Data[corev1.TLSPrivateKeyKey], []byte("7")) {
		t.Fatalf("initial serving revision = %q, want digest including resourceVersion 7", first.revision)
	}
	if second.revision != digestParts(secret.Data[corev1.TLSCertKey], secret.Data[corev1.TLSPrivateKeyKey], []byte("8")) {
		t.Fatalf("updated serving revision = %q, want digest including resourceVersion 8", second.revision)
	}
}

func testOperatorScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = mcpv1alpha1.AddToScheme(scheme)
	return scheme
}
