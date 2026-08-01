package operator

import (
	"context"
	"reflect"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	mcpv1alpha1 "github.com/samuelsupe/supek8smcp/api/v1alpha1"
)

func TestReconcileDelegatedAuthenticationCreatesExactBinding(t *testing.T) {
	t.Parallel()

	server := delegatedAuthTestServer()
	client := fake.NewClientBuilder().WithScheme(delegatedAuthTestScheme()).WithObjects(delegatedAuthServiceAccount(server), exactTokenReviewerRole()).Build()
	reconciler := &KubernetesMCPServerReconciler{Client: client}

	if err := reconciler.reconcileDelegatedAuthentication(context.Background(), server); err != nil {
		t.Fatalf("reconcileDelegatedAuthentication() error = %v", err)
	}

	binding := &rbacv1.ClusterRoleBinding{}
	if err := client.Get(context.Background(), types.NamespacedName{Name: clusterBindingName(server)}, binding); err != nil {
		t.Fatalf("get TokenReview ClusterRoleBinding: %v", err)
	}
	wantRoleRef := rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: tokenReviewerClusterRole}
	if !reflect.DeepEqual(binding.RoleRef, wantRoleRef) {
		t.Fatalf("RoleRef = %#v, want %#v", binding.RoleRef, wantRoleRef)
	}
	wantSubjects := []rbacv1.Subject{{Kind: "ServiceAccount", Name: server.Name, Namespace: server.Namespace}}
	if !reflect.DeepEqual(binding.Subjects, wantSubjects) {
		t.Fatalf("Subjects = %#v, want %#v", binding.Subjects, wantSubjects)
	}
}

func TestReconcileDelegatedAuthenticationRejectsUnexpectedRoleAndRemovesBinding(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*rbacv1.ClusterRole)
	}{
		{
			name: "extra verb",
			mutate: func(role *rbacv1.ClusterRole) {
				role.Rules[0].Verbs = append(role.Rules[0].Verbs, "get")
			},
		},
		{
			name: "extra rule",
			mutate: func(role *rbacv1.ClusterRole) {
				role.Rules = append(role.Rules, rbacv1.PolicyRule{APIGroups: []string{"*"}, Resources: []string{"pods"}, Verbs: []string{"get"}})
			},
		},
		{
			name: "extra resource",
			mutate: func(role *rbacv1.ClusterRole) {
				role.Rules[0].Resources = append(role.Rules[0].Resources, "pods")
			},
		},
		{
			name: "aggregation rule",
			mutate: func(role *rbacv1.ClusterRole) {
				role.AggregationRule = &rbacv1.AggregationRule{}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := delegatedAuthTestServer()
			role := exactTokenReviewerRole()
			tt.mutate(role)
			binding := existingTokenReviewerBinding(server)
			client := fake.NewClientBuilder().WithScheme(delegatedAuthTestScheme()).WithObjects(delegatedAuthServiceAccount(server), role, binding).Build()
			reconciler := &KubernetesMCPServerReconciler{Client: client}

			if err := reconciler.reconcileDelegatedAuthentication(context.Background(), server); err == nil {
				t.Fatal("reconcileDelegatedAuthentication() accepted an unexpected TokenReview ClusterRole")
			}
			got := &rbacv1.ClusterRoleBinding{}
			if err := client.Get(context.Background(), types.NamespacedName{Name: binding.Name}, got); !apierrors.IsNotFound(err) {
				t.Fatalf("pre-existing TokenReview binding lookup error = %v, want NotFound after rejection", err)
			}
		})
	}
}

func TestReconcileDelegatedAuthenticationRecreatesBindingAfterUnexpectedRoleRef(t *testing.T) {
	t.Parallel()

	server := delegatedAuthTestServer()
	role := exactTokenReviewerRole()
	binding := existingTokenReviewerBinding(server)
	binding.RoleRef = rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "cluster-admin"}
	client := fake.NewClientBuilder().WithScheme(delegatedAuthTestScheme()).WithObjects(delegatedAuthServiceAccount(server), role, binding).Build()
	reconciler := &KubernetesMCPServerReconciler{Client: client}

	if err := reconciler.reconcileDelegatedAuthentication(context.Background(), server); err == nil {
		t.Fatal("first reconcile accepted a binding pointing to cluster-admin")
	}
	got := &rbacv1.ClusterRoleBinding{}
	if err := client.Get(context.Background(), types.NamespacedName{Name: binding.Name}, got); !apierrors.IsNotFound(err) {
		t.Fatalf("unexpected-roleRef binding lookup error = %v, want NotFound after first reconcile", err)
	}

	if err := reconciler.reconcileDelegatedAuthentication(context.Background(), server); err != nil {
		t.Fatalf("second reconcile error = %v, want safe binding recreation", err)
	}
	if err := client.Get(context.Background(), types.NamespacedName{Name: binding.Name}, got); err != nil {
		t.Fatalf("get recreated TokenReview binding: %v", err)
	}
	wantRoleRef := rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: tokenReviewerClusterRole}
	if !reflect.DeepEqual(got.RoleRef, wantRoleRef) {
		t.Fatalf("recreated RoleRef = %#v, want %#v", got.RoleRef, wantRoleRef)
	}
	wantSubjects := []rbacv1.Subject{{Kind: "ServiceAccount", Name: server.Name, Namespace: server.Namespace}}
	if !reflect.DeepEqual(got.Subjects, wantSubjects) {
		t.Fatalf("recreated Subjects = %#v, want %#v", got.Subjects, wantSubjects)
	}
}

func TestReconcileDelegatedAuthenticationRejectsMissingRoleAndRemovesBinding(t *testing.T) {
	t.Parallel()

	server := delegatedAuthTestServer()
	binding := existingTokenReviewerBinding(server)
	client := fake.NewClientBuilder().WithScheme(delegatedAuthTestScheme()).WithObjects(delegatedAuthServiceAccount(server), binding).Build()
	reconciler := &KubernetesMCPServerReconciler{Client: client}

	if err := reconciler.reconcileDelegatedAuthentication(context.Background(), server); err == nil {
		t.Fatal("reconcileDelegatedAuthentication() accepted a missing TokenReview ClusterRole")
	}
	got := &rbacv1.ClusterRoleBinding{}
	if err := client.Get(context.Background(), types.NamespacedName{Name: binding.Name}, got); !apierrors.IsNotFound(err) {
		t.Fatalf("pre-existing TokenReview binding lookup error = %v, want NotFound after missing-role rejection", err)
	}
}

func TestReconcileDelegatedAuthenticationRejectsUnownedServiceAccountWithoutBinding(t *testing.T) {
	t.Parallel()

	server := delegatedAuthTestServer()
	foreign := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{
		Name: server.Name, Namespace: server.Namespace, UID: types.UID("foreign-sa"), ResourceVersion: "7",
		Labels: map[string]string{"owner": "another-controller"},
	}}
	role := exactTokenReviewerRole()
	client := fake.NewClientBuilder().WithScheme(delegatedAuthTestScheme()).WithObjects(foreign, role).Build()
	reconciler := &KubernetesMCPServerReconciler{Client: client}

	if err := reconciler.reconcileServiceAccount(context.Background(), server, server.ServerLabels()); err == nil {
		t.Fatal("reconcileServiceAccount() adopted an unowned ServiceAccount")
	}
	gotSA := &corev1.ServiceAccount{}
	if err := client.Get(context.Background(), types.NamespacedName{Namespace: server.Namespace, Name: server.Name}, gotSA); err != nil {
		t.Fatalf("get foreign ServiceAccount: %v", err)
	}
	if gotSA.Labels["owner"] != "another-controller" || len(gotSA.OwnerReferences) != 0 {
		t.Fatalf("foreign ServiceAccount was changed: labels=%#v ownerRefs=%#v", gotSA.Labels, gotSA.OwnerReferences)
	}

	if err := reconciler.reconcileDelegatedAuthentication(context.Background(), server); err == nil {
		t.Fatal("reconcileDelegatedAuthentication() accepted an unowned ServiceAccount")
	}
	binding := &rbacv1.ClusterRoleBinding{}
	if err := client.Get(context.Background(), types.NamespacedName{Name: clusterBindingName(server)}, binding); !apierrors.IsNotFound(err) {
		t.Fatalf("TokenReview binding lookup error = %v, want NotFound", err)
	}
}

func TestReconcileResourcesClearsServiceExposureDriftPreservesClusterAllocation(t *testing.T) {
	t.Parallel()

	server := delegatedAuthTestServer()
	loadBalancerClass := "service.k8s.aws/nlb"
	allocateNodePorts := true
	ipFamilyPolicy := corev1.IPFamilyPolicySingleStack
	internalTrafficPolicy := corev1.ServiceInternalTrafficPolicyCluster
	wantClusterIPs := []string{"10.0.0.42"}
	wantIPFamilies := []corev1.IPFamily{corev1.IPv4Protocol}
	drifted := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: server.Name, Namespace: server.Namespace},
		Spec: corev1.ServiceSpec{
			Type:                          corev1.ServiceTypeClusterIP,
			ClusterIP:                     wantClusterIPs[0],
			ClusterIPs:                    append([]string(nil), wantClusterIPs...),
			IPFamilies:                    append([]corev1.IPFamily(nil), wantIPFamilies...),
			IPFamilyPolicy:                &ipFamilyPolicy,
			InternalTrafficPolicy:         &internalTrafficPolicy,
			ExternalIPs:                   []string{"198.51.100.10"},
			LoadBalancerIP:                "198.51.100.11",
			LoadBalancerClass:             &loadBalancerClass,
			LoadBalancerSourceRanges:      []string{"0.0.0.0/0"},
			AllocateLoadBalancerNodePorts: &allocateNodePorts,
			HealthCheckNodePort:           32000,
			ExternalTrafficPolicy:         corev1.ServiceExternalTrafficPolicyTypeLocal,
			Ports: []corev1.ServicePort{{
				Name: "old", Port: 9443, NodePort: 30080, Protocol: corev1.ProtocolTCP,
			}},
		},
	}
	if err := controllerutil.SetControllerReference(server, drifted, serviceReconcileTestScheme()); err != nil {
		t.Fatalf("set Service controller reference: %v", err)
	}
	client := fake.NewClientBuilder().WithScheme(serviceReconcileTestScheme()).WithObjects(drifted).Build()
	reconciler := &KubernetesMCPServerReconciler{Client: client, Scheme: serviceReconcileTestScheme(), ServerImage: "example/server:dev"}

	if _, err := reconciler.reconcileResources(context.Background(), server, server.ServerLabels(), "revision", []byte("ca"), "tls-revision"); err != nil {
		t.Fatalf("reconcileResources() error = %v", err)
	}

	got := &corev1.Service{}
	if err := client.Get(context.Background(), types.NamespacedName{Namespace: server.Namespace, Name: server.Name}, got); err != nil {
		t.Fatalf("get reconciled Service: %v", err)
	}
	if got.Spec.ClusterIP != wantClusterIPs[0] || !reflect.DeepEqual(got.Spec.ClusterIPs, wantClusterIPs) {
		t.Fatalf("cluster allocation fields changed: ClusterIP=%q ClusterIPs=%#v", got.Spec.ClusterIP, got.Spec.ClusterIPs)
	}
	if !reflect.DeepEqual(got.Spec.IPFamilies, wantIPFamilies) || got.Spec.IPFamilyPolicy == nil || *got.Spec.IPFamilyPolicy != ipFamilyPolicy {
		t.Fatalf("IP allocation fields changed: IPFamilies=%#v IPFamilyPolicy=%v", got.Spec.IPFamilies, got.Spec.IPFamilyPolicy)
	}
	if got.Spec.InternalTrafficPolicy == nil || *got.Spec.InternalTrafficPolicy != internalTrafficPolicy {
		t.Fatalf("InternalTrafficPolicy changed: %v", got.Spec.InternalTrafficPolicy)
	}
	if got.Spec.ExternalName != "" || len(got.Spec.ExternalIPs) != 0 || got.Spec.LoadBalancerIP != "" || len(got.Spec.LoadBalancerSourceRanges) != 0 || got.Spec.LoadBalancerClass != nil || got.Spec.AllocateLoadBalancerNodePorts != nil || got.Spec.HealthCheckNodePort != 0 || got.Spec.ExternalTrafficPolicy != "" {
		t.Fatalf("service exposure fields were not cleared: %#v", got.Spec)
	}
	for _, port := range got.Spec.Ports {
		if port.NodePort != 0 {
			t.Fatalf("reconciled Service port retained nodePort %d: %#v", port.NodePort, got.Spec.Ports)
		}
	}
}

func TestReconcileServiceGateAndDisableKeepServiceAndPodsOnOneRevision(t *testing.T) {
	t.Parallel()

	server := delegatedAuthTestServer()
	scheme := serviceReconcileTestScheme()
	client := fake.NewClientBuilder().WithScheme(scheme).Build()
	reconciler := &KubernetesMCPServerReconciler{Client: client, Scheme: scheme, ServerImage: "example/server:dev"}
	labels := server.ServerLabels()
	policyRev := policyRevision(server)

	if err := reconciler.reconcileServiceGate(context.Background(), server, labels, policyRev); err != nil {
		t.Fatalf("initial reconcileServiceGate() error = %v", err)
	}
	service := &corev1.Service{}
	if err := client.Get(context.Background(), types.NamespacedName{Namespace: server.Namespace, Name: server.Name}, service); err != nil {
		t.Fatalf("get initially gated Service: %v", err)
	}
	if got := service.Spec.Selector[serverRevisionLabel]; got != disabledServerRevision {
		t.Fatalf("initial Service revision selector = %q, want %q", got, disabledServerRevision)
	}
	if got := service.Annotations[serverPolicyRevision]; got != policyRev {
		t.Fatalf("initial Service policy revision annotation = %q, want %q", got, policyRev)
	}

	if _, err := reconciler.reconcileResources(context.Background(), server, labels, policyRev, []byte("ca"), "tls-revision"); err != nil {
		t.Fatalf("successful reconcileResources() error = %v", err)
	}
	if err := client.Get(context.Background(), types.NamespacedName{Namespace: server.Namespace, Name: server.Name}, service); err != nil {
		t.Fatalf("get successfully reconciled Service: %v", err)
	}
	deployment := &appsv1.Deployment{}
	if err := client.Get(context.Background(), types.NamespacedName{Namespace: server.Namespace, Name: server.Name}, deployment); err != nil {
		t.Fatalf("get successfully reconciled Deployment: %v", err)
	}
	if got := service.Annotations[serverPolicyRevision]; got != policyRev {
		t.Fatalf("successful Service policy revision annotation = %q, want %q", got, policyRev)
	}
	if !reflect.DeepEqual(service.Spec.Selector, deployment.Spec.Template.Labels) {
		t.Fatalf("successful Service selector = %#v, want Deployment pod labels %#v", service.Spec.Selector, deployment.Spec.Template.Labels)
	}
	if got := service.Spec.Selector[serverRevisionLabel]; got == "" || got == disabledServerRevision {
		t.Fatalf("successful Service revision selector = %q, want active workload revision", got)
	}

	if err := reconciler.disableServer(context.Background(), server); err != nil {
		t.Fatalf("disableServer() error = %v", err)
	}
	if err := client.Get(context.Background(), types.NamespacedName{Namespace: server.Namespace, Name: server.Name}, service); err != nil {
		t.Fatalf("get disabled Service: %v", err)
	}
	if got := service.Spec.Selector[serverRevisionLabel]; got != disabledServerRevision {
		t.Fatalf("disabled Service revision selector = %q, want %q", got, disabledServerRevision)
	}
	if got := service.Annotations[serverPolicyRevision]; got != policyRev {
		t.Fatalf("disabled Service policy revision annotation = %q, want %q", got, policyRev)
	}
	if err := client.Get(context.Background(), types.NamespacedName{Namespace: server.Namespace, Name: server.Name}, deployment); err != nil {
		t.Fatalf("get disabled Deployment: %v", err)
	}
	if deployment.Spec.Replicas == nil || *deployment.Spec.Replicas != 0 {
		t.Fatalf("disabled Deployment replicas = %v, want 0", deployment.Spec.Replicas)
	}
}

func TestReconcileNetworkPolicyDoesNotDeleteUnownedDisabledPolicy(t *testing.T) {
	t.Parallel()

	server := delegatedAuthTestServer()
	disabled := false
	foreign := &networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{
		Name: server.Name, Namespace: server.Namespace, UID: types.UID("foreign-policy"), ResourceVersion: "9",
		Labels: map[string]string{"owner": "another-controller"},
	}}
	server.Spec.NetworkPolicy.Enabled = &disabled
	client := fake.NewClientBuilder().WithScheme(serviceReconcileTestScheme()).WithObjects(foreign).Build()
	reconciler := &KubernetesMCPServerReconciler{Client: client, Scheme: serviceReconcileTestScheme()}

	if err := reconciler.reconcileNetworkPolicy(context.Background(), server, server.ServerLabels()); err == nil {
		t.Fatal("reconcileNetworkPolicy() deleted or adopted an unowned disabled NetworkPolicy")
	}
	got := &networkingv1.NetworkPolicy{}
	if err := client.Get(context.Background(), types.NamespacedName{Namespace: server.Namespace, Name: server.Name}, got); err != nil {
		t.Fatalf("get foreign NetworkPolicy after rejected disable: %v", err)
	}
	if got.UID != types.UID("foreign-policy") || got.Labels["owner"] != "another-controller" || len(got.OwnerReferences) != 0 {
		t.Fatalf("foreign NetworkPolicy changed: UID=%q labels=%#v ownerRefs=%#v", got.UID, got.Labels, got.OwnerReferences)
	}
}

func TestReconcileResourcesRolloutRevisionIncludesConfigMapResourceVersion(t *testing.T) {
	t.Parallel()

	server := delegatedAuthTestServer()
	scheme := serviceReconcileTestScheme()
	client := fake.NewClientBuilder().WithScheme(scheme).Build()
	reconciler := &KubernetesMCPServerReconciler{Client: client, Scheme: scheme, ServerImage: "example/server:dev"}
	labels := server.ServerLabels()
	policyRev := policyRevision(server)

	if _, err := reconciler.reconcileResources(context.Background(), server, labels, policyRev, []byte("ca"), "tls-revision"); err != nil {
		t.Fatalf("initial reconcileResources() error = %v", err)
	}
	deployment := &appsv1.Deployment{}
	key := types.NamespacedName{Namespace: server.Namespace, Name: server.Name}
	if err := client.Get(context.Background(), key, deployment); err != nil {
		t.Fatalf("get initial Deployment: %v", err)
	}
	firstHash := deployment.Spec.Template.Annotations["mcp.supek8smcp.io/config-hash"]
	if firstHash == "" {
		t.Fatal("initial Deployment config hash is empty")
	}

	configMap := &corev1.ConfigMap{}
	configKey := types.NamespacedName{Namespace: server.Namespace, Name: server.Name + "-config"}
	if err := client.Get(context.Background(), configKey, configMap); err != nil {
		t.Fatalf("get reconciled ConfigMap: %v", err)
	}
	initialConfigMapRevision := configMap.ResourceVersion
	configMap.Annotations = map[string]string{"test.example/revision": "changed"}
	if err := client.Update(context.Background(), configMap); err != nil {
		t.Fatalf("update ConfigMap to advance resourceVersion: %v", err)
	}
	updatedConfigMap := &corev1.ConfigMap{}
	if err := client.Get(context.Background(), configKey, updatedConfigMap); err != nil {
		t.Fatalf("get updated ConfigMap: %v", err)
	}
	if updatedConfigMap.ResourceVersion == initialConfigMapRevision {
		t.Fatalf("ConfigMap resourceVersion did not advance: before=%q after=%q", initialConfigMapRevision, updatedConfigMap.ResourceVersion)
	}

	if _, err := reconciler.reconcileResources(context.Background(), server, labels, policyRev, []byte("ca"), "tls-revision"); err != nil {
		t.Fatalf("reconcileResources() after ConfigMap update error = %v", err)
	}
	if err := client.Get(context.Background(), key, deployment); err != nil {
		t.Fatalf("get updated Deployment: %v", err)
	}
	secondHash := deployment.Spec.Template.Annotations["mcp.supek8smcp.io/config-hash"]
	if secondHash == firstHash {
		t.Fatalf("Deployment config hash stayed %q after ConfigMap resourceVersion changed", secondHash)
	}
}

func delegatedAuthTestServer() *mcpv1alpha1.KubernetesMCPServer {
	return &mcpv1alpha1.KubernetesMCPServer{ObjectMeta: metav1.ObjectMeta{Name: "demo", Namespace: "mcp-system", UID: types.UID("server-uid")}}
}

func delegatedAuthServiceAccount(server *mcpv1alpha1.KubernetesMCPServer) *corev1.ServiceAccount {
	controller := true
	return &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{
		Name: server.Name, Namespace: server.Namespace,
		OwnerReferences: []metav1.OwnerReference{{
			APIVersion: mcpv1alpha1.GroupVersion.String(), Kind: "KubernetesMCPServer",
			Name: server.Name, UID: server.UID, Controller: &controller, BlockOwnerDeletion: &controller,
		}},
	}}
}

func exactTokenReviewerRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: tokenReviewerClusterRole},
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{"authentication.k8s.io"},
			Resources: []string{"tokenreviews"},
			Verbs:     []string{"create"},
		}},
	}
}

func existingTokenReviewerBinding(server *mcpv1alpha1.KubernetesMCPServer) *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: clusterBindingName(server)}}
}

func delegatedAuthTestScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = rbacv1.AddToScheme(scheme)
	_ = mcpv1alpha1.AddToScheme(scheme)
	return scheme
}

func serviceReconcileTestScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	_ = appsv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	_ = networkingv1.AddToScheme(scheme)
	_ = mcpv1alpha1.AddToScheme(scheme)
	return scheme
}
