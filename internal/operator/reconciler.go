package operator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	api "k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	mcpv1alpha1 "github.com/samuelsupe/supek8smcp/api/v1alpha1"
	"github.com/samuelsupe/supek8smcp/internal/runtimeconfig"
)

const (
	serverFinalizer          = "mcp.supek8smcp.io/cluster-resources"
	tokenReviewerClusterRole = "supek8smcp-tokenreviewer"
	tlsSecretIndexKey        = "spec.tls.secretName"
)

type KubernetesMCPServerReconciler struct {
	client.Client
	Scheme            *runtime.Scheme
	ServerImage       string
	OperatorNamespace string
	Logger            *slog.Logger
}

func (r *KubernetesMCPServerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	server := &mcpv1alpha1.KubernetesMCPServer{}
	if err := r.Get(ctx, req.NamespacedName, server); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if !server.DeletionTimestamp.IsZero() {
		return r.finalize(ctx, server)
	}
	if !controllerutil.ContainsFinalizer(server, serverFinalizer) {
		controllerutil.AddFinalizer(server, serverFinalizer)
		if err := r.Update(ctx, server); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}

	server.Default()
	var ca *certificateAuthority
	if server.Spec.TLS.SecretName == "" {
		var err error
		ca, err = r.ensureRootCA(ctx)
		if err != nil {
			return r.fail(ctx, server, "TLSReady", "CAError", err)
		}
	}
	caBundle, err := r.ensureServingCertificate(ctx, server, ca)
	if err != nil {
		return r.fail(ctx, server, "TLSReady", "CertificateError", err)
	}
	if err := r.reconcileResources(ctx, server, caBundle); err != nil {
		return r.fail(ctx, server, "Ready", "ReconcileError", err)
	}

	deployment := &appsv1.Deployment{}
	if err := r.Get(ctx, req.NamespacedName, deployment); err != nil {
		return ctrl.Result{}, err
	}
	ready := deployment.Status.AvailableReplicas >= 1
	r.setCondition(server, "TLSReady", metav1.ConditionTrue, "CertificateReady", "serving certificate is ready")
	r.setCondition(server, "AuthReady", metav1.ConditionTrue, "DelegatedAuthenticationReady", "TokenReview binding is ready")
	if ready {
		r.setCondition(server, "Ready", metav1.ConditionTrue, "DeploymentAvailable", "MCP server is available")
	} else {
		r.setCondition(server, "Ready", metav1.ConditionFalse, "DeploymentUnavailable", "waiting for MCP server deployment")
	}
	server.Status.ObservedGeneration = server.Generation
	server.Status.Endpoint = fmt.Sprintf("https://%s.%s.svc:8443/mcp", server.Name, server.Namespace)
	server.Status.CAConfigMapName = server.Name + "-ca"
	if err := r.Status().Update(ctx, server); err != nil {
		return ctrl.Result{}, err
	}
	if !ready {
		return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
	}
	return ctrl.Result{RequeueAfter: 12 * time.Hour}, nil
}

func (r *KubernetesMCPServerReconciler) reconcileResources(ctx context.Context, server *mcpv1alpha1.KubernetesMCPServer, caBundle []byte) error {
	labels := server.ServerLabels()
	serviceAccount := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: server.Name, Namespace: server.Namespace}}
	if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, serviceAccount, func() error {
		serviceAccount.Labels = labels
		automount := true
		serviceAccount.AutomountServiceAccountToken = &automount
		return controllerutil.SetControllerReference(server, serviceAccount, r.Scheme)
	}); err != nil {
		return fmt.Errorf("reconcile ServiceAccount: %w", err)
	}

	binding := &rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: clusterBindingName(server)}}
	if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, binding, func() error {
		binding.Labels = labels
		binding.RoleRef = rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: tokenReviewerClusterRole}
		binding.Subjects = []rbacv1.Subject{{Kind: "ServiceAccount", Name: server.Name, Namespace: server.Namespace}}
		return nil
	}); err != nil {
		return fmt.Errorf("reconcile TokenReview binding: %w", err)
	}

	configData, err := runtimeconfig.Marshal(runtimeconfig.FromResource(server))
	if err != nil {
		return err
	}
	configMap := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: server.Name + "-config", Namespace: server.Namespace}}
	if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, configMap, func() error {
		configMap.Labels = labels
		configMap.Data = map[string]string{"config.json": string(configData)}
		return controllerutil.SetControllerReference(server, configMap, r.Scheme)
	}); err != nil {
		return fmt.Errorf("reconcile server ConfigMap: %w", err)
	}

	caMap := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: server.Name + "-ca", Namespace: server.Namespace}}
	if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, caMap, func() error {
		caMap.Labels = labels
		caMap.Data = map[string]string{"ca.crt": string(caBundle)}
		return controllerutil.SetControllerReference(server, caMap, r.Scheme)
	}); err != nil {
		return fmt.Errorf("reconcile CA ConfigMap: %w", err)
	}

	tlsSecret := &corev1.Secret{}
	if err := r.Get(ctx, client.ObjectKey{Namespace: server.Namespace, Name: server.TLSSecretName()}, tlsSecret); err != nil {
		return fmt.Errorf("get serving TLS Secret: %w", err)
	}
	tlsRevision := digestParts(tlsSecret.Data[corev1.TLSCertKey], tlsSecret.Data[corev1.TLSPrivateKeyKey])

	service := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: server.Name, Namespace: server.Namespace}}
	if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, service, func() error {
		service.Labels = labels
		service.Spec.Type = corev1.ServiceTypeClusterIP
		service.Spec.Selector = labels
		service.Spec.Ports = []corev1.ServicePort{
			{Name: "mcp", Port: 8443, TargetPort: intstr.FromInt32(8443), Protocol: corev1.ProtocolTCP},
			{Name: "metrics", Port: 9090, TargetPort: intstr.FromInt32(9090), Protocol: corev1.ProtocolTCP},
		}
		return controllerutil.SetControllerReference(server, service, r.Scheme)
	}); err != nil {
		return fmt.Errorf("reconcile Service: %w", err)
	}

	if err := r.reconcileNetworkPolicy(ctx, server, labels); err != nil {
		return err
	}
	return r.reconcileDeployment(ctx, server, labels, configData, tlsRevision)
}

func (r *KubernetesMCPServerReconciler) reconcileDeployment(ctx context.Context, server *mcpv1alpha1.KubernetesMCPServer, labels map[string]string, configData []byte, tlsRevision string) error {
	deployment := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: server.Name, Namespace: server.Namespace}}
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, deployment, func() error {
		one := int32(1)
		falseValue := false
		trueValue := true
		mode := int32(0440)
		nonRoot := int64(65532)
		deployment.Labels = labels
		deployment.Spec.Replicas = &one
		deployment.Spec.Selector = &metav1.LabelSelector{MatchLabels: labels}
		deployment.Spec.Template.ObjectMeta.Labels = labels
		deployment.Spec.Template.ObjectMeta.Annotations = map[string]string{
			"mcp.supek8smcp.io/config-hash": digest(configData),
			"mcp.supek8smcp.io/tls-hash":    tlsRevision,
		}
		deployment.Spec.Template.Spec.ServiceAccountName = server.Name
		deployment.Spec.Template.Spec.AutomountServiceAccountToken = &trueValue
		deployment.Spec.Template.Spec.SecurityContext = &corev1.PodSecurityContext{
			RunAsNonRoot:   &trueValue,
			RunAsUser:      &nonRoot,
			RunAsGroup:     &nonRoot,
			FSGroup:        &nonRoot,
			SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
		}
		deployment.Spec.Template.Spec.Containers = []corev1.Container{{
			Name:           "server",
			Image:          r.ServerImage,
			Args:           []string{"serve"},
			Ports:          []corev1.ContainerPort{{Name: "mcp", ContainerPort: 8443}, {Name: "metrics", ContainerPort: 9090}},
			ReadinessProbe: &corev1.Probe{ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Path: "/readyz", Port: intstr.FromString("metrics")}}},
			LivenessProbe:  &corev1.Probe{ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Path: "/healthz", Port: intstr.FromString("metrics")}}},
			SecurityContext: &corev1.SecurityContext{
				AllowPrivilegeEscalation: &falseValue,
				ReadOnlyRootFilesystem:   &trueValue,
				Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
			},
			Resources: corev1.ResourceRequirements{
				Requests: corev1.ResourceList{corev1.ResourceCPU: resourceMustParse("50m"), corev1.ResourceMemory: resourceMustParse("64Mi")},
				Limits:   corev1.ResourceList{corev1.ResourceCPU: resourceMustParse("500m"), corev1.ResourceMemory: resourceMustParse("256Mi")},
			},
			VolumeMounts: []corev1.VolumeMount{
				{Name: "config", MountPath: "/etc/supek8smcp/config", ReadOnly: true},
				{Name: "tls", MountPath: "/etc/supek8smcp/tls", ReadOnly: true},
				{Name: "tmp", MountPath: "/tmp"},
			},
		}}
		deployment.Spec.Template.Spec.Volumes = []corev1.Volume{
			{Name: "config", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: server.Name + "-config"}, DefaultMode: &mode}}},
			{Name: "tls", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: server.TLSSecretName(), DefaultMode: &mode}}},
			{Name: "tmp", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
		}
		return controllerutil.SetControllerReference(server, deployment, r.Scheme)
	})
	if err != nil {
		return fmt.Errorf("reconcile Deployment: %w", err)
	}
	return nil
}

func (r *KubernetesMCPServerReconciler) reconcileNetworkPolicy(ctx context.Context, server *mcpv1alpha1.KubernetesMCPServer, labels map[string]string) error {
	policy := &networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: server.Name, Namespace: server.Namespace}}
	enabled := server.Spec.NetworkPolicy.Enabled == nil || *server.Spec.NetworkPolicy.Enabled
	if !enabled {
		if err := r.Delete(ctx, policy); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("delete disabled NetworkPolicy: %w", err)
		}
		return nil
	}
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, policy, func() error {
		policy.Labels = labels
		peer := networkingv1.NetworkPolicyPeer{}
		if server.Spec.NetworkPolicy.AllowedNamespaceSelector != nil {
			peer.NamespaceSelector = server.Spec.NetworkPolicy.AllowedNamespaceSelector.DeepCopy()
		} else {
			peer.PodSelector = &metav1.LabelSelector{}
		}
		if server.Spec.NetworkPolicy.AllowedPodSelector != nil {
			peer.PodSelector = server.Spec.NetworkPolicy.AllowedPodSelector.DeepCopy()
		}
		policy.Spec = networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: labels},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			Ingress: []networkingv1.NetworkPolicyIngressRule{{
				From:  []networkingv1.NetworkPolicyPeer{peer},
				Ports: []networkingv1.NetworkPolicyPort{{Port: intstrPtr(8443)}, {Port: intstrPtr(9090)}},
			}},
		}
		return controllerutil.SetControllerReference(server, policy, r.Scheme)
	})
	if err != nil {
		return fmt.Errorf("reconcile NetworkPolicy: %w", err)
	}
	return nil
}

func (r *KubernetesMCPServerReconciler) finalize(ctx context.Context, server *mcpv1alpha1.KubernetesMCPServer) (ctrl.Result, error) {
	if !controllerutil.ContainsFinalizer(server, serverFinalizer) {
		return ctrl.Result{}, nil
	}
	binding := &rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: clusterBindingName(server)}}
	if err := r.Delete(ctx, binding); err != nil && !apierrors.IsNotFound(err) {
		return ctrl.Result{}, err
	}
	controllerutil.RemoveFinalizer(server, serverFinalizer)
	return ctrl.Result{}, r.Update(ctx, server)
}

func (r *KubernetesMCPServerReconciler) fail(ctx context.Context, server *mcpv1alpha1.KubernetesMCPServer, condition, reason string, cause error) (ctrl.Result, error) {
	if r.Logger != nil {
		r.Logger.Error("reconciliation failed", "namespace", server.Namespace, "name", server.Name, "error", cause)
	}
	r.setCondition(server, condition, metav1.ConditionFalse, reason, cause.Error())
	r.setCondition(server, "Ready", metav1.ConditionFalse, reason, cause.Error())
	server.Status.ObservedGeneration = server.Generation
	_ = r.Status().Update(ctx, server)
	return ctrl.Result{}, cause
}

func (r *KubernetesMCPServerReconciler) setCondition(server *mcpv1alpha1.KubernetesMCPServer, condition string, status metav1.ConditionStatus, reason, message string) {
	api.SetStatusCondition(&server.Status.Conditions, metav1.Condition{
		Type: condition, Status: status, Reason: reason, Message: message, ObservedGeneration: server.Generation,
	})
}

func (r *KubernetesMCPServerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&mcpv1alpha1.KubernetesMCPServer{}).
		Owns(&appsv1.Deployment{}).
		Owns(&corev1.Service{}).
		Owns(&corev1.ServiceAccount{}).
		Owns(&corev1.ConfigMap{}).
		Owns(&corev1.Secret{}).
		Owns(&networkingv1.NetworkPolicy{}).
		Watches(&corev1.Secret{}, handler.EnqueueRequestsFromMapFunc(r.requestsForExternalTLSSecret)).
		Complete(r)
}

func (r *KubernetesMCPServerReconciler) requestsForExternalTLSSecret(ctx context.Context, object client.Object) []reconcile.Request {
	servers := &mcpv1alpha1.KubernetesMCPServerList{}
	if err := r.List(ctx, servers, client.InNamespace(object.GetNamespace()), client.MatchingFields{tlsSecretIndexKey: object.GetName()}); err != nil {
		if r.Logger != nil {
			r.Logger.Error("list MCP servers for TLS Secret", "namespace", object.GetNamespace(), "secret", object.GetName(), "error", err)
		}
		return nil
	}
	requests := make([]reconcile.Request, 0)
	for index := range servers.Items {
		server := &servers.Items[index]
		if server.Spec.TLS.SecretName == object.GetName() {
			requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(server)})
		}
	}
	return requests
}

func clusterBindingName(server *mcpv1alpha1.KubernetesMCPServer) string {
	sum := sha256.Sum256([]byte(server.Namespace + "/" + server.Name))
	return "supek8smcp-" + hex.EncodeToString(sum[:8])
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func digestParts(parts ...[]byte) string {
	hash := sha256.New()
	for _, part := range parts {
		hash.Write(part)
		hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func intstrPtr(value int32) *intstr.IntOrString {
	v := intstr.FromInt32(value)
	return &v
}

func resourceMustParse(value string) resource.Quantity {
	return resource.MustParse(value)
}
