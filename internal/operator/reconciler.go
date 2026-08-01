package operator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strconv"
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

	mcpv1alpha1 "github.com/samuelsupe/supek8smcp/api/v1alpha1"
	"github.com/samuelsupe/supek8smcp/internal/runtimeconfig"
)

const (
	serverFinalizer          = "mcp.supek8smcp.io/cluster-resources"
	tokenReviewerClusterRole = "supek8smcp-tokenreviewer"
	serverRevisionLabel      = "mcp.supek8smcp.io/revision"
	serverPolicyRevision     = "mcp.supek8smcp.io/policy-revision"
	disabledServerRevision   = "disabled"
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
	labels := server.ServerLabels()
	policyRev := policyRevision(server)
	if err := r.reconcileServiceGate(ctx, server, labels, policyRev); err != nil {
		return r.fail(ctx, server, "Ready", "ServiceGateError", err)
	}
	if err := r.reconcileServiceAccount(ctx, server, labels); err != nil {
		binding := &rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: clusterBindingName(server)}}
		err = r.rejectDelegatedAuthentication(ctx, binding, fmt.Errorf("reconcile Server ServiceAccount: %w", err))
		return r.fail(ctx, server, "AuthReady", "DelegatedAuthenticationError", err)
	}
	if err := r.reconcileDelegatedAuthentication(ctx, server); err != nil {
		return r.fail(ctx, server, "AuthReady", "DelegatedAuthenticationError", err)
	}
	var ca *certificateAuthority
	if server.Spec.TLS.SecretName == "" {
		var err error
		ca, err = r.ensureRootCA(ctx)
		if err != nil {
			return r.fail(ctx, server, "TLSReady", "CAError", err)
		}
	}
	certificate, err := r.ensureServingCertificate(ctx, server, ca)
	if err != nil {
		return r.fail(ctx, server, "TLSReady", "CertificateError", err)
	}
	deploymentGeneration, err := r.reconcileResources(ctx, server, labels, policyRev, certificate.caBundle, certificate.revision)
	if err != nil {
		return r.fail(ctx, server, "Ready", "ReconcileError", err)
	}

	deployment := &appsv1.Deployment{}
	deploymentFound := true
	if err := r.Get(ctx, req.NamespacedName, deployment); apierrors.IsNotFound(err) {
		deploymentFound = false
	} else if err != nil {
		return ctrl.Result{}, err
	}
	ready := deploymentFound &&
		deployment.Generation == deploymentGeneration &&
		deployment.Status.ObservedGeneration >= deployment.Generation &&
		deployment.Status.UpdatedReplicas >= 1 &&
		deployment.Status.AvailableReplicas >= 1
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
	return ctrl.Result{RequeueAfter: 5 * time.Minute}, nil
}

func (r *KubernetesMCPServerReconciler) reconcileResources(
	ctx context.Context,
	server *mcpv1alpha1.KubernetesMCPServer,
	labels map[string]string,
	policyRev string,
	caBundle []byte,
	tlsRevision string,
) (int64, error) {
	configData, err := runtimeconfig.Marshal(runtimeconfig.FromResource(server))
	if err != nil {
		return 0, err
	}
	configMap := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: server.Name + "-config", Namespace: server.Namespace}}
	if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, configMap, func() error {
		if err := requireControllerOwnership(server, configMap); err != nil {
			return err
		}
		configMap.Labels = labels
		configMap.Data = map[string]string{"config.json": string(configData)}
		return controllerutil.SetControllerReference(server, configMap, r.Scheme)
	}); err != nil {
		return 0, fmt.Errorf("reconcile server ConfigMap: %w", err)
	}

	caMap := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: server.Name + "-ca", Namespace: server.Namespace}}
	if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, caMap, func() error {
		if err := requireControllerOwnership(server, caMap); err != nil {
			return err
		}
		caMap.Labels = labels
		caMap.Data = map[string]string{"ca.crt": string(caBundle)}
		return controllerutil.SetControllerReference(server, caMap, r.Scheme)
	}); err != nil {
		return 0, fmt.Errorf("reconcile CA ConfigMap: %w", err)
	}

	if err := r.reconcileNetworkPolicy(ctx, server, labels); err != nil {
		return 0, err
	}
	configRevision := digestParts(configData, []byte(configMap.ResourceVersion))
	workloadRevision := digestParts(
		[]byte(policyRev),
		[]byte(r.ServerImage),
		[]byte(configRevision),
		[]byte(tlsRevision),
	)[:16]
	deploymentGeneration, err := r.reconcileDeployment(ctx, server, labels, workloadRevision, configRevision, tlsRevision)
	if err != nil {
		return 0, err
	}
	if err := r.reconcileService(ctx, server, labels, policyRev, workloadRevision); err != nil {
		return 0, err
	}
	return deploymentGeneration, nil
}

func (r *KubernetesMCPServerReconciler) reconcileServiceAccount(
	ctx context.Context,
	server *mcpv1alpha1.KubernetesMCPServer,
	labels map[string]string,
) error {
	serviceAccount := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: server.Name, Namespace: server.Namespace}}
	if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, serviceAccount, func() error {
		if err := requireControllerOwnership(server, serviceAccount); err != nil {
			return err
		}
		serviceAccount.Labels = labels
		automount := true
		serviceAccount.AutomountServiceAccountToken = &automount
		return controllerutil.SetControllerReference(server, serviceAccount, r.Scheme)
	}); err != nil {
		return fmt.Errorf("reconcile ServiceAccount: %w", err)
	}
	return nil
}

func (r *KubernetesMCPServerReconciler) reconcileServiceGate(
	ctx context.Context,
	server *mcpv1alpha1.KubernetesMCPServer,
	labels map[string]string,
	policyRev string,
) error {
	service := &corev1.Service{}
	err := r.Get(ctx, client.ObjectKey{Namespace: server.Namespace, Name: server.Name}, service)
	if apierrors.IsNotFound(err) {
		return r.reconcileService(ctx, server, labels, policyRev, disabledServerRevision)
	}
	if err != nil {
		return fmt.Errorf("get Server Service: %w", err)
	}
	targetRevision := service.Spec.Selector[serverRevisionLabel]
	if service.Annotations[serverPolicyRevision] != policyRev || targetRevision == "" || targetRevision == disabledServerRevision {
		targetRevision = disabledServerRevision
	}
	return r.reconcileService(ctx, server, labels, policyRev, targetRevision)
}

func (r *KubernetesMCPServerReconciler) reconcileService(
	ctx context.Context,
	server *mcpv1alpha1.KubernetesMCPServer,
	labels map[string]string,
	policyRev string,
	workloadRevision string,
) error {
	service := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: server.Name, Namespace: server.Namespace}}
	if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, service, func() error {
		if err := requireControllerOwnership(server, service); err != nil {
			return err
		}
		service.Labels = labels
		if service.Annotations == nil {
			service.Annotations = map[string]string{}
		}
		service.Annotations[serverPolicyRevision] = policyRev
		service.Spec.Type = corev1.ServiceTypeClusterIP
		service.Spec.Selector = serverPodLabels(labels, workloadRevision)
		service.Spec.ExternalName = ""
		service.Spec.ExternalIPs = nil
		service.Spec.LoadBalancerIP = ""
		service.Spec.LoadBalancerSourceRanges = nil
		service.Spec.LoadBalancerClass = nil
		service.Spec.AllocateLoadBalancerNodePorts = nil
		service.Spec.HealthCheckNodePort = 0
		service.Spec.ExternalTrafficPolicy = ""
		service.Spec.Ports = []corev1.ServicePort{
			{Name: "mcp", Port: 8443, TargetPort: intstr.FromInt32(8443), Protocol: corev1.ProtocolTCP},
			{Name: "metrics", Port: 9090, TargetPort: intstr.FromInt32(9090), Protocol: corev1.ProtocolTCP},
		}
		return controllerutil.SetControllerReference(server, service, r.Scheme)
	}); err != nil {
		return fmt.Errorf("reconcile Service: %w", err)
	}
	return nil
}

func (r *KubernetesMCPServerReconciler) reconcileDelegatedAuthentication(ctx context.Context, server *mcpv1alpha1.KubernetesMCPServer) error {
	bindingKey := client.ObjectKey{Name: clusterBindingName(server)}
	binding := &rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: bindingKey.Name}}
	serviceAccount := &corev1.ServiceAccount{}
	if err := r.Get(ctx, client.ObjectKey{Namespace: server.Namespace, Name: server.Name}, serviceAccount); err != nil {
		return r.rejectDelegatedAuthentication(ctx, binding, fmt.Errorf("get Server ServiceAccount: %w", err))
	}
	if err := requireControllerOwnership(server, serviceAccount); err != nil {
		return r.rejectDelegatedAuthentication(ctx, binding, fmt.Errorf("validate Server ServiceAccount ownership: %w", err))
	}
	role := &rbacv1.ClusterRole{}
	if err := r.Get(ctx, client.ObjectKey{Name: tokenReviewerClusterRole}, role); err != nil {
		return r.rejectDelegatedAuthentication(ctx, binding, fmt.Errorf("get TokenReview ClusterRole: %w", err))
	}
	if !validTokenReviewerRole(role) {
		return r.rejectDelegatedAuthentication(ctx, binding, fmt.Errorf("ClusterRole %s must grant only authentication.k8s.io tokenreviews.create", tokenReviewerClusterRole))
	}

	expectedRoleRef := rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: tokenReviewerClusterRole}
	if err := r.Get(ctx, bindingKey, binding); err != nil {
		if !apierrors.IsNotFound(err) {
			return r.rejectDelegatedAuthentication(ctx, binding, fmt.Errorf("get TokenReview binding: %w", err))
		}
		binding = &rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: bindingKey.Name}}
	} else if binding.RoleRef != expectedRoleRef {
		if err := r.Delete(ctx, binding); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("remove TokenReview binding with unexpected roleRef: %w", err)
		}
		return fmt.Errorf("removed TokenReview binding with unexpected roleRef; waiting to recreate it safely")
	}

	if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, binding, func() error {
		binding.Labels = server.ServerLabels()
		binding.RoleRef = expectedRoleRef
		binding.Subjects = []rbacv1.Subject{{Kind: "ServiceAccount", Name: server.Name, Namespace: server.Namespace}}
		return nil
	}); err != nil {
		return r.rejectDelegatedAuthentication(ctx, binding, fmt.Errorf("reconcile TokenReview binding: %w", err))
	}
	return nil
}

func (r *KubernetesMCPServerReconciler) rejectDelegatedAuthentication(ctx context.Context, binding *rbacv1.ClusterRoleBinding, cause error) error {
	if err := r.Delete(ctx, binding); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("%w; remove existing TokenReview binding: %v", cause, err)
	}
	return cause
}

func validTokenReviewerRole(role *rbacv1.ClusterRole) bool {
	if role == nil || role.AggregationRule != nil || len(role.Rules) != 1 {
		return false
	}
	rule := role.Rules[0]
	return exactStrings(rule.APIGroups, []string{"authentication.k8s.io"}) &&
		exactStrings(rule.Resources, []string{"tokenreviews"}) &&
		exactStrings(rule.Verbs, []string{"create"}) &&
		len(rule.ResourceNames) == 0 && len(rule.NonResourceURLs) == 0
}

func exactStrings(values, expected []string) bool {
	if len(values) != len(expected) {
		return false
	}
	actual := append([]string(nil), values...)
	wanted := append([]string(nil), expected...)
	slices.Sort(actual)
	slices.Sort(wanted)
	return slices.Equal(actual, wanted)
}

func (r *KubernetesMCPServerReconciler) reconcileDeployment(
	ctx context.Context,
	server *mcpv1alpha1.KubernetesMCPServer,
	labels map[string]string,
	revision string,
	configRevision string,
	tlsRevision string,
) (int64, error) {
	deployment := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: server.Name, Namespace: server.Namespace}}
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, deployment, func() error {
		if err := requireControllerOwnership(server, deployment); err != nil {
			return err
		}
		one := int32(1)
		ten := int32(10)
		sixHundred := int32(600)
		thirty := int64(30)
		falseValue := false
		trueValue := true
		mode := int32(0440)
		nonRoot := int64(65532)
		deployment.Labels = labels
		podLabels := serverPodLabels(labels, revision)
		// Capability signatures and write plans are pod-local in v0.1. Overlapping
		// revisions would make search/read and plan/commit nondeterministic and keep
		// an old policy revision reachable while a restrictive rollout is pending.
		deployment.Spec = appsv1.DeploymentSpec{
			Replicas:                &one,
			Selector:                &metav1.LabelSelector{MatchLabels: labels},
			Strategy:                appsv1.DeploymentStrategy{Type: appsv1.RecreateDeploymentStrategyType},
			RevisionHistoryLimit:    &ten,
			ProgressDeadlineSeconds: &sixHundred,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: podLabels,
					Annotations: map[string]string{
						"mcp.supek8smcp.io/config-hash": configRevision,
						"mcp.supek8smcp.io/tls-hash":    tlsRevision,
					},
				},
				Spec: corev1.PodSpec{
					Volumes: []corev1.Volume{
						{Name: "config", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: server.Name + "-config"}, DefaultMode: &mode}}},
						{Name: "tls", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: server.TLSSecretName(), DefaultMode: &mode}}},
						{Name: "tmp", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
					},
					Containers: []corev1.Container{{
						Name:                     "server",
						Image:                    r.ServerImage,
						ImagePullPolicy:          corev1.PullIfNotPresent,
						Args:                     []string{"serve"},
						Ports:                    []corev1.ContainerPort{{Name: "mcp", ContainerPort: 8443, Protocol: corev1.ProtocolTCP}, {Name: "metrics", ContainerPort: 9090, Protocol: corev1.ProtocolTCP}},
						ReadinessProbe:           serverProbe("/readyz"),
						LivenessProbe:            serverProbe("/healthz"),
						TerminationMessagePath:   "/dev/termination-log",
						TerminationMessagePolicy: corev1.TerminationMessageReadFile,
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
					}},
					RestartPolicy:                 corev1.RestartPolicyAlways,
					TerminationGracePeriodSeconds: &thirty,
					DNSPolicy:                     corev1.DNSClusterFirst,
					ServiceAccountName:            server.Name,
					DeprecatedServiceAccount:      server.Name,
					AutomountServiceAccountToken:  &trueValue,
					SecurityContext: &corev1.PodSecurityContext{
						RunAsNonRoot:   &trueValue,
						RunAsUser:      &nonRoot,
						RunAsGroup:     &nonRoot,
						FSGroup:        &nonRoot,
						SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
					},
					SchedulerName: corev1.DefaultSchedulerName,
				},
			},
		}
		return controllerutil.SetControllerReference(server, deployment, r.Scheme)
	})
	if err != nil {
		return 0, fmt.Errorf("reconcile Deployment: %w", err)
	}
	return deployment.Generation, nil
}

func (r *KubernetesMCPServerReconciler) reconcileNetworkPolicy(ctx context.Context, server *mcpv1alpha1.KubernetesMCPServer, labels map[string]string) error {
	policy := &networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: server.Name, Namespace: server.Namespace}}
	enabled := server.Spec.NetworkPolicy.Enabled == nil || *server.Spec.NetworkPolicy.Enabled
	if !enabled {
		if err := r.Get(ctx, client.ObjectKeyFromObject(policy), policy); apierrors.IsNotFound(err) {
			return nil
		} else if err != nil {
			return fmt.Errorf("get disabled NetworkPolicy: %w", err)
		}
		if err := requireControllerOwnership(server, policy); err != nil {
			return fmt.Errorf("refuse to delete disabled NetworkPolicy: %w", err)
		}
		uid := policy.UID
		if err := r.Delete(ctx, policy, client.Preconditions{UID: &uid}); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("delete disabled NetworkPolicy: %w", err)
		}
		return nil
	}
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, policy, func() error {
		if err := requireControllerOwnership(server, policy); err != nil {
			return err
		}
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
	if gateErr := r.disableServer(ctx, server); gateErr != nil {
		cause = errors.Join(cause, gateErr)
	}
	if r.Logger != nil {
		r.Logger.Error("reconciliation failed", "namespace", server.Namespace, "name", server.Name, "error", cause)
	}
	r.setCondition(server, condition, metav1.ConditionFalse, reason, cause.Error())
	r.setCondition(server, "Ready", metav1.ConditionFalse, reason, cause.Error())
	server.Status.ObservedGeneration = server.Generation
	_ = r.Status().Update(ctx, server)
	return ctrl.Result{}, cause
}

func (r *KubernetesMCPServerReconciler) disableServer(ctx context.Context, server *mcpv1alpha1.KubernetesMCPServer) error {
	var failures []error
	if err := r.reconcileService(ctx, server, server.ServerLabels(), policyRevision(server), disabledServerRevision); err != nil {
		failures = append(failures, fmt.Errorf("disable Server Service: %w", err))
	}
	deployment := &appsv1.Deployment{}
	key := client.ObjectKey{Namespace: server.Namespace, Name: server.Name}
	if err := r.Get(ctx, key, deployment); err != nil {
		if !apierrors.IsNotFound(err) {
			failures = append(failures, fmt.Errorf("get Server Deployment for shutdown: %w", err))
		}
	} else if deployment.Spec.Replicas == nil || *deployment.Spec.Replicas != 0 {
		if err := requireControllerOwnership(server, deployment); err != nil {
			failures = append(failures, fmt.Errorf("refuse to scale unowned Server Deployment: %w", err))
			return errors.Join(failures...)
		}
		before := deployment.DeepCopy()
		zero := int32(0)
		deployment.Spec.Replicas = &zero
		if err := r.Patch(ctx, deployment, client.MergeFrom(before)); err != nil {
			failures = append(failures, fmt.Errorf("scale failed Server Deployment to zero: %w", err))
		}
	}
	return errors.Join(failures...)
}

func (r *KubernetesMCPServerReconciler) setCondition(server *mcpv1alpha1.KubernetesMCPServer, condition string, status metav1.ConditionStatus, reason, message string) {
	api.SetStatusCondition(&server.Status.Conditions, metav1.Condition{
		Type: condition, Status: status, Reason: reason, Message: message, ObservedGeneration: server.Generation,
	})
}

func requireControllerOwnership(server *mcpv1alpha1.KubernetesMCPServer, object client.Object) error {
	if object.GetResourceVersion() == "" && object.GetUID() == "" {
		return nil
	}
	if metav1.IsControlledBy(object, server) {
		return nil
	}
	return fmt.Errorf("resource %s/%s already exists and is not controlled by this KubernetesMCPServer", object.GetNamespace(), object.GetName())
}

func (r *KubernetesMCPServerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&mcpv1alpha1.KubernetesMCPServer{}).
		Owns(&appsv1.Deployment{}).
		Owns(&corev1.Service{}).
		Owns(&corev1.ServiceAccount{}).
		Owns(&corev1.ConfigMap{}).
		Owns(&networkingv1.NetworkPolicy{}).
		Complete(r)
}

func clusterBindingName(server *mcpv1alpha1.KubernetesMCPServer) string {
	sum := sha256.Sum256([]byte(server.Namespace + "/" + server.Name))
	return "supek8smcp-" + hex.EncodeToString(sum[:8])
}

func digestParts(parts ...[]byte) string {
	hash := sha256.New()
	for _, part := range parts {
		hash.Write(part)
		hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func policyRevision(server *mcpv1alpha1.KubernetesMCPServer) string {
	return digestParts([]byte(server.UID), []byte(strconv.FormatInt(server.Generation, 10)))[:16]
}

func serverPodLabels(labels map[string]string, revision string) map[string]string {
	podLabels := maps.Clone(labels)
	podLabels[serverRevisionLabel] = revision
	return podLabels
}

func intstrPtr(value int32) *intstr.IntOrString {
	v := intstr.FromInt32(value)
	return &v
}

func serverProbe(path string) *corev1.Probe {
	return &corev1.Probe{
		ProbeHandler:     corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Path: path, Port: intstr.FromString("metrics"), Scheme: corev1.URISchemeHTTP}},
		TimeoutSeconds:   1,
		PeriodSeconds:    10,
		SuccessThreshold: 1,
		FailureThreshold: 3,
	}
}

func resourceMustParse(value string) resource.Quantity {
	return resource.MustParse(value)
}
