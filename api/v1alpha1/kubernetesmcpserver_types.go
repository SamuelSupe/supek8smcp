package v1alpha1

import (
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +kubebuilder:validation:Enum=ReadOnly;SafeWrite;Dangerous
type AccessMode string

const (
	ModeReadOnly  AccessMode = "ReadOnly"
	ModeSafeWrite AccessMode = "SafeWrite"
	ModeDangerous AccessMode = "Dangerous"
)

// +kubebuilder:validation:Enum=Redact;Deny;Allow
type SensitiveReadPolicy string

const (
	SensitiveReadRedact SensitiveReadPolicy = "Redact"
	SensitiveReadDeny   SensitiveReadPolicy = "Deny"
	SensitiveReadAllow  SensitiveReadPolicy = "Allow"
)

type ScopeSpec struct {
	// +kubebuilder:validation:items:MinLength=1
	Namespaces              []string `json:"namespaces,omitempty"`
	AllowClusterScopedRead  bool     `json:"allowClusterScopedRead,omitempty"`
	AllowClusterScopedWrite bool     `json:"allowClusterScopedWrite,omitempty"`
}

// CapabilityRule is an upper bound applied before Kubernetes authorization.
// Verbs accepts Kubernetes verbs and the logical actions returned by k8s.search.
// An empty rule set selects the conservative defaults for the configured mode.
type CapabilityRule struct {
	// +kubebuilder:validation:MinItems=1
	APIGroups []string `json:"apiGroups"`
	// +kubebuilder:validation:MinItems=1
	Resources []string `json:"resources"`
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:items:Enum=get;list;watch;create;update;patch;delete;logs;scale;restart;apply;exec;attach;*
	Verbs []string `json:"verbs"`
}

type PolicySpec struct {
	Rules []CapabilityRule `json:"rules,omitempty"`
	// +kubebuilder:default:=Redact
	SensitiveReads SensitiveReadPolicy `json:"sensitiveReads,omitempty"`
}

type TLSSpec struct {
	// SecretName references a kubernetes.io/tls Secret. When empty, the
	// operator signs and rotates a serving certificate.
	// +kubebuilder:validation:MinLength=1
	SecretName string `json:"secretName,omitempty"`
}

type LimitsSpec struct {
	// +kubebuilder:default:="30s"
	RequestTimeout metav1.Duration `json:"requestTimeout,omitempty"`
	// +kubebuilder:default:="60s"
	StreamTimeout metav1.Duration `json:"streamTimeout,omitempty"`
	// +kubebuilder:default:="30s"
	ExecTimeout metav1.Duration `json:"execTimeout,omitempty"`
	// +kubebuilder:default:=262144
	// +kubebuilder:validation:Minimum=1024
	// +kubebuilder:validation:Maximum=10485760
	MaxInputBytes int64 `json:"maxInputBytes,omitempty"`
	// +kubebuilder:default:=1048576
	// +kubebuilder:validation:Minimum=1024
	// +kubebuilder:validation:Maximum=52428800
	MaxOutputBytes int64 `json:"maxOutputBytes,omitempty"`
	// +kubebuilder:default:=100
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=1000
	MaxListItems int64 `json:"maxListItems,omitempty"`
	// +kubebuilder:default:=4
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=32
	MaxConcurrent int32 `json:"maxConcurrent,omitempty"`
	// RequestsPerMinute is the sustained MCP HTTP request budget for each
	// authenticated Kubernetes identity within one Server pod.
	// +kubebuilder:default:=120
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=6000
	RequestsPerMinute int32 `json:"requestsPerMinute,omitempty"`
	// Burst is the maximum number of requests an identity may issue at once.
	// +kubebuilder:default:=20
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=1000
	Burst int32 `json:"burst,omitempty"`
}

type NetworkPolicySpec struct {
	// +kubebuilder:default:=true
	Enabled                  *bool                 `json:"enabled,omitempty"`
	AllowedNamespaceSelector *metav1.LabelSelector `json:"allowedNamespaceSelector,omitempty"`
	AllowedPodSelector       *metav1.LabelSelector `json:"allowedPodSelector,omitempty"`
}

type KubernetesMCPServerSpec struct {
	// +kubebuilder:default:=ReadOnly
	Mode AccessMode `json:"mode,omitempty"`
	// +kubebuilder:default:={}
	Scope ScopeSpec `json:"scope,omitempty"`
	// +kubebuilder:default:={}
	Policy PolicySpec `json:"policy,omitempty"`
	// +kubebuilder:default:={}
	TLS TLSSpec `json:"tls,omitempty"`
	// +kubebuilder:default:={}
	Limits LimitsSpec `json:"limits,omitempty"`
	// +kubebuilder:default:={}
	NetworkPolicy NetworkPolicySpec `json:"networkPolicy,omitempty"`
}

type KubernetesMCPServerStatus struct {
	ObservedGeneration int64              `json:"observedGeneration,omitempty"`
	Endpoint           string             `json:"endpoint,omitempty"`
	CAConfigMapName    string             `json:"caConfigMapName,omitempty"`
	Conditions         []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=kmcp
// +kubebuilder:printcolumn:name="Mode",type=string,JSONPath=`.spec.mode`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Endpoint",type=string,JSONPath=`.status.endpoint`
// +kubebuilder:validation:XValidation:rule="size(self.metadata.name) <= 63 && self.metadata.name.matches('^[a-z]([-a-z0-9]*[a-z0-9])?$')",message="metadata.name must be a DNS service label with at most 63 characters"
// +kubebuilder:validation:XValidation:rule="!has(self.spec.scope) || !has(self.spec.scope.allowClusterScopedWrite) || !self.spec.scope.allowClusterScopedWrite || self.spec.mode == 'Dangerous'",message="cluster-scoped writes require Dangerous mode"
// +kubebuilder:validation:XValidation:rule="!has(self.spec.limits) || !has(self.spec.limits.requestTimeout) || duration(self.spec.limits.requestTimeout) > duration('0s')",message="requestTimeout must be a positive Kubernetes duration"
// +kubebuilder:validation:XValidation:rule="!has(self.spec.limits) || !has(self.spec.limits.streamTimeout) || duration(self.spec.limits.streamTimeout) > duration('0s')",message="streamTimeout must be a positive Kubernetes duration"
// +kubebuilder:validation:XValidation:rule="!has(self.spec.limits) || !has(self.spec.limits.execTimeout) || duration(self.spec.limits.execTimeout) > duration('0s')",message="execTimeout must be a positive Kubernetes duration"
type KubernetesMCPServer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   KubernetesMCPServerSpec   `json:"spec,omitempty"`
	Status KubernetesMCPServerStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
type KubernetesMCPServerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []KubernetesMCPServer `json:"items"`
}

func (s *KubernetesMCPServer) Default() {
	if s.Spec.Mode == "" {
		s.Spec.Mode = ModeReadOnly
	}
	if len(s.Spec.Scope.Namespaces) == 0 {
		s.Spec.Scope.Namespaces = []string{s.Namespace}
	}
	if s.Spec.Policy.SensitiveReads == "" {
		s.Spec.Policy.SensitiveReads = SensitiveReadRedact
	}
	if s.Spec.Limits.RequestTimeout.Duration == 0 {
		s.Spec.Limits.RequestTimeout.Duration = 30 * time.Second
	}
	if s.Spec.Limits.StreamTimeout.Duration == 0 {
		s.Spec.Limits.StreamTimeout.Duration = 60 * time.Second
	}
	if s.Spec.Limits.ExecTimeout.Duration == 0 {
		s.Spec.Limits.ExecTimeout.Duration = 30 * time.Second
	}
	if s.Spec.Limits.MaxInputBytes == 0 {
		s.Spec.Limits.MaxInputBytes = 256 << 10
	}
	if s.Spec.Limits.MaxOutputBytes == 0 {
		s.Spec.Limits.MaxOutputBytes = 1 << 20
	}
	if s.Spec.Limits.MaxListItems == 0 {
		s.Spec.Limits.MaxListItems = 100
	}
	if s.Spec.Limits.MaxConcurrent == 0 {
		s.Spec.Limits.MaxConcurrent = 4
	}
	if s.Spec.Limits.RequestsPerMinute == 0 {
		s.Spec.Limits.RequestsPerMinute = 120
	}
	if s.Spec.Limits.Burst == 0 {
		s.Spec.Limits.Burst = 20
	}
	if s.Spec.NetworkPolicy.Enabled == nil {
		enabled := true
		s.Spec.NetworkPolicy.Enabled = &enabled
	}
}

func (s *KubernetesMCPServer) TLSSecretName() string {
	if s.Spec.TLS.SecretName != "" {
		return s.Spec.TLS.SecretName
	}
	return s.Name + "-tls"
}

func (s *KubernetesMCPServer) ServerLabels() map[string]string {
	return map[string]string{
		"app.kubernetes.io/name":       "supek8smcp-server",
		"app.kubernetes.io/instance":   s.Name,
		"app.kubernetes.io/managed-by": "supek8smcp-operator",
	}
}
