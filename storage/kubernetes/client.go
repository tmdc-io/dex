package kubernetes

import (
	"context"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Masterminds/semver"
	"github.com/dexidp/dex/storage"
	"github.com/ghodss/yaml"
	"hash"
	"hash/fnv"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
)

const (
	serviceAccountPath          = "/var/run/secrets/kubernetes.io/serviceaccount/"
	serviceAccountTokenPath     = serviceAccountPath + "token"
	serviceAccountCAPath        = serviceAccountPath + "ca.crt"
	serviceAccountNamespacePath = serviceAccountPath + "namespace"

	kubernetesServiceHostENV  = "KUBERNETES_SERVICE_HOST"
	kubernetesServicePortENV  = "KUBERNETES_SERVICE_PORT"
	kubernetesPodNamespaceENV = "KUBERNETES_POD_NAMESPACE"
)

type Cluster struct {
	Server                   string `json:"server"`
	APIVersion               string `json:"api-version,omitempty"`
	InsecureSkipTLSVerify    bool   `json:"insecure-skip-tls-verify,omitempty"`
	CertificateAuthority     string `json:"certificate-authority,omitempty"`
	CertificateAuthorityData string `json:"certificate-authority-data,omitempty"`
}

type AuthInfo struct {
	ClientCertificate     string `json:"client-certificate,omitempty"`
	ClientCertificateData string `json:"client-certificate-data,omitempty"`
	ClientKey             string `json:"client-key,omitempty"`
	ClientKeyData         string `json:"client-key-data,omitempty"`
	Token                 string `json:"token,omitempty"`
	Username              string `json:"username,omitempty"`
	Password              string `json:"password,omitempty"`
}

type ConfigK8s struct {
	Clusters       []NamedCluster  `json:"clusters"`
	AuthInfos      []NamedAuthInfo `json:"users"`
	Contexts       []NamedContext  `json:"contexts"`
	CurrentContext string          `json:"current-context"`
}

type NamedCluster struct {
	Name    string  `json:"name"`
	Cluster Cluster `json:"cluster"`
}

type NamedAuthInfo struct {
	Name     string   `json:"name"`
	AuthInfo AuthInfo `json:"user"`
}

type NamedContext struct {
	Name    string  `json:"name"`
	Context Context `json:"context"`
}

type Context struct {
	Cluster   string `json:"cluster"`
	AuthInfo  string `json:"user"`
	Namespace string `json:"namespace,omitempty"`
}

type client struct {
	client    kubernetes.Interface
	dynamic   dynamic.Interface
	namespace string
	logger    *slog.Logger

	// Hash function to map IDs (which could span a large range) to Kubernetes names.
	hash func() hash.Hash

	// API version of the oidc resources. For example "oidc.coreos.com".
	apiVersion string
	// API version of the custom resource definitions.
	crdAPIVersion string

	// CRD handling behavior controls how missing Custom Resource Definitions are handled.
	crdHandling string

	ctx    context.Context
	cancel context.CancelFunc
}

func (cli *client) idToName(s string) string {
	return idToName(s, cli.hash)
}

// offlineTokenName maps two arbitrary IDs, to a single Kubernetes object name.
// This is used when more than one field is used to uniquely identify the object.
func (cli *client) offlineTokenName(userID string, connID string) string {
	return offlineTokenName(userID, connID, cli.hash)
}

// Kubernetes names must match the regexp '[a-z0-9]([-a-z0-9]*[a-z0-9])?'.
var encoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567")

func idToName(s string, h func() hash.Hash) string {
	return strings.TrimRight(encoding.EncodeToString(h().Sum([]byte(s))), "=")
}

func offlineTokenName(userID string, connID string, hFn func() hash.Hash) string {
	h := hFn()
	h.Write([]byte(userID))
	h.Write([]byte(connID))
	return strings.TrimRight(encoding.EncodeToString(h.Sum(nil)), "=")
}

func (cli *client) get(ctx context.Context, resource, name string, v any) error {
	return cli.getResource(ctx, cli.apiVersion, cli.namespace, resource, name, v)
}

func (cli *client) getResource(ctx context.Context, apiVersion, namespace, resource, name string, v any) error {
	gv, err := schema.ParseGroupVersion(apiVersion)
	if err != nil {
		return err
	}
	resourceInterface := cli.dynamic.Resource(gv.WithResource(resource)).Namespace(namespace)
	u, err := resourceInterface.Get(ctx, name, v1.GetOptions{})
	if err != nil {
		if isNotFound(err) {
			return storage.ErrNotFound
		}
		return err
	}
	raw, err := u.MarshalJSON()
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, v)
}

func (cli *client) listN(ctx context.Context, resource string, v any, n int) error {
	gv, err := schema.ParseGroupVersion(cli.apiVersion)
	if err != nil {
		return err
	}
	resourceInterface := cli.dynamic.Resource(gv.WithResource(resource)).Namespace(cli.namespace)
	unstructuredList, err := resourceInterface.List(ctx, v1.ListOptions{Limit: int64(n)})
	if err != nil {
		return err
	}
	raw, err := unstructuredList.MarshalJSON()
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, v)
}

func (cli *client) list(ctx context.Context, resource string, v any) error {
	return cli.listN(ctx, resource, v, 0)
}

func (cli *client) post(ctx context.Context, resource string, v any) error {
	return cli.postResource(ctx, cli.apiVersion, cli.namespace, resource, v)
}

func (cli *client) postResource(ctx context.Context, apiVersion, namespace, resource string, v any) error {
	gv, err := schema.ParseGroupVersion(apiVersion)
	if err != nil {
		return err
	}

	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	var obj unstructured.Unstructured
	if err := json.Unmarshal(raw, &obj); err != nil {
		return err
	}

	resourceInterface := cli.dynamic.Resource(gv.WithResource(resource)).Namespace(namespace)
	_, err = resourceInterface.Create(ctx, &obj, v1.CreateOptions{})
	if err != nil {
		if isAlreadyExists(err) {
			return storage.ErrAlreadyExists
		}
		return err
	}
	return nil
}

func (cli *client) detectKubernetesVersion() error {
	version, err := cli.client.Discovery().ServerVersion()
	if err != nil {
		return err
	}

	clusterVersion, err := semver.NewVersion(version.GitVersion)
	if err != nil {
		cli.logger.Warn("cannot detect Kubernetes version", "version", version.GitVersion, "err", err)
		return nil
	}

	if clusterVersion.LessThan(semver.MustParse("v1.16.0")) {
		cli.crdAPIVersion = legacyCRDAPIVersion
	}

	return nil
}

func (cli *client) delete(ctx context.Context, resource, name string) error {
	gv, err := schema.ParseGroupVersion(cli.apiVersion)
	if err != nil {
		return err
	}
	resourceInterface := cli.dynamic.Resource(gv.WithResource(resource)).Namespace(cli.namespace)
	err = resourceInterface.Delete(ctx, name, v1.DeleteOptions{})
	if err != nil {
		if isNotFound(err) {
			return storage.ErrNotFound
		}
		return err
	}
	return nil
}

func (cli *client) deleteAll(resource string) error {
	gv, err := schema.ParseGroupVersion(cli.apiVersion)
	if err != nil {
		return err
	}
	resourceInterface := cli.dynamic.Resource(gv.WithResource(resource)).Namespace(cli.namespace)
	return resourceInterface.DeleteCollection(cli.ctx, v1.DeleteOptions{}, v1.ListOptions{})
}

func (cli *client) put(ctx context.Context, resource, name string, v any) error {
	gv, err := schema.ParseGroupVersion(cli.apiVersion)
	if err != nil {
		return err
	}

	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	var obj unstructured.Unstructured
	if err := json.Unmarshal(raw, &obj); err != nil {
		return err
	}

	resourceInterface := cli.dynamic.Resource(gv.WithResource(resource)).Namespace(cli.namespace)
	_, err = resourceInterface.Update(ctx, &obj, v1.UpdateOptions{})
	if err != nil {
		if isNotFound(err) {
			return storage.ErrNotFound
		}
		return err
	}
	return nil
}

func isNotFound(err error) bool {
	if statusErr, ok := errors.AsType[*k8serrors.StatusError](err); ok {
		return statusErr.ErrStatus.Code == http.StatusNotFound
	}
	return false
}

func isAlreadyExists(err error) bool {
	if statusErr, ok := errors.AsType[*k8serrors.StatusError](err); ok {
		return statusErr.ErrStatus.Code == http.StatusConflict || statusErr.ErrStatus.Reason == v1.StatusReasonAlreadyExists
	}
	return false
}

func newClient(
	cluster Cluster,
	user AuthInfo,
	namespace string,
	logger *slog.Logger,
	inCluster bool,
	crdHandling string,
	qps float32,
	burst int,
) (*client, error) {
	var config *rest.Config
	var err error

	if inCluster {
		config, err = rest.InClusterConfig()
		if err != nil {
			return nil, err
		}
	} else {
		config = &rest.Config{
			Host: cluster.Server,
			TLSClientConfig: rest.TLSClientConfig{
				Insecure: cluster.InsecureSkipTLSVerify,
			},
		}

		if cluster.CertificateAuthorityData != "" {
			caData, err := base64.StdEncoding.DecodeString(cluster.CertificateAuthorityData)
			if err != nil {
				return nil, fmt.Errorf("decode ca data: %v", err)
			}
			config.TLSClientConfig.CAData = caData
		} else if cluster.CertificateAuthority != "" {
			config.TLSClientConfig.CAFile = cluster.CertificateAuthority
		}

		if user.Token != "" {
			config.BearerToken = user.Token
		}

		if user.Username != "" && user.Password != "" {
			config.Username = user.Username
			config.Password = user.Password
		}

		if user.ClientCertificateData != "" {
			certData, err := base64.StdEncoding.DecodeString(user.ClientCertificateData)
			if err != nil {
				return nil, fmt.Errorf("decode client cert data: %v", err)
			}
			config.TLSClientConfig.CertData = certData
		} else if user.ClientCertificate != "" {
			config.TLSClientConfig.CertFile = user.ClientCertificate
		}

		if user.ClientKeyData != "" {
			keyData, err := base64.StdEncoding.DecodeString(user.ClientKeyData)
			if err != nil {
				return nil, fmt.Errorf("decode client key data: %v", err)
			}
			config.TLSClientConfig.KeyData = keyData
		} else if user.ClientKey != "" {
			config.TLSClientConfig.KeyFile = user.ClientKey
		}
	}

	config.QPS = qps
	config.Burst = burst

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("create kubernetes clientset: %v", err)
	}

	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("create dynamic client: %v", err)
	}

	apiVersion := "dex.coreos.com/v1"

	logger.Info("kubernetes client", "api_version", apiVersion)
	return &client{
		client:        clientset,
		dynamic:       dynamicClient,
		hash:          func() hash.Hash { return fnv.New64() },
		namespace:     namespace,
		apiVersion:    apiVersion,
		crdAPIVersion: crdAPIVersion,
		crdHandling:   crdHandling,
		logger:        logger,
	}, nil
}

func loadKubeConfig(kubeConfigPath string) (cluster Cluster, user AuthInfo, namespace string, err error) {
	data, err := os.ReadFile(kubeConfigPath)
	if err != nil {
		err = fmt.Errorf("read %s: %v", kubeConfigPath, err)
		return
	}

	var c ConfigK8s
	if err = yaml.Unmarshal(data, &c); err != nil {
		err = fmt.Errorf("unmarshal %s: %v", kubeConfigPath, err)
		return
	}

	cluster, user, namespace, err = currentContext(&c)
	if namespace == "" {
		namespace = "default"
	}
	return
}

func namespaceFromServiceAccountJWT(s string) (string, error) {
	// The service account token is just a JWT. Parse it as such.
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		// It's extremely important we don't log the actual service account token.
		return "", fmt.Errorf("malformed service account token: expected 3 parts got %d", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("malformed service account token: %v", err)
	}
	var data struct {
		// The claim Kubernetes uses to identify which namespace a service account belongs to.
		//
		// See: https://github.com/kubernetes/kubernetes/blob/v1.4.3/pkg/serviceaccount/jwt.go#L42
		Namespace string `json:"kubernetes.io/serviceaccount/namespace"`
	}
	if err := json.Unmarshal(payload, &data); err != nil {
		return "", fmt.Errorf("malformed service account token: %v", err)
	}
	if data.Namespace == "" {
		return "", errors.New(`jwt claim "kubernetes.io/serviceaccount/namespace" not found`)
	}
	return data.Namespace, nil
}

func namespaceFromFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}

	return string(data), nil
}

func getInClusterConfigNamespace(token, namespaceENV, namespacePath string) (string, error) {
	namespace := os.Getenv(namespaceENV)
	if namespace != "" {
		return namespace, nil
	}

	namespace, err := namespaceFromServiceAccountJWT(token)
	if err == nil {
		return namespace, nil
	}

	err = fmt.Errorf("inspect service account token: %v", err)
	namespace, fileErr := namespaceFromFile(namespacePath)
	if fileErr == nil {
		return namespace, nil
	}

	return "", fmt.Errorf("%v: trying to get namespace from file: %v", err, fileErr)
}

func getInClusterConnectOptions(host, port string) (Cluster, error) {
	if len(host) == 0 || len(port) == 0 {
		return Cluster{}, fmt.Errorf(
			"unable to load in-cluster configuration, %s and %s must be defined",
			kubernetesServiceHostENV,
			kubernetesServicePortENV,
		)
	}

	cluster := Cluster{
		Server:               "https://" + net.JoinHostPort(host, port),
		CertificateAuthority: serviceAccountCAPath,
	}
	return cluster, nil
}

func inClusterConfig() (cluster Cluster, user AuthInfo, namespace string, err error) {
	cluster, err = getInClusterConnectOptions(os.Getenv(kubernetesServiceHostENV), os.Getenv(kubernetesServicePortENV))
	if err != nil {
		return cluster, AuthInfo{}, "", err
	}

	token, err := os.ReadFile(serviceAccountTokenPath)
	if err != nil {
		return cluster, AuthInfo{}, "", err
	}

	user = AuthInfo{Token: string(token)}

	namespace, err = getInClusterConfigNamespace(user.Token, kubernetesPodNamespaceENV, serviceAccountNamespacePath)
	if err != nil {
		return cluster, user, "", err
	}

	return cluster, user, namespace, nil
}

func currentContext(config *ConfigK8s) (cluster Cluster, user AuthInfo, ns string, err error) {
	if config.CurrentContext == "" {
		if len(config.Contexts) == 1 {
			config.CurrentContext = config.Contexts[0].Name
		} else {
			return cluster, user, "", errors.New("kubeconfig has no current context")
		}
	}
	k8sContext, ok := func() (Context, bool) {
		for _, namedContext := range config.Contexts {
			if namedContext.Name == config.CurrentContext {
				return namedContext.Context, true
			}
		}
		return Context{}, false
	}()
	if !ok {
		return cluster, user, "", fmt.Errorf("no context named %q found", config.CurrentContext)
	}

	cluster, ok = func() (Cluster, bool) {
		for _, namedCluster := range config.Clusters {
			if namedCluster.Name == k8sContext.Cluster {
				return namedCluster.Cluster, true
			}
		}
		return Cluster{}, false
	}()
	if !ok {
		return cluster, user, "", fmt.Errorf("no cluster named %q found", k8sContext.Cluster)
	}

	user, ok = func() (AuthInfo, bool) {
		for _, namedAuthInfo := range config.AuthInfos {
			if namedAuthInfo.Name == k8sContext.AuthInfo {
				return namedAuthInfo.AuthInfo, true
			}
		}
		return AuthInfo{}, false
	}()
	if !ok {
		return cluster, user, "", fmt.Errorf("no user named %q found", k8sContext.AuthInfo)
	}
	return cluster, user, k8sContext.Namespace, nil
}
