package kubernetes

import (
	"github.com/stretchr/testify/suite"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dexidp/dex/storage"
	"github.com/dexidp/dex/storage/conformance"
)

const kubeconfigPathVariableName = "DEX_KUBERNETES_CONFIG_PATH"

func TestStorage(t *testing.T) {
	if os.Getenv(kubeconfigPathVariableName) == "" {
		t.Skipf("variable %q not set, skipping kubernetes storage tests\n", kubeconfigPathVariableName)
	}

	suite.Run(t, new(StorageTestSuite))
}

type StorageTestSuite struct {
	suite.Suite
	client *client
}

func expandDir(dir string) (string, error) {
	dir = strings.Trim(dir, `"`)
	if strings.HasPrefix(dir, "~/") {
		homedir, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}

		dir = filepath.Join(homedir, strings.TrimPrefix(dir, "~/"))
	}
	return dir, nil
}

func (s *StorageTestSuite) SetupTest() {
	kubeconfigPath, err := expandDir(os.Getenv(kubeconfigPathVariableName))
	s.Require().NoError(err)

	config := Config{
		KubeConfigFile: kubeconfigPath,
	}

	logger := slog.New(slog.NewTextHandler(s.T().Output(), &slog.HandlerOptions{Level: slog.LevelDebug}))

	kubeClient, err := config.open(logger, true)
	s.Require().NoError(err)

	s.client = kubeClient
}

func (s *StorageTestSuite) TestStorage() {
	newStorage := func(t *testing.T) storage.Storage {
		for _, resource := range []string{
			resourceAuthCode,
			resourceAuthRequest,
			resourceDeviceRequest,
			resourceDeviceToken,
			resourceClient,
			resourceRefreshToken,
			resourceKeys,
			resourcePassword,
		} {
			if err := s.client.deleteAll(resource); err != nil {
				s.T().Fatalf("delete all %q failed: %v", resource, err)
			}
		}
		return s.client
	}

	conformance.RunTests(s.T(), newStorage)
	conformance.RunConcurrencyTests(s.T(), newStorage)
	conformance.RunTransactionTests(s.T(), newStorage)
}

func TestUpdateKeys(t *testing.T) {
	t.Skip("UpdateKeys test requires a real or fake dynamic client")
}

func newStatusCodesResponseTestClient(getResponseCode, actionResponseCode int) *client {
	return &client{
		logger: slog.New(slog.DiscardHandler),
	}
}

func TestRetryOnConflict(t *testing.T) {
	t.Skip("RetryOnConflict test requires a real or fake dynamic client")
}

func TestRefreshTokenLock(t *testing.T) {
	t.Skip("RefreshTokenLock test requires a real or fake dynamic client")
}
