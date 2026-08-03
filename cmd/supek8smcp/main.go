package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/samuelsupe/supek8smcp/internal/operator"
	mcpserver "github.com/samuelsupe/supek8smcp/internal/server"
)

var version = "0.3.0"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	var err error
	switch os.Args[1] {
	case "operator":
		fs := flag.NewFlagSet("operator", flag.ExitOnError)
		serverImage := fs.String("server-image", os.Getenv("SUPEK8SMCP_SERVER_IMAGE"), "container image used for MCP server instances")
		operatorNamespace := fs.String("namespace", envOr("POD_NAMESPACE", "supek8smcp-system"), "namespace containing the operator CA")
		metricsAddr := fs.String("metrics-bind-address", ":8080", "operator metrics address")
		healthAddr := fs.String("health-probe-bind-address", ":8081", "operator health address")
		leaderElect := fs.Bool("leader-elect", true, "enable leader election")
		_ = fs.Parse(os.Args[2:])
		if *serverImage == "" {
			err = fmt.Errorf("--server-image or SUPEK8SMCP_SERVER_IMAGE is required")
			break
		}
		err = operator.Run(ctx, operator.Options{
			ServerImage:       *serverImage,
			OperatorNamespace: *operatorNamespace,
			MetricsAddress:    *metricsAddr,
			HealthAddress:     *healthAddr,
			LeaderElection:    *leaderElect,
			Logger:            logger,
		})
	case "serve":
		fs := flag.NewFlagSet("serve", flag.ExitOnError)
		configPath := fs.String("config", "/etc/supek8smcp/config/config.json", "server configuration file")
		listenAddr := fs.String("listen", ":8443", "HTTPS listen address")
		metricsAddr := fs.String("metrics-listen", ":9090", "metrics and health listen address")
		certFile := fs.String("tls-cert", "/etc/supek8smcp/tls/tls.crt", "TLS certificate")
		keyFile := fs.String("tls-key", "/etc/supek8smcp/tls/tls.key", "TLS private key")
		_ = fs.Parse(os.Args[2:])
		err = mcpserver.Run(ctx, mcpserver.Options{
			ConfigPath:     *configPath,
			ListenAddress:  *listenAddr,
			MetricsAddress: *metricsAddr,
			CertFile:       *certFile,
			KeyFile:        *keyFile,
			Version:        version,
			Logger:         logger,
		})
	case "version":
		fmt.Println(version)
		return
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		logger.Error("command failed", "command", os.Args[1], "error", err)
		os.Exit(1)
	}
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: supek8smcp <operator|serve|version> [flags]")
}
