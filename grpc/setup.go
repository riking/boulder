package grpc

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"net"

	"github.com/letsencrypt/boulder/cmd"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/google.golang.org/grpc"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/google.golang.org/grpc/credentials"
)

// LoadClientCreds loads various TLS certificates and creates a
// gRPC TransportAuthenticator that presents the client certificate
// and validates the certificate presented by the server is for a
// specific hostname and issued by the provided issuer certificate.
func LoadClientCreds(c *cmd.GRPCClientConfig) (credentials.TransportAuthenticator, error) {
	serverIssuerBytes, err := ioutil.ReadFile(c.ServerIssuerPath)
	if err != nil {
		return nil, err
	}
	serverIssuer, err := x509.ParseCertificate(serverIssuerBytes)
	if err != nil {
		return nil, err
	}
	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(serverIssuer)
	clientCert, err := tls.LoadX509KeyPair(c.ClientCertificatePath, c.ClientKeyPath)
	if err != nil {
		return nil, err
	}
	return credentials.NewTLS(&tls.Config{
		ServerName:   c.ServerHostname,
		RootCAs:      rootCAs,
		Certificates: []tls.Certificate{clientCert},
	}), nil
}

// NewServer loads various TLS certificates and creates a
// gRPC Server that verifies the client certificate was
// issued by the provided issuer certificate and presents a
// a server TLS certificate.
func NewServer(c *cmd.GRPCServerConfig) (*grpc.Server, *net.Listener, error) {
	cert, err := tls.LoadX509KeyPair(c.ServerCertificatePath, c.ServerKeyPath)
	if err != nil {
		return nil, nil, err
	}
	clientIssuerBytes, err := ioutil.ReadFile(c.ClientIssuerPath)
	if err != nil {
		return nil, nil, err
	}
	clientIssuer, err := x509.ParseCertificate(clientIssuerBytes)
	if err != nil {
		return nil, nil, err
	}
	clientCAs := x509.NewCertPool()
	clientCAs.AddCert(clientIssuer)

	servConf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
	}
	creds := credentials.NewTLS(servConf)
	l, err := net.Listen("tcp", c.Address)
	if err != nil {
		return nil, nil, err
	}
	return grpc.NewServer(grpc.Creds(creds)), &l, nil
}
