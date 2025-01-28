package dataplane

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/gofrs/uuid"
)

var (
	errInvalidAuthHeader = errors.New("could not parse the provided WWW-Authenticate header")
	errInvalidTenantID   = errors.New("the provided tenantID is invalid")
)

// Authenticating with MSI: https://eng.ms/docs/products/arm/rbac/managed_identities/msionboardinginteractionwithmsi .
func newAuthenticatorPolicy(cred azcore.TokenCredential, audience string) policy.Policy {
	return runtime.NewBearerTokenPolicy(cred, nil, &policy.BearerTokenOptions{
		AuthorizationHandler: policy.AuthorizationHandler{
			// Make an unauthenticated request
			OnRequest: func(*policy.Request, func(policy.TokenRequestOptions) error) error {
				return nil
			},
			// Inspect WWW-Authenticate header returned from challenge
			OnChallenge: func(req *policy.Request, resp *http.Response, authenticateAndAuthorize func(policy.TokenRequestOptions) error) error {
				authHeader := resp.Header.Get("WWW-Authenticate")

				// TODO:(skuznets): write a proper parser, https://www.rfc-editor.org/rfc/rfc9110.html#name-www-authenticate
				// Parse the returned challenge
				parts := strings.Split(authHeader, " ")
				vals := map[string]string{}
				for _, part := range parts {
					subParts := strings.Split(part, "=")
					if len(subParts) == 2 {
						stripped := strings.ReplaceAll(subParts[1], "\"", "")
						stripped = strings.TrimSuffix(stripped, ",")
						vals[subParts[0]] = stripped
					}
				}

				u, err := url.Parse(vals["authorization"])
				if err != nil {
					return fmt.Errorf("%w: %w", errInvalidAuthHeader, err)
				}
				tenantID := strings.ToLower(strings.Trim(u.Path, "/"))

				// check if valid tenantId
				if _, err = uuid.FromString(tenantID); err != nil {
					return fmt.Errorf("%w: %w", errInvalidTenantID, err)
				}

				req.Raw().Context()

				// Note: "In api versions prior to 2023-09-30, the audience is included in the bearer challenge, but we recommend that partners
				// rely on hard-configuring the explicit values above for security reasons."

				// Authenticate from tenantID and audience
				return authenticateAndAuthorize(policy.TokenRequestOptions{
					Scopes:   []string{audience + "/.default"},
					TenantID: tenantID,
				})
			},
		},
	})
}

type DynamicAuthenticationEndpointToken interface {
	azcore.TokenCredential

	// Sentinel is a no-op method we declare here to ensure that only
	// dynamic authentication endpoint tokens can be passed to the
	// authenticator policy above.
	Sentinel()
}

type dynamicAuthenticationEndpointToken struct {
	newDelegate func(endpoint string) azcore.TokenCredential
}

var _ DynamicAuthenticationEndpointToken = (*dynamicAuthenticationEndpointToken)(nil)

func (d dynamicAuthenticationEndpointToken) GetToken(ctx context.Context, options interface{}) (interface{}, error) {
	//TODO implement me
	panic("implement me")
}

func (d dynamicAuthenticationEndpointToken) Sentinel() {}

type authEndpointKey int

const (
	// authEndpointContextKey is the context key for an auth endpoint.
	authEndpointContextKey authEndpointKey = iota
)

// withAuthEndpointInContext returns a context with the given shard set.
func withAuthEndpointInContext(parent context.Context, authEndpoint string) context.Context {
	return context.WithValue(parent, authEndpointContextKey, authEndpoint)
}

// authEndpointFromContext returns the value of the shard key on the ctx,
// or an empty Name if there is no shard key.
func authEndpointFromContext(ctx context.Context) string {
	authEndpoint, ok := ctx.Value(authEndpointContextKey).(string)
	if !ok {
		return ""
	}
	return authEndpoint
}

// NewDynamicAuthenticationEndpointToken creates a token credential that can dynamically
func NewDynamicAuthenticationEndpointToken(newDelegate func(endpoint string) azcore.TokenCredential) DynamicAuthenticationEndpointToken {

}
