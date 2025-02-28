package armauthorization

// Copyright (c) Microsoft Corporation.
// Licensed under the Apache License 2.0.

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v3"
)

type RoleDefinitionsClient interface {
	GetByID(ctx context.Context, roleID string, options *armauthorization.RoleDefinitionsClientGetByIDOptions) (armauthorization.RoleDefinitionsClientGetByIDResponse, error)
}

type ArmRoleDefinitionsClient struct {
	*armauthorization.RoleDefinitionsClient
}

var _ RoleDefinitionsClient = &ArmRoleDefinitionsClient{}

func NewArmRoleDefinitionsClient(credential azcore.TokenCredential, options *arm.ClientOptions) (*ArmRoleDefinitionsClient, error) {
	client, err := armauthorization.NewRoleDefinitionsClient(credential, options)
	return &ArmRoleDefinitionsClient{
		RoleDefinitionsClient: client,
	}, err
}
