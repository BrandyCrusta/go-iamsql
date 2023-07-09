package iamsql

import (
	"context"
	"fmt"

	"cloud.google.com/go/iam/admin/apiv1/adminpb"
	"cloud.google.com/go/iam/apiv1/iampb"
	"go.einride.tech/aip/resourcename"
	"go.einride.tech/aip/validation"
	"go.einride.tech/iam/iampermission"
	"go.einride.tech/iam/iamresource"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestIamPermissions implements iampb.IAMPolicyServer.
func (s *IAMServer) TestIamPermissions(
	ctx context.Context,
	request *iampb.TestIamPermissionsRequest,
) (*iampb.TestIamPermissionsResponse, error) {
	if err := validateTestIamPermissionsRequest(request); err != nil {
		return nil, err
	}
	caller, err := s.callerResolver.ResolveCaller(ctx)
	if err != nil {
		return nil, err
	}
	permissions := make(map[string]struct{}, len(request.Permissions))
	if err := s.readBindingsByResourcesAndMembers(
		ctx,
		[]string{request.Resource},
		caller.Members,
		func(ctx context.Context, _ string, role *adminpb.Role, _ string) error {
			for _, permission := range request.Permissions {
				if s.roles.RoleHasPermission(role.Name, permission) {
					permissions[permission] = struct{}{}
				}
			}
			return nil
		},
	); err != nil {
		return nil, status.Errorf(codes.Unauthenticated, err.Error())
	}
	response := &iampb.TestIamPermissionsResponse{
		Permissions: make([]string, 0, len(permissions)),
	}
	for _, permission := range request.Permissions {
		if _, ok := permissions[permission]; ok {
			response.Permissions = append(response.Permissions, permission)
		}
	}
	return response, nil
}

func validateTestIamPermissionsRequest(request *iampb.TestIamPermissionsRequest) error {
	var result validation.MessageValidator
	switch request.Resource {
	case iamresource.Root: // OK
	case "":
		result.AddFieldViolation("resource", "missing required field")
	default:
		if err := resourcename.Validate(request.GetResource()); err != nil {
			result.AddFieldError("resource", err)
		}
		if resourcename.ContainsWildcard(request.GetResource()) {
			result.AddFieldViolation("resource", "must not contain wildcard")
		}
	}
	for i, permission := range request.Permissions {
		if err := iampermission.Validate(permission); err != nil {
			result.AddFieldError(fmt.Sprintf("permissions[%d]", i), err)
		}
	}
	return result.Err()
}
