package iamsql

import (
	"context"

	"cloud.google.com/go/iam/admin/apiv1/adminpb"
	"go.einride.tech/aip/resourcename"
	"go.einride.tech/aip/validation"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *IAMServer) GetRole(
	ctx context.Context,
	request *adminpb.GetRoleRequest,
) (*adminpb.Role, error) {
	var parsedRequest getRoleRequest
	if err := parsedRequest.parse(request); err != nil {
		return nil, err
	}
	return s.getRole(ctx, &parsedRequest)
}

// GetRole implements adminpb.IAMServer.
func (s *IAMServer) getRole(
	_ context.Context,
	request *getRoleRequest,
) (*adminpb.Role, error) {
	role, ok := s.roles.FindRoleByName(request.name)
	if !ok {
		return nil, status.Error(codes.NotFound, "not found")
	}
	return role, nil
}

type getRoleRequest struct {
	name string
}

func (r *getRoleRequest) parse(request *adminpb.GetRoleRequest) error {
	var v validation.MessageValidator
	// name = 1
	switch {
	case request.Name == "":
		v.AddFieldViolation("name", "required field")
	case resourcename.ContainsWildcard(request.Name):
		v.AddFieldViolation("name", "must not contain wildcards")
	case !resourcename.Match("roles/{role}", request.Name):
		v.AddFieldViolation("name", "invalid format")
	default:
		r.name = request.Name
	}
	return v.Err()
}
