package iamsql

import (
	"context"
	"fmt"

	"cloud.google.com/go/iam/admin/apiv1/adminpb"
	"go.einride.tech/aip/resourcename"
	"go.einride.tech/iam/iamresource"
)

func (s *IAMServer) readBindingsByResourcesAndMembers(
	ctx context.Context,
	resources []string,
	members []string,
	fn func(ctx context.Context, resource string, role *adminpb.Role, member string) error,
) error {
	if len(members) == 0 {
		return fmt.Errorf("Request missing members")
	}
	// Deduplicate resources and parents to read.
	resourcesAndParents := make(map[string]struct{}, len(resources))
	// Include root resource.
	resourcesAndParents[iamresource.Root] = struct{}{}
	for _, resource := range resources {
		if resource == iamresource.Root {
			continue
		}
		if !resourcename.ContainsWildcard(resource) {
			resourcesAndParents[resource] = struct{}{}
		}
		resourcename.RangeParents(resource, func(parent string) bool {
			if !resourcename.ContainsWildcard(parent) {
				resourcesAndParents[parent] = struct{}{}
			}
			return true
		})
	}

	query := s.sqlClient.Model(&PolicyBinding{})

	for resource := range resourcesAndParents {
		for _, member := range members {
			query = query.Or(&PolicyBinding{Member: member, Resource: resource})
		}
	}

	policyBindingsResult := []*PolicyBinding{}

	if err := query.Find(&policyBindingsResult).Error; err != nil {
		s.handleStorageError(ctx, err)
	}

	for _, policyBinding := range policyBindingsResult {
		role, ok := s.roles.FindRoleByName(policyBinding.Role)
		if !ok {
			s.logError(ctx, fmt.Errorf("missing built-in role: %s", policyBinding.Role))
			return nil
		}

		if err := fn(ctx, policyBinding.Resource, role, policyBinding.Member); err != nil {
			return err
		}
	}

	return nil
}
