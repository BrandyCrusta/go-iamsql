package iamsql

import (
	"bytes"
	"context"
	"fmt"

	"cloud.google.com/go/iam/apiv1/iampb"
	"go.einride.tech/aip/resourcename"
	"go.einride.tech/aip/validation"
	"go.einride.tech/iam/iamresource"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"
)

// SetIamPolicy implements iampb.IAMPolicyServer.
func (s *IAMServer) SetIamPolicy(
	ctx context.Context,
	request *iampb.SetIamPolicyRequest,
) (*iampb.Policy, error) {

	if err := s.validateSetIamPolicyRequest(request); err != nil {
		return nil, err
	}

	return s.setIamPolicy(ctx, request)
}

func (s *IAMServer) setIamPolicy(
	ctx context.Context,
	request *iampb.SetIamPolicyRequest,
) (*iampb.Policy, error) {
	if err := s.validateSetIamPolicyRequest(request); err != nil {
		return nil, err
	}

	tx := s.sqlClient.Begin()
	if ok, err := s.validatePolicyFreshnessInTransaction(
		ctx, tx, request.GetResource(), request.GetPolicy().GetEtag(),
	); err != nil {
		tx.Rollback()
		return nil, err
	} else if !ok {
		tx.Rollback()
		return nil, status.Error(codes.Aborted, "resource freshness validation failed")
	}

	policyBindings := []*PolicyBinding{}
	for i, binding := range request.Policy.GetBindings() {
		for j, member := range binding.Members {
			policyBindings = append(policyBindings, &PolicyBinding{
				Resource:     request.Resource,
				BindingIndex: int64(i),
				Role:         binding.Role,
				MemberIndex:  int64(j),
				Member:       member,
			})
		}
	}

	if err := tx.Create(policyBindings).Error; err != nil {
		tx.Rollback()
		return nil, s.handleStorageError(ctx, err)
	}

	if err := tx.Commit().Error; err != nil {
		tx.Rollback()
		return nil, err
	}

	request.Policy.Etag = nil
	etag, err := computeETag(request.Policy)
	if err != nil {
		return nil, err
	}

	request.Policy.Etag = etag
	return request.Policy, nil
}

func (s *IAMServer) validatePolicyFreshnessInTransaction(
	ctx context.Context,
	tx *gorm.DB,
	resource string,
	etag []byte,
) (bool, error) {
	if len(etag) == 0 {
		return true, nil
	}
	existingPolicy, err := s.getIamPolicy(ctx, tx, resource)
	if err != nil {
		return false, fmt.Errorf("validate freshness: %w", err)
	}
	return bytes.Equal(existingPolicy.Etag, etag), nil
}

func (s *IAMServer) validateSetIamPolicyRequest(request *iampb.SetIamPolicyRequest) error {
	var result validation.MessageValidator
	switch request.Resource {
	case iamresource.Root: // OK
	case "":
		result.AddFieldViolation("resource", "missing required field")
	default:
		if err := resourcename.Validate(request.GetResource()); err != nil {
			result.AddFieldError("resource", err)
		} else if resourcename.ContainsWildcard(request.GetResource()) {
			result.AddFieldViolation("resource", "must not contain wildcard")
		}
	}

	roleSet := map[string]bool{}
	for i, binding := range request.GetPolicy().GetBindings() {
		if binding.GetRole() == "" {
			result.AddFieldViolation(fmt.Sprintf("policy.bindings[%d].role", i), "missing required field")
		}
		if _, ok := s.roles.FindRoleByName(binding.GetRole()); !ok {
			result.AddFieldViolation(
				fmt.Sprintf("policy.bindings[%d].role", i),
				"unknown role: '%s'",
				binding.GetRole(),
			)
		}
		_, ok := roleSet[binding.GetRole()]
		if ok {
			result.AddFieldViolation(
				fmt.Sprintf("policy.bindings[%d].role", i),
				"duplicate role: '%s'",
				binding.GetRole(),
			)
		}
		roleSet[binding.GetRole()] = true

		if len(binding.Members) == 0 {
			result.AddFieldViolation(fmt.Sprintf("policy.bindings[%d].members", i), "missing required field")
		}
		memberSet := map[string]bool{}
		for j, member := range binding.Members {
			if err := s.validateMember(member); err != nil {
				result.AddFieldError(fmt.Sprintf("policy.bindings[%d].members[%d]", i, j), err)
			}
			_, ok := memberSet[member]
			if ok {
				// duplicate member
				result.AddFieldViolation(fmt.Sprintf("policy.bindings[%d].members[%d]", i, j), "duplicate member")
			}
			memberSet[member] = true
		}
	}
	return result.Err()
}
