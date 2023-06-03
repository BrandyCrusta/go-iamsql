package iamsql

import (
	"context"

	"cloud.google.com/go/iam/apiv1/iampb"
	"go.einride.tech/aip/resourcename"
	"go.einride.tech/aip/validation"
	"go.einride.tech/iam/iamresource"
	"gorm.io/gorm"
)

// GetIamPolicy implements iampb.IAMPolicyServer.
func (s *IAMServer) GetIamPolicy(
	ctx context.Context,
	request *iampb.GetIamPolicyRequest,
) (*iampb.Policy, error) {
	if err := validateGetIamPolicyRequest(request); err != nil {
		return nil, err
	}

	return s.getIamPolicy(ctx, s.sqlClient, request.Resource)
}

func (s *IAMServer) getIamPolicy(
	ctx context.Context,
	tx *gorm.DB,
	resource string,
) (*iampb.Policy, error) {
	var policy iampb.Policy
	var binding *iampb.Binding

	var policyBindings []PolicyBinding
	if err := s.sqlClient.Where(&PolicyBinding{Resource: resource}).Find(&policyBindings).Error; err != nil {
		return nil, s.handleStorageError(ctx, err)
	}

	for _, policyBinding := range policyBindings {
		if binding == nil || int(policyBinding.BindingIndex) >= len(policy.Bindings) {
			binding = &iampb.Binding{Role: policyBinding.Role}
			policy.Bindings = append(policy.Bindings, binding)
		}
		binding.Members = append(binding.Members, policyBinding.Member)
	}

	etag, err := computeETag(&policy)
	if err != nil {
		return nil, err
	}

	policy.Etag = etag

	return &policy, nil
}

func validateGetIamPolicyRequest(request *iampb.GetIamPolicyRequest) error {
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
	return result.Err()
}
