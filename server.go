package iamsql

import (
	"context"
	"errors"
	"fmt"
	"hash/crc32"

	"cloud.google.com/go/iam/admin/apiv1/adminpb"
	"cloud.google.com/go/iam/apiv1/iampb"
	"go.einride.tech/iam/iamcaller"
	"go.einride.tech/iam/iammember"
	"go.einride.tech/iam/iamregistry"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"gorm.io/gorm"
)

type IAMServer struct {
	iampb.UnimplementedIAMPolicyServer
	adminpb.UnimplementedIAMServer
	sqlClient      *gorm.DB
	roles          *iamregistry.Roles
	callerResolver iamcaller.Resolver
	config         ServerConfig
}

// ServerConfig configures a Spanner IAM policy server.
type ServerConfig struct {
	// ErrorHook is called when errors occur in the IAMServer.
	ErrorHook func(context.Context, error)
	// ValidateMember is a custom IAM member validator.
	// When not provided, iammember.Validate will be used.
	ValidateMember func(string) error
}

func NewIAMServer(
	sqlClient *gorm.DB,
	roles []*adminpb.Role,
	callerResolver iamcaller.Resolver,
	config ServerConfig,
) (*IAMServer, error) {
	roleRegistry, err := iamregistry.NewRoles(roles...)
	if err != nil {
		return nil, fmt.Errorf("new IAM server: %w", err)
	}

	s := &IAMServer{
		sqlClient:      sqlClient,
		config:         config,
		roles:          roleRegistry,
		callerResolver: callerResolver,
	}

	return s, nil
}

func (s *IAMServer) validateMember(member string) error {
	if s.config.ValidateMember != nil {
		return s.config.ValidateMember(member)
	}
	return iammember.Validate(member)
}

func (s *IAMServer) logError(ctx context.Context, err error) {
	if s.config.ErrorHook != nil {
		s.config.ErrorHook(ctx, err)
	}
}

func (s *IAMServer) handleStorageError(ctx context.Context, err error) error {
	s.logError(ctx, err)
	if gormErr := errors.Unwrap(err); gormErr != nil {
		if gormErr == gorm.ErrRecordNotFound {
			return status.Error(codes.NotFound, "record not found")
		}
	}

	return status.Error(codes.Internal, "storage error")
}

func computeETag(policy *iampb.Policy) ([]byte, error) {
	data, err := proto.Marshal(policy)
	if err != nil {
		return nil, fmt.Errorf("compute etag: %w", err)
	}
	return []byte(fmt.Sprintf("W/%d-%08X", len(data), crc32.ChecksumIEEE(data))), nil
}
