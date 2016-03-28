// Code generated by protoc-gen-go.
// source: rpc/pb/va.proto
// DO NOT EDIT!

package pb

import proto "github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

import (
	context "github.com/letsencrypt/boulder/Godeps/_workspace/src/golang.org/x/net/context"
	grpc "github.com/letsencrypt/boulder/Godeps/_workspace/src/google.golang.org/grpc"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

type PerformValidationRequest struct {
	Domain    string       `protobuf:"bytes,1,opt,name=domain" json:"domain,omitempty"`
	Challenge *VAChallenge `protobuf:"bytes,2,opt,name=challenge" json:"challenge,omitempty"`
	Authz     *AuthzMeta   `protobuf:"bytes,3,opt,name=authz" json:"authz,omitempty"`
}

func (m *PerformValidationRequest) Reset()                    { *m = PerformValidationRequest{} }
func (m *PerformValidationRequest) String() string            { return proto.CompactTextString(m) }
func (*PerformValidationRequest) ProtoMessage()               {}
func (*PerformValidationRequest) Descriptor() ([]byte, []int) { return fileDescriptor1, []int{0} }

func (m *PerformValidationRequest) GetChallenge() *VAChallenge {
	if m != nil {
		return m.Challenge
	}
	return nil
}

func (m *PerformValidationRequest) GetAuthz() *AuthzMeta {
	if m != nil {
		return m.Authz
	}
	return nil
}

// VAChallenge contains just the fields of core.Challenge that the VA needs
type VAChallenge struct {
	Id               int64             `protobuf:"varint,1,opt,name=id" json:"id,omitempty"`
	Type             string            `protobuf:"bytes,2,opt,name=type" json:"type,omitempty"`
	Token            string            `protobuf:"bytes,3,opt,name=token" json:"token,omitempty"`
	AccountKey       string            `protobuf:"bytes,4,opt,name=accountKey" json:"accountKey,omitempty"`
	KeyAuthorization *KeyAuthorization `protobuf:"bytes,5,opt,name=keyAuthorization" json:"keyAuthorization,omitempty"`
}

func (m *VAChallenge) Reset()                    { *m = VAChallenge{} }
func (m *VAChallenge) String() string            { return proto.CompactTextString(m) }
func (*VAChallenge) ProtoMessage()               {}
func (*VAChallenge) Descriptor() ([]byte, []int) { return fileDescriptor1, []int{1} }

func (m *VAChallenge) GetKeyAuthorization() *KeyAuthorization {
	if m != nil {
		return m.KeyAuthorization
	}
	return nil
}

type AuthzMeta struct {
	Id    string `protobuf:"bytes,1,opt,name=id" json:"id,omitempty"`
	RegID int64  `protobuf:"varint,2,opt,name=regID" json:"regID,omitempty"`
}

func (m *AuthzMeta) Reset()                    { *m = AuthzMeta{} }
func (m *AuthzMeta) String() string            { return proto.CompactTextString(m) }
func (*AuthzMeta) ProtoMessage()               {}
func (*AuthzMeta) Descriptor() ([]byte, []int) { return fileDescriptor1, []int{2} }

type ValidationRecords struct {
	Records  []*ValidationRecord `protobuf:"bytes,1,rep,name=records" json:"records,omitempty"`
	Problems *ProblemDetails     `protobuf:"bytes,2,opt,name=problems" json:"problems,omitempty"`
}

func (m *ValidationRecords) Reset()                    { *m = ValidationRecords{} }
func (m *ValidationRecords) String() string            { return proto.CompactTextString(m) }
func (*ValidationRecords) ProtoMessage()               {}
func (*ValidationRecords) Descriptor() ([]byte, []int) { return fileDescriptor1, []int{3} }

func (m *ValidationRecords) GetRecords() []*ValidationRecord {
	if m != nil {
		return m.Records
	}
	return nil
}

func (m *ValidationRecords) GetProblems() *ProblemDetails {
	if m != nil {
		return m.Problems
	}
	return nil
}

type ValidationRecord struct {
	Hostname          string   `protobuf:"bytes,1,opt,name=hostname" json:"hostname,omitempty"`
	Port              string   `protobuf:"bytes,2,opt,name=port" json:"port,omitempty"`
	AddressesResolved []string `protobuf:"bytes,3,rep,name=addressesResolved" json:"addressesResolved,omitempty"`
	AddressUsed       string   `protobuf:"bytes,4,opt,name=addressUsed" json:"addressUsed,omitempty"`
	Authorities       []string `protobuf:"bytes,5,rep,name=authorities" json:"authorities,omitempty"`
	Url               string   `protobuf:"bytes,6,opt,name=url" json:"url,omitempty"`
}

func (m *ValidationRecord) Reset()                    { *m = ValidationRecord{} }
func (m *ValidationRecord) String() string            { return proto.CompactTextString(m) }
func (*ValidationRecord) ProtoMessage()               {}
func (*ValidationRecord) Descriptor() ([]byte, []int) { return fileDescriptor1, []int{4} }

func init() {
	proto.RegisterType((*PerformValidationRequest)(nil), "pb.PerformValidationRequest")
	proto.RegisterType((*VAChallenge)(nil), "pb.VAChallenge")
	proto.RegisterType((*AuthzMeta)(nil), "pb.AuthzMeta")
	proto.RegisterType((*ValidationRecords)(nil), "pb.ValidationRecords")
	proto.RegisterType((*ValidationRecord)(nil), "pb.ValidationRecord")
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion1

// Client API for VA service

type VAClient interface {
	IsSafeDomain(ctx context.Context, in *Domain, opts ...grpc.CallOption) (*Valid, error)
	PerformValidation(ctx context.Context, in *PerformValidationRequest, opts ...grpc.CallOption) (*ValidationRecords, error)
}

type vAClient struct {
	cc *grpc.ClientConn
}

func NewVAClient(cc *grpc.ClientConn) VAClient {
	return &vAClient{cc}
}

func (c *vAClient) IsSafeDomain(ctx context.Context, in *Domain, opts ...grpc.CallOption) (*Valid, error) {
	out := new(Valid)
	err := grpc.Invoke(ctx, "/pb.VA/IsSafeDomain", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *vAClient) PerformValidation(ctx context.Context, in *PerformValidationRequest, opts ...grpc.CallOption) (*ValidationRecords, error) {
	out := new(ValidationRecords)
	err := grpc.Invoke(ctx, "/pb.VA/PerformValidation", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Server API for VA service

type VAServer interface {
	IsSafeDomain(context.Context, *Domain) (*Valid, error)
	PerformValidation(context.Context, *PerformValidationRequest) (*ValidationRecords, error)
}

func RegisterVAServer(s *grpc.Server, srv VAServer) {
	s.RegisterService(&_VA_serviceDesc, srv)
}

func _VA_IsSafeDomain_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error) (interface{}, error) {
	in := new(Domain)
	if err := dec(in); err != nil {
		return nil, err
	}
	out, err := srv.(VAServer).IsSafeDomain(ctx, in)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func _VA_PerformValidation_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error) (interface{}, error) {
	in := new(PerformValidationRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	out, err := srv.(VAServer).PerformValidation(ctx, in)
	if err != nil {
		return nil, err
	}
	return out, nil
}

var _VA_serviceDesc = grpc.ServiceDesc{
	ServiceName: "pb.VA",
	HandlerType: (*VAServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "IsSafeDomain",
			Handler:    _VA_IsSafeDomain_Handler,
		},
		{
			MethodName: "PerformValidation",
			Handler:    _VA_PerformValidation_Handler,
		},
	},
	Streams: []grpc.StreamDesc{},
}

var fileDescriptor1 = []byte{
	// 458 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x09, 0x6e, 0x88, 0x02, 0xff, 0x74, 0x53, 0xdb, 0x6e, 0xd3, 0x40,
	0x10, 0xad, 0xe3, 0x26, 0xd4, 0x13, 0xa0, 0xc9, 0xa8, 0x20, 0x2b, 0x42, 0xa8, 0x32, 0x0f, 0xf0,
	0x00, 0xa9, 0x28, 0x3f, 0x40, 0x44, 0x5e, 0x4a, 0x85, 0x54, 0x2d, 0x22, 0xef, 0x6b, 0x7b, 0xda,
	0x58, 0x75, 0xbc, 0x66, 0x77, 0x53, 0x29, 0xfd, 0x00, 0xfe, 0x85, 0x1f, 0xe1, 0xbb, 0xd8, 0x8b,
	0xe3, 0x58, 0x09, 0xbc, 0x9d, 0x39, 0x73, 0xc6, 0x7b, 0xf6, 0xec, 0x18, 0x4e, 0x65, 0x9d, 0x5d,
	0xd4, 0xe9, 0xc5, 0x03, 0x9f, 0xd6, 0x52, 0x68, 0x81, 0xbd, 0x3a, 0x9d, 0x8c, 0x1b, 0x32, 0x13,
	0x92, 0x3c, 0x9d, 0xfc, 0x0a, 0x20, 0xbe, 0x21, 0x79, 0x2b, 0xe4, 0x6a, 0xc1, 0xcb, 0x22, 0xe7,
	0xba, 0x10, 0x15, 0xa3, 0x9f, 0x6b, 0x52, 0x1a, 0x5f, 0xc2, 0x20, 0x17, 0x2b, 0x5e, 0x54, 0x71,
	0x70, 0x1e, 0xbc, 0x8b, 0x58, 0x53, 0xe1, 0x07, 0x88, 0xb2, 0x25, 0x2f, 0x4b, 0xaa, 0xee, 0x28,
	0xee, 0x99, 0xd6, 0xf0, 0xf2, 0x74, 0x5a, 0xa7, 0xd3, 0xc5, 0xec, 0xcb, 0x96, 0x66, 0x3b, 0x05,
	0xbe, 0x81, 0x3e, 0x5f, 0xeb, 0xe5, 0x63, 0x1c, 0x3a, 0xe9, 0x33, 0x2b, 0x9d, 0x59, 0xe2, 0x1b,
	0x69, 0xce, 0x7c, 0x2f, 0xf9, 0x1d, 0xc0, 0xb0, 0x33, 0x8f, 0xcf, 0xa1, 0x57, 0xe4, 0xee, 0xdc,
	0x90, 0x19, 0x84, 0x08, 0xc7, 0x7a, 0x53, 0xfb, 0xe3, 0x22, 0xe6, 0x30, 0x9e, 0x41, 0x5f, 0x8b,
	0x7b, 0xaa, 0xdc, 0x87, 0x23, 0xe6, 0x0b, 0x7c, 0x0d, 0xc0, 0xb3, 0x4c, 0xac, 0x2b, 0x7d, 0x4d,
	0x9b, 0xf8, 0xd8, 0xb5, 0x3a, 0x0c, 0x7e, 0x86, 0xd1, 0x3d, 0x6d, 0xac, 0x01, 0x21, 0x8b, 0x47,
	0x77, 0xe1, 0xb8, 0xef, 0x9c, 0x9d, 0x59, 0x67, 0xd7, 0x7b, 0x3d, 0x76, 0xa0, 0x4e, 0x3e, 0x42,
	0xd4, 0xfa, 0xef, 0x18, 0x8d, 0x9c, 0x51, 0x63, 0x4a, 0xd2, 0xdd, 0xd5, 0xdc, 0x39, 0x0d, 0x99,
	0x2f, 0x12, 0x05, 0xe3, 0x6e, 0xbe, 0xe6, 0x05, 0x72, 0x85, 0x53, 0x78, 0x22, 0x3d, 0x34, 0xf3,
	0xe1, 0xd6, 0xc0, 0xbe, 0x8e, 0x6d, 0x45, 0x46, 0x7f, 0x62, 0x5e, 0x2d, 0x2d, 0x69, 0xa5, 0x9a,
	0xd8, 0xd1, 0x0e, 0xdc, 0x78, 0x6e, 0x6e, 0xdc, 0x14, 0xa5, 0x62, 0xad, 0x26, 0xf9, 0x13, 0xc0,
	0x68, 0xff, 0x6b, 0x38, 0x81, 0x93, 0xa5, 0x50, 0xba, 0xe2, 0x2b, 0x6a, 0x5c, 0xb7, 0xb5, 0x0d,
	0xb9, 0x16, 0x52, 0x6f, 0x43, 0xb6, 0x18, 0xdf, 0xc3, 0x98, 0xe7, 0xb9, 0x24, 0xa5, 0x48, 0x31,
	0x52, 0xa2, 0x7c, 0xa0, 0xdc, 0x04, 0x1e, 0x1a, 0xc1, 0x61, 0x03, 0xcf, 0x61, 0xd8, 0x90, 0x3f,
	0x94, 0xd1, 0xf9, 0xf4, 0xbb, 0x94, 0x53, 0xf8, 0x34, 0x75, 0x41, 0xca, 0x24, 0x1f, 0x3a, 0xc5,
	0x8e, 0xc2, 0x11, 0x84, 0x6b, 0x59, 0xc6, 0x03, 0x37, 0x6b, 0xe1, 0xe5, 0x06, 0x7a, 0x8b, 0x19,
	0xbe, 0x85, 0xa7, 0x57, 0xea, 0x3b, 0xbf, 0xa5, 0xb9, 0x5f, 0x43, 0xb0, 0x97, 0xf7, 0x78, 0x12,
	0xb5, 0xc9, 0x25, 0x47, 0xf8, 0x15, 0xc6, 0x07, 0x3b, 0x8d, 0xaf, 0x5c, 0x54, 0xff, 0x59, 0xf5,
	0xc9, 0x8b, 0x7f, 0x25, 0xaf, 0x92, 0xa3, 0x74, 0xe0, 0xfe, 0x93, 0x4f, 0x7f, 0x03, 0x00, 0x00,
	0xff, 0xff, 0x5f, 0xcf, 0x6a, 0xff, 0x51, 0x03, 0x00, 0x00,
}
