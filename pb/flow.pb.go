// Code generated by protoc-gen-go. DO NOT EDIT.
// source: pb/flow.proto

package flowprotob

import (
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

type FlowMessage_FlowType int32

const (
	FlowMessage_FLOWUNKNOWN FlowMessage_FlowType = 0
	FlowMessage_SFLOW_5     FlowMessage_FlowType = 1
	FlowMessage_NETFLOW_V5  FlowMessage_FlowType = 2
	FlowMessage_NETFLOW_V9  FlowMessage_FlowType = 3
	FlowMessage_IPFIX       FlowMessage_FlowType = 4
)

var FlowMessage_FlowType_name = map[int32]string{
	0: "FLOWUNKNOWN",
	1: "SFLOW_5",
	2: "NETFLOW_V5",
	3: "NETFLOW_V9",
	4: "IPFIX",
}

var FlowMessage_FlowType_value = map[string]int32{
	"FLOWUNKNOWN": 0,
	"SFLOW_5":     1,
	"NETFLOW_V5":  2,
	"NETFLOW_V9":  3,
	"IPFIX":       4,
}

func (x FlowMessage_FlowType) String() string {
	return proto.EnumName(FlowMessage_FlowType_name, int32(x))
}

func (FlowMessage_FlowType) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_0beab9b6746e934c, []int{0, 0}
}

type FlowMessage struct {
	// === Mutated objects
	Gate        string
	Exporter    string
	IngressPort string

	// === Edited by Gustavo Santiago - 2020-10-05

	Type          FlowMessage_FlowType `protobuf:"varint,1,opt,name=Type,proto3,enum=flowprotob.FlowMessage_FlowType" json:"Type,omitempty"`
	TimeReceived  uint64               `protobuf:"varint,2,opt,name=TimeReceived,proto3" json:"TimeReceived,omitempty"`
	SequenceNum   uint32               `protobuf:"varint,4,opt,name=SequenceNum,proto3" json:"SequenceNum,omitempty"`
	SamplingRate  uint64               `protobuf:"varint,3,opt,name=SamplingRate,proto3" json:"SamplingRate,omitempty"`
	FlowDirection uint32               `protobuf:"varint,42,opt,name=FlowDirection,proto3" json:"FlowDirection,omitempty"`
	// Sampler information
	SamplerAddress []byte `protobuf:"bytes,11,opt,name=SamplerAddress,proto3" json:"SamplerAddress,omitempty"`
	// Found inside packet
	TimeFlowStart uint64 `protobuf:"varint,38,opt,name=TimeFlowStart,proto3" json:"TimeFlowStart,omitempty"`
	TimeFlowEnd   uint64 `protobuf:"varint,5,opt,name=TimeFlowEnd,proto3" json:"TimeFlowEnd,omitempty"`
	// Size of the sampled packet
	Bytes   uint64 `protobuf:"varint,9,opt,name=Bytes,proto3" json:"Bytes,omitempty"`
	Packets uint64 `protobuf:"varint,10,opt,name=Packets,proto3" json:"Packets,omitempty"`
	// Source/destination addresses
	SrcAddr []byte `protobuf:"bytes,6,opt,name=SrcAddr,proto3" json:"SrcAddr,omitempty"`
	DstAddr []byte `protobuf:"bytes,7,opt,name=DstAddr,proto3" json:"DstAddr,omitempty"`
	// Layer 3 protocol (IPv4/IPv6/ARP/MPLS...)
	Etype uint32 `protobuf:"varint,30,opt,name=Etype,proto3" json:"Etype,omitempty"`
	// Layer 4 protocol
	Proto uint32 `protobuf:"varint,20,opt,name=Proto,proto3" json:"Proto,omitempty"`
	// Ports for UDP and TCP
	SrcPort uint32 `protobuf:"varint,21,opt,name=SrcPort,proto3" json:"SrcPort,omitempty"`
	DstPort uint32 `protobuf:"varint,22,opt,name=DstPort,proto3" json:"DstPort,omitempty"`
	// Interfaces
	InIf  uint32 `protobuf:"varint,18,opt,name=InIf,proto3" json:"InIf,omitempty"`
	OutIf uint32 `protobuf:"varint,19,opt,name=OutIf,proto3" json:"OutIf,omitempty"`
	// Ethernet information
	SrcMac uint64 `protobuf:"varint,27,opt,name=SrcMac,proto3" json:"SrcMac,omitempty"`
	DstMac uint64 `protobuf:"varint,28,opt,name=DstMac,proto3" json:"DstMac,omitempty"`
	// Vlan
	SrcVlan uint32 `protobuf:"varint,33,opt,name=SrcVlan,proto3" json:"SrcVlan,omitempty"`
	DstVlan uint32 `protobuf:"varint,34,opt,name=DstVlan,proto3" json:"DstVlan,omitempty"`
	// 802.1q VLAN in sampled packet
	VlanId uint32 `protobuf:"varint,29,opt,name=VlanId,proto3" json:"VlanId,omitempty"`
	// VRF
	IngressVrfID uint32 `protobuf:"varint,39,opt,name=IngressVrfID,proto3" json:"IngressVrfID,omitempty"`
	EgressVrfID  uint32 `protobuf:"varint,40,opt,name=EgressVrfID,proto3" json:"EgressVrfID,omitempty"`
	// IP and TCP special flags
	IPTos            uint32 `protobuf:"varint,23,opt,name=IPTos,proto3" json:"IPTos,omitempty"`
	ForwardingStatus uint32 `protobuf:"varint,24,opt,name=ForwardingStatus,proto3" json:"ForwardingStatus,omitempty"`
	IPTTL            uint32 `protobuf:"varint,25,opt,name=IPTTL,proto3" json:"IPTTL,omitempty"`
	TCPFlags         uint32 `protobuf:"varint,26,opt,name=TCPFlags,proto3" json:"TCPFlags,omitempty"`
	IcmpType         uint32 `protobuf:"varint,31,opt,name=IcmpType,proto3" json:"IcmpType,omitempty"`
	IcmpCode         uint32 `protobuf:"varint,32,opt,name=IcmpCode,proto3" json:"IcmpCode,omitempty"`
	IPv6FlowLabel    uint32 `protobuf:"varint,37,opt,name=IPv6FlowLabel,proto3" json:"IPv6FlowLabel,omitempty"`
	// Fragments (IPv4/IPv6)
	FragmentId      uint32 `protobuf:"varint,35,opt,name=FragmentId,proto3" json:"FragmentId,omitempty"`
	FragmentOffset  uint32 `protobuf:"varint,36,opt,name=FragmentOffset,proto3" json:"FragmentOffset,omitempty"`
	BiFlowDirection uint32 `protobuf:"varint,41,opt,name=BiFlowDirection,proto3" json:"BiFlowDirection,omitempty"`
	// Autonomous system information
	SrcAS     uint32 `protobuf:"varint,14,opt,name=SrcAS,proto3" json:"SrcAS,omitempty"`
	DstAS     uint32 `protobuf:"varint,15,opt,name=DstAS,proto3" json:"DstAS,omitempty"`
	NextHop   []byte `protobuf:"bytes,12,opt,name=NextHop,proto3" json:"NextHop,omitempty"`
	NextHopAS uint32 `protobuf:"varint,13,opt,name=NextHopAS,proto3" json:"NextHopAS,omitempty"`
	// Prefix size
	SrcNet uint32 `protobuf:"varint,16,opt,name=SrcNet,proto3" json:"SrcNet,omitempty"`
	DstNet uint32 `protobuf:"varint,17,opt,name=DstNet,proto3" json:"DstNet,omitempty"`
	// IP encapsulation information
	HasEncap            bool   `protobuf:"varint,43,opt,name=HasEncap,proto3" json:"HasEncap,omitempty"`
	SrcAddrEncap        []byte `protobuf:"bytes,44,opt,name=SrcAddrEncap,proto3" json:"SrcAddrEncap,omitempty"`
	DstAddrEncap        []byte `protobuf:"bytes,45,opt,name=DstAddrEncap,proto3" json:"DstAddrEncap,omitempty"`
	ProtoEncap          uint32 `protobuf:"varint,46,opt,name=ProtoEncap,proto3" json:"ProtoEncap,omitempty"`
	EtypeEncap          uint32 `protobuf:"varint,47,opt,name=EtypeEncap,proto3" json:"EtypeEncap,omitempty"`
	IPTosEncap          uint32 `protobuf:"varint,48,opt,name=IPTosEncap,proto3" json:"IPTosEncap,omitempty"`
	IPTTLEncap          uint32 `protobuf:"varint,49,opt,name=IPTTLEncap,proto3" json:"IPTTLEncap,omitempty"`
	IPv6FlowLabelEncap  uint32 `protobuf:"varint,50,opt,name=IPv6FlowLabelEncap,proto3" json:"IPv6FlowLabelEncap,omitempty"`
	FragmentIdEncap     uint32 `protobuf:"varint,51,opt,name=FragmentIdEncap,proto3" json:"FragmentIdEncap,omitempty"`
	FragmentOffsetEncap uint32 `protobuf:"varint,52,opt,name=FragmentOffsetEncap,proto3" json:"FragmentOffsetEncap,omitempty"`
	// MPLS information
	HasMPLS       bool   `protobuf:"varint,53,opt,name=HasMPLS,proto3" json:"HasMPLS,omitempty"`
	MPLSCount     uint32 `protobuf:"varint,54,opt,name=MPLSCount,proto3" json:"MPLSCount,omitempty"`
	MPLS1TTL      uint32 `protobuf:"varint,55,opt,name=MPLS1TTL,proto3" json:"MPLS1TTL,omitempty"`
	MPLS1Label    uint32 `protobuf:"varint,56,opt,name=MPLS1Label,proto3" json:"MPLS1Label,omitempty"`
	MPLS2TTL      uint32 `protobuf:"varint,57,opt,name=MPLS2TTL,proto3" json:"MPLS2TTL,omitempty"`
	MPLS2Label    uint32 `protobuf:"varint,58,opt,name=MPLS2Label,proto3" json:"MPLS2Label,omitempty"`
	MPLS3TTL      uint32 `protobuf:"varint,59,opt,name=MPLS3TTL,proto3" json:"MPLS3TTL,omitempty"`
	MPLS3Label    uint32 `protobuf:"varint,60,opt,name=MPLS3Label,proto3" json:"MPLS3Label,omitempty"`
	MPLSLastTTL   uint32 `protobuf:"varint,61,opt,name=MPLSLastTTL,proto3" json:"MPLSLastTTL,omitempty"`
	MPLSLastLabel uint32 `protobuf:"varint,62,opt,name=MPLSLastLabel,proto3" json:"MPLSLastLabel,omitempty"`
	// PPP information
	HasPPP               bool     `protobuf:"varint,63,opt,name=HasPPP,proto3" json:"HasPPP,omitempty"`
	PPPAddressControl    uint32   `protobuf:"varint,64,opt,name=PPPAddressControl,proto3" json:"PPPAddressControl,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *FlowMessage) Reset()         { *m = FlowMessage{} }
func (m *FlowMessage) String() string { return proto.CompactTextString(m) }
func (*FlowMessage) ProtoMessage()    {}
func (*FlowMessage) Descriptor() ([]byte, []int) {
	return fileDescriptor_0beab9b6746e934c, []int{0}
}

func (m *FlowMessage) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_FlowMessage.Unmarshal(m, b)
}
func (m *FlowMessage) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_FlowMessage.Marshal(b, m, deterministic)
}
func (m *FlowMessage) XXX_Merge(src proto.Message) {
	xxx_messageInfo_FlowMessage.Merge(m, src)
}
func (m *FlowMessage) XXX_Size() int {
	return xxx_messageInfo_FlowMessage.Size(m)
}
func (m *FlowMessage) XXX_DiscardUnknown() {
	xxx_messageInfo_FlowMessage.DiscardUnknown(m)
}

var xxx_messageInfo_FlowMessage proto.InternalMessageInfo

func (m *FlowMessage) GetType() FlowMessage_FlowType {
	if m != nil {
		return m.Type
	}
	return FlowMessage_FLOWUNKNOWN
}

func (m *FlowMessage) GetTimeReceived() uint64 {
	if m != nil {
		return m.TimeReceived
	}
	return 0
}

func (m *FlowMessage) GetSequenceNum() uint32 {
	if m != nil {
		return m.SequenceNum
	}
	return 0
}

func (m *FlowMessage) GetSamplingRate() uint64 {
	if m != nil {
		return m.SamplingRate
	}
	return 0
}

func (m *FlowMessage) GetFlowDirection() uint32 {
	if m != nil {
		return m.FlowDirection
	}
	return 0
}

func (m *FlowMessage) GetSamplerAddress() []byte {
	if m != nil {
		return m.SamplerAddress
	}
	return nil
}

func (m *FlowMessage) GetTimeFlowStart() uint64 {
	if m != nil {
		return m.TimeFlowStart
	}
	return 0
}

func (m *FlowMessage) GetTimeFlowEnd() uint64 {
	if m != nil {
		return m.TimeFlowEnd
	}
	return 0
}

func (m *FlowMessage) GetBytes() uint64 {
	if m != nil {
		return m.Bytes
	}
	return 0
}

func (m *FlowMessage) GetPackets() uint64 {
	if m != nil {
		return m.Packets
	}
	return 0
}

func (m *FlowMessage) GetSrcAddr() []byte {
	if m != nil {
		return m.SrcAddr
	}
	return nil
}

func (m *FlowMessage) GetDstAddr() []byte {
	if m != nil {
		return m.DstAddr
	}
	return nil
}

func (m *FlowMessage) GetEtype() uint32 {
	if m != nil {
		return m.Etype
	}
	return 0
}

func (m *FlowMessage) GetProto() uint32 {
	if m != nil {
		return m.Proto
	}
	return 0
}

func (m *FlowMessage) GetSrcPort() uint32 {
	if m != nil {
		return m.SrcPort
	}
	return 0
}

func (m *FlowMessage) GetDstPort() uint32 {
	if m != nil {
		return m.DstPort
	}
	return 0
}

func (m *FlowMessage) GetInIf() uint32 {
	if m != nil {
		return m.InIf
	}
	return 0
}

func (m *FlowMessage) GetOutIf() uint32 {
	if m != nil {
		return m.OutIf
	}
	return 0
}

func (m *FlowMessage) GetSrcMac() uint64 {
	if m != nil {
		return m.SrcMac
	}
	return 0
}

func (m *FlowMessage) GetDstMac() uint64 {
	if m != nil {
		return m.DstMac
	}
	return 0
}

func (m *FlowMessage) GetSrcVlan() uint32 {
	if m != nil {
		return m.SrcVlan
	}
	return 0
}

func (m *FlowMessage) GetDstVlan() uint32 {
	if m != nil {
		return m.DstVlan
	}
	return 0
}

func (m *FlowMessage) GetVlanId() uint32 {
	if m != nil {
		return m.VlanId
	}
	return 0
}

func (m *FlowMessage) GetIngressVrfID() uint32 {
	if m != nil {
		return m.IngressVrfID
	}
	return 0
}

func (m *FlowMessage) GetEgressVrfID() uint32 {
	if m != nil {
		return m.EgressVrfID
	}
	return 0
}

func (m *FlowMessage) GetIPTos() uint32 {
	if m != nil {
		return m.IPTos
	}
	return 0
}

func (m *FlowMessage) GetForwardingStatus() uint32 {
	if m != nil {
		return m.ForwardingStatus
	}
	return 0
}

func (m *FlowMessage) GetIPTTL() uint32 {
	if m != nil {
		return m.IPTTL
	}
	return 0
}

func (m *FlowMessage) GetTCPFlags() uint32 {
	if m != nil {
		return m.TCPFlags
	}
	return 0
}

func (m *FlowMessage) GetIcmpType() uint32 {
	if m != nil {
		return m.IcmpType
	}
	return 0
}

func (m *FlowMessage) GetIcmpCode() uint32 {
	if m != nil {
		return m.IcmpCode
	}
	return 0
}

func (m *FlowMessage) GetIPv6FlowLabel() uint32 {
	if m != nil {
		return m.IPv6FlowLabel
	}
	return 0
}

func (m *FlowMessage) GetFragmentId() uint32 {
	if m != nil {
		return m.FragmentId
	}
	return 0
}

func (m *FlowMessage) GetFragmentOffset() uint32 {
	if m != nil {
		return m.FragmentOffset
	}
	return 0
}

func (m *FlowMessage) GetBiFlowDirection() uint32 {
	if m != nil {
		return m.BiFlowDirection
	}
	return 0
}

func (m *FlowMessage) GetSrcAS() uint32 {
	if m != nil {
		return m.SrcAS
	}
	return 0
}

func (m *FlowMessage) GetDstAS() uint32 {
	if m != nil {
		return m.DstAS
	}
	return 0
}

func (m *FlowMessage) GetNextHop() []byte {
	if m != nil {
		return m.NextHop
	}
	return nil
}

func (m *FlowMessage) GetNextHopAS() uint32 {
	if m != nil {
		return m.NextHopAS
	}
	return 0
}

func (m *FlowMessage) GetSrcNet() uint32 {
	if m != nil {
		return m.SrcNet
	}
	return 0
}

func (m *FlowMessage) GetDstNet() uint32 {
	if m != nil {
		return m.DstNet
	}
	return 0
}

func (m *FlowMessage) GetHasEncap() bool {
	if m != nil {
		return m.HasEncap
	}
	return false
}

func (m *FlowMessage) GetSrcAddrEncap() []byte {
	if m != nil {
		return m.SrcAddrEncap
	}
	return nil
}

func (m *FlowMessage) GetDstAddrEncap() []byte {
	if m != nil {
		return m.DstAddrEncap
	}
	return nil
}

func (m *FlowMessage) GetProtoEncap() uint32 {
	if m != nil {
		return m.ProtoEncap
	}
	return 0
}

func (m *FlowMessage) GetEtypeEncap() uint32 {
	if m != nil {
		return m.EtypeEncap
	}
	return 0
}

func (m *FlowMessage) GetIPTosEncap() uint32 {
	if m != nil {
		return m.IPTosEncap
	}
	return 0
}

func (m *FlowMessage) GetIPTTLEncap() uint32 {
	if m != nil {
		return m.IPTTLEncap
	}
	return 0
}

func (m *FlowMessage) GetIPv6FlowLabelEncap() uint32 {
	if m != nil {
		return m.IPv6FlowLabelEncap
	}
	return 0
}

func (m *FlowMessage) GetFragmentIdEncap() uint32 {
	if m != nil {
		return m.FragmentIdEncap
	}
	return 0
}

func (m *FlowMessage) GetFragmentOffsetEncap() uint32 {
	if m != nil {
		return m.FragmentOffsetEncap
	}
	return 0
}

func (m *FlowMessage) GetHasMPLS() bool {
	if m != nil {
		return m.HasMPLS
	}
	return false
}

func (m *FlowMessage) GetMPLSCount() uint32 {
	if m != nil {
		return m.MPLSCount
	}
	return 0
}

func (m *FlowMessage) GetMPLS1TTL() uint32 {
	if m != nil {
		return m.MPLS1TTL
	}
	return 0
}

func (m *FlowMessage) GetMPLS1Label() uint32 {
	if m != nil {
		return m.MPLS1Label
	}
	return 0
}

func (m *FlowMessage) GetMPLS2TTL() uint32 {
	if m != nil {
		return m.MPLS2TTL
	}
	return 0
}

func (m *FlowMessage) GetMPLS2Label() uint32 {
	if m != nil {
		return m.MPLS2Label
	}
	return 0
}

func (m *FlowMessage) GetMPLS3TTL() uint32 {
	if m != nil {
		return m.MPLS3TTL
	}
	return 0
}

func (m *FlowMessage) GetMPLS3Label() uint32 {
	if m != nil {
		return m.MPLS3Label
	}
	return 0
}

func (m *FlowMessage) GetMPLSLastTTL() uint32 {
	if m != nil {
		return m.MPLSLastTTL
	}
	return 0
}

func (m *FlowMessage) GetMPLSLastLabel() uint32 {
	if m != nil {
		return m.MPLSLastLabel
	}
	return 0
}

func (m *FlowMessage) GetHasPPP() bool {
	if m != nil {
		return m.HasPPP
	}
	return false
}

func (m *FlowMessage) GetPPPAddressControl() uint32 {
	if m != nil {
		return m.PPPAddressControl
	}
	return 0
}

func init() {
	proto.RegisterEnum("flowprotob.FlowMessage_FlowType", FlowMessage_FlowType_name, FlowMessage_FlowType_value)
	proto.RegisterType((*FlowMessage)(nil), "flowprotob.FlowMessage")
}

func init() { proto.RegisterFile("pb/flow.proto", fileDescriptor_0beab9b6746e934c) }

var fileDescriptor_0beab9b6746e934c = []byte{
	// 943 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x6c, 0x96, 0x6f, 0x73, 0xda, 0xc6,
	0x13, 0xc7, 0x7f, 0x24, 0xc4, 0x7f, 0x0e, 0x63, 0x93, 0x4b, 0x7e, 0xee, 0xd6, 0x4d, 0x53, 0xea,
	0xa6, 0x29, 0x4d, 0x52, 0x92, 0x40, 0x9c, 0x36, 0xfd, 0x1f, 0xdb, 0x30, 0xd6, 0x14, 0x63, 0x0d,
	0xa2, 0x4e, 0x9f, 0x75, 0x0e, 0xe9, 0x60, 0x98, 0x0a, 0x89, 0x4a, 0x47, 0xdc, 0xbc, 0x85, 0xbe,
	0xea, 0xce, 0xee, 0x9e, 0x90, 0xe4, 0xe4, 0x11, 0xfa, 0x7e, 0xbe, 0xbb, 0xcb, 0xdd, 0xed, 0x9e,
	0x40, 0xd4, 0x97, 0x93, 0xa7, 0xd3, 0x30, 0xbe, 0x6a, 0x2f, 0x93, 0xd8, 0xc4, 0x52, 0xe0, 0x33,
	0x3d, 0x4e, 0x0e, 0xff, 0x6d, 0x88, 0x5a, 0x3f, 0x8c, 0xaf, 0xce, 0x75, 0x9a, 0xaa, 0x99, 0x96,
	0x2f, 0x44, 0x75, 0xfc, 0x6e, 0xa9, 0xa1, 0xd2, 0xac, 0xb4, 0x76, 0x3b, 0xcd, 0x76, 0x1e, 0xda,
	0x2e, 0x84, 0xd1, 0x33, 0xc6, 0x8d, 0x28, 0x5a, 0x1e, 0x8a, 0x9d, 0xf1, 0x7c, 0xa1, 0x47, 0xda,
	0xd7, 0xf3, 0xb7, 0x3a, 0x80, 0x1b, 0xcd, 0x4a, 0xab, 0x3a, 0x2a, 0x31, 0xd9, 0x14, 0x35, 0x4f,
	0xff, 0xbd, 0xd2, 0x91, 0xaf, 0x87, 0xab, 0x05, 0x54, 0x9b, 0x95, 0x56, 0x7d, 0x54, 0x44, 0x58,
	0xc5, 0x53, 0x8b, 0x65, 0x38, 0x8f, 0x66, 0x23, 0x65, 0x34, 0xdc, 0xe4, 0x2a, 0x45, 0x26, 0x1f,
	0x88, 0x3a, 0x7e, 0xf7, 0xe9, 0x3c, 0xd1, 0xbe, 0x99, 0xc7, 0x11, 0x3c, 0xa2, 0x3a, 0x65, 0x28,
	0x1f, 0x8a, 0x5d, 0xca, 0xd2, 0xc9, 0xeb, 0x20, 0x48, 0x74, 0x9a, 0x42, 0xad, 0x59, 0x69, 0xed,
	0x8c, 0xae, 0x51, 0xac, 0x86, 0x6b, 0xc4, 0x64, 0xcf, 0xa8, 0xc4, 0xc0, 0x43, 0xfa, 0xca, 0x32,
	0xc4, 0x95, 0x67, 0xa0, 0x17, 0x05, 0x70, 0x8b, 0x62, 0x8a, 0x48, 0xde, 0x15, 0xb7, 0x8e, 0xdf,
	0x19, 0x9d, 0xc2, 0x36, 0x79, 0x2c, 0x24, 0x88, 0x4d, 0x57, 0xf9, 0x7f, 0x69, 0x93, 0x82, 0x20,
	0x9e, 0x49, 0x74, 0xbc, 0xc4, 0xc7, 0x55, 0xc0, 0x06, 0x2d, 0x2c, 0x93, 0xe8, 0x9c, 0xa6, 0x86,
	0x9c, 0x4d, 0x76, 0xac, 0xc4, 0xef, 0xe8, 0x19, 0x6c, 0xcd, 0x7d, 0xda, 0x31, 0x0b, 0xa4, 0x2e,
	0xb6, 0x07, 0xee, 0x32, 0x25, 0x61, 0xeb, 0xbb, 0x71, 0x62, 0xe0, 0xff, 0xc4, 0x33, 0x69, 0xeb,
	0x93, 0xb3, 0xcf, 0x8e, 0x95, 0x52, 0x8a, 0xaa, 0x13, 0x39, 0x53, 0x90, 0x84, 0xe9, 0x19, 0xab,
	0x5f, 0xac, 0x8c, 0x33, 0x85, 0x3b, 0x5c, 0x9d, 0x84, 0xdc, 0x17, 0x1b, 0x5e, 0xe2, 0x9f, 0x2b,
	0x1f, 0x3e, 0xa1, 0x6d, 0x59, 0x85, 0xfc, 0x34, 0x35, 0xc8, 0xef, 0x31, 0x67, 0x65, 0x57, 0x73,
	0x19, 0xaa, 0x08, 0x3e, 0x5f, 0xaf, 0x06, 0xa5, 0x5d, 0x0d, 0x39, 0x87, 0xeb, 0xd5, 0x90, 0xb3,
	0x2f, 0x36, 0xf0, 0xd3, 0x09, 0xe0, 0x53, 0x32, 0xac, 0xc2, 0x19, 0x71, 0xa2, 0x19, 0x36, 0xef,
	0x32, 0x99, 0x3a, 0xa7, 0xf0, 0x15, 0xb9, 0x25, 0x86, 0xfd, 0xea, 0x15, 0x42, 0x5a, 0x3c, 0x69,
	0x05, 0x84, 0xfb, 0x72, 0xdc, 0x71, 0x9c, 0xc2, 0x47, 0xbc, 0x2f, 0x12, 0xf2, 0x91, 0x68, 0xf4,
	0xe3, 0xe4, 0x4a, 0x25, 0xc1, 0x3c, 0x9a, 0x79, 0x46, 0x99, 0x55, 0x0a, 0x40, 0x01, 0xef, 0x71,
	0x5b, 0x61, 0x3c, 0x80, 0x8f, 0xd7, 0x15, 0xc6, 0x03, 0x79, 0x20, 0xb6, 0xc6, 0x27, 0x6e, 0x3f,
	0x54, 0xb3, 0x14, 0x0e, 0xc8, 0x58, 0x6b, 0xf4, 0x1c, 0x7f, 0xb1, 0xa4, 0xdb, 0xf5, 0x19, 0x7b,
	0x99, 0xce, 0xbc, 0x93, 0x38, 0xd0, 0xd0, 0xcc, 0x3d, 0xd4, 0x38, 0xa3, 0x8e, 0xfb, 0xf6, 0x25,
	0x8e, 0xda, 0x40, 0x4d, 0x74, 0x08, 0x5f, 0xf2, 0xc4, 0x97, 0xa0, 0xbc, 0x2f, 0x44, 0x3f, 0x51,
	0xb3, 0x85, 0x8e, 0x8c, 0x13, 0xc0, 0x17, 0x14, 0x52, 0x20, 0x78, 0x23, 0x32, 0x75, 0x31, 0x9d,
	0xa6, 0xda, 0xc0, 0x03, 0x8a, 0xb9, 0x46, 0x65, 0x4b, 0xec, 0x1d, 0xcf, 0xcb, 0x37, 0xec, 0x6b,
	0x0a, 0xbc, 0x8e, 0xf1, 0x04, 0x70, 0x68, 0x3d, 0xd8, 0xe5, 0x13, 0x20, 0x81, 0x14, 0x07, 0xd6,
	0x83, 0x3d, 0xa6, 0x24, 0xb0, 0xcf, 0x43, 0xfd, 0x8f, 0x39, 0x8b, 0x97, 0xb0, 0xc3, 0x53, 0x6d,
	0xa5, 0xbc, 0x27, 0xb6, 0xed, 0xe3, 0x6b, 0x0f, 0xea, 0x94, 0x93, 0x03, 0x3b, 0x69, 0x43, 0x6d,
	0xa0, 0xc1, 0x53, 0xc0, 0xca, 0x4e, 0x1a, 0xf2, 0xdb, 0xcc, 0x59, 0xe1, 0x39, 0x9e, 0xa9, 0xb4,
	0x17, 0xf9, 0x6a, 0x09, 0x8f, 0x9b, 0x95, 0xd6, 0xd6, 0x68, 0xad, 0xe9, 0xed, 0xc2, 0x97, 0x8c,
	0xfd, 0x27, 0xb4, 0x90, 0x12, 0xc3, 0x18, 0x7b, 0xdd, 0x38, 0xe6, 0x1b, 0x8e, 0x29, 0x32, 0x3c,
	0x69, 0xba, 0x64, 0x1c, 0xd1, 0xe6, 0x93, 0xce, 0x09, 0xfa, 0x74, 0x35, 0xd9, 0x7f, 0xca, 0x7e,
	0x4e, 0xd0, 0xa7, 0x71, 0x63, 0xff, 0x19, 0xfb, 0x39, 0xb1, 0xfe, 0x78, 0xc0, 0xfe, 0xf3, 0xb5,
	0x6f, 0x89, 0x6c, 0x0b, 0x59, 0x6a, 0x3d, 0xc7, 0x75, 0x28, 0xee, 0x03, 0x0e, 0x76, 0x34, 0x9f,
	0x03, 0x0e, 0xee, 0x72, 0x47, 0xaf, 0x61, 0xf9, 0x4c, 0xdc, 0x29, 0x4f, 0x03, 0x47, 0xbf, 0xa0,
	0xe8, 0x0f, 0x59, 0xd8, 0xd7, 0x33, 0x95, 0x9e, 0xbb, 0x03, 0x0f, 0x8e, 0xe8, 0xb8, 0x33, 0x89,
	0x7d, 0xc5, 0xcf, 0x93, 0x78, 0x15, 0x19, 0x78, 0xc9, 0x7d, 0x5d, 0x03, 0xec, 0x13, 0x8a, 0xe7,
	0x78, 0x81, 0xbe, 0xe5, 0x79, 0xcf, 0x34, 0xee, 0x9f, 0x9e, 0x79, 0xd8, 0xbf, 0xe3, 0xfd, 0xe7,
	0x24, 0xcb, 0xed, 0x60, 0xee, 0xab, 0x3c, 0xb7, 0x53, 0xc8, 0xed, 0x70, 0xee, 0xf7, 0x79, 0x6e,
	0xa7, 0x94, 0xdb, 0xc5, 0xdc, 0x1f, 0xf2, 0xdc, 0x6e, 0x21, 0xb7, 0xcb, 0xb9, 0x3f, 0xe6, 0xb9,
	0x4c, 0xf0, 0xad, 0x82, 0x6a, 0xa0, 0x52, 0x83, 0xe9, 0x3f, 0xf1, 0x5b, 0xa5, 0x80, 0xf0, 0xa6,
	0x66, 0x92, 0x8b, 0xfc, 0xcc, 0x37, 0xb5, 0x04, 0x71, 0x76, 0xcf, 0x54, 0xea, 0xba, 0x2e, 0xfc,
	0x42, 0x47, 0x66, 0x95, 0x7c, 0x22, 0x6e, 0xbb, 0xae, 0x6b, 0x7f, 0x99, 0x4e, 0xe2, 0xc8, 0x24,
	0x71, 0x08, 0xbf, 0x52, 0x85, 0xf7, 0x8d, 0x43, 0x4f, 0x6c, 0x65, 0xbf, 0xc1, 0x72, 0x4f, 0xd4,
	0xfa, 0x83, 0x8b, 0x37, 0xbf, 0x0f, 0x7f, 0x1b, 0x5e, 0xbc, 0x19, 0x36, 0xfe, 0x27, 0x6b, 0x62,
	0xd3, 0x43, 0xf2, 0xe7, 0x51, 0xa3, 0x22, 0x77, 0x85, 0x18, 0xf6, 0xc6, 0x24, 0x2f, 0x8f, 0x1a,
	0x37, 0x4a, 0xfa, 0x55, 0xe3, 0xa6, 0xdc, 0xc6, 0x37, 0x59, 0xdf, 0xf9, 0xa3, 0x51, 0x3d, 0x7e,
	0x2c, 0x0e, 0xfc, 0x78, 0xd1, 0xf6, 0xc3, 0x78, 0x15, 0x4c, 0x43, 0x95, 0xe8, 0x76, 0xa4, 0x0d,
	0xfd, 0x05, 0x50, 0xb3, 0xd9, 0x71, 0xbd, 0xf0, 0x07, 0xc0, 0x9d, 0x4c, 0x36, 0xe8, 0x6f, 0x41,
	0xf7, 0xbf, 0x00, 0x00, 0x00, 0xff, 0xff, 0xaa, 0x12, 0x2f, 0x89, 0x5d, 0x08, 0x00, 0x00,
}
