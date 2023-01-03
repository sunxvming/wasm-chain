// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: getmac.proto

#ifndef GOOGLE_PROTOBUF_INCLUDED_getmac_2eproto
#define GOOGLE_PROTOBUF_INCLUDED_getmac_2eproto

#include <limits>
#include <string>

#include <google/protobuf/port_def.inc>
#if PROTOBUF_VERSION < 3011000
#error This file was generated by a newer version of protoc which is
#error incompatible with your Protocol Buffer headers. Please update
#error your headers.
#endif
#if 3011001 < PROTOBUF_MIN_PROTOC_VERSION
#error This file was generated by an older version of protoc which is
#error incompatible with your Protocol Buffer headers. Please
#error regenerate this file with a newer version of protoc.
#endif

#include <google/protobuf/port_undef.inc>
#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/arena.h>
#include <google/protobuf/arenastring.h>
#include <google/protobuf/generated_message_table_driven.h>
#include <google/protobuf/generated_message_util.h>
#include <google/protobuf/inlined_string_field.h>
#include <google/protobuf/metadata.h>
#include <google/protobuf/generated_message_reflection.h>
#include <google/protobuf/message.h>
#include <google/protobuf/repeated_field.h>  // IWYU pragma: export
#include <google/protobuf/extension_set.h>  // IWYU pragma: export
#include <google/protobuf/unknown_field_set.h>
// @@protoc_insertion_point(includes)
#include <google/protobuf/port_def.inc>
#define PROTOBUF_INTERNAL_EXPORT_getmac_2eproto
PROTOBUF_NAMESPACE_OPEN
namespace internal {
class AnyMetadata;
}  // namespace internal
PROTOBUF_NAMESPACE_CLOSE

// Internal implementation detail -- do not use these members.
struct TableStruct_getmac_2eproto {
  static const ::PROTOBUF_NAMESPACE_ID::internal::ParseTableField entries[]
    PROTOBUF_SECTION_VARIABLE(protodesc_cold);
  static const ::PROTOBUF_NAMESPACE_ID::internal::AuxillaryParseTableField aux[]
    PROTOBUF_SECTION_VARIABLE(protodesc_cold);
  static const ::PROTOBUF_NAMESPACE_ID::internal::ParseTable schema[2]
    PROTOBUF_SECTION_VARIABLE(protodesc_cold);
  static const ::PROTOBUF_NAMESPACE_ID::internal::FieldMetadata field_metadata[];
  static const ::PROTOBUF_NAMESPACE_ID::internal::SerializationTable serialization_table[];
  static const ::PROTOBUF_NAMESPACE_ID::uint32 offsets[];
};
extern const ::PROTOBUF_NAMESPACE_ID::internal::DescriptorTable descriptor_table_getmac_2eproto;
class GetMacAck;
class GetMacAckDefaultTypeInternal;
extern GetMacAckDefaultTypeInternal _GetMacAck_default_instance_;
class GetMacReq;
class GetMacReqDefaultTypeInternal;
extern GetMacReqDefaultTypeInternal _GetMacReq_default_instance_;
PROTOBUF_NAMESPACE_OPEN
template<> ::GetMacAck* Arena::CreateMaybeMessage<::GetMacAck>(Arena*);
template<> ::GetMacReq* Arena::CreateMaybeMessage<::GetMacReq>(Arena*);
PROTOBUF_NAMESPACE_CLOSE

// ===================================================================

class GetMacReq :
    public ::PROTOBUF_NAMESPACE_ID::Message /* @@protoc_insertion_point(class_definition:GetMacReq) */ {
 public:
  GetMacReq();
  virtual ~GetMacReq();

  GetMacReq(const GetMacReq& from);
  GetMacReq(GetMacReq&& from) noexcept
    : GetMacReq() {
    *this = ::std::move(from);
  }

  inline GetMacReq& operator=(const GetMacReq& from) {
    CopyFrom(from);
    return *this;
  }
  inline GetMacReq& operator=(GetMacReq&& from) noexcept {
    if (GetArenaNoVirtual() == from.GetArenaNoVirtual()) {
      if (this != &from) InternalSwap(&from);
    } else {
      CopyFrom(from);
    }
    return *this;
  }

  static const ::PROTOBUF_NAMESPACE_ID::Descriptor* descriptor() {
    return GetDescriptor();
  }
  static const ::PROTOBUF_NAMESPACE_ID::Descriptor* GetDescriptor() {
    return GetMetadataStatic().descriptor;
  }
  static const ::PROTOBUF_NAMESPACE_ID::Reflection* GetReflection() {
    return GetMetadataStatic().reflection;
  }
  static const GetMacReq& default_instance();

  static void InitAsDefaultInstance();  // FOR INTERNAL USE ONLY
  static inline const GetMacReq* internal_default_instance() {
    return reinterpret_cast<const GetMacReq*>(
               &_GetMacReq_default_instance_);
  }
  static constexpr int kIndexInFileMessages =
    0;

  friend void swap(GetMacReq& a, GetMacReq& b) {
    a.Swap(&b);
  }
  inline void Swap(GetMacReq* other) {
    if (other == this) return;
    InternalSwap(other);
  }

  // implements Message ----------------------------------------------

  inline GetMacReq* New() const final {
    return CreateMaybeMessage<GetMacReq>(nullptr);
  }

  GetMacReq* New(::PROTOBUF_NAMESPACE_ID::Arena* arena) const final {
    return CreateMaybeMessage<GetMacReq>(arena);
  }
  void CopyFrom(const ::PROTOBUF_NAMESPACE_ID::Message& from) final;
  void MergeFrom(const ::PROTOBUF_NAMESPACE_ID::Message& from) final;
  void CopyFrom(const GetMacReq& from);
  void MergeFrom(const GetMacReq& from);
  PROTOBUF_ATTRIBUTE_REINITIALIZES void Clear() final;
  bool IsInitialized() const final;

  size_t ByteSizeLong() const final;
  const char* _InternalParse(const char* ptr, ::PROTOBUF_NAMESPACE_ID::internal::ParseContext* ctx) final;
  ::PROTOBUF_NAMESPACE_ID::uint8* _InternalSerialize(
      ::PROTOBUF_NAMESPACE_ID::uint8* target, ::PROTOBUF_NAMESPACE_ID::io::EpsCopyOutputStream* stream) const final;
  int GetCachedSize() const final { return _cached_size_.Get(); }

  private:
  inline void SharedCtor();
  inline void SharedDtor();
  void SetCachedSize(int size) const final;
  void InternalSwap(GetMacReq* other);
  friend class ::PROTOBUF_NAMESPACE_ID::internal::AnyMetadata;
  static ::PROTOBUF_NAMESPACE_ID::StringPiece FullMessageName() {
    return "GetMacReq";
  }
  private:
  inline ::PROTOBUF_NAMESPACE_ID::Arena* GetArenaNoVirtual() const {
    return nullptr;
  }
  inline void* MaybeArenaPtr() const {
    return nullptr;
  }
  public:

  ::PROTOBUF_NAMESPACE_ID::Metadata GetMetadata() const final;
  private:
  static ::PROTOBUF_NAMESPACE_ID::Metadata GetMetadataStatic() {
    ::PROTOBUF_NAMESPACE_ID::internal::AssignDescriptors(&::descriptor_table_getmac_2eproto);
    return ::descriptor_table_getmac_2eproto.file_level_metadata[kIndexInFileMessages];
  }

  public:

  // nested types ----------------------------------------------------

  // accessors -------------------------------------------------------

  // @@protoc_insertion_point(class_scope:GetMacReq)
 private:
  class _Internal;

  ::PROTOBUF_NAMESPACE_ID::internal::InternalMetadataWithArena _internal_metadata_;
  mutable ::PROTOBUF_NAMESPACE_ID::internal::CachedSize _cached_size_;
  friend struct ::TableStruct_getmac_2eproto;
};
// -------------------------------------------------------------------

class GetMacAck :
    public ::PROTOBUF_NAMESPACE_ID::Message /* @@protoc_insertion_point(class_definition:GetMacAck) */ {
 public:
  GetMacAck();
  virtual ~GetMacAck();

  GetMacAck(const GetMacAck& from);
  GetMacAck(GetMacAck&& from) noexcept
    : GetMacAck() {
    *this = ::std::move(from);
  }

  inline GetMacAck& operator=(const GetMacAck& from) {
    CopyFrom(from);
    return *this;
  }
  inline GetMacAck& operator=(GetMacAck&& from) noexcept {
    if (GetArenaNoVirtual() == from.GetArenaNoVirtual()) {
      if (this != &from) InternalSwap(&from);
    } else {
      CopyFrom(from);
    }
    return *this;
  }

  static const ::PROTOBUF_NAMESPACE_ID::Descriptor* descriptor() {
    return GetDescriptor();
  }
  static const ::PROTOBUF_NAMESPACE_ID::Descriptor* GetDescriptor() {
    return GetMetadataStatic().descriptor;
  }
  static const ::PROTOBUF_NAMESPACE_ID::Reflection* GetReflection() {
    return GetMetadataStatic().reflection;
  }
  static const GetMacAck& default_instance();

  static void InitAsDefaultInstance();  // FOR INTERNAL USE ONLY
  static inline const GetMacAck* internal_default_instance() {
    return reinterpret_cast<const GetMacAck*>(
               &_GetMacAck_default_instance_);
  }
  static constexpr int kIndexInFileMessages =
    1;

  friend void swap(GetMacAck& a, GetMacAck& b) {
    a.Swap(&b);
  }
  inline void Swap(GetMacAck* other) {
    if (other == this) return;
    InternalSwap(other);
  }

  // implements Message ----------------------------------------------

  inline GetMacAck* New() const final {
    return CreateMaybeMessage<GetMacAck>(nullptr);
  }

  GetMacAck* New(::PROTOBUF_NAMESPACE_ID::Arena* arena) const final {
    return CreateMaybeMessage<GetMacAck>(arena);
  }
  void CopyFrom(const ::PROTOBUF_NAMESPACE_ID::Message& from) final;
  void MergeFrom(const ::PROTOBUF_NAMESPACE_ID::Message& from) final;
  void CopyFrom(const GetMacAck& from);
  void MergeFrom(const GetMacAck& from);
  PROTOBUF_ATTRIBUTE_REINITIALIZES void Clear() final;
  bool IsInitialized() const final;

  size_t ByteSizeLong() const final;
  const char* _InternalParse(const char* ptr, ::PROTOBUF_NAMESPACE_ID::internal::ParseContext* ctx) final;
  ::PROTOBUF_NAMESPACE_ID::uint8* _InternalSerialize(
      ::PROTOBUF_NAMESPACE_ID::uint8* target, ::PROTOBUF_NAMESPACE_ID::io::EpsCopyOutputStream* stream) const final;
  int GetCachedSize() const final { return _cached_size_.Get(); }

  private:
  inline void SharedCtor();
  inline void SharedDtor();
  void SetCachedSize(int size) const final;
  void InternalSwap(GetMacAck* other);
  friend class ::PROTOBUF_NAMESPACE_ID::internal::AnyMetadata;
  static ::PROTOBUF_NAMESPACE_ID::StringPiece FullMessageName() {
    return "GetMacAck";
  }
  private:
  inline ::PROTOBUF_NAMESPACE_ID::Arena* GetArenaNoVirtual() const {
    return nullptr;
  }
  inline void* MaybeArenaPtr() const {
    return nullptr;
  }
  public:

  ::PROTOBUF_NAMESPACE_ID::Metadata GetMetadata() const final;
  private:
  static ::PROTOBUF_NAMESPACE_ID::Metadata GetMetadataStatic() {
    ::PROTOBUF_NAMESPACE_ID::internal::AssignDescriptors(&::descriptor_table_getmac_2eproto);
    return ::descriptor_table_getmac_2eproto.file_level_metadata[kIndexInFileMessages];
  }

  public:

  // nested types ----------------------------------------------------

  // accessors -------------------------------------------------------

  enum : int {
    kMacFieldNumber = 1,
    kIpFieldNumber = 2,
    kPortFieldNumber = 3,
  };
  // string mac = 1;
  void clear_mac();
  const std::string& mac() const;
  void set_mac(const std::string& value);
  void set_mac(std::string&& value);
  void set_mac(const char* value);
  void set_mac(const char* value, size_t size);
  std::string* mutable_mac();
  std::string* release_mac();
  void set_allocated_mac(std::string* mac);
  private:
  const std::string& _internal_mac() const;
  void _internal_set_mac(const std::string& value);
  std::string* _internal_mutable_mac();
  public:

  // string ip = 2;
  void clear_ip();
  const std::string& ip() const;
  void set_ip(const std::string& value);
  void set_ip(std::string&& value);
  void set_ip(const char* value);
  void set_ip(const char* value, size_t size);
  std::string* mutable_ip();
  std::string* release_ip();
  void set_allocated_ip(std::string* ip);
  private:
  const std::string& _internal_ip() const;
  void _internal_set_ip(const std::string& value);
  std::string* _internal_mutable_ip();
  public:

  // uint32 port = 3;
  void clear_port();
  ::PROTOBUF_NAMESPACE_ID::uint32 port() const;
  void set_port(::PROTOBUF_NAMESPACE_ID::uint32 value);
  private:
  ::PROTOBUF_NAMESPACE_ID::uint32 _internal_port() const;
  void _internal_set_port(::PROTOBUF_NAMESPACE_ID::uint32 value);
  public:

  // @@protoc_insertion_point(class_scope:GetMacAck)
 private:
  class _Internal;

  ::PROTOBUF_NAMESPACE_ID::internal::InternalMetadataWithArena _internal_metadata_;
  ::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr mac_;
  ::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr ip_;
  ::PROTOBUF_NAMESPACE_ID::uint32 port_;
  mutable ::PROTOBUF_NAMESPACE_ID::internal::CachedSize _cached_size_;
  friend struct ::TableStruct_getmac_2eproto;
};
// ===================================================================


// ===================================================================

#ifdef __GNUC__
  #pragma GCC diagnostic push
  #pragma GCC diagnostic ignored "-Wstrict-aliasing"
#endif  // __GNUC__
// GetMacReq

// -------------------------------------------------------------------

// GetMacAck

// string mac = 1;
inline void GetMacAck::clear_mac() {
  mac_.ClearToEmptyNoArena(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
}
inline const std::string& GetMacAck::mac() const {
  // @@protoc_insertion_point(field_get:GetMacAck.mac)
  return _internal_mac();
}
inline void GetMacAck::set_mac(const std::string& value) {
  _internal_set_mac(value);
  // @@protoc_insertion_point(field_set:GetMacAck.mac)
}
inline std::string* GetMacAck::mutable_mac() {
  // @@protoc_insertion_point(field_mutable:GetMacAck.mac)
  return _internal_mutable_mac();
}
inline const std::string& GetMacAck::_internal_mac() const {
  return mac_.GetNoArena();
}
inline void GetMacAck::_internal_set_mac(const std::string& value) {
  
  mac_.SetNoArena(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), value);
}
inline void GetMacAck::set_mac(std::string&& value) {
  
  mac_.SetNoArena(
    &::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), ::std::move(value));
  // @@protoc_insertion_point(field_set_rvalue:GetMacAck.mac)
}
inline void GetMacAck::set_mac(const char* value) {
  GOOGLE_DCHECK(value != nullptr);
  
  mac_.SetNoArena(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), ::std::string(value));
  // @@protoc_insertion_point(field_set_char:GetMacAck.mac)
}
inline void GetMacAck::set_mac(const char* value, size_t size) {
  
  mac_.SetNoArena(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(),
      ::std::string(reinterpret_cast<const char*>(value), size));
  // @@protoc_insertion_point(field_set_pointer:GetMacAck.mac)
}
inline std::string* GetMacAck::_internal_mutable_mac() {
  
  return mac_.MutableNoArena(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
}
inline std::string* GetMacAck::release_mac() {
  // @@protoc_insertion_point(field_release:GetMacAck.mac)
  
  return mac_.ReleaseNoArena(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
}
inline void GetMacAck::set_allocated_mac(std::string* mac) {
  if (mac != nullptr) {
    
  } else {
    
  }
  mac_.SetAllocatedNoArena(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), mac);
  // @@protoc_insertion_point(field_set_allocated:GetMacAck.mac)
}

// string ip = 2;
inline void GetMacAck::clear_ip() {
  ip_.ClearToEmptyNoArena(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
}
inline const std::string& GetMacAck::ip() const {
  // @@protoc_insertion_point(field_get:GetMacAck.ip)
  return _internal_ip();
}
inline void GetMacAck::set_ip(const std::string& value) {
  _internal_set_ip(value);
  // @@protoc_insertion_point(field_set:GetMacAck.ip)
}
inline std::string* GetMacAck::mutable_ip() {
  // @@protoc_insertion_point(field_mutable:GetMacAck.ip)
  return _internal_mutable_ip();
}
inline const std::string& GetMacAck::_internal_ip() const {
  return ip_.GetNoArena();
}
inline void GetMacAck::_internal_set_ip(const std::string& value) {
  
  ip_.SetNoArena(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), value);
}
inline void GetMacAck::set_ip(std::string&& value) {
  
  ip_.SetNoArena(
    &::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), ::std::move(value));
  // @@protoc_insertion_point(field_set_rvalue:GetMacAck.ip)
}
inline void GetMacAck::set_ip(const char* value) {
  GOOGLE_DCHECK(value != nullptr);
  
  ip_.SetNoArena(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), ::std::string(value));
  // @@protoc_insertion_point(field_set_char:GetMacAck.ip)
}
inline void GetMacAck::set_ip(const char* value, size_t size) {
  
  ip_.SetNoArena(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(),
      ::std::string(reinterpret_cast<const char*>(value), size));
  // @@protoc_insertion_point(field_set_pointer:GetMacAck.ip)
}
inline std::string* GetMacAck::_internal_mutable_ip() {
  
  return ip_.MutableNoArena(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
}
inline std::string* GetMacAck::release_ip() {
  // @@protoc_insertion_point(field_release:GetMacAck.ip)
  
  return ip_.ReleaseNoArena(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
}
inline void GetMacAck::set_allocated_ip(std::string* ip) {
  if (ip != nullptr) {
    
  } else {
    
  }
  ip_.SetAllocatedNoArena(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), ip);
  // @@protoc_insertion_point(field_set_allocated:GetMacAck.ip)
}

// uint32 port = 3;
inline void GetMacAck::clear_port() {
  port_ = 0u;
}
inline ::PROTOBUF_NAMESPACE_ID::uint32 GetMacAck::_internal_port() const {
  return port_;
}
inline ::PROTOBUF_NAMESPACE_ID::uint32 GetMacAck::port() const {
  // @@protoc_insertion_point(field_get:GetMacAck.port)
  return _internal_port();
}
inline void GetMacAck::_internal_set_port(::PROTOBUF_NAMESPACE_ID::uint32 value) {
  
  port_ = value;
}
inline void GetMacAck::set_port(::PROTOBUF_NAMESPACE_ID::uint32 value) {
  _internal_set_port(value);
  // @@protoc_insertion_point(field_set:GetMacAck.port)
}

#ifdef __GNUC__
  #pragma GCC diagnostic pop
#endif  // __GNUC__
// -------------------------------------------------------------------


// @@protoc_insertion_point(namespace_scope)


// @@protoc_insertion_point(global_scope)

#include <google/protobuf/port_undef.inc>
#endif  // GOOGLE_PROTOBUF_INCLUDED_GOOGLE_PROTOBUF_INCLUDED_getmac_2eproto
