#pragma once

#include <pybind11/pybind11.h>
namespace py = pybind11;

#include "NameBuffer.hpp"
#include "tracy/Tracy.hpp"

using OptionalString = std::optional<std::string>;
using OptionalInt = std::optional<int>;

template <typename Type = uint64_t>
OptionalNumber MemoryAllocate(const Type &type, std::size_t size,
                              const OptionalString &name = std::nullopt,
                              const OptionalNumber &id = std::nullopt,
                              OptionalInt depth = std::nullopt) {
#ifdef TRACY_ENABLE
  if (!name && !id) {
    if (!depth)
      TracyAlloc(reinterpret_cast<void *>(type), size);
    else
      TracyAllocS(reinterpret_cast<void *>(type), size, *depth);
    return std::nullopt;
  }

  BufferEntry entry;

  if (id) {
    entry.second = NameBuffer::Get(*id);
    if (!entry.second) return std::nullopt;
  } else {
    entry = NameBuffer::Add(*name);
    if (!entry.first) return std::nullopt;
  }

  if (!depth)
    TracyAllocN(reinterpret_cast<void *>(type), size, entry.second);
  else
    TracyAllocNS(reinterpret_cast<void *>(type), size, *depth, entry.second);
  return entry.first;
#else
  static_cast<void>(type);   // unused
  static_cast<void>(size);   // unused
  static_cast<void>(name);   // unused
  static_cast<void>(id);     // unused
  static_cast<void>(depth);  // unused
#endif
}

template <>
OptionalNumber MemoryAllocate(const py::object &object, std::size_t size,
                              const OptionalString &name,
                              const OptionalNumber &id, OptionalInt depth) {
  return MemoryAllocate<uint64_t>(reinterpret_cast<uint64_t>(object.ptr()),
                                  size, name, id, depth);
}

template <typename Type = uint64_t>
bool MemoryFree(const Type &type, const OptionalNumber &id = std::nullopt,
                OptionalInt depth = std::nullopt) {
#ifdef TRACY_ENABLE
  if (!id) {
    if (!depth)
      TracyFree(reinterpret_cast<void *>(type));
    else
      TracyFreeS(reinterpret_cast<void *>(type), *depth);
    return true;
  }

  auto ptr = NameBuffer::Get(*id);
  if (!ptr) return false;

  if (!depth)
    TracyFreeN(reinterpret_cast<void *>(type), ptr);
  else
    TracyFreeNS(reinterpret_cast<void *>(type), *depth, ptr);
  return true;
#else
  static_cast<void>(type);   // unused
  static_cast<void>(id);     // unused
  static_cast<void>(depth);  // unused
#endif
}

template <>
bool MemoryFree(const py::object &object, const OptionalNumber &id,
                OptionalInt depth) {
  return MemoryFree<uint64_t>(reinterpret_cast<uint64_t>(object.ptr()), id,
                              depth);
}
