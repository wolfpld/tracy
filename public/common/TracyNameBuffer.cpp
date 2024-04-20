#include "TracyNameBuffer.hpp"
using namespace tracy;

#include "TracyApi.h"

#ifndef TRACY_BUFFER_SIZE
#define TRACY_BUFFER_SIZE = 128
#endif

#ifndef TRACY_NAME_LENGTH
#define TRACY_NAME_LENGTH = 128
#endif

NameBuffer::NameBuffer() : m_buffer(TRACY_BUFFER_SIZE, nullptr), m_index(0ul) {
  for (std::size_t index = 0ul, end = m_buffer.size(); index < end; ++index)
    m_buffer[index] = new char[TRACY_NAME_LENGTH];
}

BufferEntry NameBuffer::add( const std::string& name ) {
  std::lock_guard<std::mutex> lock(m_mutex);
  if (m_index >= TRACY_BUFFER_SIZE || name.size() > TRACY_NAME_LENGTH)
    return std::make_pair(std::nullopt, nullptr);

  auto index = m_index++;
  name.copy(m_buffer[index], name.size());
  return std::make_pair(index, m_buffer[index]);
}

const char* NameBuffer::get( uint16_t index ) {
  std::lock_guard<std::mutex> lock(m_mutex);
  if (index >= TRACY_BUFFER_SIZE) return nullptr;
  return m_buffer[index];
}

#ifdef TRACY_NAME_BUFFER
TRACY_API const char* ___tracy_name_buffer_add( const char* name, uint16_t* id ) {
  auto entry = NameBuffer::Add(name);
  if (!entry.first) return nullptr;

  if (id != nullptr) *id = *entry.first;
  return entry.second;
}
TRACY_API const char* ___tracy_name_buffer_get( uint16_t id ) { return NameBuffer::Get(id); }
#endif
