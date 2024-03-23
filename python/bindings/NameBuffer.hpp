#pragma once

#include <mutex>
#include <optional>
#include <string>
#include <vector>

#ifndef BUFFER_SIZE
#define BUFFER_SIZE = 128
#endif

#ifndef NAME_LENGTH
#define NAME_LENGTH = 128
#endif

using OptionalNumber = std::optional<std::size_t>;
using BufferEntry = std::pair<OptionalNumber, const char*>;

class NameBuffer {
 public:
  static inline BufferEntry Add(const std::string& name) {
    return getBuffer().add(name);
  }

  static inline const char* Get(std::size_t index) {
    return getBuffer().get(index);
  }

 private:
  NameBuffer() : m_buffer(BUFFER_SIZE, nullptr), m_index(0ul) {
    for (std::size_t index = 0ul, end = m_buffer.size(); index < end; ++index)
      m_buffer[index] = new char[NAME_LENGTH];
  }

  std::mutex m_mutex;
  std::vector<char*> m_buffer;
  std::size_t m_index;

  static inline NameBuffer& getBuffer() {
    static NameBuffer buffer;
    return buffer;
  }

  BufferEntry add(const std::string& name) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_index >= BUFFER_SIZE || name.size() > NAME_LENGTH)
      return std::make_pair(std::nullopt, nullptr);

    auto index = m_index++;
    name.copy(m_buffer[index], name.size());
    return std::make_pair(index, m_buffer[index]);
  }

  const char* get(std::size_t index) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (index >= BUFFER_SIZE) return nullptr;
    return m_buffer[index];
  }
};
