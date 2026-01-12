#pragma once

#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace tracy {
using OptionalNumber = std::optional<uint16_t>;
using BufferEntry = std::pair<OptionalNumber, const char*>;

class NameBuffer {
 public:
  static inline BufferEntry Add( const std::string& name ) {
    return getBuffer().add(name);
  }

  static inline const char* Get( uint16_t index ) {
    return getBuffer().get(index);
  }

 private:
  NameBuffer();

  std::mutex m_mutex;
  std::vector<char*> m_buffer;
  std::size_t m_index;

  static inline NameBuffer& getBuffer() {
    static NameBuffer buffer;
    return buffer;
  }

  BufferEntry add( const std::string& name );
  const char* get( uint16_t index );
};
}  // namespace tracy
