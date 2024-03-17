#pragma once

#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

namespace py = pybind11;
using namespace pybind11::literals;

#include <optional>
#include <string>

#include "tracy/Tracy.hpp"

#ifdef TRACY_ENABLE
template <typename Type = std::string>
bool SetText(const Type& text, tracy::ScopedZone* zone) {
  return SetText<std::string>(py::str(text), zone);
}
template <>
bool SetText(const std::string& text, tracy::ScopedZone* zone) {
  if (!zone || text.size() >= std::numeric_limits<uint16_t>::max())
    return false;
  zone->Text(text.c_str(), text.size());
  return true;
}
#endif

class PyScopedZone {
 public:
  PyScopedZone(const std::optional<std::string>& name, uint32_t color,
               std::optional<int> depth, bool active,
               const std::string& function, const std::string& source,
               uint32_t line)
      : m_name(name),
        m_color(color),
        m_depth(depth),
        m_active(active),
        m_function(function),
        m_source(source),
        m_line(line) {
#if defined TRACY_HAS_CALLSTACK && defined TRACY_CALLSTACK
    if (!depth) depth = TRACY_CALLSTACK;
#endif
  }
  virtual ~PyScopedZone() { Exit(); };

  bool IsActive() const {
#ifdef TRACY_ENABLE
    if (!m_zone) return m_active;
    return m_zone->IsActive();
#else
    return false;
#endif
  }

  template <typename Type>
  bool Text(const Type& text) {
#ifdef TRACY_ENABLE
    return SetText(text, m_zone);
#else
    static_cast<void>(text);  // unused
#endif
  }

  bool Name(const std::string& name) {
#ifdef TRACY_ENABLE
    if (name.size() >= std::numeric_limits<uint16_t>::max()) return false;
    m_name = name;
    if (!m_zone) return true;
    m_zone->Name(m_name->c_str(), m_name->size());
    return true;
#else
    static_cast<void>(name);  // unused
#endif
  }

  void Color(uint32_t color) {
#ifdef TRACY_ENABLE
    m_color = color;
    if (!m_zone) return;
    m_zone->Color(m_color);
#else
    static_cast<void>(color);  // unused
#endif
  }

  void Enter() {
#ifdef TRACY_ENABLE
    if (m_depth)
      m_zone = new tracy::ScopedZone(
          m_line, m_source.c_str(), m_source.size(), m_function.c_str(),
          m_function.size(), m_name ? m_name->c_str() : nullptr,
          m_name ? m_name->size() : 0ul, m_color, *m_depth, m_active);
    else
      m_zone = new tracy::ScopedZone(
          m_line, m_source.c_str(), m_source.size(), m_function.c_str(),
          m_function.size(), m_name ? m_name->c_str() : nullptr,
          m_name ? m_name->size() : 0ul, m_color, m_active);
#endif
  }

  void Exit() {
#ifdef TRACY_ENABLE
    if (m_zone) delete m_zone;
    m_zone = nullptr;
#endif
  }

 private:
  std::optional<std::string> m_name;
  uint32_t m_color;
  std::optional<int> m_depth;
  bool m_active;

  std::string m_function;
  std::string m_source;
  uint32_t m_line;

#ifdef TRACY_ENABLE
  tracy::ScopedZone* m_zone;
#endif
};
