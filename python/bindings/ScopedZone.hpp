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
    if (!m_zone) return m_active;
    return m_zone->IsActive();
  }

  template <typename Type>
  bool Text(const Type& text) {
    return SetText(text, m_zone);
  }

  bool Name(const std::string& name) {
    if (name.size() >= std::numeric_limits<uint16_t>::max()) return false;
    m_name = name;
    if (!m_zone) return true;
    m_zone->Name(m_name->c_str(), m_name->size());
    return true;
  }

  void Color(uint32_t color) {
    m_color = color;
    if (!m_zone) return;
    m_zone->Color(m_color);
  }

  void Enter() {
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
  }

  void Exit() {
    if (m_zone) delete m_zone;
    m_zone = nullptr;
  }

 private:
  std::optional<std::string> m_name;
  uint32_t m_color;
  std::optional<int> m_depth;
  bool m_active;

  std::string m_function;
  std::string m_source;
  uint32_t m_line;

  tracy::ScopedZone* m_zone;
};
#else

class PyScopedZone {
 public:
  PyScopedZone(const std::optional<std::string>&, uint32_t, std::optional<int>,
               bool, const std::string&, const std::string&, uint32_t line) {}
  virtual ~PyScopedZone(){};

  bool IsActive() const { return false; }

  template <typename Type>
  bool Text(const Type&) {
    return true;
  }

  bool Name(const std::string&) { return true; }
  void Color(uint32_t) {}
  void Enter() {}
  void Exit() {}
};
#endif
