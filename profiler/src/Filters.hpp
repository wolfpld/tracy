#ifndef __FILTERS_HPP__
#define __FILTERS_HPP__

#include <imgui.h>
#include <string>

class Filters
{
public:
    Filters();
    ~Filters();

    void Clear();
    void Draw( float w );

    bool IsActive() const;

    bool FailAddr( const char* addr );
    bool FailPort( uint16_t port );
    bool FailProg( const char* prog );

private:
    std::string m_fn;

    ImGuiTextFilter m_addrFilter, m_portFilter, m_progFilter;
};

#endif
