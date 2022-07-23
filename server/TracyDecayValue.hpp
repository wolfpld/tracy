#ifndef __TRACYDECAYVALUE_HPP__
#define __TRACYDECAYVALUE_HPP__

#include "../public/common/TracyForceInline.hpp"

namespace tracy
{

template<typename T>
class DecayValue
{
public:
    DecayValue( const T& init, bool active = false )
        : m_value( init )
        , m_active( active )
    {
    }

    tracy_force_inline operator const T& () const { return m_value; }
    tracy_force_inline T operator->() const { return m_value; }

    tracy_force_inline DecayValue& operator=( const T& value )
    {
        m_value = value;
        m_active = true;
        return *this;
    }

    tracy_force_inline void Decay( const T& value )
    {
        if( m_active )
        {
            m_active = false;
        }
        else
        {
            m_value = value;
        }
    }

private:
    T m_value;
    bool m_active;
};

}

#endif
