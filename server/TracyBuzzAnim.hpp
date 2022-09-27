#ifndef __TRACYBUZZANIM_HPP__
#define __TRACYBUZZANIM_HPP__

#include <assert.h>

namespace tracy
{

template<typename T>
class BuzzAnim
{
public:
    bool Match( const T& comp ) const
    {
        return active && comp == id;
    }

    float Time() const
    {
        assert( active );
        return time;
    }

    void Enable( const T& val, float len )
    {
        active = true;
        time = len;
        id = val;
    }

    bool Update( float dt )
    {
        if( active )
        {
            time -= dt;
            if( time <= 0 ) active = false;
            return true;
        }
        return false;
    }

private:
    bool active = false;
    float time;
    T id;
};

}

#endif
