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

    void Update( float dt )
    {
        if( active )
        {
            time -= dt;
            if( time <= 0 ) active = false;
        }
    }

private:
    bool active = false;
    float time;
    T id;
};

}

#endif
