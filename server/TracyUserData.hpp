#ifndef __TRACYUSERDATA_HPP__
#define __TRACYUSERDATA_HPP__

#include <stdint.h>
#include <string>

namespace tracy
{

class UserData
{
public:
    UserData();
    UserData( const char* program, uint64_t time );

    bool Valid() const { return !m_program.empty(); }
    void Init( const char* program, uint64_t time );

    const std::string& GetDescription() const { return m_description; }
    bool SetDescription( const char* description );

private:
    std::string m_program;
    uint64_t m_time;

    std::string m_description;
};

}

#endif
