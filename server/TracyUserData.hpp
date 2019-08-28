#ifndef __TRACYUSERDATA_HPP__
#define __TRACYUSERDATA_HPP__

#include <stdint.h>
#include <stdio.h>
#include <string>

namespace tracy
{

struct ViewData;

class UserData
{
public:
    UserData();
    UserData( const char* program, uint64_t time );

    bool Valid() const { return !m_program.empty(); }
    void Init( const char* program, uint64_t time );

    const std::string& GetDescription() const { return m_description; }
    bool SetDescription( const char* description );

    void LoadState( ViewData& data );
    void SaveState( const ViewData& data );
    void StateShouldBePreserved();

private:
    FILE* OpenFile( const char* filename, bool write );

    std::string m_program;
    uint64_t m_time;

    std::string m_description;

    bool m_preserveState;
};

}

#endif
