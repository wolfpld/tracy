#ifndef __TRACYUSERDATA_HPP__
#define __TRACYUSERDATA_HPP__

#include <memory>
#include <stdint.h>
#include <stdio.h>
#include <string>
#include <vector>

namespace tracy
{

struct Annotation;
struct SourceRegex;
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

    void LoadAnnotations( std::vector<std::unique_ptr<Annotation>>& data );
    void SaveAnnotations( const std::vector<std::unique_ptr<Annotation>>& data );

    bool LoadSourceSubstitutions( std::vector<SourceRegex>& data );
    void SaveSourceSubstitutions( const std::vector<SourceRegex>& data );

    const char* GetConfigLocation() const;

private:
    FILE* OpenFile( const char* filename, bool write );
    void Remove( const char* filename );

    std::string m_program;
    uint64_t m_time;

    std::string m_description;

    bool m_preserveState;
};

}

#endif
