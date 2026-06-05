#ifndef __TRACYUSERDATA_HPP__
#define __TRACYUSERDATA_HPP__

#include <memory>
#include <stdint.h>
#include <stdio.h>
#include <string>
#include <vector>

#include "TracyViewData.hpp"

namespace tracy
{

struct Annotation;
struct SourceRegex;
struct ViewData;

class UserData
{
public:
    UserData();
    UserData( const char* program, uint64_t time, const char* filePath );

    bool Valid() const { return !m_program.empty(); }
    void Init( const char* program, uint64_t time, const char* filePath );
    void SetFilePath( const char* filePath );

    const std::string& GetDescription() const { return m_description; }
    void SetDescription( const char* description );

    void LoadState( ViewData& data );
    void StoreState( const ViewData& data );
    void StateShouldBePreserved();

    void LoadAnnotations( std::vector<std::shared_ptr<Annotation>>& data );
    void StoreAnnotations( const std::vector<std::shared_ptr<Annotation>>& data );

    void LoadSourceSubstitutions( std::vector<SourceRegex>& data );
    void StoreSourceSubstitutions( const std::vector<SourceRegex>& data );

    bool Save();

    bool IsSidecarPublic() const { return m_sidecarPublic; }
    void SetSidecarPublic( bool state );

private:
    FILE* OpenFile( bool write );
    FILE* OpenFileLegacy( const char* filename );

    std::string GetSidecarPath( bool write ) const;

    bool Load();

    void LoadLegacyDescription();
    void LoadLegacyState();
    void LoadLegacyAnnotations();
    void LoadLegacySourceSubstitutions();

    std::string m_program;
    uint64_t m_time;
    std::string m_filePath;

    std::string m_description;
    ViewData m_viewData;
    std::vector<std::shared_ptr<Annotation>> m_annotations;
    std::vector<SourceRegex> m_sourceSubstitutions;

    bool m_preserveState;
    bool m_sidecarPublic;
};

}

#endif
