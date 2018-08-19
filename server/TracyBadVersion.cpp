#include <assert.h>

#include "IconsFontAwesome5.h"
#include "TracyBadVersion.hpp"
#include "TracyImGui.hpp"

namespace tracy
{

namespace detail
{

void BadVersionImpl( int& badVer )
{
    assert( badVer != 0 );

    if( badVer > 0 )
    {
        ImGui::OpenPopup( "Unsupported file version" );
    }
    else
    {
        ImGui::OpenPopup( "Bad file" );
    }
    if( ImGui::BeginPopupModal( "Unsupported file version", nullptr, ImGuiWindowFlags_AlwaysAutoResize ) )
    {
#ifdef TRACY_EXTENDED_FONT
        TextCentered( ICON_FA_CLOUD_DOWNLOAD_ALT );
#endif
        ImGui::Text( "The file you are trying to open is unsupported.\nYou should update to tracy %i.%i.%i or newer and try again.", badVer >> 16, ( badVer >> 8 ) & 0xFF, badVer & 0xFF );
        ImGui::Separator();
        if( ImGui::Button( "I understand" ) )
        {
            ImGui::CloseCurrentPopup();
            badVer = 0;
        }
        ImGui::EndPopup();
    }
    if( ImGui::BeginPopupModal( "Bad file", nullptr, ImGuiWindowFlags_AlwaysAutoResize ) )
    {
#ifdef TRACY_EXTENDED_FONT
        TextCentered( ICON_FA_EXCLAMATION_TRIANGLE );
#endif
        ImGui::Text( "The file you are trying to open is not a tracy dump." );
        ImGui::Separator();
        if( ImGui::Button( "Oops" ) )
        {
            ImGui::CloseCurrentPopup();
            badVer = 0;
        }
        ImGui::EndPopup();
    }
}

}

}
