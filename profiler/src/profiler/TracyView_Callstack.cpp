#include <inttypes.h>
#include <sstream>

#include "../public/common/TracyStackFrames.hpp"
#include "TracyImGui.hpp"
#include "TracyPrint.hpp"
#include "TracyUtility.hpp"
#include "TracyView.hpp"

namespace tracy
{

static bool IsFrameExternal( const char* filename, const char* image )
{
    if( strncmp( filename, "/usr/", 5 ) == 0 || strncmp( filename, "/lib/", 5 ) == 0 || strcmp( filename, "[unknown]" ) == 0 ) return true;
    if( strncmp( filename, "C:\\Program Files\\", 17 ) == 0 || strncmp( filename, "d:\\a01\\_work\\", 13 ) == 0 ) return true;
    if( !image ) return false;
    return strncmp( image, "/usr/", 5 ) == 0 || strncmp( image, "/lib/", 5 ) == 0 || strncmp( image, "/lib64/", 7 ) == 0 || strcmp( image, "<kernel>" ) == 0;
}

void View::DrawCallstackWindow()
{
    bool show = true;
    const auto scale = GetScale();
    ImGui::SetNextWindowSize( ImVec2( 1400 * scale, 500 * scale ), ImGuiCond_FirstUseEver );
    ImGui::Begin( "Call stack", &show, ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse );
    if( !ImGui::GetCurrentWindowRead()->SkipItems )
    {
        DrawCallstackTable( m_callstackInfoWindow, true );
    }
    ImGui::End();
    if( !show ) m_callstackInfoWindow = 0;
}

void View::DrawCallstackTable( uint32_t callstack, bool globalEntriesButton )
{
    auto& cs = m_worker.GetCallstack( callstack );
    if( ClipboardButton() )
    {
        std::ostringstream s;
        int fidx = 0;
        for( auto& entry : cs )
        {
            char buf[64*1024];
            auto frameData = m_worker.GetCallstackFrame( entry );
            if( !frameData )
            {
                sprintf( buf, "%3i. %p\n", fidx++, (void*)m_worker.GetCanonicalPointer( entry ) );
            }
            else
            {
                auto ptr = buf;
                const auto fsz = frameData->size;
                for( uint8_t f=0; f<fsz; f++ )
                {
                    const auto& frame = frameData->data[f];
                    auto txt = m_worker.GetString( frame.name );

                    if( fidx == 0 && f != fsz-1 )
                    {
                        auto test = tracy::s_tracyStackFrames;
                        bool match = false;
                        do
                        {
                            if( strcmp( txt, *test ) == 0 )
                            {
                                match = true;
                                break;
                            }
                        }
                        while( *++test );
                        if( match ) continue;
                    }

                    if( f == fsz-1 )
                    {
                        ptr += sprintf( ptr, "%3i. ", fidx++ );
                    }
                    else
                    {
                        ptr += sprintf( ptr, "inl. " );
                    }
                    ptr += sprintf( ptr, "%s  ", txt );
                    txt = m_worker.GetString( frame.file );
                    if( frame.line == 0 )
                    {
                        ptr += sprintf( ptr, "(%s)", txt );
                    }
                    else
                    {
                        ptr += sprintf( ptr, "(%s:%" PRIu32 ")", txt, frame.line );
                    }
                    if( frameData->imageName.Active() )
                    {
                        ptr += sprintf( ptr, " %s\n", m_worker.GetString( frameData->imageName ) );
                    }
                    else
                    {
                        ptr += sprintf( ptr, "\n" );
                    }
                }
            }
            s << buf;
        }
        ImGui::SetClipboardText( s.str().c_str() );
    }
    ImGui::SameLine();
    ImGui::Spacing();
    ImGui::SameLine();
    SmallCheckbox( "External frames", &m_showExternalFrames );
    ImGui::SameLine();
    ImGui::Spacing();
    ImGui::SameLine();
    ImGui::TextUnformatted( ICON_FA_AT " Frame location:" );
    ImGui::SameLine();
    ImGui::PushStyleVar( ImGuiStyleVar_FramePadding, ImVec2( 0, 0 ) );
    ImGui::RadioButton( "Source code", &m_showCallstackFrameAddress, 0 );
    ImGui::SameLine();
    ImGui::RadioButton( "Entry point", &m_showCallstackFrameAddress, 3 );
    ImGui::SameLine();
    ImGui::RadioButton( "Return address", &m_showCallstackFrameAddress, 1 );
    ImGui::SameLine();
    ImGui::RadioButton( "Symbol address", &m_showCallstackFrameAddress, 2 );

    if( globalEntriesButton && m_worker.AreCallstackSamplesReady() )
    {
        auto frame = m_worker.GetCallstackFrame( *cs.begin() );
        if( frame && frame->data[0].symAddr != 0 )
        {
            auto sym = m_worker.GetSymbolStats( frame->data[0].symAddr );
            if( sym && !sym->parents.empty() )
            {
                ImGui::SameLine();
                ImGui::Spacing();
                ImGui::SameLine();
                if( ImGui::Button( ICON_FA_DOOR_OPEN " Global entry statistics" ) )
                {
                    ShowSampleParents( frame->data[0].symAddr, true );
                }
            }
        }
    }
    ImGui::PopStyleVar();

    ImGui::Separator();
    if( ImGui::BeginTable( "##callstack", 4, ImGuiTableFlags_Resizable | ImGuiTableFlags_Reorderable | ImGuiTableFlags_Hideable | ImGuiTableFlags_Borders | ImGuiTableFlags_ScrollY ) )
    {
        ImGui::TableSetupScrollFreeze( 0, 1 );
        ImGui::TableSetupColumn( "Frame", ImGuiTableColumnFlags_NoHide | ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_NoResize );
        ImGui::TableSetupColumn( "Function" );
        ImGui::TableSetupColumn( "Location" );
        ImGui::TableSetupColumn( "Image" );
        ImGui::TableHeadersRow();

        bool external = false;
        int fidx = 0;
        int bidx = 0;
        for( auto& entry : cs )
        {
            auto frameData = m_worker.GetCallstackFrame( entry );
            if( !frameData )
            {
                if( !m_showExternalFrames )
                {
                    external = true;
                    continue;
                }
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::Text( "%i", fidx++ );
                ImGui::TableNextColumn();
                char buf[32];
                sprintf( buf, "%p", (void*)m_worker.GetCanonicalPointer( entry ) );
                ImGui::TextUnformatted( buf );
                if( ImGui::IsItemClicked() )
                {
                    ImGui::SetClipboardText( buf );
                }
            }
            else
            {
                const auto fsz = frameData->size;
                for( uint8_t f=0; f<fsz; f++ )
                {
                    const auto& frame = frameData->data[f];
                    auto txt = m_worker.GetString( frame.name );

                    if( fidx == 0 && f != fsz-1 )
                    {
                        auto test = s_tracyStackFrames;
                        bool match = false;
                        do
                        {
                            if( strcmp( txt, *test ) == 0 )
                            {
                                match = true;
                                break;
                            }
                        }
                        while( *++test );
                        if( match ) continue;
                    }

                    auto filename = m_worker.GetString( frame.file );
                    auto image = frameData->imageName.Active() ? m_worker.GetString( frameData->imageName ) : nullptr;

                    if( IsFrameExternal( filename, image ) )
                    {
                        if( !m_showExternalFrames )
                        {
                            if( f == fsz-1 ) fidx++;
                            external = true;
                            continue;
                        }
                    }
                    else
                    {
                        if( external )
                        {
                            ImGui::TableNextRow();
                            ImGui::TableNextColumn();
                            ImGui::PushFont( m_smallFont );
                            TextDisabledUnformatted( "external" );
                            ImGui::PopFont();
                            ImGui::TableNextColumn();
                            TextDisabledUnformatted( "\xe2\x80\xa6" );
                            external = false;
                        }
                    }

                    ImGui::TableNextRow();
                    ImGui::TableNextColumn();
                    bidx++;
                    if( f == fsz-1 )
                    {
                        ImGui::Text( "%i", fidx++ );
                    }
                    else
                    {
                        ImGui::PushFont( m_smallFont );
                        TextDisabledUnformatted( "inline" );
                        ImGui::PopFont();
                    }
                    ImGui::TableNextColumn();
                    {
                        ImGui::PushTextWrapPos( 0.0f );
                        if( txt[0] == '[' )
                        {
                            TextDisabledUnformatted( txt );
                        }
                        else if( m_worker.GetCanonicalPointer( entry ) >> 63 != 0 )
                        {
                            TextColoredUnformatted( 0xFF8888FF, txt );
                        }
                        else if( m_vd.shortenName == ShortenName::Never )
                        {
                            ImGui::TextUnformatted( txt );
                        }
                        else
                        {
                            const auto normalized = ShortenZoneName( ShortenName::OnlyNormalize, txt );
                            ImGui::TextUnformatted( normalized );
                            TooltipNormalizedName( txt, normalized );
                        }
                        ImGui::PopTextWrapPos();
                    }
                    if( ImGui::IsItemClicked() )
                    {
                        ImGui::SetClipboardText( txt );
                    }
                    ImGui::TableNextColumn();
                    ImGui::PushTextWrapPos( 0.0f );
                    float indentVal = 0.f;
                    if( m_callstackBuzzAnim.Match( bidx ) )
                    {
                        const auto time = m_callstackBuzzAnim.Time();
                        indentVal = sin( time * 60.f ) * 10.f * time;
                        ImGui::Indent( indentVal );
                    }
                    switch( m_showCallstackFrameAddress )
                    {
                    case 0:
                        TextDisabledUnformatted( LocationToString( filename, frame.line ) );
                        if( ImGui::IsItemClicked() )
                        {
                            ImGui::SetClipboardText( LocationToString( filename, frame.line ) );
                        }
                        break;
                    case 1:
                        if( entry.sel == 0 )
                        {
                            const auto addr = m_worker.GetCanonicalPointer( entry );
                            ImGui::TextDisabled( "0x%" PRIx64, addr );
                            if( ImGui::IsItemClicked() )
                            {
                                char tmp[32];
                                sprintf( tmp, "0x%" PRIx64, addr );
                                ImGui::SetClipboardText( tmp );
                            }
                        }
                        else
                        {
                            ImGui::TextDisabled( "Custom #%" PRIu64, entry.idx );
                        }
                        break;
                    case 2:
                        if( entry.sel == 0 )
                        {
                            ImGui::TextDisabled( "0x%" PRIx64, frame.symAddr );
                            if( ImGui::IsItemClicked() )
                            {
                                char tmp[32];
                                sprintf( tmp, "0x%" PRIx64, frame.symAddr );
                                ImGui::SetClipboardText( tmp );
                            }
                        }
                        else
                        {
                            ImGui::TextDisabled( "Custom #%" PRIu64, entry.idx );
                        }
                        break;
                    case 3:
                    {
                        const auto sym = m_worker.GetSymbolData( frame.symAddr );
                        if( sym )
                        {
                            const auto symtxt = m_worker.GetString( sym->file );
                            TextDisabledUnformatted( LocationToString( symtxt, sym->line ) );
                            if( ImGui::IsItemClicked() )
                            {
                                ImGui::SetClipboardText( symtxt );
                            }
                        }
                        else
                        {
                            TextDisabledUnformatted( "[unknown]" );
                        }
                        break;
                    }
                    default:
                        assert( false );
                        break;
                    }
                    if( ImGui::IsItemHovered() )
                    {
                        if( m_showCallstackFrameAddress == 3 )
                        {
                            const auto sym = m_worker.GetSymbolData( frame.symAddr );
                            if( sym )
                            {
                                const auto symtxt = m_worker.GetString( sym->file );
                                DrawSourceTooltip( symtxt, sym->line );
                            }
                        }
                        else
                        {
                            DrawSourceTooltip( filename, frame.line );
                        }
                        if( ImGui::IsItemClicked( 1 ) )
                        {
                            if( m_showCallstackFrameAddress == 3 )
                            {
                                const auto sym = m_worker.GetSymbolData( frame.symAddr );
                                if( sym )
                                {
                                    const auto symtxt = m_worker.GetString( sym->file );
                                    if( !ViewDispatch( symtxt, sym->line, frame.symAddr ) )
                                    {
                                        m_callstackBuzzAnim.Enable( bidx, 0.5f );
                                    }
                                }
                                else
                                {
                                    m_callstackBuzzAnim.Enable( bidx, 0.5f );
                                }
                            }
                            else
                            {
                                if( !ViewDispatch( filename, frame.line, frame.symAddr ) )
                                {
                                    m_callstackBuzzAnim.Enable( bidx, 0.5f );
                                }
                            }
                        }
                    }
                    if( indentVal != 0.f )
                    {
                        ImGui::Unindent( indentVal );
                    }
                    ImGui::PopTextWrapPos();
                    ImGui::TableNextColumn();
                    if( image ) TextDisabledUnformatted( image );
                }
            }
        }
        if( external )
        {
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::PushFont( m_smallFont );
            TextDisabledUnformatted( "external" );
            ImGui::PopFont();
            ImGui::TableNextColumn();
            TextDisabledUnformatted( "\xe2\x80\xa6" );
        }
        ImGui::EndTable();
    }
}

void View::SmallCallstackButton( const char* name, uint32_t callstack, int& idx, bool tooltip )
{
    bool hilite = m_callstackInfoWindow == callstack;
    if( hilite )
    {
        SetButtonHighlightColor();
    }
    ImGui::PushID( idx++ );
    if( ImGui::SmallButton( name ) )
    {
        m_callstackInfoWindow = callstack;
    }
    ImGui::PopID();
    if( hilite )
    {
        ImGui::PopStyleColor( 3 );
    }
    if( tooltip && ImGui::IsItemHovered() )
    {
        CallstackTooltip( callstack );
    }
}

void View::DrawCallstackCalls( uint32_t callstack, uint16_t limit ) const
{
    const auto& csdata = m_worker.GetCallstack( callstack );
    const auto cssz = std::min( csdata.size(), limit );
    bool first = true;
    for( uint16_t i=0; i<cssz; i++ )
    {
        const auto frameData = m_worker.GetCallstackFrame( csdata[i] );
        if( !frameData ) break;
        if( first )
        {
            first = false;
        }
        else
        {
            ImGui::SameLine();
            TextDisabledUnformatted( ICON_FA_LEFT_LONG );
            ImGui::SameLine();
        }
        const auto& frame = frameData->data[frameData->size - 1];
        auto txt = m_worker.GetString( frame.name );
        if( txt[0] == '[' )
        {
            TextDisabledUnformatted( txt );
        }
        else if( m_vd.shortenName == ShortenName::Never )
        {
            ImGui::TextUnformatted( txt );
        }
        else
        {
            ImGui::TextUnformatted( ShortenZoneName( ShortenName::Always, txt ) );
        }
    }
}

void View::CallstackTooltip( uint32_t idx )
{
    ImGui::BeginTooltip();
    CallstackTooltipContents( idx );
    ImGui::EndTooltip();
}

void View::CallstackTooltipContents( uint32_t idx )
{
    auto& cs = m_worker.GetCallstack( idx );
    int fidx = 0;
    for( auto& entry : cs )
    {
        auto frameData = m_worker.GetCallstackFrame( entry );
        if( !frameData )
        {
            ImGui::TextDisabled( "%i.", fidx++ );
            ImGui::SameLine();
            ImGui::Text( "%p", (void*)m_worker.GetCanonicalPointer( entry ) );
        }
        else
        {
            const auto fsz = frameData->size;
            for( uint8_t f=0; f<fsz; f++ )
            {
                const auto& frame = frameData->data[f];
                auto txt = m_worker.GetString( frame.name );

                if( fidx == 0 && f != fsz-1 )
                {
                    auto test = s_tracyStackFrames;
                    bool match = false;
                    do
                    {
                        if( strcmp( txt, *test ) == 0 )
                        {
                            match = true;
                            break;
                        }
                    }
                    while( *++test );
                    if( match ) continue;
                }
                if( f == fsz-1 )
                {
                    ImGui::TextDisabled( "%i.", fidx++ );
                }
                else
                {
                    TextDisabledUnformatted( ICON_FA_CARET_RIGHT );
                }
                ImGui::SameLine();
                if( txt[0] == '[' )
                {
                    TextDisabledUnformatted( txt );
                }
                else if( m_worker.GetCanonicalPointer( entry ) >> 63 != 0 )
                {
                    TextColoredUnformatted( 0xFF8888FF, txt );
                }
                else if( m_vd.shortenName == ShortenName::Never )
                {
                    ImGui::TextUnformatted( txt );
                }
                else
                {
                    ImGui::TextUnformatted( ShortenZoneName( ShortenName::OnlyNormalize, txt ) );
                }
                if( frameData->imageName.Active() )
                {
                    ImGui::SameLine();
                    ImGui::PushFont( m_smallFont );
                    ImGui::AlignTextToFramePadding();
                    TextDisabledUnformatted( m_worker.GetString( frameData->imageName ) );
                    ImGui::PopFont();
                }
            }
        }
    }
}

}
