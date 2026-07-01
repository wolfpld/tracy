#include <inttypes.h>
#include <nlohmann/json.hpp>
#include <sstream>

#include "../public/common/TracyStackFrames.hpp"
#include "TracyConfig.hpp"
#include "TracyImGui.hpp"
#include "TracyMouse.hpp"
#include "TracyPrint.hpp"
#include "TracyUtility.hpp"
#include "TracyView.hpp"
#include "../Fonts.hpp"

namespace tracy
{

extern double s_time;

void View::DrawCallstackWindow()
{
    bool show = true;
    const auto scale = GetScale();
    ImGui::SetNextWindowSize( ImVec2( 1400 * scale, 500 * scale ), ImGuiCond_FirstUseEver );
    ImGui::Begin( "Call stack", &show, ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse );
    if( !ImGui::GetCurrentWindowRead()->SkipItems )
    {
        DrawCallstackTable( m_callstackView.id, {
            .thread = m_callstackView.thread,
            .wait = m_callstackView.wait,
            .entryStacks = true,
            .showThread = true,
        } );
    }
    ImGui::End();
    if( !show ) m_callstackView = {};
}

void View::DrawCallstackTable( uint32_t callstack, const CallstackTableParams& params )
{
    auto& crash = m_worker.GetCrashEvent();
    auto& cs = m_worker.GetCallstack( callstack );

    DrawCallstackTable( cs.data(), cs.size(), {
        .thread = params.thread,
        .wait = params.wait,
        .entryStacks = params.entryStacks,
        .showThread = params.showThread,
        .hasCrashed = crash.thread != 0 && crash.callstack == callstack,
        .callstack = callstack,
    } );
}

void View::DrawCallstackTable( const CallstackFrameId* data, size_t size, const CallstackTableParams& params )
{
    if( ClipboardButton() )
    {
        std::ostringstream s;
        int fidx = 0;
        for( size_t i = 0; i < size; i++ )
        {
            auto& entry = data[i];
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
    if( s_config.llm )
    {
        auto Attach = [this, data, size, &params]() {
            auto json = GetCallstackJson( data, size );
            if( params.hasCrashed )
            {
                auto& crash = m_worker.GetCrashEvent();
                json["crashed"] = true;
                if( crash.message ) json["crash_reason"] = m_worker.GetString( crash.message );
                auto threadName = m_worker.GetThreadName( crash.thread );
                if( strcmp( threadName, "???" ) != 0 ) json["thread_name"] = threadName;
                json["thread_id"] = crash.thread;
            }
            else
            {
                auto threadName = m_worker.GetThreadName( params.thread );
                if( strcmp( threadName, "???" ) != 0 ) json["thread_name"] = threadName;
                json["thread_id"] = params.thread;
            }
            if( params.callstack >= 0 ) json["id"] = params.callstack;
            if( params.wait.time != 0 )
            {
                json["wait_time"] = TimeToString( params.wait.time );
                if( params.wait.reasonCode ) json["wait_reason"] = params.wait.reasonCode;
                if( params.wait.reason ) json["wait_reason_hint"] = params.wait.reason;
                if( params.wait.stateCode ) json["wait_state"] = params.wait.stateCode;
                if( params.wait.state ) json["wait_state_hint"] = params.wait.state;
            }

            AddLlmAttachment( json );
        };

        ImGui::SameLine();
        if( ImGui::SmallButton( ICON_FA_ROBOT ) )
        {
            Attach();
        }
        if( ImGui::IsItemHovered() && IsMouseClicked( ImGuiMouseButton_Right ) )
        {
            ImGui::OpenPopup( "##callstackllm" );
        }
        if( ImGui::BeginPopup( "##callstackllm" ) )
        {
            if( params.hasCrashed && ImGui::Selectable( "How to fix this crash?" ) )
            {
                Attach();
                AddLlmQuery( "How to fix this crash?" );
                ImGui::CloseCurrentPopup();
            }
            if( ImGui::Selectable( "What is program doing at this moment?" ) )
            {
                Attach();
                AddLlmQuery( "What is program doing at this moment?" );
                ImGui::CloseCurrentPopup();
            }
            if( ImGui::Selectable( "Walk me through the details of this callstack, step by step, explaining the code." ) )
            {
                Attach();
                AddLlmQuery( "Walk me through the details of this callstack, step by step, explaining the code." );
                ImGui::CloseCurrentPopup();
            }
            ImGui::EndPopup();
        }
    }
    ImGui::SameLine();
    ImGui::Spacing();
    ImGui::SameLine();
    if( params.wait.time != 0 )
    {
        SmallCheckbox( ICON_FA_SHIELD_HALVED " External", &m_showExternalFramesWaitStacks );
    }
    else
    {
        SmallCheckbox( ICON_FA_SHIELD_HALVED " External", &m_showExternalFrames );
    }
    ImGui::SameLine();
    ImGui::Spacing();
    ImGui::SameLine();
    SmallCheckbox( ICON_FA_SCISSORS " Short images", &m_shortImageNames );
    ImGui::SameLine();
    ImGui::Spacing();
    ImGui::SameLine();
    ImGui::TextUnformatted( " Frame at:" );
    ImGui::SameLine();
    ImGui::PushStyleVar( ImGuiStyleVar_FramePadding, ImVec2( 0, 0 ) );
    ImGui::SetNextItemWidth( ImGui::CalcTextSize( "Symbol address xxx" ).x );
    ImGui::Combo( "##frameat", &m_showCallstackFrameAddress, "Source code\0Return address\0Symbol address\0Entry point\0" );

    if( params.hasCrashed )
    {
        ImGui::SameLine();
        ImGui::Spacing();
        ImGui::SameLine();
        TextColoredUnformatted( ImVec4( 1.f, 0.2f, 0.2f, 1.f ), ICON_FA_SKULL " Crash" );
        if( ImGui::IsItemHovered() )
        {
            CrashTooltip();
            if( ImGui::IsItemClicked() )
            {
                auto& crash = m_worker.GetCrashEvent();
                CenterAtTime( crash.time );
            }
        }
    }

    if( params.wait.time != 0 )
    {
        ImGui::SameLine();
        ImGui::Spacing();
        ImGui::SameLine();
        TextColoredUnformatted( ImVec4( 0.6f, 0.6f, 1.f, 1.f ), ICON_FA_HOURGLASS_HALF " Wait stack" );
        if( ImGui::IsItemHovered() )
        {
            ImGui::BeginTooltip();
            TextFocused( "Time:", TimeToString( params.wait.time ) );
            if( params.wait.reasonCode )
            {
                TextFocused( "Reason:", params.wait.reasonCode );
                ImGui::SameLine();
                TextDisabledUnformatted( params.wait.reason );
            }
            if( params.wait.stateCode )
            {
                TextFocused( "State:", params.wait.stateCode );
                ImGui::SameLine();
                TextDisabledUnformatted( params.wait.state );
            }
            ImGui::EndTooltip();
        }
    }

    if( params.entryStacks && m_worker.AreCallstackSamplesReady() )
    {
        auto frame = m_worker.GetCallstackFrame( *data );
        if( frame && frame->data[0].symAddr != 0 )
        {
            auto sym = m_worker.GetSymbolStats( frame->data[0].symAddr );
            if( sym && !sym->parents.empty() )
            {
                ImGui::SameLine();
                ImGui::Spacing();
                ImGui::SameLine();
                if( ImGui::Button( ICON_FA_ARROW_DOWN_SHORT_WIDE " Entry stacks" ) )
                {
                    ShowSampleParents( frame->data[0].symAddr, true );
                }
            }
        }
    }
    ImGui::PopStyleVar();

#ifndef __EMSCRIPTEN__
    bool clicked = false;
    if( s_config.llm && params.callstack >= 0 )
    {
        bool force = false;
        if( s_config.llmAnnotateCallstacks )
        {
            std::lock_guard lock( m_callstackDescLock );
            auto it = m_callstackDesc.find( params.callstack );
            if( it == m_callstackDesc.end() ) force = true;
        }
        ImGui::SameLine();
        ImGui::Spacing();
        ImGui::SameLine();
        bool clicked = false;
        if( ImGui::SmallButton( ICON_FA_TAG ) || force )
        {
            nlohmann::json req = {
                {
                    { "role", "system" },
                    { "content", "You are a helpful assistant. You analyze callstacks and provide a short description of what the program is doing at this moment. Your reply must be less than 100 characters." }
                },
                {
                    { "role", "user" },
                    { "content", GetCallstackJson( data, size )["frames"].dump() }
                }
            };

            m_llm.QueueFastMessageLocking( req, [this, callstack = params.callstack] (nlohmann::json res) {
                if( res.contains( "choices" ) )
                {
                    auto& choices = res["choices"];
                    if( choices.is_array() && !choices.empty() )
                    {
                        auto& c0 = choices[0];
                        if( c0.contains( "message" ) )
                        {
                            auto& msg = c0["message"];
                            if( msg.contains( "role" ) && msg.contains( "content" ) )
                            {
                                auto& role = msg["role"];
                                auto& content = msg["content"];
                                if( role.is_string() && content.is_string() && msg["role"].get_ref<const std::string&>() == "assistant" )
                                {
                                    auto& str = msg["content"].get_ref<const std::string&>();
                                    if( str.size() <= 120 )
                                    {
                                        if( str.find( '\n' ) != std::string::npos || str.find( '\r' ) != std::string::npos )
                                        {
                                            auto tmp = str;
                                            std::ranges::replace( tmp, '\n', ' ' );
                                            std::ranges::replace( tmp, '\r', ' ' );

                                            std::lock_guard lock( m_callstackDescLock );
                                            m_callstackDesc[callstack] = tmp;
                                        }
                                        else
                                        {
                                            std::lock_guard lock( m_callstackDescLock );
                                            m_callstackDesc[callstack] = str;
                                        }
                                        return;
                                    }
                                }
                            }
                        }
                    }
                }

                if( res.contains( "error" ) )
                {
                    auto& err = res["error"];
                    if( err.contains( "message" ) )
                    {
                        auto& msg = err["message"];
                        if( msg.is_string() )
                        {
                            std::lock_guard lock( m_callstackDescLock );
                            m_callstackDesc[callstack] = "<error> " + msg.get_ref<const std::string&>();
                            return;
                        }
                    }
                }

                std::lock_guard lock( m_callstackDescLock );
                m_callstackDesc[callstack] = "<error>";
            } );
        }
    }
#endif

    if( params.showThread && params.thread != 0 )
    {
        ImGui::SameLine();
        ImGui::Spacing();
        ImGui::SameLine();

        ImGui::SeparatorEx( ImGuiSeparatorFlags_Vertical );

        ImGui::SameLine();
        ImGui::Spacing();
        ImGui::SameLine();

        SmallColorBox( GetThreadColor( params.thread, 0 ) );
        ImGui::SameLine();
        TextFocused( "Thread:", m_worker.GetThreadName( params.thread ) );
        ImGui::SameLine();
        ImGui::TextDisabled( "(%s)", RealToString( params.thread ) );
        if( m_worker.IsThreadFiber( params.thread ) )
        {
            ImGui::SameLine();
            TextColoredUnformatted( ImVec4( 0.2f, 0.6f, 0.2f, 1.f ), "Fiber" );
        }
    }

#ifndef __EMSCRIPTEN__
    if( s_config.llm && params.callstack >= 0 )
    {
        std::lock_guard lock( m_callstackDescLock );
        auto it = m_callstackDesc.find( params.callstack );
        if( it != m_callstackDesc.end() )
        {
            TextDisabledUnformatted( ICON_FA_HAND_POINT_RIGHT );
            ImGui::SameLine();
            if( strcmp( it->second.c_str(), "…" ) == 0 )
            {
                DrawWaitingDots( s_time, true, true );
            }
            else if( strncmp( it->second.c_str(), "<error>", 7 ) == 0 )
            {
                TextColoredUnformatted( ImVec4( 1.0f, 0.3f, 0.3f, 0.5f ), it->second.c_str() );
            }
            else
            {
                TextDisabledUnformatted( it->second.c_str() );
            }
            if( clicked ) it->second = "…";
        }
        else if( clicked )
        {
            m_callstackDesc.emplace( params.callstack, "…" );
        }
    }
#endif

    ImGui::Separator();
    if( ImGui::BeginTable( "##callstack", 4, ImGuiTableFlags_Resizable | ImGuiTableFlags_Reorderable | ImGuiTableFlags_Hideable | ImGuiTableFlags_Borders | ImGuiTableFlags_ScrollY ) )
    {
        ImGui::TableSetupScrollFreeze( 0, 1 );
        ImGui::TableSetupColumn( "Frame", ImGuiTableColumnFlags_NoHide | ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_NoResize );
        ImGui::TableSetupColumn( "Function" );
        ImGui::TableSetupColumn( "Location" );
        ImGui::TableSetupColumn( "Image" );
        ImGui::TableHeadersRow();

        const bool showExternal = params.wait.time != 0 ? m_showExternalFramesWaitStacks : m_showExternalFrames;

        int external = 0;
        int fidx = 0;
        int bidx = 0;
        for( size_t i = 0; i < size; i++ )
        {
            auto& entry = data[i];
            auto frameData = m_worker.GetCallstackFrame( entry );
            if( !frameData )
            {
                if( !showExternal )
                {
                    external++;
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

                    const bool isExternal = m_worker.IsFrameExternal( frame.file, frameData->imageName );
                    if( isExternal )
                    {
                        if( !showExternal )
                        {
                            if( f == fsz-1 ) fidx++;
                            external++;
                            continue;
                        }
                    }
                    else if( external != 0 )
                    {
                        ImGui::TableNextRow();
                        ImGui::TableNextColumn();
                        ImGui::PushFont( g_fonts.normal, FontSmall );
                        TextDisabledUnformatted( "external" );
                        ImGui::TableNextColumn();
                        if( external == 1 )
                        {
                            TextDisabledUnformatted( "1 frame" );
                        }
                        else
                        {
                            ImGui::TextDisabled( "%i frames", external );
                        }
                        ImGui::PopFont();
                        external = 0;
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
                        ImGui::PushFont( g_fonts.normal, FontSmall );
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
                        else if( isExternal )
                        {
                            if( m_vd.shortenName == ShortenName::Never )
                            {
                                TextDisabledUnformatted( txt );
                            }
                            else
                            {
                                const auto normalized = ShortenZoneName( ShortenName::OnlyNormalize, txt );
                                TextDisabledUnformatted( normalized );
                                TooltipNormalizedName( txt, normalized );
                            }
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
                    auto filename = m_worker.GetString( frame.file );
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
                    if( frameData->imageName.Active() )
                    {
                        auto image = m_worker.GetString( frameData->imageName );
                        const char* end = image + strlen( image );

                        if( m_shortImageNames )
                        {
                            const char* ptr = end - 1;
                            while( ptr > image && *ptr != '/' && *ptr != '\\' ) ptr--;
                            if( *ptr == '/' || *ptr == '\\' ) ptr++;
                            const auto cw = ImGui::GetContentRegionAvail().x;
                            const auto tw = ImGui::CalcTextSize( image, end ).x;
                            TextDisabledUnformatted( ptr );
                            if( ptr != image || tw > cw ) TooltipIfHovered( image );
                        }
                        else
                        {
                            const auto cw = ImGui::GetContentRegionAvail().x;
                            const auto tw = ImGui::CalcTextSize( image, end ).x;
                            TextDisabledUnformatted( image );
                            if( tw > cw ) TooltipIfHovered( image );
                        }
                    }
                }
            }
        }
        if( external != 0 )
        {
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::PushFont( g_fonts.normal, FontSmall );
            TextDisabledUnformatted( "external" );
            ImGui::TableNextColumn();
            if( external == 1 )
            {
                TextDisabledUnformatted( "1 frame" );
            }
            else
            {
                ImGui::TextDisabled( "%i frames", external );
            }
            ImGui::PopFont();
        }
        ImGui::EndTable();
    }
}

void View::SmallCallstackButton( const char* name, uint32_t callstack, int& idx, uint64_t tid, bool tooltip )
{
    bool hilite = m_callstackView.id == callstack;
    if( hilite )
    {
        SetButtonHighlightColor();
    }
    ImGui::PushID( idx++ );
    if( ImGui::SmallButton( name ) )
    {
        m_callstackView = {
            .id = callstack,
            .thread = tid
        };
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
    DrawCallstackCalls( csdata.data(), csdata.size(), limit );
}

void View::DrawCallstackCalls( const CallstackFrameId* data, size_t size, uint16_t limit ) const
{
    bool first = true;
    int i;
    for( i = 0; i < size; i++ )
    {
        const auto& v = data[i];
        const auto frameData = m_worker.GetCallstackFrame( v );
        if( !frameData ) break;
        const auto& frame = frameData->data[frameData->size - 1];
        if( m_worker.IsFrameExternal( frame.file, frameData->imageName ) ) continue;
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
        if( --limit == 0 ) break;
    }
    if( limit == 0 )
    {
        bool framesLeft = false;
        while( ++i < size )
        {
            const auto& v = data[i];
            const auto frameData = m_worker.GetCallstackFrame( v );
            if( !frameData ) break;
            const auto& frame = frameData->data[frameData->size - 1];
            if( m_worker.IsFrameExternal( frame.file, frameData->imageName ) ) continue;
            framesLeft = true;
            break;
        }
        if( framesLeft )
        {
            ImGui::SameLine();
            TextDisabledUnformatted( ICON_FA_LEFT_LONG );
            ImGui::SameLine();
            TextDisabledUnformatted( ICON_FA_ELLIPSIS );
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
                else if( m_worker.IsFrameExternal( frame.file, frameData->imageName ) )
                {
                    if( m_vd.shortenName == ShortenName::Never )
                    {
                        TextDisabledUnformatted( txt );
                    }
                    else
                    {
                        const auto normalized = ShortenZoneName( ShortenName::OnlyNormalize, txt );
                        TextDisabledUnformatted( normalized );
                        TooltipNormalizedName( txt, normalized );
                    }
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
                    ImGui::PushFont( g_fonts.normal, FontSmall );
                    ImGui::AlignTextToFramePadding();
                    TextDisabledUnformatted( m_worker.GetString( frameData->imageName ) );
                    ImGui::PopFont();
                }
            }
        }
    }
}

}
