#include "TracyImGui.hpp"
#include "TracyPrint.hpp"
#include "TracyTexture.hpp"
#include "TracyView.hpp"
#include "../Fonts.hpp"

namespace tracy
{

void View::DrawMessages()
{
    const auto& msgs = m_worker.GetMessages();

    const auto scale = GetScale();
    ImGui::SetNextWindowSize( ImVec2( 1200 * scale, 600 * scale ), ImGuiCond_FirstUseEver );
    ImGui::Begin( "Messages", &m_showMessages );
    if( ImGui::GetCurrentWindowRead()->SkipItems ) { ImGui::End(); return; }

    if( msgs.empty() )
    {
        const auto ty = ImGui::GetTextLineHeight();
        ImGui::PushFont( g_fonts.normal, FontBig );
        ImGui::Dummy( ImVec2( 0, ( ImGui::GetContentRegionAvail().y - ImGui::GetTextLineHeight() * 2 ) * 0.5f ) );
        TextCentered( ICON_FA_FISH_FINS );
        TextCentered( "No messages were collected" );
        ImGui::PopFont();
        ImGui::End();
        return;
    }

    ImGui::AlignTextToFramePadding();
    ImGui::Text( ICON_FA_FILTER );
    ImGui::SameLine();
    bool filterChanged = m_messageFilter.m_text.Draw( "##Filter messages", 200 );

    ImGui::SameLine();
    ImGui::Spacing();
    ImGui::SameLine();
    ImGui::SeparatorEx( ImGuiSeparatorFlags_Vertical );

    const auto& style = ImGui::GetStyle();
    const float frameheight = ImGui::GetFrameHeight();
    const ImVec4 filterButtonColor = style.Colors[ImGuiCol_Button];
    const ImVec4 filterButtonColorDisabled{ filterButtonColor.x, filterButtonColor.y, filterButtonColor.z, style.DisabledAlpha };
    const float buttonSpacing = 2 * style.ItemSpacing.x;

    auto FilterButton = [&]( const char* label, ImVec2 size, bool& value, const char* sideText = nullptr ) {
        const bool disabled = !value;
        if( disabled )
        {
            ImGui::PushStyleVar( ImGuiStyleVar_Alpha, style.Alpha * style.DisabledAlpha );
            ImGui::PushStyleColor( ImGuiCol_Button, filterButtonColorDisabled );
        }

        // Make sure button is at least as wide as it is tall.
        if( size.x >= 0 ) size.x = ImMax( ImGui::CalcTextSize( label, nullptr, true ).x + 2.0f * style.FramePadding.x, frameheight );

        // Toggle when button is pressed
        if( ImGui::ButtonEx( label, size, ImGuiButtonFlags_AlignTextBaseLine ) ) 
        {
            value = !value;
            filterChanged = true;
        }

        if( sideText )
        {
            ImGui::SameLine();
            ImGui::TextUnformatted( sideText );
            if( ImGui::IsItemClicked() )
            {
                value = !value;
                filterChanged = true;
            }
        }
        
        if( disabled )
        {
            ImGui::PopStyleColor();
            ImGui::PopStyleVar();
        }
    };

    ImGui::SameLine( 0.0, buttonSpacing );
    TextDisabledUnformatted( "Source" );

    static const char* const sourceNames[] = { "User", "Tracy" };
    static_assert( std::size( sourceNames ) == (size_t)MessageSourceType::COUNT, "Please provide a name for each source" );
    static const char* const sourceIcons[] = { ICON_FA_USER, ICON_FA_MICROSCOPE };
    static_assert( std::size( sourceIcons ) == (size_t)MessageSourceType::COUNT, "Please provide an icon for each source" );
    for( int i=0; i<(int)MessageSourceType::COUNT; i++ )
    {
        ImGui::SameLine();
        FilterButton( sourceIcons[i], ImVec2( frameheight, frameheight ), m_messageFilter.m_showMessageSourceFilter[i] );
        tracy::TooltipIfHovered( sourceNames[i] );
    }

    ImGui::SameLine( 0.0, buttonSpacing );
    TextDisabledUnformatted( "Severity" );

    constexpr const char* severityNames[(size_t)MessageSeverity::COUNT] = { "Trace", "Debug", "Info", "Warning", "Error", "Fatal" };
    constexpr const char* severityIcons[(size_t)MessageSeverity::COUNT] = { ICON_FA_SHOE_PRINTS, ICON_FA_BUG, ICON_FA_INFO, ICON_FA_TRIANGLE_EXCLAMATION, ICON_FA_CIRCLE_XMARK, ICON_FA_SKULL_CROSSBONES };
    static_assert( std::size( severityNames ) == (size_t)MessageSeverity::COUNT, "Please provide a name for each severity" );
    static_assert( std::size( severityIcons ) == (size_t)MessageSeverity::COUNT, "Please provide an icon for each severity" );

    for( int i=0; i<(int)MessageSeverity::COUNT; i++ )
    {
        ImGui::SameLine();

        char buffer[128];
        if( m_visibleMessagesPerSeverity[i] == m_messagesPerSeverity[i] )
        {
            snprintf( buffer, sizeof( buffer ), "%s  %s###%s", severityIcons[i], RealToString( m_messagesPerSeverity[i] ), severityIcons[i] );
        }
        else
        {
            snprintf( buffer, sizeof( buffer ), "%s  %s / %s###%s", severityIcons[i], RealToString( m_visibleMessagesPerSeverity[i] ), RealToString( m_messagesPerSeverity[i] ), severityIcons[i] );
        }
        FilterButton( buffer, ImVec2( 0, 0 ), m_messageFilter.m_showMessageSeverityFilter[i] );
        tracy::TooltipIfHovered( severityNames[i] );
    }
    ImGui::SameLine( 0.0, buttonSpacing );
    if( ImGui::Button( ICON_FA_DELETE_LEFT " Reset" ) )
    {
        m_messageFilter.Clear();
        filterChanged = true;
    }

    if( m_worker.GetFrameImageCount() != 0 )
    {
        ImGui::SameLine();
        ImGui::Spacing();
        ImGui::SameLine();
        ImGui::SeparatorEx( ImGuiSeparatorFlags_Vertical );
        ImGui::SameLine();
        ImGui::Spacing();
        ImGui::SameLine();
        ImGui::Checkbox( ICON_FA_IMAGE " Show frame images", &m_showMessageImages );
    }

    bool threadsChanged = false;
    ImGui::AlignTextToFramePadding();
    auto expand = ImGui::TreeNodeEx( ICON_FA_SHUFFLE " Visible threads:", ImGuiTreeNodeFlags_SpanLabelWidth );
    ImGui::SameLine();
    size_t visibleThreads = 0;
    size_t tsz = 0;
    for( const auto& t : m_threadOrder )
    {
        if( t->messages.empty() ) continue;
        if( VisibleMsgThread( t->id ) ) visibleThreads++;
        tsz++;
    }
    if( visibleThreads == tsz )
    {
        ImGui::AlignTextToFramePadding();
        ImGui::TextDisabled( "(%zu)", tsz );
    }
    else
    {
        ImGui::AlignTextToFramePadding();
        ImGui::TextDisabled( "(%zu/%zu)", visibleThreads, tsz );
    }

    if( expand )
    {
        ImGui::SameLine();
        if( ImGui::SmallButton( "Select all" ) )
        {
            for( const auto& t : m_threadOrder )
            {
                VisibleMsgThread( t->id ) = true;
            }
            threadsChanged = true;
        }
        ImGui::SameLine();
        if( ImGui::SmallButton( "Unselect all" ) )
        {
            for( const auto& t : m_threadOrder )
            {
                VisibleMsgThread( t->id ) = false;
            }
            threadsChanged = true;
        }
    }

    ImGui::SameLine();
    ImGui::Spacing();
    ImGui::SameLine();
    ImGui::AlignTextToFramePadding();
    TextFocused( "Total message count:", RealToString( msgs.size() ) );
    ImGui::SameLine();
    ImGui::Spacing();
    ImGui::SameLine();
    ImGui::AlignTextToFramePadding();
    TextFocused( "Visible messages:", RealToString( m_visibleMessages ) );

    if( expand )
    {
        auto& crash = m_worker.GetCrashEvent();
        int idx = 0;
        for( const auto& t : m_threadOrder )
        {
            if( t->messages.empty() ) continue;
            ImGui::PushID( idx++ );
            const auto threadColor = GetThreadColor( t->id, 0 );
            SmallColorBox( threadColor );
            ImGui::SameLine();
            if( SmallCheckbox( m_worker.GetThreadName( t->id ), &VisibleMsgThread( t->id ) ) )
            {
                threadsChanged = true;
            }
            ImGui::PopID();
            ImGui::SameLine();
            ImGui::TextDisabled( "(%s)", RealToString( t->messages.size() ) );
            if( crash.thread == t->id )
            {
                ImGui::SameLine();
                TextColoredUnformatted( ImVec4( 1.f, 0.2f, 0.2f, 1.f ), ICON_FA_SKULL " Crashed" );
            }
            if( t->isFiber )
            {
                ImGui::SameLine();
                TextColoredUnformatted( ImVec4( 0.2f, 0.6f, 0.2f, 1.f ), "Fiber" );
            }
        }
        ImGui::TreePop();
    }

    if( filterChanged || threadsChanged )
    {
        m_prevMessages = 0;
        m_messagesShowCallstack = false;
        m_msgList.clear();
        for( int& count : m_messagesPerSeverity ) count = 0;
        for( int& count : m_visibleMessagesPerSeverity ) count = 0;
    }

    if( m_prevMessages < msgs.size() )
    {
        bool showCallstack = m_messagesShowCallstack;
        m_msgList.reserve( msgs.size() );
        
        bool isThreadVisible = true;
        uint16_t previousThread = msgs[m_prevMessages]->thread + 1; // Value different from first entry since + 1

        for( size_t i=m_prevMessages; i<msgs.size(); i++ )
        {
            const auto& v = msgs[i];
            if( previousThread != v->thread )
            {
                previousThread = v->thread;
                const auto tid = m_worker.DecompressThread( v->thread );
                isThreadVisible = VisibleMsgThread( tid );
            }
            if( isThreadVisible )
            {
                if( m_messageFilter.PassFilter( *v, m_worker ) )
                {
                    if( !showCallstack && v->callstack.Val() != 0 ) showCallstack = true;
                    m_msgList.push_back_no_space_check( uint32_t( i ) );
                    m_visibleMessagesPerSeverity[(size_t)v->severity]++;
                }
            }
            m_messagesPerSeverity[(size_t)v->severity]++;
        }
        m_messagesShowCallstack = showCallstack;
        m_visibleMessages = m_msgList.size();
        m_prevMessages = msgs.size();
    }

    bool hasCallstack = m_messagesShowCallstack;
    ImGui::Separator();
    ImGui::BeginChild( "##messages" );
    const int colNum = hasCallstack ? 4 : 3;
    if( ImGui::BeginTable( "##messages", colNum, ImGuiTableFlags_Resizable | ImGuiTableFlags_Reorderable | ImGuiTableFlags_ScrollY | ImGuiTableFlags_Hideable ) )
    {
        ImGui::TableSetupScrollFreeze( 0, 1 );
        ImGui::TableSetupColumn( "Time", ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_NoResize );
        ImGui::TableSetupColumn( "Thread" );
        ImGui::TableSetupColumn( "Message" );
        if( hasCallstack ) ImGui::TableSetupColumn( "Call stack" );
        ImGui::TableHeadersRow();

        int idx = 0;
        if( m_msgToFocus )
        {
            for( const auto& msgIdx : m_msgList )
            {
                DrawMessageLine( *msgs[msgIdx], hasCallstack, idx );
            }
        }
        else
        {
            ImGuiListClipper clipper;
            clipper.Begin( m_msgList.size() );
            while( clipper.Step() )
            {
                for( auto i=clipper.DisplayStart; i<clipper.DisplayEnd; i++ )
                {
                    DrawMessageLine( *msgs[m_msgList[i]], hasCallstack, idx );
                }
            }
        }

        if( m_worker.IsConnected() && ImGui::GetScrollY() >= ImGui::GetScrollMaxY() )
        {
            ImGui::SetScrollHereY( 1.f );
        }
        ImGui::EndTable();
    }
    ImGui::EndChild();
    ImGui::End();
}

void View::DrawMessageLine( const MessageData& msg, bool hasCallstack, int& idx )
{
    ImGui::TableNextRow();
    ImGui::TableNextColumn();
    const auto text = m_worker.GetString( msg.ref );
    const auto tid = m_worker.DecompressThread( msg.thread );
    ImGui::PushID( &msg );
    if( ImGui::Selectable( TimeToStringExact( msg.time ), m_msgHighlight == &msg, ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowOverlap ) )
    {
        CenterAtTime( msg.time );
    }
    if( ImGui::IsItemHovered() )
    {
        m_msgHighlight = &msg;

        if( m_showMessageImages )
        {
            const auto frameIdx = m_worker.GetFrameRange( *m_frames, msg.time, msg.time ).first;
            auto fi = m_worker.GetFrameImage( *m_frames, frameIdx );
            if( fi )
            {
                ImGui::BeginTooltip();
                DrawFrameImage( m_FrameTextureCache , *fi );
                ImGui::EndTooltip();
            }
        }
    }
    if( m_msgToFocus == &msg )
    {
        ImGui::SetScrollHereY();
        m_msgToFocus.Decay( nullptr );
        m_messagesScrollBottom = false;
    }
    ImGui::PopID();
    ImGui::TableNextColumn();
    SmallColorBox( GetThreadColor( tid, 0 ) );
    ImGui::SameLine();
    if( m_worker.IsThreadFiber( tid ) )
    {
        TextColoredUnformatted( 0xFF88FF88, m_worker.GetThreadName( tid ) );
    }
    else
    {
        ImGui::TextUnformatted( m_worker.GetThreadName( tid ) );
    }
    ImGui::SameLine();
    ImGui::TextDisabled( "(%s)", RealToString( tid ) );
    ImGui::TableNextColumn();
    auto tend = text;
    while( *tend != '\0' && *tend != '\n' ) tend++;
    ImGui::PushStyleColor( ImGuiCol_Text, msg.color );
    const auto cw = ImGui::GetContentRegionAvail().x;
    const auto tw = ImGui::CalcTextSize( text, tend ).x;
    ImGui::TextUnformatted( text, tend );
    if( tw > cw && ImGui::IsItemHovered() )
    {
        ImGui::SetNextWindowSize( ImVec2( 1000 * GetScale(), 0 ) );
        ImGui::BeginTooltip();
        ImGui::TextWrapped( "%s", text );
        ImGui::EndTooltip();
    }
    ImGui::PopStyleColor();
    if( hasCallstack )
    {
        ImGui::TableNextColumn();
        const auto cs = msg.callstack.Val();
        if( cs != 0 )
        {
            SmallCallstackButton( ICON_FA_ALIGN_JUSTIFY, cs, idx );
            ImGui::SameLine();
            DrawCallstackCalls( cs, 6 );
        }
    }
}

}
