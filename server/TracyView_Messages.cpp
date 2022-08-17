#include "TracyImGui.hpp"
#include "TracyPrint.hpp"
#include "TracyTexture.hpp"
#include "TracyView.hpp"

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
        ImGui::TextUnformatted( "No messages were collected." );
        ImGui::End();
        return;
    }

    size_t tsz = 0;
    for( const auto& t : m_threadOrder ) if( !t->messages.empty() ) tsz++;

    bool filterChanged = m_messageFilter.Draw( ICON_FA_FILTER " Filter messages", 200 );
    ImGui::SameLine();
    if( ImGui::Button( ICON_FA_DELETE_LEFT " Clear" ) )
    {
        m_messageFilter.Clear();
        filterChanged = true;
    }
    ImGui::SameLine();
    ImGui::Spacing();
    ImGui::SameLine();
    TextFocused( "Total message count:", RealToString( msgs.size() ) );
    ImGui::SameLine();
    ImGui::Spacing();
    ImGui::SameLine();
    TextFocused( "Visible messages:", RealToString( m_visibleMessages ) );
    if( m_worker.GetFrameImageCount() != 0 )
    {
        ImGui::SameLine();
        ImGui::Spacing();
        ImGui::SameLine();
        ImGui::Checkbox( ICON_FA_IMAGE " Show frame images", &m_showMessageImages );
    }

    bool threadsChanged = false;
    auto expand = ImGui::TreeNode( ICON_FA_SHUFFLE " Visible threads:" );
    ImGui::SameLine();
    ImGui::TextDisabled( "(%zu)", tsz );
    if( expand )
    {
        auto& crash = m_worker.GetCrashEvent();

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

    const bool msgsChanged = msgs.size() != m_prevMessages;
    if( filterChanged || threadsChanged )
    {
        bool showCallstack = false;
        m_msgList.reserve( msgs.size() );
        m_msgList.clear();
        if( m_messageFilter.IsActive() )
        {
            for( size_t i=0; i<msgs.size(); i++ )
            {
                const auto& v = msgs[i];
                const auto tid = m_worker.DecompressThread( v->thread );
                if( VisibleMsgThread( tid ) )
                {
                    const auto text = m_worker.GetString( msgs[i]->ref );
                    if( m_messageFilter.PassFilter( text ) )
                    {
                        if( !showCallstack && msgs[i]->callstack.Val() != 0 ) showCallstack = true;
                        m_msgList.push_back_no_space_check( uint32_t( i ) );
                    }
                }
            }
        }
        else
        {
            for( size_t i=0; i<msgs.size(); i++ )
            {
                const auto& v = msgs[i];
                const auto tid = m_worker.DecompressThread( v->thread );
                if( VisibleMsgThread( tid ) )
                {
                    if( !showCallstack && msgs[i]->callstack.Val() != 0 ) showCallstack = true;
                    m_msgList.push_back_no_space_check( uint32_t( i ) );
                }
            }
        }
        m_messagesShowCallstack = showCallstack;
        m_visibleMessages = m_msgList.size();
        if( msgsChanged ) m_prevMessages = msgs.size();
    }
    else if( msgsChanged )
    {
        assert( m_prevMessages < msgs.size() );
        bool showCallstack = m_messagesShowCallstack;
        m_msgList.reserve( msgs.size() );
        if( m_messageFilter.IsActive() )
        {
            for( size_t i=m_prevMessages; i<msgs.size(); i++ )
            {
                const auto& v = msgs[i];
                const auto tid = m_worker.DecompressThread( v->thread );
                if( VisibleMsgThread( tid ) )
                {
                    const auto text = m_worker.GetString( msgs[i]->ref );
                    if( m_messageFilter.PassFilter( text ) )
                    {
                        if( !showCallstack && msgs[i]->callstack.Val() != 0 ) showCallstack = true;
                        m_msgList.push_back_no_space_check( uint32_t( i ) );
                    }
                }
            }
        }
        else
        {
            for( size_t i=m_prevMessages; i<msgs.size(); i++ )
            {
                const auto& v = msgs[i];
                const auto tid = m_worker.DecompressThread( v->thread );
                if( VisibleMsgThread( tid ) )
                {
                    if( !showCallstack && msgs[i]->callstack.Val() != 0 ) showCallstack = true;
                    m_msgList.push_back_no_space_check( uint32_t( i ) );
                }
            }
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
    if( ImGui::Selectable( TimeToStringExact( msg.time ), m_msgHighlight == &msg, ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowItemOverlap ) )
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
                if( fi != m_frameTexturePtr )
                {
                    if( !m_frameTexture ) m_frameTexture = MakeTexture();
                    UpdateTexture( m_frameTexture, m_worker.UnpackFrameImage( *fi ), fi->w, fi->h );
                    m_frameTexturePtr = fi;
                }
                if( fi->flip )
                {
                    ImGui::Image( m_frameTexture, ImVec2( fi->w, fi->h ), ImVec2( 0, 1 ), ImVec2( 1, 0 ) );
                }
                else
                {
                    ImGui::Image( m_frameTexture, ImVec2( fi->w, fi->h ) );
                }
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
