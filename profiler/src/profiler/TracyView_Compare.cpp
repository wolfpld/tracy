#include <numeric>
#include <sstream>

#include "../dtl/dtl.hpp"

#include "TracyImGui.hpp"
#include "TracyFileRead.hpp"
#include "TracyFileselector.hpp"
#include "TracyPrint.hpp"
#include "TracyView.hpp"

namespace tracy
{

extern double s_time;

#ifndef TRACY_NO_STATISTICS
    void View::FindZonesCompare()
    {
        m_compare.match[0] = m_worker.GetMatchingSourceLocation( m_compare.pattern, m_compare.ignoreCase );
        if( !m_compare.match[0].empty() )
        {
            auto it = m_compare.match[0].begin();
            while( it != m_compare.match[0].end() )
            {
                if( m_worker.GetZonesForSourceLocation( *it ).zones.empty() )
                {
                    it = m_compare.match[0].erase( it );
                }
                else
                {
                    ++it;
                }
            }
        }

        m_compare.match[1] = m_compare.second->GetMatchingSourceLocation( m_compare.pattern, m_compare.ignoreCase );
        if( !m_compare.match[1].empty() )
        {
            auto it = m_compare.match[1].begin();
            while( it != m_compare.match[1].end() )
            {
                if( m_compare.second->GetZonesForSourceLocation( *it ).zones.empty() )
                {
                    it = m_compare.match[1].erase( it );
                }
                else
                {
                    ++it;
                }
            }
        }
    }
#endif

bool View::FindMatchingZone( int prev0, int prev1, int flags )
{
    int idx = 0;
    bool found = false;
    auto& srcloc0 = m_worker.GetSourceLocation( m_compare.match[0][m_compare.selMatch[0]] );
    auto& srcloc1 = m_compare.second->GetSourceLocation( m_compare.match[1][m_compare.selMatch[1]] );
    auto string0 = m_worker.GetString( srcloc0.name.active ? srcloc0.name : srcloc0.function );
    auto string1 = m_compare.second->GetString( srcloc1.name.active ? srcloc1.name : srcloc1.function );
    auto file0 = m_worker.GetString( srcloc0.file );
    auto file1 = m_compare.second->GetString( srcloc1.file );
    bool wrongFile = false;
    bool wrongLine = false;
    if( flags & FindMatchingZoneFlagSourceFile )
    {
        wrongFile = strcmp( file0, file1 ) != 0;
    }
    if( flags & FindMatchingZoneFlagLineNum )
    {
        wrongLine = srcloc0.line != srcloc1.line;
    }

    if( strcmp( string0, string1 ) != 0 || wrongFile || wrongLine )
    {
        if( prev0 != m_compare.selMatch[0] )
        {
            for( auto& v : m_compare.match[1] )
            {
                auto& srcloc = m_compare.second->GetSourceLocation( v );
                auto string = m_compare.second->GetString( srcloc.name.active ? srcloc.name : srcloc.function );
                auto file = m_compare.second->GetString( srcloc.file );
                bool sameFile = true;
                bool sameLine = true;
                if( flags & FindMatchingZoneFlagSourceFile )
                {
                    sameFile = strcmp( file0, file ) == 0;
                }
                if( flags & FindMatchingZoneFlagLineNum )
                {
                    sameLine = srcloc0.line == srcloc.line;
                }
                if( strcmp( string0, string ) == 0 && sameFile && sameLine )
                {
                    m_compare.selMatch[1] = idx;
                    found = true;
                    break;
                }
                idx++;
            }
        }
        else
        {
            assert( prev1 != m_compare.selMatch[1] );
            for( auto& v : m_compare.match[0] )
            {
                auto& srcloc = m_worker.GetSourceLocation( v );
                auto string = m_worker.GetString( srcloc.name.active ? srcloc.name : srcloc.function );
                auto file = m_worker.GetString( srcloc.file );
                bool sameFile = true;
                bool sameLine = true;
                if( flags & FindMatchingZoneFlagSourceFile )
                {
                    sameFile = strcmp( file1, file ) == 0;
                }
                if( flags & FindMatchingZoneFlagLineNum )
                {
                    sameLine = srcloc1.line == srcloc.line;
                }
                if( strcmp( string1, string ) == 0 && sameFile && sameLine )
                {
                    m_compare.selMatch[0] = idx;
                    found = true;
                    break;
                }
                idx++;
            }

        }
    }
    return found;
}

static std::vector<std::string> SplitLines( const char* data, size_t sz )
{
    std::vector<std::string> ret;
    auto txt = data;
    for(;;)
    {
        auto end = txt;
        while( *end != '\n' && *end != '\r' && end - data < sz ) end++;
        ret.emplace_back( std::string { txt, end } );
        if( end - data == sz ) break;
        if( *end == '\n' )
        {
            end++;
            if( end - data < sz && *end == '\r' ) end++;
        }
        else if( *end == '\r' )
        {
            end++;
            if( end - data < sz && *end == '\n' ) end++;
        }
        if( end - data == sz ) break;
        txt = end;
    }
    return ret;
}

static void PrintFile( const char* data, size_t sz, uint32_t color )
{
    auto lines = SplitLines( data, sz );
    for( auto& v : lines )
    {
        TextColoredUnformatted( color, v.c_str() );
    }
}

static void PrintDiff( const std::string& diff )
{
    auto lines = SplitLines( diff.data(), diff.size() );
    for( auto& v : lines )
    {
        assert( !v.empty() );
        switch( v[0] )
        {
            case '@': TextColoredUnformatted( 0xFFFFAAAA, v.c_str() ); break;
            case '-': TextColoredUnformatted( 0xFF6666FF, v.c_str() ); break;
            case '+': TextColoredUnformatted( 0xFF66DD66, v.c_str() ); break;
            default:  TextDisabledUnformatted( v.c_str() ); break;
        }
    }
}

static void PrintSpeedupOrSlowdown( double time_this, double time_external, const char *metric )
{
    const char* label;
    const char* time_diff = TimeToString( abs( time_external - time_this ) );
    ImVec4 color;
    double factor = time_this / time_external;
    if( time_external >= time_this )
    {
        label = "less";
        color = ImVec4( 0.1f, 0.6f, 0.1f, 1.0f );
    } else {
        label = "more";
        color = ImVec4( 0.8f, 0.1f, 0.1f, 1.0f );
    }
    ImGui::TextDisabled( "%s:", metric );
    ImGui::SameLine();
    ImGui::TextUnformatted( time_diff );
    ImGui::SameLine();
    TextColoredUnformatted( color, label );
    ImGui::SameLine();
    TextDisabledUnformatted( "than external" );
    ImGui::SameLine();
    ImGui::Spacing();
    ImGui::SameLine();

    TextDisabledUnformatted("(");
    ImGui::SameLine( 0, 0 );
    TextColoredUnformatted( ImVec4( 0xDD/511.f, 0xDD/511.f, 0x22/511.f, 1.f ), ICON_FA_LEMON );
    ImGui::SameLine();
    ImGui::TextDisabled("=  %.2f%%", factor * 100 );
    ImGui::SameLine();
    TextColoredUnformatted( ImVec4( 0xDD/511.f, 0x22/511.f, 0x22/511.f, 1.f ), ICON_FA_GEM );
    ImGui::SameLine( 0, 0 );
    TextDisabledUnformatted(")");
}

void View::DrawCompare()
{
    const auto scale = GetScale();
    ImGui::SetNextWindowSize( ImVec2( 590 * scale, 800 * scale ), ImGuiCond_FirstUseEver );
    ImGui::Begin( "Compare traces", &m_compare.show, ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse );
    if( ImGui::GetCurrentWindowRead()->SkipItems ) { ImGui::End(); return; }
#ifdef TRACY_NO_STATISTICS
    ImGui::TextWrapped( "Collection of statistical data is disabled in this build." );
    ImGui::TextWrapped( "Rebuild without the TRACY_NO_STATISTICS macro to enable trace comparison." );
#elif defined TRACY_NO_FILESELECTOR
    ImGui::TextWrapped( "File selector is disabled in this build." );
    ImGui::TextWrapped( "Rebuild without the TRACY_NO_FILESELECTOR macro to enable trace comparison." );
#else
    if( !m_compare.second )
    {
        ImGui::TextWrapped( "Please load a second trace to compare results." );
        if( ImGui::Button( ICON_FA_FOLDER_OPEN " Open second trace" ) && !m_compare.loadThread.joinable() )
        {
            Fileselector::OpenFile( "tracy", "Tracy Profiler trace file", [this]( const char* fn ) {
                try
                {
                    auto f = std::shared_ptr<tracy::FileRead>( tracy::FileRead::Open( fn ) );
                    if( f )
                    {
                        m_compare.loadThread = std::thread( [this, f] {
                            try
                            {
                                m_compare.second = std::make_unique<Worker>( *f, EventType::SourceCache );
                                m_compare.userData = std::make_unique<UserData>( m_compare.second->GetCaptureProgram().c_str(), m_compare.second->GetCaptureTime() );
                                m_compare.diffDirection = m_worker.GetCaptureTime() < m_compare.second->GetCaptureTime();
                            }
                            catch( const tracy::UnsupportedVersion& e )
                            {
                                m_compare.badVer.state = BadVersionState::UnsupportedVersion;
                                m_compare.badVer.version = e.version;
                            }
                        } );
                    }
                }
                catch( const tracy::NotTracyDump& )
                {
                    m_compare.badVer.state = BadVersionState::BadFile;
                }
                catch( const tracy::FileReadError& )
                {
                    m_compare.badVer.state = BadVersionState::ReadError;
                }
            } );
        }
        tracy::BadVersion( m_compare.badVer, m_bigFont );
        ImGui::End();
        return;
    }

    if( m_compare.loadThread.joinable() ) m_compare.loadThread.join();

    if( !m_worker.AreSourceLocationZonesReady() || !m_compare.second->AreSourceLocationZonesReady() )
    {
        ImGui::TextWrapped( "Please wait, computing data..." );
        DrawWaitingDots( s_time );
        ImGui::End();
        return;
    }

    TextColoredUnformatted( ImVec4( 0xDD/255.f, 0xDD/255.f, 0x22/255.f, 1.f ), ICON_FA_LEMON );
    ImGui::SameLine();
    TextDisabledUnformatted( "This trace:" );
    ImGui::SameLine();
    const auto& desc0 = m_userData.GetDescription();
    if( desc0.empty() )
    {
        ImGui::TextUnformatted( m_worker.GetCaptureName().c_str() );
    }
    else
    {
        ImGui::TextUnformatted( desc0.c_str() );
        ImGui::SameLine();
        ImGui::TextDisabled( "(%s)", m_worker.GetCaptureName().c_str() );
    }

    TextColoredUnformatted( ImVec4( 0xDD/255.f, 0x22/255.f, 0x22/255.f, 1.f ), ICON_FA_GEM );
    ImGui::SameLine();
    TextDisabledUnformatted( "External trace:" );
    ImGui::SameLine();
    const auto& desc1 = m_compare.userData->GetDescription();
    if( desc1.empty() )
    {
        ImGui::TextUnformatted( m_compare.second->GetCaptureName().c_str() );
    }
    else
    {
        ImGui::TextUnformatted( desc1.c_str() );
        ImGui::SameLine();
        ImGui::TextDisabled( "(%s)", m_compare.second->GetCaptureName().c_str() );
    }

    if( ImGui::Button( ICON_FA_TRASH_CAN " Unload" ) )
    {
        m_compare.Reset();
        m_compare.second.reset();
        m_compare.userData.reset();
        ImGui::End();
        return;
    }
    ImGui::SameLine();
    ImGui::Spacing();
    ImGui::SameLine();
    ImGui::Text( "Compare mode: " );
    ImGui::SameLine();
    const auto oldMode = m_compare.compareMode;
    ImGui::RadioButton( "Zones", &m_compare.compareMode, 0 );
    ImGui::SameLine();
    ImGui::RadioButton( "Frames", &m_compare.compareMode, 1 );
    ImGui::SameLine();
    ImGui::RadioButton( "Source diff", &m_compare.compareMode, 2 );
    if( oldMode != m_compare.compareMode )
    {
        m_compare.Reset();
    }

    if( m_compare.compareMode == 2 )
    {
        ImGui::Separator();
        ImGui::BeginChild( "##compare" );

        TextDisabledUnformatted( "Diff direction: " );
        ImGui::SameLine();
        TextColoredUnformatted( ImVec4( 0xDD/255.f, 0xDD/255.f, 0x22/255.f, 1.f ), ICON_FA_LEMON );
        ImGui::SameLine();
        ImGui::Text( " %s ", m_compare.diffDirection ? ICON_FA_ARROW_RIGHT : ICON_FA_ARROW_LEFT );
        ImGui::SameLine();
        TextColoredUnformatted( ImVec4( 0xDD/255.f, 0x22/255.f, 0x22/255.f, 1.f ), ICON_FA_GEM );
        ImGui::SameLine();
        if( ImGui::SmallButton( "Switch" ) )
        {
            m_compare.diffDirection = !m_compare.diffDirection;
            m_compare.Reset();
        }
        ImGui::Separator();

        ImGui::BeginChild( "##diff" );

        const auto& tfc = m_compare.diffDirection ? m_worker.GetSourceFileCache() : m_compare.second->GetSourceFileCache();
        const auto& ofc = m_compare.diffDirection ? m_compare.second->GetSourceFileCache() : m_worker.GetSourceFileCache();

        if( !m_compare.diffDone )
        {
            m_compare.diffDone = true;

            if( !tfc.empty() && !ofc.empty() )
            {
                for( auto& tv : tfc )
                {
                    auto it = ofc.find( tv.first );
                    if( it == ofc.end() )
                    {
                        m_compare.thisUnique.emplace_back( tv.first );
                    }
                    else if( tv.second.len != it->second.len || memcmp( tv.second.data, it->second.data, tv.second.len ) != 0 )
                    {
                        auto src0 = SplitLines( tv.second.data, tv.second.len );
                        auto src1 = SplitLines( it->second.data, it->second.len );
                        dtl::Diff<std::string, std::vector<std::string>> diff { src0, src1 };
                        diff.compose();
                        diff.composeUnifiedHunks();
                        std::ostringstream stream;
                        diff.printUnifiedFormat( stream );
                        m_compare.diffs.emplace_back( std::make_pair( tv.first, stream.str() ) );
                    }
                }
                for( auto& ov : ofc )
                {
                    auto it = tfc.find( ov.first );
                    if( it == tfc.end() )
                    {
                        m_compare.secondUnique.emplace_back( ov.first );
                    }
                }

                std::sort( m_compare.thisUnique.begin(), m_compare.thisUnique.end(), []( const auto& lhs, const auto& rhs ) { return strcmp( lhs, rhs ) < 0; } );
                std::sort( m_compare.secondUnique.begin(), m_compare.secondUnique.end(), []( const auto& lhs, const auto& rhs ) { return strcmp( lhs, rhs ) < 0; } );
                std::sort( m_compare.diffs.begin(), m_compare.diffs.end(), []( const auto& lhs, const auto& rhs ) { return strcmp( lhs.first, rhs.first ) < 0; } );
            }
        }

        if( m_compare.thisUnique.empty() && m_compare.secondUnique.empty() && m_compare.diffs.empty() )
        {
            ImGui::TextUnformatted( "Source files are identical." );
        }
        else
        {
            if( !m_compare.thisUnique.empty() )
            {
                const auto expand = ImGui::TreeNode( ICON_FA_FILE_CIRCLE_XMARK " Deleted files" );
                ImGui::SameLine();
                ImGui::TextDisabled( "(%s)", RealToString( m_compare.thisUnique.size() ) );
                if( expand )
                {
                    for( auto& v : m_compare.thisUnique )
                    {
                        if( ImGui::TreeNode( v ) )
                        {
                            auto it = tfc.find( v );
                            assert( it != tfc.end() );
                            ImGui::PushFont( m_fixedFont );
                            ImGui::PushStyleVar( ImGuiStyleVar_ItemSpacing, ImVec2( 0, 0 ) );
                            PrintFile( it->second.data, it->second.len, 0xFF6666FF );
                            ImGui::PopStyleVar();
                            ImGui::PopFont();
                            ImGui::TreePop();
                        }
                    }
                    ImGui::TreePop();
                }
            }
            if( !m_compare.secondUnique.empty() )
            {
                const auto expand = ImGui::TreeNode( ICON_FA_FILE_CIRCLE_PLUS " Added files" );
                ImGui::SameLine();
                ImGui::TextDisabled( "(%s)", RealToString( m_compare.secondUnique.size() ) );
                if( expand )
                {
                    for( auto& v : m_compare.secondUnique )
                    {
                        if( ImGui::TreeNode( v ) )
                        {
                            auto it = ofc.find( v );
                            assert( it != ofc.end() );
                            ImGui::PushFont( m_fixedFont );
                            ImGui::PushStyleVar( ImGuiStyleVar_ItemSpacing, ImVec2( 0, 0 ) );
                            PrintFile( it->second.data, it->second.len, 0xFF66DD66 );
                            ImGui::PopStyleVar();
                            ImGui::PopFont();
                            ImGui::TreePop();
                        }
                    }
                    ImGui::TreePop();
                }
            }
            if( !m_compare.diffs.empty() )
            {
                const auto expand = ImGui::TreeNodeEx( ICON_FA_FILE_PEN " Changed files", ImGuiTreeNodeFlags_DefaultOpen );
                ImGui::SameLine();
                ImGui::TextDisabled( "(%s)", RealToString( m_compare.diffs.size() ) );
                if( expand )
                {
                    for( auto& v : m_compare.diffs )
                    {
                        if( ImGui::TreeNode( v.first ) )
                        {
                            ImGui::PushFont( m_fixedFont );
                            ImGui::PushStyleVar( ImGuiStyleVar_ItemSpacing, ImVec2( 0, 0 ) );
                            PrintDiff( v.second );
                            ImGui::PopStyleVar();
                            ImGui::PopFont();
                            ImGui::TreePop();
                        }
                    }

                    ImGui::TreePop();
                }
            }
        }
        ImGui::EndChild();
    }
    else
    {
        bool findClicked = false;

        if( m_compare.compareMode == 0 )
        {
            ImGui::PushItemWidth( -0.01f );
            findClicked |= ImGui::InputTextWithHint( "###compare", "Enter zone name to search for", m_compare.pattern, 1024, ImGuiInputTextFlags_EnterReturnsTrue );
            ImGui::PopItemWidth();

            findClicked |= ImGui::Button( ICON_FA_MAGNIFYING_GLASS " Find" );
            ImGui::SameLine();

            if( ImGui::Button( ICON_FA_BAN " Clear" ) )
            {
                m_compare.Reset();
            }
            ImGui::SameLine();
            ImGui::Checkbox( "Ignore case", &m_compare.ignoreCase );

            if( findClicked )
            {
                m_compare.Reset();
                FindZonesCompare();
            }

            if( m_compare.match[0].empty() && m_compare.match[1].empty() )
            {
                ImGui::End();
                return;
            }

            ImGui::Separator();
            ImGui::BeginChild( "##compare" );

            if( ImGui::TreeNodeEx( "Matched source locations", ImGuiTreeNodeFlags_DefaultOpen ) )
            {
                ImGui::SameLine();
                SmallCheckbox( "Link selection", &m_compare.link );

                ImGui::Separator();
                ImGui::Columns( 2 );
                TextColoredUnformatted( ImVec4( 0xDD/255.f, 0xDD/255.f, 0x22/255.f, 1.f ), ICON_FA_LEMON );
                ImGui::SameLine();
                ImGui::TextUnformatted( "This trace" );
                ImGui::SameLine();
                ImGui::TextDisabled( "(%zu)", m_compare.match[0].size() );
                ImGui::NextColumn();
                TextColoredUnformatted( ImVec4( 0xDD/255.f, 0x22/255.f, 0x22/255.f, 1.f ), ICON_FA_GEM );
                ImGui::SameLine();
                ImGui::TextUnformatted( "External trace" );
                ImGui::SameLine();
                ImGui::TextDisabled( "(%zu)", m_compare.match[1].size() );
                ImGui::Separator();
                ImGui::NextColumn();

                const auto prev0 = m_compare.selMatch[0];
                int idx = 0;
                for( auto& v : m_compare.match[0] )
                {
                    auto& srcloc = m_worker.GetSourceLocation( v );
                    auto& zones = m_worker.GetZonesForSourceLocation( v ).zones;
                    SmallColorBox( GetSrcLocColor( srcloc, 0 ) );
                    ImGui::SameLine();
                    ImGui::PushID( idx );
                    ImGui::PushStyleVar( ImGuiStyleVar_FramePadding, ImVec2( 0, 0 ) );
                    ImGui::RadioButton( m_worker.GetString( srcloc.name.active ? srcloc.name : srcloc.function ), &m_compare.selMatch[0], idx++ );
                    ImGui::PopStyleVar();
                    ImGui::SameLine();
                    ImGui::TextColored( ImVec4( 0.5, 0.5, 0.5, 1 ), "(%s) %s", RealToString( zones.size() ), LocationToString( m_worker.GetString( srcloc.file ), srcloc.line ) );
                    ImGui::PopID();
                }
                ImGui::NextColumn();

                const auto prev1 = m_compare.selMatch[1];
                idx = 0;
                for( auto& v : m_compare.match[1] )
                {
                    auto& srcloc = m_compare.second->GetSourceLocation( v );
                    auto& zones = m_compare.second->GetZonesForSourceLocation( v ).zones;
                    ImGui::PushID( -1 - idx );
                    ImGui::PushStyleVar( ImGuiStyleVar_FramePadding, ImVec2( 0, 0 ) );
                    ImGui::RadioButton( m_compare.second->GetString( srcloc.name.active ? srcloc.name : srcloc.function ), &m_compare.selMatch[1], idx++ );
                    ImGui::PopStyleVar();
                    ImGui::SameLine();
                    ImGui::TextColored( ImVec4( 0.5, 0.5, 0.5, 1 ), "(%s) %s", RealToString( zones.size() ), LocationToString( m_compare.second->GetString( srcloc.file ), srcloc.line ) );
                    ImGui::PopID();
                }
                ImGui::NextColumn();
                ImGui::EndColumns();
                ImGui::TreePop();

                if( prev0 != m_compare.selMatch[0] || prev1 != m_compare.selMatch[1] )
                {
                    m_compare.ResetSelection();

                    if( m_compare.link )
                    {
                        if( !FindMatchingZone( prev0, prev1, FindMatchingZoneFlagSourceFile | FindMatchingZoneFlagLineNum ) )
                        {
                            if( !FindMatchingZone( prev0, prev1, FindMatchingZoneFlagSourceFile ) )
                            {
                                FindMatchingZone( prev0, prev1, FindMatchingZoneFlagDefault );
                            }
                        }
                    }
                }
            }

            if( m_compare.match[0].empty() || m_compare.match[1].empty() )
            {
                ImGui::Separator();
                ImGui::TextWrapped( "Both traces must have matches." );
                ImGui::End();
                return;
            }
        }
        else
        {
            assert( m_compare.compareMode == 1 );

            ImGui::Separator();
            ImGui::BeginChild( "##compare" );
            if( ImGui::TreeNodeEx( "Frame sets", ImGuiTreeNodeFlags_DefaultOpen ) )
            {
                const auto& f0 = m_worker.GetFrames();
                const auto& f1 = m_compare.second->GetFrames();

                ImGui::SameLine();
                SmallCheckbox( "Link selection", &m_compare.link );

                ImGui::Separator();
                ImGui::Columns( 2 );
                TextColoredUnformatted( ImVec4( 0xDD/255.f, 0xDD/255.f, 0x22/255.f, 1.f ), ICON_FA_LEMON );
                ImGui::SameLine();
                ImGui::TextUnformatted( "This trace" );
                ImGui::SameLine();
                ImGui::TextDisabled( "(%zu)", f0.size() );
                ImGui::NextColumn();
                TextColoredUnformatted( ImVec4( 0xDD/255.f, 0x22/255.f, 0x22/255.f, 1.f ), ICON_FA_GEM );
                ImGui::SameLine();
                ImGui::TextUnformatted( "External trace" );
                ImGui::SameLine();
                ImGui::TextDisabled( "(%zu)", f1.size() );
                ImGui::Separator();
                ImGui::NextColumn();

                const auto prev0 = m_compare.selMatch[0];
                int idx = 0;
                for( auto& v : f0 )
                {
                    const auto name = GetFrameSetName( *v );
                    ImGui::PushID( -1 - idx );
                    ImGui::RadioButton( name, &m_compare.selMatch[0], idx++ );
                    ImGui::SameLine();
                    ImGui::TextDisabled( "(%s)", RealToString( v->frames.size() ) );
                    ImGui::PopID();
                }
                ImGui::NextColumn();

                const auto prev1 = m_compare.selMatch[1];
                idx = 0;
                for( auto& v : f1 )
                {
                    const auto name = GetFrameSetName( *v, *m_compare.second );
                    ImGui::PushID( idx );
                    ImGui::RadioButton( name, &m_compare.selMatch[1], idx++ );
                    ImGui::SameLine();
                    ImGui::TextDisabled( "(%s)", RealToString( v->frames.size() ) );
                    ImGui::PopID();
                }
                ImGui::NextColumn();
                ImGui::EndColumns();
                ImGui::TreePop();

                if( prev0 != m_compare.selMatch[0] || prev1 != m_compare.selMatch[1] )
                {
                    m_compare.ResetSelection();

                    if( m_compare.link )
                    {
                        auto string0 = GetFrameSetName( *f0[m_compare.selMatch[0]] );
                        auto string1 = GetFrameSetName( *f1[m_compare.selMatch[1]], *m_compare.second );

                        if( strcmp( string0, string1 ) != 0 )
                        {
                            idx = 0;
                            if( prev0 != m_compare.selMatch[0] )
                            {
                                for( auto& v : f1 )
                                {
                                    auto string = GetFrameSetName( *v, *m_compare.second );
                                    if( strcmp( string0, string ) == 0 )
                                    {
                                        m_compare.selMatch[1] = idx;
                                        break;
                                    }
                                    idx++;
                                }
                            }
                            else
                            {
                                assert( prev1 != m_compare.selMatch[1] );
                                for( auto& v : f0 )
                                {
                                    auto string = GetFrameSetName( *v );
                                    if( strcmp( string1, string ) == 0 )
                                    {
                                        m_compare.selMatch[0] = idx;
                                        break;
                                    }
                                    idx++;
                                }
                            }
                        }
                    }
                }
            }
        }

        ImGui::Separator();
        if( ImGui::TreeNodeEx( "Histogram", ImGuiTreeNodeFlags_DefaultOpen ) )
        {
            const auto ty = ImGui::GetTextLineHeight();

            int64_t tmin, tmax;
            size_t size0, size1;
            int64_t total0, total1;
            double sumSq0, sumSq1;

            if( m_compare.compareMode == 0 )
            {
                auto& zoneData0 = m_worker.GetZonesForSourceLocation( m_compare.match[0][m_compare.selMatch[0]] );
                auto& zoneData1 = m_compare.second->GetZonesForSourceLocation( m_compare.match[1][m_compare.selMatch[1]] );
                auto& zones0 = zoneData0.zones;
                auto& zones1 = zoneData1.zones;
                zones0.ensure_sorted();
                zones1.ensure_sorted();

                tmin = std::min( zoneData0.min, zoneData1.min );
                tmax = std::max( zoneData0.max, zoneData1.max );

                size0 = zones0.size();
                size1 = zones1.size();
                total0 = zoneData0.total;
                total1 = zoneData1.total;
                sumSq0 = zoneData0.sumSq;
                sumSq1 = zoneData1.sumSq;

                const size_t zsz[2] = { size0, size1 };
                for( int k=0; k<2; k++ )
                {
                    if( m_compare.sortedNum[k] != zsz[k] )
                    {
                        auto& zones = k == 0 ? zones0 : zones1;
                        auto& vec = m_compare.sorted[k];
                        vec.reserve( zsz[k] );
                        int64_t total = m_compare.total[k];
                        size_t i;
                        for( i=m_compare.sortedNum[k]; i<zsz[k]; i++ )
                        {
                            auto& zone = *zones[i].Zone();
                            const auto t = zone.End() - zone.Start();
                            vec.emplace_back( t );
                            total += t;
                        }
                        auto mid = vec.begin() + m_compare.sortedNum[k];
                        pdqsort_branchless( mid, vec.end() );
                        std::inplace_merge( vec.begin(), mid, vec.end() );

                        m_compare.average[k] = float( total ) / i;
                        m_compare.median[k] = vec[i/2];
                        m_compare.total[k] = total;
                        m_compare.sortedNum[k] = i;
                    }
                }
            }
            else
            {
                assert( m_compare.compareMode == 1 );

                const auto& f0 = m_worker.GetFrames()[m_compare.selMatch[0]];
                const auto& f1 = m_compare.second->GetFrames()[m_compare.selMatch[1]];

                tmin = std::min( f0->min, f1->min );
                tmax = std::max( f0->max, f1->max );

                size0 = f0->frames.size();
                size1 = f1->frames.size();
                total0 = f0->total;
                total1 = f1->total;
                sumSq0 = f0->sumSq;
                sumSq1 = f1->sumSq;

                const size_t zsz[2] = { size0, size1 };
                for( int k=0; k<2; k++ )
                {
                    if( m_compare.sortedNum[k] != zsz[k] )
                    {
                        auto& frameSet = k == 0 ? f0 : f1;
                        auto worker = k == 0 ? &m_worker : m_compare.second.get();
                        auto& vec = m_compare.sorted[k];
                        vec.reserve( zsz[k] );
                        int64_t total = m_compare.total[k];
                        size_t i;
                        for( i=m_compare.sortedNum[k]; i<zsz[k]; i++ )
                        {
                            if( worker->GetFrameEnd( *frameSet, i ) == worker->GetLastTime() ) break;
                            const auto t = worker->GetFrameTime( *frameSet, i );
                            vec.emplace_back( t );
                            total += t;
                        }
                        auto mid = vec.begin() + m_compare.sortedNum[k];
                        pdqsort_branchless( mid, vec.end() );
                        std::inplace_merge( vec.begin(), mid, vec.end() );

                        m_compare.average[k] = float( total ) / i;
                        m_compare.median[k] = vec[i/2];
                        m_compare.total[k] = total;
                        m_compare.sortedNum[k] = i;
                    }
                }
            }

            if( tmin != std::numeric_limits<int64_t>::max() )
            {
                TextDisabledUnformatted( "Minimum values in bin:" );
                ImGui::SameLine();
                ImGui::SetNextItemWidth( ImGui::CalcTextSize( "123456890123456" ).x );
                ImGui::PushStyleVar( ImGuiStyleVar_FramePadding, ImVec2( 1, 1 ) );
                ImGui::InputInt( "##minBinVal", &m_compare.minBinVal );
                if( m_compare.minBinVal < 1 ) m_compare.minBinVal = 1;
                ImGui::SameLine();
                if( ImGui::Button( "Reset" ) ) m_compare.minBinVal = 1;
                ImGui::PopStyleVar();

                SmallCheckbox( "Log values", &m_compare.logVal );
                ImGui::SameLine();
                SmallCheckbox( "Log time", &m_compare.logTime );
                ImGui::SameLine();
                SmallCheckbox( "Cumulate time", &m_compare.cumulateTime );
                ImGui::SameLine();
                DrawHelpMarker( "Show total time taken by calls in each bin instead of call counts." );
                ImGui::SameLine();
                SmallCheckbox( "Normalize values", &m_compare.normalize );
                ImGui::SameLine();
                DrawHelpMarker( "Normalization will rescale the total time of the external trace to match the count of this trace. This will skew reported total values!" );

                const auto cumulateTime = m_compare.cumulateTime;

                if( tmax - tmin > 0 )
                {
                    const auto w = ImGui::GetContentRegionAvail().x;

                    const auto numBins = int64_t( w - 4 );
                    if( numBins > 1 )
                    {
                        if( numBins > m_compare.numBins )
                        {
                            m_compare.numBins = numBins;
                            m_compare.bins = std::make_unique<CompVal[]>( numBins );
                            m_compare.binTime = std::make_unique<CompVal[]>( numBins );
                        }

                        const auto& bins = m_compare.bins;
                        const auto& binTime = m_compare.binTime;

                        memset( bins.get(), 0, sizeof( CompVal ) * numBins );
                        memset( binTime.get(), 0, sizeof( CompVal ) * numBins );

                        double adj0 = 1;
                        double adj1 = 1;
                        if( m_compare.normalize )
                        {
                            if( size0 > size1 )
                            {
                                adj1 = double( size0 ) / size1;
                            }
                            else
                            {
                                adj0 = double( size1 ) / size0;
                            }
                        }

                        const auto& sorted = m_compare.sorted;
                        auto sBegin0 = sorted[0].begin();
                        auto sBegin1 = sorted[1].begin();
                        auto sEnd0 = sorted[0].end();
                        auto sEnd1 = sorted[1].end();

                        if( m_compare.minBinVal > 1 )
                        {
                            if( m_compare.logTime )
                            {
                                const auto tMinLog = log10( tmin );
                                const auto zmax = ( log10( tmax ) - tMinLog ) / numBins;
                                int64_t i;
                                for( i=0; i<numBins; i++ )
                                {
                                    const auto nextBinVal = int64_t( pow( 10.0, tMinLog + ( i+1 ) * zmax ) );
                                    auto nit0 = std::lower_bound( sBegin0, sEnd0, nextBinVal );
                                    auto nit1 = std::lower_bound( sBegin1, sEnd1, nextBinVal );
                                    const auto distance0 = std::distance( sBegin0, nit0 );
                                    const auto distance1 = std::distance( sBegin1, nit1 );
                                    if( distance0 >= m_compare.minBinVal || distance1 >= m_compare.minBinVal ) break;
                                    sBegin0 = nit0;
                                    sBegin1 = nit1;
                                }
                                for( int64_t j=numBins-1; j>i; j-- )
                                {
                                    const auto nextBinVal = int64_t( pow( 10.0, tMinLog + ( j-1 ) * zmax ) );
                                    auto nit0 = std::lower_bound( sBegin0, sEnd0, nextBinVal );
                                    auto nit1 = std::lower_bound( sBegin1, sEnd1, nextBinVal );
                                    const auto distance0 = std::distance( nit0, sEnd0 );
                                    const auto distance1 = std::distance( nit1, sEnd1 );
                                    if( distance0 >= m_compare.minBinVal || distance1 >= m_compare.minBinVal ) break;
                                    sEnd0 = nit0;
                                    sEnd1 = nit1;
                                }
                            }
                            else
                            {
                                const auto zmax = tmax - tmin;
                                int64_t i;
                                for( i=0; i<numBins; i++ )
                                {
                                    const auto nextBinVal = tmin + ( i+1 ) * zmax / numBins;
                                    auto nit0 = std::lower_bound( sBegin0, sEnd0, nextBinVal );
                                    auto nit1 = std::lower_bound( sBegin1, sEnd1, nextBinVal );
                                    const auto distance0 = std::distance( sBegin0, nit0 );
                                    const auto distance1 = std::distance( sBegin1, nit1 );
                                    if( distance0 >= m_compare.minBinVal || distance1 >= m_compare.minBinVal ) break;
                                    sBegin0 = nit0;
                                    sBegin1 = nit1;
                                }
                                for( int64_t j=numBins-1; j>i; j-- )
                                {
                                    const auto nextBinVal = tmin + ( j-1 ) * zmax / numBins;
                                    auto nit0 = std::lower_bound( sBegin0, sEnd0, nextBinVal );
                                    auto nit1 = std::lower_bound( sBegin1, sEnd1, nextBinVal );
                                    const auto distance0 = std::distance( nit0, sEnd0 );
                                    const auto distance1 = std::distance( nit1, sEnd1 );
                                    if( distance0 >= m_compare.minBinVal || distance1 >= m_compare.minBinVal ) break;
                                    sEnd0 = nit0;
                                    sEnd1 = nit1;
                                }
                            }

                            tmin = std::min( *sBegin0, *sBegin1 );
                            tmax = std::max( *(sEnd0-1), *(sEnd1-1) );
                        }

                        auto zit0 = sBegin0;
                        auto zit1 = sBegin1;
                        if( m_compare.logTime )
                        {
                            const auto tMinLog = log10( tmin );
                            const auto zmax = ( log10( tmax ) - tMinLog ) / numBins;
                            for( int64_t i=0; i<numBins; i++ )
                            {
                                const auto nextBinVal = int64_t( pow( 10.0, tMinLog + ( i+1 ) * zmax ) );
                                auto nit0 = std::lower_bound( zit0, sEnd0, nextBinVal );
                                auto nit1 = std::lower_bound( zit1, sEnd1, nextBinVal );
                                bins[i].v0 += adj0 * std::distance( zit0, nit0 );
                                bins[i].v1 += adj1 * std::distance( zit1, nit1 );
                                binTime[i].v0 += adj0 * std::accumulate( zit0, nit0, int64_t( 0 ) );
                                binTime[i].v1 += adj1 * std::accumulate( zit1, nit1, int64_t( 0 ) );
                                zit0 = nit0;
                                zit1 = nit1;
                            }
                        }
                        else
                        {
                            const auto zmax = tmax - tmin;
                            for( int64_t i=0; i<numBins; i++ )
                            {
                                const auto nextBinVal = tmin + ( i+1 ) * zmax / numBins;
                                auto nit0 = std::lower_bound( zit0, sEnd0, nextBinVal );
                                auto nit1 = std::lower_bound( zit1, sEnd1, nextBinVal );
                                bins[i].v0 += adj0 * std::distance( zit0, nit0 );
                                bins[i].v1 += adj1 * std::distance( zit1, nit1 );
                                binTime[i].v0 += adj0 * std::accumulate( zit0, nit0, int64_t( 0 ) );
                                binTime[i].v1 += adj1 * std::accumulate( zit1, nit1, int64_t( 0 ) );
                                zit0 = nit0;
                                zit1 = nit1;
                            }
                        }

                        double maxVal;
                        if( cumulateTime )
                        {
                            maxVal = std::max( binTime[0].v0, binTime[0].v1 );
                            for( int i=1; i<numBins; i++ )
                            {
                                maxVal = std::max( { maxVal, binTime[i].v0, binTime[i].v1 } );
                            }
                        }
                        else
                        {
                            maxVal = std::max( bins[0].v0, bins[0].v1 );
                            for( int i=1; i<numBins; i++ )
                            {
                                maxVal = std::max( { maxVal, bins[i].v0, bins[i].v1 } );
                            }
                        }

                        TextColoredUnformatted( ImVec4( 0xDD/511.f, 0xDD/511.f, 0x22/511.f, 1.f ), ICON_FA_LEMON );
                        ImGui::SameLine();
                        TextFocused( "Total time (this):", TimeToString( total0 * adj0 ) );
                        ImGui::SameLine();
                        ImGui::Spacing();
                        ImGui::SameLine();
                        TextColoredUnformatted( ImVec4( 0xDD/511.f, 0x22/511.f, 0x22/511.f, 1.f ), ICON_FA_GEM );
                        ImGui::SameLine();
                        TextFocused( "Total time (ext.):", TimeToString( total1 * adj1 ) );
                        ImGui::Indent();
                        PrintSpeedupOrSlowdown( total0 * adj0, total1 * adj1, "Total time" );
                        ImGui::Unindent();
                        TextFocused( "Max counts:", cumulateTime ? TimeToString( maxVal ) : RealToString( floor( maxVal ) ) );

                        TextColoredUnformatted( ImVec4( 0xDD/511.f, 0xDD/511.f, 0x22/511.f, 1.f ), ICON_FA_LEMON );
                        ImGui::SameLine();
                        TextFocused( "Mean time (this):", TimeToString( m_compare.average[0] ) );
                        ImGui::SameLine();
                        ImGui::Spacing();
                        ImGui::SameLine();
                        TextColoredUnformatted( ImVec4( 0xDD/511.f, 0xDD/511.f, 0x22/511.f, 1.f ), ICON_FA_LEMON );
                        ImGui::SameLine();
                        TextFocused( "Median time (this):", TimeToString( m_compare.median[0] ) );
                        if( sorted[0].size() > 1 )
                        {
                            const auto sz = sorted[0].size();
                            const auto avg = m_compare.average[0];
                            const auto ss = sumSq0 - 2. * total0 * avg + avg * avg * sz;
                            const auto sd = sqrt( ss / ( sz - 1 ) );

                            ImGui::SameLine();
                            ImGui::Spacing();
                            ImGui::SameLine();
                            TextColoredUnformatted( ImVec4( 0xDD/511.f, 0xDD/511.f, 0x22/511.f, 1.f ), ICON_FA_LEMON );
                            ImGui::SameLine();
                            TextFocused( "\xcf\x83 (this):", TimeToString( sd ) );
                            TooltipIfHovered( "Standard deviation" );
                        }


                        TextColoredUnformatted( ImVec4( 0xDD/511.f, 0x22/511.f, 0x22/511.f, 1.f ), ICON_FA_GEM );
                        ImGui::SameLine();
                        TextFocused( "Mean time (ext.):", TimeToString( m_compare.average[1] ) );
                        ImGui::SameLine();
                        ImGui::Spacing();
                        ImGui::SameLine();
                        TextColoredUnformatted( ImVec4( 0xDD/511.f, 0x22/511.f, 0x22/511.f, 1.f ), ICON_FA_GEM );
                        ImGui::SameLine();
                        TextFocused( "Median time (ext.):", TimeToString( m_compare.median[1] ) );
                        if( sorted[1].size() > 1 )
                        {
                            const auto sz = sorted[1].size();
                            const auto avg = m_compare.average[1];
                            const auto ss = sumSq1 - 2. * total1 * avg + avg * avg * sz;
                            const auto sd = sqrt( ss / ( sz - 1 ) );

                            ImGui::SameLine();
                            ImGui::Spacing();
                            ImGui::SameLine();
                            TextColoredUnformatted( ImVec4( 0xDD/511.f, 0x22/511.f, 0x22/511.f, 1.f ), ICON_FA_GEM );
                            ImGui::SameLine();
                            TextFocused( "\xcf\x83 (ext.):", TimeToString( sd ) );
                            TooltipIfHovered( "Standard deviation" );
                        }
                        ImGui::Indent();
                        PrintSpeedupOrSlowdown( m_compare.average[0], m_compare.average[1], "Mean time" );
                        PrintSpeedupOrSlowdown( m_compare.median[0], m_compare.median[1], "Median time" );
                        ImGui::Unindent();

                        ImGui::PushStyleColor( ImGuiCol_Text, ImVec4( 0xDD/511.f, 0xDD/511.f, 0x22/511.f, 1.f ) );
                        ImGui::PushStyleColor( ImGuiCol_Button, ImVec4( 0xDD/255.f, 0xDD/255.f, 0x22/255.f, 1.f ) );
                        ImGui::PushStyleColor( ImGuiCol_ButtonHovered, ImVec4( 0xDD/255.f, 0xDD/255.f, 0x22/255.f, 1.f ) );
                        ImGui::PushStyleColor( ImGuiCol_ButtonActive, ImVec4( 0xDD/255.f, 0xDD/255.f, 0x22/255.f, 1.f ) );
                        ImGui::Button( ICON_FA_LEMON );
                        ImGui::PopStyleColor( 4 );
                        ImGui::SameLine();
                        ImGui::TextUnformatted( "This trace" );
                        ImGui::SameLine();
                        ImGui::Spacing();
                        ImGui::SameLine();

                        ImGui::PushStyleColor( ImGuiCol_Text, ImVec4( 0xDD/511.f, 0x22/511.f, 0x22/511.f, 1.f ) );
                        ImGui::PushStyleColor( ImGuiCol_Button, ImVec4( 0xDD/255.f, 0x22/255.f, 0x22/255.f, 1.f ) );
                        ImGui::PushStyleColor( ImGuiCol_ButtonHovered, ImVec4( 0xDD/255.f, 0x22/255.f, 0x22/255.f, 1.f ) );
                        ImGui::PushStyleColor( ImGuiCol_ButtonActive, ImVec4( 0xDD/255.f, 0x22/255.f, 0x22/255.f, 1.f ) );
                        ImGui::Button( ICON_FA_GEM );
                        ImGui::PopStyleColor( 4 );
                        ImGui::SameLine();
                        ImGui::TextUnformatted( "External trace" );
                        ImGui::SameLine();
                        ImGui::Spacing();
                        ImGui::SameLine();

                        ImGui::ColorButton( "c3", ImVec4( 0x44/255.f, 0xBB/255.f, 0xBB/255.f, 1.f ), ImGuiColorEditFlags_NoTooltip | ImGuiColorEditFlags_NoDragDrop );
                        ImGui::SameLine();
                        ImGui::TextUnformatted( "Overlap" );

                        const auto Height = 200 * scale;
                        const auto wpos = ImGui::GetCursorScreenPos();
                        const auto dpos = wpos + ImVec2( 0.5f, 0.5f );

                        ImGui::InvisibleButton( "##histogram", ImVec2( w, Height + round( ty * 2.5 ) ) );
                        const bool hover = ImGui::IsItemHovered();

                        auto draw = ImGui::GetWindowDrawList();
                        draw->AddRectFilled( wpos, wpos + ImVec2( w, Height ), 0x22FFFFFF );
                        draw->AddRect( wpos, wpos + ImVec2( w, Height ), 0x88FFFFFF );

                        if( m_compare.logVal )
                        {
                            const auto hAdj = double( Height - 4 ) / log10( maxVal + 1 );
                            for( int i=0; i<numBins; i++ )
                            {
                                const auto val0 = cumulateTime ? binTime[i].v0 : bins[i].v0;
                                const auto val1 = cumulateTime ? binTime[i].v1 : bins[i].v1;
                                if( val0 > 0 || val1 > 0 )
                                {
                                    const auto val = std::min( val0, val1 );
                                    if( val > 0 )
                                    {
                                        DrawLine( draw, dpos + ImVec2( 2+i, Height-3 ), dpos + ImVec2( 2+i, Height-3 - log10( val + 1 ) * hAdj ), 0xFFBBBB44 );
                                    }
                                    if( val1 == val )
                                    {
                                        DrawLine( draw, dpos + ImVec2( 2+i, Height-3 - log10( val + 1 ) * hAdj ), dpos + ImVec2( 2+i, Height-3 - log10( val0 + 1 ) * hAdj ), 0xFF22DDDD );
                                    }
                                    else
                                    {
                                        DrawLine( draw, dpos + ImVec2( 2+i, Height-3 - log10( val + 1 ) * hAdj ), dpos + ImVec2( 2+i, Height-3 - log10( val1 + 1 ) * hAdj ), 0xFF2222DD );
                                    }
                                }
                            }
                        }
                        else
                        {
                            const auto hAdj = double( Height - 4 ) / maxVal;
                            for( int i=0; i<numBins; i++ )
                            {
                                const auto val0 = cumulateTime ? binTime[i].v0 : bins[i].v0;
                                const auto val1 = cumulateTime ? binTime[i].v1 : bins[i].v1;
                                if( val0 > 0 || val1 > 0 )
                                {
                                    const auto val = std::min( val0, val1 );
                                    if( val > 0 )
                                    {
                                        DrawLine( draw, dpos + ImVec2( 2+i, Height-3 ), dpos + ImVec2( 2+i, Height-3 - val * hAdj ), 0xFFBBBB44 );
                                    }
                                    if( val1 == val )
                                    {
                                        DrawLine( draw, dpos + ImVec2( 2+i, Height-3 - val * hAdj ), dpos + ImVec2( 2+i, Height-3 - val0 * hAdj ), 0xFF22DDDD );
                                    }
                                    else
                                    {
                                        DrawLine( draw, dpos + ImVec2( 2+i, Height-3 - val * hAdj ), dpos + ImVec2( 2+i, Height-3 - val1 * hAdj ), 0xFF2222DD );
                                    }
                                }
                            }
                        }

                        const auto xoff = 2;
                        const auto yoff = Height + 1;

                        DrawHistogramMinMaxLabel( draw, tmin, tmax, wpos + ImVec2( 0, yoff ), w, ty );

                        const auto ty05 = round( ty * 0.5f );
                        const auto ty025 = round( ty * 0.25f );
                        if( m_compare.logTime )
                        {
                            const auto ltmin = log10( tmin );
                            const auto ltmax = log10( tmax );
                            const auto start = int( floor( ltmin ) );
                            const auto end = int( ceil( ltmax ) );

                            const auto range = ltmax - ltmin;
                            const auto step = w / range;
                            auto offset = start - ltmin;
                            int tw = 0;
                            int tx = 0;

                            auto tt = int64_t( pow( 10, start ) );

                            static const double logticks[] = { log10( 2 ), log10( 3 ), log10( 4 ), log10( 5 ), log10( 6 ), log10( 7 ), log10( 8 ), log10( 9 ) };

                            for( int i=start; i<=end; i++ )
                            {
                                const auto x = ( i - start + offset ) * step;

                                if( x >= 0 )
                                {
                                    DrawLine( draw, dpos + ImVec2( x, yoff ), dpos + ImVec2( x, yoff + ty05 ), 0x66FFFFFF );
                                    if( tw == 0 || x > tx + tw + ty * 1.1 )
                                    {
                                        tx = x;
                                        auto txt = TimeToString( tt );
                                        draw->AddText( wpos + ImVec2( x, yoff + ty05 ), 0x66FFFFFF, txt );
                                        tw = ImGui::CalcTextSize( txt ).x;
                                    }
                                }

                                for( int j=0; j<8; j++ )
                                {
                                    const auto xoff = x + logticks[j] * step;
                                    if( xoff >= 0 )
                                    {
                                        DrawLine( draw, dpos + ImVec2( xoff, yoff ), dpos + ImVec2( xoff, yoff + ty025 ), 0x66FFFFFF );
                                    }
                                }

                                tt *= 10;
                            }
                        }
                        else
                        {
                            const auto pxns = numBins / double( tmax - tmin );
                            const auto nspx = 1.0 / pxns;
                            const auto scale = std::max<float>( 0.0f, round( log10( nspx ) + 2 ) );
                            const auto step = pow( 10, scale );

                            const auto dx = step * pxns;
                            double x = 0;
                            int tw = 0;
                            int tx = 0;

                            const auto sstep = step / 10.0;
                            const auto sdx = dx / 10.0;

                            static const double linelen[] = { 0.5, 0.25, 0.25, 0.25, 0.25, 0.375, 0.25, 0.25, 0.25, 0.25 };

                            int64_t tt = int64_t( ceil( tmin / sstep ) * sstep );
                            const auto diff = tmin / sstep - int64_t( tmin / sstep );
                            const auto xo = ( diff == 0 ? 0 : ( ( 1 - diff ) * sstep * pxns ) ) + xoff;
                            int iter = int( ceil( ( tmin - int64_t( tmin / step ) * step ) / sstep ) );

                            while( x < numBins )
                            {
                                DrawLine( draw, dpos + ImVec2( xo + x, yoff ), dpos + ImVec2( xo + x, yoff + round( ty * linelen[iter] ) ), 0x66FFFFFF );
                                if( iter == 0 && ( tw == 0 || x > tx + tw + ty * 1.1 ) )
                                {
                                    tx = x;
                                    auto txt = TimeToString( tt );
                                    draw->AddText( wpos + ImVec2( xo + x, yoff + ty05 ), 0x66FFFFFF, txt );
                                    tw = ImGui::CalcTextSize( txt ).x;
                                }

                                iter = ( iter + 1 ) % 10;
                                x += sdx;
                                tt += sstep;
                            }
                        }

                        if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( 2, 2 ), wpos + ImVec2( w-2, Height + round( ty * 1.5 ) ) ) )
                        {
                            const auto ltmin = log10( tmin );
                            const auto ltmax = log10( tmax );

                            auto& io = ImGui::GetIO();
                            DrawLine( draw, ImVec2( io.MousePos.x + 0.5f, dpos.y ), ImVec2( io.MousePos.x + 0.5f, dpos.y+Height-2 ), 0x33FFFFFF );

                            const auto bin = int64_t( io.MousePos.x - wpos.x - 2 );
                            int64_t t0, t1;
                            if( m_compare.logTime )
                            {
                                t0 = int64_t( pow( 10, ltmin + double( bin )   / numBins * ( ltmax - ltmin ) ) );
                                t1 = int64_t( pow( 10, ltmin + double( bin+1 ) / numBins * ( ltmax - ltmin ) ) );
                            }
                            else
                            {
                                t0 = int64_t( tmin + double( bin )   / numBins * ( tmax - tmin ) );
                                t1 = int64_t( tmin + double( bin+1 ) / numBins * ( tmax - tmin ) );
                            }

                            int64_t tBefore[2] = { 0, 0 };
                            for( int i=0; i<bin; i++ )
                            {
                                tBefore[0] += binTime[i].v0;
                                tBefore[1] += binTime[i].v1;
                            }

                            int64_t tAfter[2] = { 0, 0 };
                            for( int i=bin+1; i<numBins; i++ )
                            {
                                tAfter[0] += binTime[i].v0;
                                tAfter[1] += binTime[i].v1;
                            }

                            ImGui::BeginTooltip();
                            TextDisabledUnformatted( "Time range:" );
                            ImGui::SameLine();
                            ImGui::Text( "%s - %s", TimeToString( t0 ), TimeToString( t1 ) );
                            TextDisabledUnformatted( "Count:" );
                            ImGui::SameLine();
                            ImGui::Text( "%s / %s", RealToString( floor( bins[bin].v0 ) ), RealToString( floor( bins[bin].v1 ) ) );
                            TextDisabledUnformatted( "Time spent in bin:" );
                            ImGui::SameLine();
                            ImGui::Text( "%s / %s", TimeToString( binTime[bin].v0 ), TimeToString( binTime[bin].v1 ) );
                            TextDisabledUnformatted( "Time spent in the left bins:" );
                            ImGui::SameLine();
                            ImGui::Text( "%s / %s", TimeToString( tBefore[0] ), TimeToString( tBefore[1] ) );
                            TextDisabledUnformatted( "Time spent in the right bins:" );
                            ImGui::SameLine();
                            ImGui::Text( "%s / %s", TimeToString( tAfter[0] ), TimeToString( tAfter[1] ) );
                            TextDisabledUnformatted( "(Data is displayed as:" );
                            ImGui::SameLine();
                            TextColoredUnformatted( ImVec4( 0xDD/511.f, 0xDD/511.f, 0x22/511.f, 1.f ), ICON_FA_LEMON );
                            ImGui::SameLine();
                            TextDisabledUnformatted( "[this trace] /" );
                            ImGui::SameLine();
                            TextColoredUnformatted( ImVec4( 0xDD/511.f, 0x22/511.f, 0x22/511.f, 1.f ), ICON_FA_GEM );
                            ImGui::SameLine();
                            TextDisabledUnformatted( "[external trace])" );
                            ImGui::EndTooltip();
                        }
                    }
                }
            }
            ImGui::TreePop();
        }
    }

    ImGui::EndChild();
#endif
    ImGui::End();
}

}
