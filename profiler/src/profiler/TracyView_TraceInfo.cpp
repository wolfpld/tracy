#include <inttypes.h>

#include "TracyImGui.hpp"
#include "TracyNameGen.hpp"
#include "TracyPrint.hpp"
#include "TracyView.hpp"
#include "tracy_pdqsort.h"
#include "../Fonts.hpp"

namespace tracy
{

void View::DrawInfo()
{
    const auto scale = GetScale();
    ImGui::SetNextWindowSize( ImVec2( 400 * scale, 650 * scale ), ImGuiCond_FirstUseEver );
    ImGui::Begin( "Trace information", &m_showInfo, ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse );
    if( ImGui::GetCurrentWindowRead()->SkipItems ) { ImGui::End(); return; }
    ImGui::PushFont( g_fonts.normal, FontBig );
    TextFocused( "Program:", m_worker.GetCaptureProgram().c_str() );
    ImGui::PopFont();
    const auto exectime = m_worker.GetExecutableTime();
    if( exectime != 0 )
    {
        char etmp[64];
        time_t et = exectime;
        auto elt = localtime( &et );
        strftime( etmp, 64, "%F %T", elt );
        TextFocused( "Build time:", etmp );
    }
    {
        char dtmp[64];
        time_t date = m_worker.GetCaptureTime();
        auto lt = localtime( &date );
        strftime( dtmp, 64, "%F %T", lt );
        TextFocused( "Capture time:", dtmp );
    }
    if( !m_filename.empty() )
    {
        TextFocused( "File:", m_filename.c_str() );
        if( m_userData.Valid() )
        {
            ImGui::SameLine();
            auto sidecarPublic = m_userData.IsSidecarPublic();
            if( SmallCheckbox( ICON_FA_USER_GEAR " Public sidecar", &sidecarPublic ) )
            {
                m_userData.SetSidecarPublic( sidecarPublic );
            }
        }
    }
    {
        const auto& desc = m_userData.GetDescription();
        const auto descsz = std::min<size_t>( 255, desc.size() );
        char buf[256];
        buf[descsz] = '\0';
        memcpy( buf, desc.c_str(), descsz );

        const char* buttonText = ICON_FA_DICE;
        auto buttonSize = ImGui::CalcTextSize( buttonText );
        buttonSize.x += ImGui::GetStyle().FramePadding.x * 2.0f + ImGui::GetStyle().ItemSpacing.x;
        ImGui::SetNextItemWidth( ImGui::GetContentRegionAvail().x - buttonSize.x );
        bool changed = ImGui::InputTextWithHint( "##traceDesc", "Enter description of the trace", buf, 256 );
        ImGui::SameLine();
        if( ImGui::Button( buttonText ) )
        {
            changed = true;
            const auto name = GenerateAbstractName();
            const auto len = std::min( sizeof( buf ) - 1, name.size() );
            memcpy( buf, name.c_str(), len );
            buf[len] = '\0';
        }
        if( changed )
        {
            m_userData.SetDescription( buf );
            if( m_stcb ) UpdateTitle();
        }
    }

    ImGui::Separator();
    ImGui::BeginChild( "##info" );

    const auto ficnt = m_worker.GetFrameImageCount();
    if( ImGui::TreeNode( "Trace statistics" ) )
    {
        ImGui::TextDisabled( "Trace version:" );
        ImGui::SameLine();
        const auto version = m_worker.GetTraceVersion();
        ImGui::Text( "%i.%i.%i", version >> 16, ( version >> 8 ) & 0xFF, version & 0xFF );
        TextFocused( "Timer resolution:", TimeToString( m_worker.GetResolution() ) );
        TextFocused( "CPU zones:", RealToString( m_worker.GetZoneCount() ) );
        ImGui::SameLine();
        ImGui::Spacing();
        ImGui::SameLine();
        TextFocused( "Extra data:", RealToString( m_worker.GetZoneExtraCount() ) );
        TooltipIfHovered( "Count of zones containing any of the following: call stack trace, custom name, user text" );
        TextFocused( "GPU zones:", RealToString( m_worker.GetGpuZoneCount() ) );
        TextFocused( "Lock events:", RealToString( m_worker.GetLockCount() ) );
        TextFocused( "Plot data points:", RealToString( m_worker.GetPlotCount() ) );
        TooltipIfHovered( "User plots" );
        ImGui::SameLine();
        TextFocused( "+", RealToString( m_worker.GetTracyPlotCount() ) );
        TooltipIfHovered( "Automated Tracy plots" );
        auto& memNameMap = m_worker.GetMemNameMap();
        TextFocused( "Memory pools:", RealToString( memNameMap.size() ) );
        uint64_t memTotalCnt = 0;
        for( auto v : memNameMap ) memTotalCnt += v.second->data.size();
        TextFocused( "Memory allocations:", RealToString( memTotalCnt ) );
        TextFocused( "Source locations:", RealToString( m_worker.GetSrcLocCount() ) );
        TextFocused( "Strings:", RealToString( m_worker.GetStringsCount() ) );
        TextFocused( "Symbols:", RealToString( m_worker.GetSymbolsCount() ) );
        TextFocused( "Symbol code fragments:", RealToString( m_worker.GetSymbolCodeCount() ) );
        TooltipIfHovered( MemSizeToString( m_worker.GetSymbolCodeSize() ) );
        TextFocused( "Call stacks:", RealToString( m_worker.GetCallstackPayloadCount() ) );
        if( m_worker.AreCallstackSamplesReady() )
        {
            ImGui::SameLine();
            TextFocused( "+", RealToString( m_worker.GetCallstackParentPayloadCount() ) );
            TooltipIfHovered( "Parent call stacks for stack samples" );
        }
        TextFocused( "Call stack frames:", RealToString( m_worker.GetCallstackFrameCount() ) );
        if( m_worker.AreCallstackSamplesReady() )
        {
            ImGui::SameLine();
            TextFocused( "+", RealToString( m_worker.GetCallstackParentFrameCount() ) );
            TooltipIfHovered( "Parent call stack frames for stack samples" );
        }
        TextFocused( "Call stack samples:", RealToString( m_worker.GetCallstackSampleCount() ) );
        TextFocused( "Ghost zones:", RealToString( m_worker.GetGhostZonesCount() ) );
        TextFocused( "Child sample symbols:", RealToString( m_worker.GetChildSamplesCountSyms() ) );
        if( ImGui::IsItemHovered() )
        {
            ImGui::BeginTooltip();
            TextFocused( "Child samples:", RealToString( m_worker.GetChildSamplesCountFull() ) );
            ImGui::EndTooltip();
        }
        TextFocused( "Context switch samples:", RealToString( m_worker.GetContextSwitchSampleCount() ) );
        TextFocused( "Hardware samples:", RealToString( m_worker.GetHwSampleCount() ) );
        if( ImGui::IsItemHovered() )
        {
            ImGui::BeginTooltip();
            TextFocused( "Unique addresses:", RealToString( m_worker.GetHwSampleCountAddress() ) );
            ImGui::EndTooltip();
        }
        TextFocused( "Frame images:", RealToString( ficnt ) );
        if( ficnt != 0 && ImGui::IsItemHovered() )
        {
            const auto bytes = m_worker.GetTextureCompressionBytes();
            ImGui::BeginTooltip();
            TextFocused( "Input data:", MemSizeToString( bytes.first ) );
            TextFocused( "Compressed:", MemSizeToString( bytes.second ) );
            char buf[64];
            auto ptr = PrintFloat( buf, buf+62, 100. * bytes.second / bytes.first, 2 );
            memcpy( ptr, "%", 2 );
            TextFocused( "Ratio:", buf );
            ImGui::EndTooltip();
        }
        TextFocused( "Context switch regions:", RealToString( m_worker.GetContextSwitchCount() ) );
        TooltipIfHovered( "Detailed context switch data regarding application threads" );
        ImGui::SameLine();
        TextFocused( "+", RealToString( m_worker.GetContextSwitchPerCpuCount() ) );
        TooltipIfHovered( "Coarse CPU core context switch data" );
        TextFocused( "Sections:", RealToString( m_worker.GetSections().size() ) );
        if( m_worker.GetSourceFileCacheCount() == 0 )
        {
            TextFocused( "Source file cache:", "0" );
        }
        else
        {
            ImGui::PushStyleColor( ImGuiCol_Text, GImGui->Style.Colors[ImGuiCol_TextDisabled] );
            const bool expand = ImGui::TreeNode( "Source file cache:" );
            ImGui::PopStyleColor();
            ImGui::SameLine();
            ImGui::TextUnformatted( RealToString( m_worker.GetSourceFileCacheCount() ) );
            TooltipIfHovered( MemSizeToString( m_worker.GetSourceFileCacheSize() ) );
            if( expand )
            {
                auto& cache = m_worker.GetSourceFileCache();
                std::vector<decltype(cache.begin())> vec;
                vec.reserve( cache.size() );
                for( auto it = cache.begin(); it != cache.end(); ++it ) vec.emplace_back( it );
                pdqsort_branchless( vec.begin(), vec.end(), []( const auto& lhs, const auto& rhs ) { return strcmp( lhs->first, rhs->first ) < 0; } );
                for( auto& v : vec )
                {
                    ImGui::BulletText( "%s", v->first );
                    if( ImGui::IsItemClicked() ) ViewSource( v->first, 0 );
                    ImGui::SameLine();
                    ImGui::TextDisabled( "(%s)", MemSizeToString( v->second.len ) );
                }
                ImGui::TreePop();
            }
        }
        ImGui::TreePop();
    }

    auto& topology = m_worker.GetCpuTopology();
    if( !topology.empty() )
    {
        if( ImGui::TreeNode( "CPU topology" ) )
        {
            char buf[128];

            const auto ty = ImGui::GetFontSize();
            ImGui::PushFont( g_fonts.normal, FontSmall );
            const auto sty = ImGui::GetFontSize();
            ImGui::PopFont();
            const float margin = round( ty * 0.5 );
            const float small = round( sty * 0.5 );

            std::vector<int> maxthreads( topology.size() );

            float ptsz = 0;
            float dtsz = 0;
            float ctsz = 0;
            float ttsz = 0;
            for( auto& package : topology )
            {
                sprintf( buf, ICON_FA_BOX " Package %" PRIu32, package.first );
                ImGui::PushFont( g_fonts.normal, FontSmall );
                const auto psz = ImGui::CalcTextSize( buf ).x;
                if( psz > ptsz ) ptsz = psz;
                ImGui::PopFont();

                size_t mt = 0;
                for( auto& die : package.second )
                {
                    sprintf( buf, ICON_FA_DICE_D6 " Die %" PRIu32, die.first );
                    const auto dsz = ImGui::CalcTextSize( buf ).x;
                    if( dsz > dtsz ) dtsz = dsz;

                    for( auto& core : die.second )
                    {
                        sprintf( buf, ICON_FA_MICROCHIP "%" PRIu32, core.first );
                        const auto csz = ImGui::CalcTextSize( buf ).x;
                        if( csz > ctsz ) ctsz = csz;

                        const auto tnum = core.second.size();
                        if( tnum > mt ) mt = tnum;

                        for( auto& thread : core.second )
                        {
                            sprintf( buf, ICON_FA_SHUFFLE "%" PRIu32, thread );
                            const auto tsz = ImGui::CalcTextSize( buf ).x;
                            if( tsz > ttsz ) ttsz = tsz;
                        }
                    }
                }
                maxthreads[package.first] = (int)mt;
            }

            const auto remainingWidth = ImGui::GetContentRegionAvail().x;
            auto dpos = ImGui::GetCursorScreenPos() + ImVec2( margin, 0 );
            const auto draw = ImGui::GetWindowDrawList();

            float width = 0;
            float origy = dpos.y;

            std::vector<decltype(topology.begin())> tsort;
            tsort.reserve( topology.size() );
            for( auto it = topology.begin(); it != topology.end(); ++it ) tsort.emplace_back( it );
            pdqsort_branchless( tsort.begin(), tsort.end(), [] ( const auto& l, const auto& r ) { return l->first < r->first; } );
            for( auto& package : tsort )
            {
                if( package->first != 0 ) dpos.y += ty;
                sprintf( buf, ICON_FA_BOX " Package %" PRIu32, package->first );
                draw->AddText( dpos, 0xFFFFFFFF, buf );
                dpos.y += ty;

                std::vector<decltype(package->second.begin())> dsort;
                dsort.reserve( package->second.size() );
                for( auto it = package->second.begin(); it != package->second.end(); ++it ) dsort.emplace_back( it );
                pdqsort_branchless( dsort.begin(), dsort.end(), [] ( const auto& l, const auto& r ) { return l->first < r->first; } );
                for( auto& die : dsort )
                {
                    dpos.y += small;
                    sprintf( buf, ICON_FA_DICE_D6 " Die %" PRIu32, die->first );
                    draw->AddText( dpos, 0xFFFFFFFF, buf );
                    dpos.y += ty;

                    const auto inCoreWidth = ( ttsz + margin ) * maxthreads[package->first];
                    const auto coreWidth = inCoreWidth + 2 * margin;
                    const auto inCoreHeight = margin + 2 * small + ty;
                    const auto coreHeight = inCoreHeight + ty;
                    const auto cpl = std::max( 1, (int)floor( ( remainingWidth - 2 * margin ) / coreWidth ) );
                    const auto cl = ( die->second.size() + cpl - 1 ) / cpl;
                    const auto pw = cpl * coreWidth + 2 * margin;
                    const auto ph = margin + cl * coreHeight;
                    if( pw > width ) width = pw;

                    draw->AddRect( dpos, dpos + ImVec2( margin + coreWidth * std::min<size_t>( cpl, die->second.size() ), ph ), 0xFFFFFFFF );

                    std::vector<decltype(die->second.begin())> csort;
                    csort.reserve( die->second.size() );
                    for( auto it = die->second.begin(); it != die->second.end(); ++it ) csort.emplace_back( it );
                    pdqsort_branchless( csort.begin(), csort.end(), [] ( const auto& l, const auto& r ) { return l->first < r->first; } );
                    auto cpos = dpos + ImVec2( margin, margin );
                    int ll = cpl;
                    for( auto& core : csort )
                    {
                        sprintf( buf, ICON_FA_MICROCHIP "%" PRIu32, core->first );
                        draw->AddText( cpos, 0xFFFFFFFF, buf );
                        draw->AddRect( cpos + ImVec2( 0, ty ), cpos + ImVec2( inCoreWidth + small, inCoreHeight + small ), 0xFFFFFFFF );

                        for( int i=0; i<core->second.size(); i++ )
                        {
                            sprintf( buf, ICON_FA_SHUFFLE "%" PRIu32, core->second[i] );
                            draw->AddText( cpos + ImVec2( margin + i * ( margin + ttsz ), ty + small ), 0xFFFFFFFF, buf );
                        }

                        if( --ll == 0 )
                        {
                            ll = cpl;
                            cpos.x -= (cpl-1) * coreWidth;
                            cpos.y += coreHeight;
                        }
                        else
                        {
                            cpos.x += coreWidth;
                        }
                    }
                    dpos.y += ph;
                }
            }
            ImGui::ItemSize( ImVec2( width, dpos.y - origy ) );
            ImGui::TreePop();
        }
    }

    if( ImGui::TreeNode( "Source location substitutions" ) )
    {
        static char test[1024] = {};
        ImGui::SetNextItemWidth( -1 );
        ImGui::InputTextWithHint( "##srcSubstTest", "Enter example source location to test substitutions", test, 1024 );
        if( m_sourceRegexValid )
        {
            TextFocused( "Result:", SourceSubstitution( test ) );
        }
        else
        {
            ImGui::TextColored( ImVec4( 255, 0, 0, 255 ), "Error in regular expression" );
        }
        if( ImGui::SmallButton( "Add new substitution" ) ) m_sourceSubstitutions.emplace_back( SourceRegex {} );
        int idx = 0, remove = -1;
        bool changed = false;
        ImGui::Columns( 2, nullptr, false );
        for( auto& v : m_sourceSubstitutions )
        {
            ImGui::PushID( idx );
            if( ImGui::Button( ICON_FA_TRASH_CAN ) ) remove = idx;
            ImGui::SameLine();
            char tmp[1024];
            strncpy( tmp, v.pattern.c_str(), 1024 );
            ImGui::SetNextItemWidth( -1 );
            if( ImGui::InputTextWithHint( "##pattern", "Regex pattern", tmp, 1024 ) )
            {
                v.pattern.assign( tmp );
                changed = true;
            }
            ImGui::NextColumn();
            strncpy( tmp, v.target.c_str(), 1024 );
            ImGui::SetNextItemWidth( -1 );
            if( ImGui::InputTextWithHint( "##replacement", "Regex replacement", tmp, 1024 ) ) v.target.assign( tmp );
            ImGui::PopID();
            ImGui::NextColumn();
            idx++;
        }
        ImGui::EndColumns();
        if( remove != -1 )
        {
            m_sourceSubstitutions.erase( m_sourceSubstitutions.begin() + remove );
            changed = true;
        }
        if( changed ) ValidateSourceRegex();

        ImGui::Checkbox("Enforce source file modification time older than trace capture time", &m_validateSourceAge);

        ImGui::TreePop();
    }

    ImGui::Separator();
    TextFocused( "PID:", RealToString( m_worker.GetPid() ) );
    TextDisabledUnformatted( "Host info:" );
    ImGui::Indent();
    const auto hostInfo = m_worker.GetHostInfo();
    const auto hostLines = SplitLines( hostInfo.c_str(), hostInfo.size() );
    ImGui::PushStyleVar( ImGuiStyleVar_ItemSpacing, ImVec2( ImGui::GetStyle().ItemSpacing.x, 0.0f ) );
    for( auto& line : hostLines )
    {
        auto pos = line.find( ':' );
        if( pos != std::string::npos )
        {
            pos++;
            TextFocused( line.substr( 0, pos ).c_str(), line.substr( pos+1 ).c_str() );
        }
        else
        {
            ImGui::TextUnformatted( line.c_str() );
        }
    }
    ImGui::PopStyleVar();
    ImGui::Unindent();
    ImGui::SameLine();
    ImGui::NewLine();

    const auto cpuId = m_worker.GetCpuId();
    if( cpuId != 0 )
    {
        const auto stepping = cpuId & 0xF;
        const auto baseModel = ( cpuId >> 4 ) & 0xF;
        const auto baseFamily = ( cpuId >> 8 ) & 0xF;
        // 12-15 unused
        const auto extModel = ( cpuId >> 16 ) & 0xF;
        const auto extFamily = ( cpuId >> 20 ) & 0xFF;

        const uint32_t model = ( baseFamily == 6 || baseFamily == 15 ) ? ( ( extModel << 4 ) | baseModel ) : baseModel;
        const uint32_t family = baseFamily == 15 ? baseFamily + extFamily : baseFamily;

        TextFocused( "CPU:", m_worker.GetCpuManufacturer() );
        ImGui::SameLine();
        TextFocused( "Family", RealToString( family ) );
        ImGui::SameLine();
        TextFocused( "Model", RealToString( model ) );
        ImGui::SameLine();
        TextFocused( "Stepping", RealToString( stepping ) );
    }

    auto& appInfo = m_worker.GetAppInfo();
    if( !appInfo.empty() )
    {
        ImGui::Separator();
        TextDisabledUnformatted( "Application info:" );
        for( auto& v : appInfo )
        {
            ImGui::TextUnformatted( m_worker.GetString( v ) );
        }
    }

    auto& crash = m_worker.GetCrashEvent();
    if( crash.thread != 0 )
    {
        ImGui::Separator();
        TextColoredUnformatted( ImVec4( 1.f, 0.2f, 0.2f, 1.f ), ICON_FA_SKULL " Application has crashed. " ICON_FA_SKULL );
        TextFocused( "Time of crash:", TimeToString( crash.time ) );
        SmallColorBox( GetThreadColor( crash.thread, 0 ) );
        ImGui::SameLine();
        TextFocused( "Thread:", m_worker.GetThreadName( crash.thread ) );
        ImGui::SameLine();
        ImGui::TextDisabled( "(%s)", RealToString( crash.thread ) );
        if( m_worker.IsThreadFiber( crash.thread ) )
        {
            ImGui::SameLine();
            TextColoredUnformatted( ImVec4( 0.2f, 0.6f, 0.2f, 1.f ), "Fiber" );
        }
        TextDisabledUnformatted( "Reason:" );
        ImGui::SameLine();
        ImGui::TextWrapped( "%s", m_worker.GetString( crash.message ) );
        if( ImGui::Button( ICON_FA_MICROSCOPE " Focus" ) )
        {
            CenterAtTime( crash.time );
        }
        if( crash.callstack != 0 )
        {
            ImGui::SameLine();
            bool hilite = m_callstackView.id == crash.callstack;
            if( hilite )
            {
                SetButtonHighlightColor();
            }
            if( ImGui::Button( ICON_FA_ALIGN_JUSTIFY " Call stack" ) )
            {
                m_callstackView = {
                    .id = crash.callstack,
                    .thread = crash.thread
                };
            }
            if( hilite )
            {
                ImGui::PopStyleColor( 3 );
            }
            if( ImGui::IsItemHovered() )
            {
                CallstackTooltip( crash.callstack );
            }
        }
    }

    ImGui::EndChild();
    ImGui::End();
}

}
