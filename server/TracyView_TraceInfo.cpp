#include <inttypes.h>

#include "TracyImGui.hpp"
#include "TracyPrint.hpp"
#include "TracyView.hpp"

namespace tracy
{

extern double s_time;

void View::DrawInfo()
{
    const auto scale = GetScale();
    ImGui::SetNextWindowSize( ImVec2( 400 * scale, 650 * scale ), ImGuiCond_FirstUseEver );
    ImGui::Begin( "Trace information", &m_showInfo, ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse );
    if( ImGui::GetCurrentWindowRead()->SkipItems ) { ImGui::End(); return; }
    ImGui::PushFont( m_bigFont );
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
            const auto save = m_userData.GetConfigLocation();
            if( save )
            {
                ImGui::SameLine();
                if( ImGui::SmallButton( ICON_FA_FOLDER ) )
                {
                    ImGui::SetClipboardText( save );
                }
                TooltipIfHovered( "Copy user settings location to clipboard." );
            }
        }
    }
    {
        const auto& desc = m_userData.GetDescription();
        const auto descsz = std::min<size_t>( 255, desc.size() );
        char buf[256];
        buf[descsz] = '\0';
        memcpy( buf, desc.c_str(), descsz );
        ImGui::SetNextItemWidth( -1 );
        if( ImGui::InputTextWithHint( "##traceDesc", "Enter description of the trace", buf, 256 ) )
        {
            m_userData.SetDescription( buf );
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
        TextFocused( "Queue delay:", TimeToString( m_worker.GetDelay() ) );
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
#ifndef TRACY_NO_STATISTICS
        TextFocused( "Child sample symbols:", RealToString( m_worker.GetChildSamplesCountSyms() ) );
        if( ImGui::IsItemHovered() )
        {
            ImGui::BeginTooltip();
            TextFocused( "Child samples:", RealToString( m_worker.GetChildSamplesCountFull() ) );
            ImGui::EndTooltip();
        }
        TextFocused( "Context switch samples:", RealToString( m_worker.GetContextSwitchSampleCount() ) );
#endif
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

    if( m_worker.AreFramesUsed() && ImGui::TreeNode( "Frame statistics" ) )
    {
        auto fsz = m_worker.GetFullFrameCount( *m_frames );
        if( fsz != 0 )
        {
            TextFocused( "Frame set:", GetFrameSetName( *m_frames ) );
            ImGui::SameLine();
            ImGui::TextDisabled( "(%s)", m_frames->continuous ? "continuous" : "discontinuous" );
            ImGui::SameLine();
            ImGui::PushStyleVar( ImGuiStyleVar_FramePadding, ImVec2( 0, 0 ) );
            if( ImGui::BeginCombo( "##frameCombo", nullptr, ImGuiComboFlags_NoPreview ) )
            {
                auto& frames = m_worker.GetFrames();
                for( auto& fd : frames )
                {
                    bool isSelected = m_frames == fd;
                    if( ImGui::Selectable( GetFrameSetName( *fd ), isSelected ) )
                    {
                        m_frames = fd;
                        fsz = m_worker.GetFullFrameCount( *m_frames );
                    }
                    if( isSelected )
                    {
                        ImGui::SetItemDefaultFocus();
                    }
                    ImGui::SameLine();
                    ImGui::TextDisabled( "(%s)", RealToString( fd->frames.size() ) );
                }
                ImGui::EndCombo();
            }
            ImGui::PopStyleVar();
            ImGui::SameLine();
            SmallCheckbox( "Limit to view", &m_frameSortData.limitToView );
            if( m_frameSortData.limitToView )
            {
                ImGui::SameLine();
                TextColoredUnformatted( 0xFF00FFFF, ICON_FA_TRIANGLE_EXCLAMATION );
            }

            const auto frameRange = m_worker.GetFrameRange( *m_frames, m_vd.zvStart, m_vd.zvEnd );
            if( m_frameSortData.frameSet != m_frames || ( m_frameSortData.limitToView && m_frameSortData.limitRange != frameRange ) || ( !m_frameSortData.limitToView && m_frameSortData.limitRange.first != -1 ) )
            {
                m_frameSortData.frameSet = m_frames;
                m_frameSortData.frameNum = 0;
                m_frameSortData.data.clear();
                m_frameSortData.total = 0;
            }
            bool recalc = false;
            int64_t total = 0;
            if( !m_frameSortData.limitToView )
            {
                if( m_frameSortData.frameNum != fsz || m_frameSortData.limitRange.first != -1 )
                {
                    auto& vec = m_frameSortData.data;
                    vec.reserve( fsz );
                    const auto midSz = vec.size();
                    total = m_frameSortData.total;
                    for( size_t i=m_frameSortData.frameNum; i<fsz; i++ )
                    {
                        const auto t = m_worker.GetFrameTime( *m_frames, i );
                        if( t > 0 )
                        {
                            vec.emplace_back( t );
                            total += t;
                        }
                    }
                    auto mid = vec.begin() + midSz;
                    pdqsort_branchless( mid, vec.end() );
                    std::inplace_merge( vec.begin(), mid, vec.end() );
                    recalc = true;
                    m_frameSortData.limitRange.first = -1;
                }
            }
            else
            {
                if( m_frameSortData.limitRange != frameRange )
                {
                    auto& vec = m_frameSortData.data;
                    assert( vec.empty() );
                    vec.reserve( frameRange.second - frameRange.first );
                    for( int i=frameRange.first; i<frameRange.second; i++ )
                    {
                        const auto t = m_worker.GetFrameTime( *m_frames, i );
                        if( t > 0 )
                        {
                            vec.emplace_back( t );
                            total += t;
                        }
                    }
                    pdqsort_branchless( vec.begin(), vec.end() );
                    recalc = true;
                    m_frameSortData.limitRange = frameRange;
                }
            }
            if( recalc )
            {
                auto& vec = m_frameSortData.data;
                const auto vsz = vec.size();
                m_frameSortData.average = float( total ) / vsz;
                m_frameSortData.median = vec[vsz/2];
                m_frameSortData.total = total;
                m_frameSortData.frameNum = fsz;
            }

            const auto profileSpan = m_worker.GetLastTime();
            TextFocused( "Count:", RealToString( fsz ) );
            TextFocused( "Total time:", TimeToString( m_frameSortData.total ) );
            ImGui::SameLine();
            ImGui::TextDisabled( "(%.2f%% of profile time span)", m_frameSortData.total / float( profileSpan ) * 100.f );
            TextFocused( "Mean frame time:", TimeToString( m_frameSortData.average ) );
            ImGui::SameLine();
            ImGui::TextDisabled( "(%s FPS)", RealToString( round( 1000000000.0 / m_frameSortData.average ) ) );
            if( ImGui::IsItemHovered() )
            {
                ImGui::BeginTooltip();
                ImGui::Text( "%s FPS", RealToString( 1000000000.0 / m_frameSortData.average ) );
                ImGui::EndTooltip();
            }
            TextFocused( "Median frame time:", TimeToString( m_frameSortData.median ) );
            ImGui::SameLine();
            ImGui::TextDisabled( "(%s FPS)", RealToString( round( 1000000000.0 / m_frameSortData.median ) ) );
            if( ImGui::IsItemHovered() )
            {
                ImGui::BeginTooltip();
                ImGui::Text( "%s FPS", RealToString( 1000000000.0 / m_frameSortData.median ) );
                ImGui::EndTooltip();
            }

            if( ImGui::TreeNodeEx( "Histogram", ImGuiTreeNodeFlags_DefaultOpen ) )
            {
                const auto ty = ImGui::GetTextLineHeight();

                auto& frames = m_frameSortData.data;
                auto tmin = frames.front();
                auto tmax = frames.back();

                if( tmin != std::numeric_limits<int64_t>::max() )
                {
                    TextDisabledUnformatted( "Minimum values in bin:" );
                    ImGui::SameLine();
                    ImGui::SetNextItemWidth( ImGui::CalcTextSize( "123456890123456" ).x );
                    ImGui::PushStyleVar( ImGuiStyleVar_FramePadding, ImVec2( 1, 1 ) );
                    ImGui::InputInt( "##minBinVal", &m_frameSortData.minBinVal );
                    if( m_frameSortData.minBinVal < 1 ) m_frameSortData.minBinVal = 1;
                    ImGui::SameLine();
                    if( ImGui::Button( "Reset" ) ) m_frameSortData.minBinVal = 1;
                    ImGui::PopStyleVar();

                    SmallCheckbox( "Log values", &m_frameSortData.logVal );
                    ImGui::SameLine();
                    SmallCheckbox( "Log time", &m_frameSortData.logTime );

                    TextDisabledUnformatted( "FPS range:" );
                    ImGui::SameLine();
                    ImGui::Text( "%s FPS - %s FPS", RealToString( round( 1000000000.0 / tmin ) ), RealToString( round( 1000000000.0 / tmax ) ) );

                    if( tmax - tmin > 0 )
                    {
                        const auto w = ImGui::GetContentRegionAvail().x;

                        const auto numBins = int64_t( w - 4 );
                        if( numBins > 1 )
                        {
                            if( numBins > m_frameSortData.numBins )
                            {
                                m_frameSortData.numBins = numBins;
                                m_frameSortData.bins = std::make_unique<int64_t[]>( numBins );
                            }

                            const auto& bins = m_frameSortData.bins;

                            memset( bins.get(), 0, sizeof( int64_t ) * numBins );

                            auto framesBegin = frames.begin();
                            auto framesEnd = frames.end();
                            while( framesBegin != framesEnd && *framesBegin == 0 ) ++framesBegin;

                            if( m_frameSortData.minBinVal > 1 )
                            {
                                if( m_frameSortData.logTime )
                                {
                                    const auto tMinLog = log10( tmin );
                                    const auto zmax = ( log10( tmax ) - tMinLog ) / numBins;
                                    int64_t i;
                                    for( i=0; i<numBins; i++ )
                                    {
                                        const auto nextBinVal = int64_t( pow( 10.0, tMinLog + ( i+1 ) * zmax ) );
                                        auto nit = std::lower_bound( framesBegin, framesEnd, nextBinVal );
                                        const auto distance = std::distance( framesBegin, nit );
                                        if( distance >= m_frameSortData.minBinVal ) break;
                                        framesBegin = nit;
                                    }
                                    for( int64_t j=numBins-1; j>i; j-- )
                                    {
                                        const auto nextBinVal = int64_t( pow( 10.0, tMinLog + ( j-1 ) * zmax ) );
                                        auto nit = std::lower_bound( framesBegin, framesEnd, nextBinVal );
                                        const auto distance = std::distance( nit, framesEnd );
                                        if( distance >= m_frameSortData.minBinVal ) break;
                                        framesEnd = nit;
                                    }
                                }
                                else
                                {
                                    const auto zmax = tmax - tmin;
                                    int64_t i;
                                    for( i=0; i<numBins; i++ )
                                    {
                                        const auto nextBinVal = tmin + ( i+1 ) * zmax / numBins;
                                        auto nit = std::lower_bound( framesBegin, framesEnd, nextBinVal );
                                        const auto distance = std::distance( framesBegin, nit );
                                        if( distance >= m_frameSortData.minBinVal ) break;
                                        framesBegin = nit;
                                    }
                                    for( int64_t j=numBins-1; j>i; j-- )
                                    {
                                        const auto nextBinVal = tmin + ( j-1 ) * zmax / numBins;
                                        auto nit = std::lower_bound( framesBegin, framesEnd, nextBinVal );
                                        const auto distance = std::distance( nit, framesEnd );
                                        if( distance >= m_frameSortData.minBinVal ) break;
                                        framesEnd = nit;
                                    }
                                }

                                tmin = *framesBegin;
                                tmax = *(framesEnd-1);
                            }

                            if( m_frameSortData.logTime )
                            {
                                const auto tMinLog = log10( tmin );
                                const auto zmax = ( log10( tmax ) - tMinLog ) / numBins;
                                auto fit = framesBegin;
                                for( int64_t i=0; i<numBins; i++ )
                                {
                                    const auto nextBinVal = int64_t( pow( 10.0, tMinLog + ( i+1 ) * zmax ) );
                                    auto nit = std::lower_bound( fit, framesEnd, nextBinVal );
                                    bins[i] = std::distance( fit, nit );
                                    fit = nit;
                                }
                                bins[numBins-1] += std::distance( fit, framesEnd );
                            }
                            else
                            {
                                const auto zmax = tmax - tmin;
                                auto fit = framesBegin;
                                for( int64_t i=0; i<numBins; i++ )
                                {
                                    const auto nextBinVal = tmin + ( i+1 ) * zmax / numBins;
                                    auto nit = std::lower_bound( fit, framesEnd, nextBinVal );
                                    bins[i] = std::distance( fit, nit );
                                    fit = nit;
                                }
                                bins[numBins-1] += std::distance( fit, framesEnd );
                            }

                            int64_t maxVal = bins[0];
                            for( int i=1; i<numBins; i++ )
                            {
                                maxVal = std::max( maxVal, bins[i] );
                            }

                            TextFocused( "Max counts:", RealToString( maxVal ) );

                            ImGui::PushStyleVar( ImGuiStyleVar_FramePadding, ImVec2( 0, 0 ) );
                            ImGui::Checkbox( "###draw1", &m_frameSortData.drawAvgMed );
                            ImGui::SameLine();
                            ImGui::ColorButton( "c1", ImVec4( 0xFF/255.f, 0x44/255.f, 0x44/255.f, 1.f ), ImGuiColorEditFlags_NoTooltip | ImGuiColorEditFlags_NoDragDrop );
                            ImGui::SameLine();
                            ImGui::TextUnformatted( "Mean time" );
                            ImGui::SameLine();
                            ImGui::Spacing();
                            ImGui::SameLine();
                            ImGui::ColorButton( "c2", ImVec4( 0x44/255.f, 0x88/255.f, 0xFF/255.f, 1.f ), ImGuiColorEditFlags_NoTooltip | ImGuiColorEditFlags_NoDragDrop );
                            ImGui::SameLine();
                            ImGui::TextUnformatted( "Median time" );
                            ImGui::PopStyleVar();

                            const auto Height = 200 * scale;
                            const auto wpos = ImGui::GetCursorScreenPos();
                            const auto dpos = wpos + ImVec2( 0.5f, 0.5f );

                            ImGui::InvisibleButton( "##histogram", ImVec2( w, Height + round( ty * 2.5 ) ) );
                            const bool hover = ImGui::IsItemHovered();

                            auto draw = ImGui::GetWindowDrawList();
                            draw->AddRectFilled( wpos, wpos + ImVec2( w, Height ), 0x22FFFFFF );
                            draw->AddRect( wpos, wpos + ImVec2( w, Height ), 0x88FFFFFF );

                            if( m_frameSortData.logVal )
                            {
                                const auto hAdj = double( Height - 4 ) / log10( maxVal + 1 );
                                for( int i=0; i<numBins; i++ )
                                {
                                    const auto val = bins[i];
                                    if( val > 0 )
                                    {
                                        DrawLine( draw, dpos + ImVec2( 2+i, Height-3 ), dpos + ImVec2( 2+i, Height-3 - log10( val + 1 ) * hAdj ), 0xFF22DDDD );
                                    }
                                }
                            }
                            else
                            {
                                const auto hAdj = double( Height - 4 ) / maxVal;
                                for( int i=0; i<numBins; i++ )
                                {
                                    const auto val = bins[i];
                                    if( val > 0 )
                                    {
                                        DrawLine( draw, dpos + ImVec2( 2+i, Height-3 ), dpos + ImVec2( 2+i, Height-3 - val * hAdj ), 0xFF22DDDD );
                                    }
                                }
                            }

                            const auto xoff = 2;
                            const auto yoff = Height + 1;

                            DrawHistogramMinMaxLabel( draw, tmin, tmax, wpos + ImVec2( 0, yoff ), w, ty );

                            const auto ty05 = round( ty * 0.5f );
                            const auto ty025 = round( ty * 0.25f );
                            if( m_frameSortData.logTime )
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

                            if( m_frameSortData.drawAvgMed )
                            {
                                float ta, tm;
                                if( m_frameSortData.logTime )
                                {
                                    const auto ltmin = log10( tmin );
                                    const auto ltmax = log10( tmax );

                                    ta = ( log10( m_frameSortData.average ) - ltmin ) / float( ltmax - ltmin ) * numBins;
                                    tm = ( log10( m_frameSortData.median ) - ltmin ) / float( ltmax - ltmin ) * numBins;
                                }
                                else
                                {
                                    ta = ( m_frameSortData.average - tmin ) / float( tmax - tmin ) * numBins;
                                    tm = ( m_frameSortData.median - tmin ) / float( tmax - tmin ) * numBins;
                                }
                                ta = round( ta );
                                tm = round( tm );

                                if( ta == tm )
                                {
                                    DrawLine( draw, ImVec2( dpos.x + ta, dpos.y ), ImVec2( dpos.x + ta, dpos.y+Height-2 ), 0xFFFF88FF );
                                }
                                else
                                {
                                    DrawLine( draw, ImVec2( dpos.x + ta, dpos.y ), ImVec2( dpos.x + ta, dpos.y+Height-2 ), 0xFF4444FF );
                                    DrawLine( draw, ImVec2( dpos.x + tm, dpos.y ), ImVec2( dpos.x + tm, dpos.y+Height-2 ), 0xFFFF8844 );
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
                                if( m_frameSortData.logTime )
                                {
                                    t0 = int64_t( pow( 10, ltmin + double( bin ) / numBins * ( ltmax - ltmin ) ) );

                                    // Hackfix for inability to select data in last bin.
                                    // A proper solution would be nice.
                                    if( bin+1 == numBins )
                                    {
                                        t1 = tmax;
                                    }
                                    else
                                    {
                                        t1 = int64_t( pow( 10, ltmin + double( bin+1 ) / numBins * ( ltmax - ltmin ) ) );
                                    }
                                }
                                else
                                {
                                    t0 = int64_t( tmin + double( bin )   / numBins * ( tmax - tmin ) );
                                    t1 = int64_t( tmin + double( bin+1 ) / numBins * ( tmax - tmin ) );
                                }

                                ImGui::BeginTooltip();
                                TextDisabledUnformatted( "Time range:" );
                                ImGui::SameLine();
                                ImGui::Text( "%s - %s", TimeToString( t0 ), TimeToString( t1 ) );
                                ImGui::SameLine();
                                ImGui::TextDisabled( "(%s FPS - %s FPS)", RealToString( round( 1000000000.0 / t0 ) ), RealToString( round( 1000000000.0 / t1 ) ) );
                                TextFocused( "Count:", RealToString( bins[bin] ) );
                                ImGui::EndTooltip();
                            }

                            if( m_frameHover != -1 )
                            {
                                const auto frameTime = m_worker.GetFrameTime( *m_frames, m_frameHover );
                                float framePos;
                                if( m_frameSortData.logTime )
                                {
                                    const auto ltmin = log10( tmin );
                                    const auto ltmax = log10( tmax );
                                    framePos = round( ( log10( frameTime ) - ltmin ) / float( ltmax - ltmin ) * numBins );
                                }
                                else
                                {
                                    framePos = round( ( frameTime - tmin ) / float( tmax - tmin ) * numBins );
                                }
                                const auto c = uint32_t( ( sin( s_time * 10 ) * 0.25 + 0.75 ) * 255 );
                                const auto color = 0xFF000000 | ( c << 16 ) | ( c << 8 ) | c;
                                DrawLine( draw, ImVec2( dpos.x + framePos, dpos.y ), ImVec2( dpos.x + framePos, dpos.y+Height-2 ), color );
                                m_wasActive = true;
                            }
                        }
                    }
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
            ImGui::PushFont( m_smallFont );
            const auto sty = ImGui::GetFontSize();
            ImGui::PopFont();
            const float margin = round( ty * 0.5 );
            const float small = round( sty * 0.5 );

            std::vector<int> maxthreads( topology.size() );

            float ptsz = 0;
            float ctsz = 0;
            float ttsz = 0;
            for( auto& package : topology )
            {
                sprintf( buf, ICON_FA_BOX " Package %" PRIu32, package.first );
                ImGui::PushFont( m_smallFont );
                const auto psz = ImGui::CalcTextSize( buf ).x;
                if( psz > ptsz ) ptsz = psz;
                ImGui::PopFont();

                size_t mt = 0;
                for( auto& core : package.second )
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
            std::sort( tsort.begin(), tsort.end(), [] ( const auto& l, const auto& r ) { return l->first < r->first; } );
            for( auto& package : tsort )
            {
                if( package->first != 0 ) dpos.y += ty;
                sprintf( buf, ICON_FA_BOX " Package %" PRIu32, package->first );
                draw->AddText( dpos, 0xFFFFFFFF, buf );
                dpos.y += ty;

                const auto inCoreWidth = ( ttsz + margin ) * maxthreads[package->first];
                const auto coreWidth = inCoreWidth + 2 * margin;
                const auto inCoreHeight = margin + 2 * small + ty;
                const auto coreHeight = inCoreHeight + ty;
                const auto cpl = std::max( 1, (int)floor( ( remainingWidth - 2 * margin ) / coreWidth ) );
                const auto cl = ( package->second.size() + cpl - 1 ) / cpl;
                const auto pw = cpl * coreWidth + 2 * margin;
                const auto ph = margin + cl * coreHeight;
                if( pw > width ) width = pw;

                draw->AddRect( dpos, dpos + ImVec2( margin + coreWidth * std::min<size_t>( cpl, package->second.size() ), ph ), 0xFFFFFFFF );

                std::vector<decltype(package->second.begin())> csort;
                csort.reserve( package->second.size() );
                for( auto it = package->second.begin(); it != package->second.end(); ++it ) csort.emplace_back( it );
                std::sort( csort.begin(), csort.end(), [] ( const auto& l, const auto& r ) { return l->first < r->first; } );
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

        if( changed )
        {
            bool regexValid = true;
            for( auto& v : m_sourceSubstitutions )
            {
                try
                {
                    v.regex.assign( v.pattern );
                }
                catch( std::regex_error& )
                {
                    regexValid = false;
                    break;
                }
            }
            m_sourceRegexValid = regexValid;
        }

        ImGui::TreePop();
    }

    ImGui::Separator();
    TextFocused( "PID:", RealToString( m_worker.GetPid() ) );
    TextFocused( "Host info:", m_worker.GetHostInfo().c_str() );

    const auto cpuId = m_worker.GetCpuId();
    if( cpuId != 0 )
    {
        const auto stepping = cpuId & 0xF;
        const auto baseModel = ( cpuId >> 4 ) & 0xF;
        const auto baseFamily = ( cpuId >> 8 ) & 0xF;
        const auto extModel = ( cpuId >> 12 ) & 0xF;
        const auto extFamily = ( cpuId >> 16 );

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
            bool hilite = m_callstackInfoWindow == crash.callstack;
            if( hilite )
            {
                SetButtonHighlightColor();
            }
            if( ImGui::Button( ICON_FA_ALIGN_JUSTIFY " Call stack" ) )
            {
                m_callstackInfoWindow = crash.callstack;
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
