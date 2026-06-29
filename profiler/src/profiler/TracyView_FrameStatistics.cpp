#include "TracyPrint.hpp"
#include "TracyView.hpp"
#include "../Fonts.hpp"

#include "tracy_pdqsort.h"

namespace tracy
{

extern double s_time;

void View::DrawFrameStatistics()
{
    const auto scale = GetScale();
    ImGui::SetNextWindowSize( ImVec2( 700 * scale, 500 * scale ), ImGuiCond_FirstUseEver );
    ImGui::Begin( "Frame statistics", &m_showFrameStatistics );

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
        ImGui::SameLine();
        if( SmallCheckbox( "Limit range", &m_framesRange.active ) )
        {
            if( m_framesRange.active && m_framesRange.min == 0 && m_framesRange.max == 0 )
            {
                m_framesRange.min = m_vd.zvStart;
                m_framesRange.max = m_vd.zvEnd;
            }
        }
        const auto limitingRange = m_frameSortData.limitToView || m_framesRange.active;
        if( limitingRange )
        {
            ImGui::SameLine();
            TextColoredUnformatted( 0xFF00FFFF, ICON_FA_TRIANGLE_EXCLAMATION );
        }
        if( m_framesRange.active )
        {
            ImGui::SameLine();
            ImGui::PushStyleVar( ImGuiStyleVar_FramePadding, ImVec2( 0, 0 ) );
            ToggleButton( ICON_FA_RULER " Limits", m_showRanges );
            ImGui::PopStyleVar();
        }

        std::pair<int, int> frameRange = { -1, -1 };
        if( limitingRange )
        {
            if( m_frameSortData.limitToView )
            {
                frameRange = m_worker.GetFrameRange( *m_frames, m_vd.zvStart, m_vd.zvEnd );
                if( m_framesRange.active )
                {
                    const auto r = m_worker.GetFrameRange( *m_frames, m_framesRange.min, m_framesRange.max );
                    if( r.first > frameRange.first ) frameRange.first = r.first;
                    if( r.second < frameRange.second ) frameRange.second = r.second;
                    if( frameRange.second < frameRange.first ) frameRange.second = frameRange.first;
                }
            }
            else
            {
                assert( m_framesRange.active );
                frameRange = m_worker.GetFrameRange( *m_frames, m_framesRange.min, m_framesRange.max );
            }
        }
        if( m_frameSortData.frameSet != m_frames || ( limitingRange && m_frameSortData.limitRange != frameRange ) || ( !limitingRange && m_frameSortData.limitRange.first != -1 ) )
        {
            m_frameSortData.frameSet = m_frames;
            m_frameSortData.frameNum = 0;
            m_frameSortData.data.clear();
            m_frameSortData.total = 0;
            m_frameSortData.sumSq = 0;
        }
        bool recalc = false;
        int64_t total = 0;
        double sumSq = 0;
        if( !limitingRange )
        {
            if( m_frameSortData.frameNum != fsz || m_frameSortData.limitRange.first != -1 )
            {
                auto& vec = m_frameSortData.data;
                vec.reserve( fsz );
                const auto midSz = vec.size();
                total = m_frameSortData.total;
                sumSq = m_frameSortData.sumSq;
                for( size_t i=m_frameSortData.frameNum; i<fsz; i++ )
                {
                    const auto t = m_worker.GetFrameTime( *m_frames, i );
                    if( t > 0 )
                    {
                        vec.emplace_back( t );
                        total += t;
                        sumSq += double( t ) * t;
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
                        sumSq += double( t ) * t;
                    }
                }
                pdqsort_branchless( vec.begin(), vec.end() );
                recalc = true;
                m_frameSortData.limitRange = frameRange;
            }
        }
        const auto vsz = m_frameSortData.data.size();
        if( vsz == 0 )
        {
            TextFocused( "Count:", "0" );
            ImGui::Separator();
            ImGui::PushFont( g_fonts.normal, FontBig );
            ImGui::Dummy( ImVec2( 0, ( ImGui::GetContentRegionAvail().y - ImGui::GetTextLineHeight() * 2 ) * 0.5f ) );
            TextCentered( ICON_FA_COW );
            TextCentered( "No frames to show" );
            ImGui::PopFont();
            ImGui::End();
            return;
        }

        if( recalc )
        {
            auto& vec = m_frameSortData.data;
            auto Percentile = [&vec, vsz]( double p ) { return vec[std::min<size_t>( vsz - 1, p * vsz )]; };
            m_frameSortData.average = float( total ) / vsz;
            m_frameSortData.median = Percentile( 0.5 );
            m_frameSortData.p75    = Percentile( 0.75 );
            m_frameSortData.p90    = Percentile( 0.9 );
            m_frameSortData.p99    = Percentile( 0.99 );
            m_frameSortData.p99_9  = Percentile( 0.999 );
            m_frameSortData.total = total;
            m_frameSortData.sumSq = sumSq;
            m_frameSortData.frameNum = fsz;

            if( vsz > 1 )
            {
                const auto avg = m_frameSortData.average;
                const auto ss = m_frameSortData.sumSq - 2. * total * avg + double( avg ) * avg * vsz;
                m_frameSortData.sd = sqrt( ss / ( vsz - 1 ) );
            }
            else
            {
                m_frameSortData.sd = 0;
            }
        }

        const auto profileSpan = m_worker.GetLastTime();
        TextFocused( "Count:", RealToString( vsz ) );
        ImGui::SameLine();
        ImGui::TextDisabled( "(%.2f%%)", 100.f * vsz / fsz );
        if( ImGui::IsItemHovered() )
        {
            ImGui::BeginTooltip();
            TextFocused( "Total count:", RealToString( fsz ) );
            ImGui::EndTooltip();
        }
        ImGui::SameLine();
        ImGui::Spacing();
        ImGui::SameLine();
        TextFocused( "Total time:", TimeToString( m_frameSortData.total ) );
        ImGui::SameLine();
        ImGui::TextDisabled( "(%.2f%% of profile time span)", m_frameSortData.total / float( profileSpan ) * 100.f );
        ImGui::Separator();

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

                    int maxBin = 0;
                    int64_t maxVal = bins[0];
                    for( int i=1; i<numBins; i++ )
                    {
                        if( maxVal < bins[i] )
                        {
                            maxVal = bins[i];
                            maxBin = i;
                        }
                    }

                    ImGui::SameLine();
                    ImGui::Spacing();
                    ImGui::SameLine();
                    TextFocused( "Max counts:", RealToString( maxVal ) );

                    TextFocused( "Mean:", TimeToString( m_frameSortData.average ) );
                    ImGui::SameLine();
                    ImGui::TextDisabled( "(%s FPS)", RealToString( round( 1000000000.0 / m_frameSortData.average ) ) );
                    if( ImGui::IsItemHovered() )
                    {
                        ImGui::BeginTooltip();
                        ImGui::Text( "%s FPS", RealToString( 1000000000.0 / m_frameSortData.average ) );
                        ImGui::EndTooltip();
                    }
                    ImGui::SameLine();
                    ImGui::Spacing();
                    ImGui::SameLine();
                    TextFocused( "Median:", TimeToString( m_frameSortData.median ) );
                    ImGui::SameLine();
                    ImGui::TextDisabled( "(%s FPS)", RealToString( round( 1000000000.0 / m_frameSortData.median ) ) );
                    if( ImGui::IsItemHovered() )
                    {
                        ImGui::BeginTooltip();
                        ImGui::Text( "%s FPS", RealToString( 1000000000.0 / m_frameSortData.median ) );
                        ImGui::EndTooltip();
                    }
                    ImGui::SameLine();
                    ImGui::Spacing();
                    ImGui::SameLine();
                    {
                        int64_t t0, t1;
                        if( m_frameSortData.logTime )
                        {
                            const auto ltmin = log10( tmin );
                            const auto ltmax = log10( tmax );
                            t0 = int64_t( pow( 10, ltmin + double( maxBin )   / numBins * ( ltmax - ltmin ) ) );
                            t1 = int64_t( pow( 10, ltmin + double( maxBin+1 ) / numBins * ( ltmax - ltmin ) ) );
                        }
                        else
                        {
                            t0 = int64_t( tmin + double( maxBin )   / numBins * ( tmax - tmin ) );
                            t1 = int64_t( tmin + double( maxBin+1 ) / numBins * ( tmax - tmin ) );
                        }
                        const auto mode = ( t0 + t1 ) / 2;
                        TextFocused( "Mode:", TimeToString( mode ) );
                        ImGui::SameLine();
                        ImGui::TextDisabled( "(%s FPS)", RealToString( round( 1000000000.0 / mode ) ) );
                        if( ImGui::IsItemHovered() )
                        {
                            ImGui::BeginTooltip();
                            ImGui::Text( "%s FPS", RealToString( 1000000000.0 / mode ) );
                            ImGui::EndTooltip();
                        }
                    }
                    ImGui::SameLine();
                    ImGui::Spacing();
                    ImGui::SameLine();
                    TextFocused( "\xcf\x83:", TimeToString( m_frameSortData.sd ) );
                    TooltipIfHovered( "Standard deviation" );
                    ImGui::SameLine();
                    ImGui::TextDisabled( "(%.2f%%)", 100.f * m_frameSortData.sd / m_frameSortData.average );
                    TooltipIfHovered( "Coefficient of variation" );

                    constexpr auto PercentileLine = []( const char* label, int64_t t ) {
                        TextFocused( label, TimeToString( t ) );
                        ImGui::SameLine();
                        ImGui::TextDisabled( "(%s FPS)", RealToString( round( 1000000000.0 / t ) ) );
                        if( ImGui::IsItemHovered() )
                        {
                            ImGui::BeginTooltip();
                            ImGui::Text( "%s FPS", RealToString( 1000000000.0 / t ) );
                            ImGui::EndTooltip();
                        }
                    };
                    PercentileLine( "P75:", m_frameSortData.p75 );
                    ImGui::SameLine();
                    ImGui::Spacing();
                    ImGui::SameLine();
                    PercentileLine( "P90:", m_frameSortData.p90 );
                    ImGui::SameLine();
                    ImGui::Spacing();
                    ImGui::SameLine();
                    PercentileLine( "P99:", m_frameSortData.p99 );
                    ImGui::SameLine();
                    ImGui::Spacing();
                    ImGui::SameLine();
                    PercentileLine( "P99.9:", m_frameSortData.p99_9 );

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
                        m_wasActive.store( true, std::memory_order_release );
                    }
                }
            }
        }
    }
    ImGui::End();
}

}
