#include <inttypes.h>
#include <math.h>

#include "TracyFilesystem.hpp"
#include "TracyImGui.hpp"
#include "TracyMouse.hpp"
#include "TracyPrint.hpp"
#include "TracySourceView.hpp"
#include "TracyTimelineContext.hpp"
#include "TracyTimelineDraw.hpp"
#include "TracyView.hpp"

namespace tracy
{

void View::DrawSampleList( const TimelineContext& ctx, const std::vector<SamplesDraw>& drawList, const Vector<SampleData>& vec, int offset )
{
    const auto& wpos = ctx.wpos;
    const auto ty = ctx.ty;
    const auto vStart = ctx.vStart;
    const auto pxns = ctx.pxns;
    const auto hover = ctx.hover;

    const auto MinVis = 3 * GetScale();
    const auto ty0375 = offset + round( ty * 0.375f );
    const auto ty02 = round( ty * 0.2f );
    const auto ty01 = round( ty * 0.1f );
    const auto y0 = ty0375 - ty02 - 3;
    const auto y1 = ty0375 + ty02 - 1;
    auto begin = vec.begin();
    auto draw = ImGui::GetWindowDrawList();
    bool tooltipDisplayed = false;

    for( auto& v : drawList )
    {
        auto it = begin + v.idx;
        const auto t0 = it->time.Val();
        const auto px0 = ( t0 - vStart ) * pxns;
        if( v.num > 0 )
        {
            const auto eit = it + v.num;
            const auto t1 = eit->time.Val();
            const auto px1 = ( t1 - vStart ) * pxns;

            DrawZigZag( draw, wpos + ImVec2( 0, ty0375 ), px0, std::max( px1, px0+MinVis ), ty01, 0xFF997777 );
            if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( px0, y0 ), wpos + ImVec2( std::max( px1, px0+MinVis ), y1 ) ) )
            {
                ImGui::BeginTooltip();
                ImGui::TextUnformatted( "Multiple call stack samples" );
                TextFocused( "Number of samples:", RealToString( v.num + 1 ) );
                ImGui::EndTooltip();

                if( IsMouseClicked( 2 ) )
                {
                    ZoomToRange( t0, t1 );
                }
            }
        }
        else
        {
            draw->AddCircleFilled( wpos + ImVec2( px0, ty0375 ), ty02, 0xFFDD8888 );
            if( !tooltipDisplayed && hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( px0 - ty02 - 2, y0 ), wpos + ImVec2( px0 + ty02 + 1, y1 ) ) )
            {
                tooltipDisplayed = true;
                CallstackTooltip( it->callstack.Val() );
                if( IsMouseClicked( 0 ) )
                {
                    m_callstackInfoWindow = it->callstack.Val();
                }
            }
        }
    }
}

void View::DrawSamplesStatistics( Vector<SymList>& data, int64_t timeRange, AccumulationMode accumulationMode )
{
    static unordered_flat_map<uint64_t, SymList> inlineMap;
    assert( inlineMap.empty() );
    if( !m_statSeparateInlines )
    {
        static unordered_flat_map<uint64_t, SymList> baseMap;
        assert( baseMap.empty() );
        for( auto& v : data )
        {
            auto sym = m_worker.GetSymbolData( v.symAddr );
            const auto symAddr = ( sym && sym->isInline ) ? m_worker.GetSymbolForAddress( v.symAddr ) : v.symAddr;
            auto it = baseMap.find( symAddr );
            if( it == baseMap.end() )
            {
                baseMap.emplace( symAddr, SymList { symAddr, v.incl, v.excl, 0 } );
            }
            else
            {
                assert( symAddr == it->second.symAddr );
                it->second.incl += v.incl;
                it->second.excl += v.excl;
                it->second.count++;
            }
        }
        for( auto& v : data ) inlineMap.emplace( v.symAddr, SymList { v.symAddr, v.incl, v.excl, v.count } );
        data.clear();
        for( auto& v : baseMap )
        {
            data.push_back_no_space_check( v.second );
        }
        baseMap.clear();
    }

    if( data.empty() )
    {
        ImGui::TextUnformatted( "No entries to be displayed." );
    }
    else
    {
        const auto& symMap = m_worker.GetSymbolMap();

        if( accumulationMode == AccumulationMode::SelfOnly )
        {
            pdqsort_branchless( data.begin(), data.end(), []( const auto& l, const auto& r ) { return l.excl != r.excl ? l.excl > r.excl : l.symAddr < r.symAddr; } );
        }
        else
        {
            pdqsort_branchless( data.begin(), data.end(), []( const auto& l, const auto& r ) { return l.incl != r.incl ? l.incl > r.incl : l.symAddr < r.symAddr; } );
        }

        ImGui::BeginChild( "##statisticsSampling" );
        if( ImGui::BeginTable( "##statisticsSampling", 5, ImGuiTableFlags_Resizable | ImGuiTableFlags_Reorderable | ImGuiTableFlags_Hideable | ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_ScrollY ) )
        {
            ImGui::TableSetupScrollFreeze( 0, 1 );
            ImGui::TableSetupColumn( "Name", ImGuiTableColumnFlags_NoHide );
            ImGui::TableSetupColumn( "Location", ImGuiTableColumnFlags_NoSort );
            ImGui::TableSetupColumn( "Image" );
            ImGui::TableSetupColumn( m_statSampleTime ? "Time" : "Count", ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_NoResize );
            ImGui::TableSetupColumn( "Code size", ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_NoResize );
            ImGui::TableHeadersRow();

            double revSampleCount100;
            if( m_statRange.active && m_worker.GetSamplingPeriod() != 0 )
            {
                const auto st = m_statRange.max - m_statRange.min;
                const auto cnt = st / m_worker.GetSamplingPeriod();
                revSampleCount100 = 100. / cnt;
            }
            else
            {
                revSampleCount100 = 100. / m_worker.GetCallstackSampleCount();
            }

            const bool showAll = m_showAllSymbols;
            const auto period = m_worker.GetSamplingPeriod();
            int idx = 0;
            for( auto& v : data )
            {
                const auto cnt = accumulationMode == AccumulationMode::SelfOnly ? v.excl : v.incl;
                if( cnt > 0 || showAll )
                {
                    const char* name = "[unknown]";
                    const char* file = "[unknown]";
                    const char* imageName = "[unknown]";
                    uint32_t line = 0;
                    bool isInline = false;
                    uint32_t symlen = 0;
                    auto codeAddr = v.symAddr;

                    auto sit = symMap.find( v.symAddr );
                    if( sit != symMap.end() )
                    {
                        name = m_worker.GetString( sit->second.name );
                        imageName = m_worker.GetString( sit->second.imageName );
                        isInline = sit->second.isInline;
                        switch( m_statSampleLocation )
                        {
                        case 0:
                            file = m_worker.GetString( sit->second.file );
                            line = sit->second.line;
                            break;
                        case 1:
                            file = m_worker.GetString( sit->second.callFile );
                            line = sit->second.callLine;
                            break;
                        case 2:
                            if( sit->second.isInline )
                            {
                                file = m_worker.GetString( sit->second.callFile );
                                line = sit->second.callLine;
                            }
                            else
                            {
                                file = m_worker.GetString( sit->second.file );
                                line = sit->second.line;
                            }
                            break;
                        default:
                            assert( false );
                            break;
                        }
                        if( m_statHideUnknown && file[0] == '[' ) continue;
                        symlen = sit->second.size.Val();
                    }
                    else if( m_statHideUnknown )
                    {
                        continue;
                    }

                    ImGui::TableNextRow();
                    ImGui::TableNextColumn();

                    const bool isKernel = v.symAddr >> 63 != 0;
                    const char* parentName = nullptr;
                    if( symlen == 0 && !isKernel )
                    {
                        const auto parentAddr = m_worker.GetSymbolForAddress( v.symAddr );
                        if( parentAddr != 0 )
                        {
                            auto pit = symMap.find( parentAddr );
                            if( pit != symMap.end() )
                            {
                                codeAddr = parentAddr;
                                symlen = pit->second.size.Val();
                                parentName = m_worker.GetString( pit->second.name );
                            }
                        }
                    }

                    bool expand = false;
                    if( !m_statSeparateInlines )
                    {
                        if( v.count > 0 && v.symAddr != 0 )
                        {
                            ImGui::PushID( v.symAddr );
                            expand = ImGui::TreeNodeEx( "", v.count == 0 ? ImGuiTreeNodeFlags_Leaf : 0 );
                            ImGui::PopID();
                            ImGui::SameLine();
                        }
                    }
                    else if( isInline )
                    {
                        TextDisabledUnformatted( ICON_FA_CARET_RIGHT );
                        ImGui::SameLine();
                    }
                    uint32_t excl;
                    if( m_statSeparateInlines )
                    {
                        excl = v.excl;
                    }
                    else
                    {
                        auto it = inlineMap.find( v.symAddr );
                        excl = it != inlineMap.end() ? it->second.excl : 0;
                    }
                    bool hasNoSamples = v.symAddr == 0 || excl == 0;
                    if( !m_statSeparateInlines && hasNoSamples && v.symAddr != 0 && v.count > 0 )
                    {
                        auto inSym = m_worker.GetInlineSymbolList( v.symAddr, symlen );
                        if( inSym )
                        {
                            const auto symEnd = v.symAddr + symlen;
                            while( *inSym < symEnd )
                            {
                                auto sit = inlineMap.find( *inSym );
                                if( sit != inlineMap.end() )
                                {
                                    if( sit->second.excl != 0 )
                                    {
                                        hasNoSamples = false;
                                        break;
                                    }
                                }
                                inSym++;
                            }
                        }
                    }
                    if( hasNoSamples )
                    {
                        if( isKernel )
                        {
                            TextColoredUnformatted( 0xFF8888FF, name );
                        }
                        else if( m_vd.shortenName == ShortenName::Never )
                        {
                            ImGui::TextUnformatted( name );
                        }
                        else
                        {
                            const auto normalized = ShortenZoneName( ShortenName::OnlyNormalize, name );
                            ImGui::TextUnformatted( normalized );
                            TooltipNormalizedName( name, normalized );
                        }
                    }
                    else
                    {
                        ImGui::PushID( idx++ );
                        bool clicked;
                        if( isKernel )
                        {
                            ImGui::PushStyleColor( ImGuiCol_Text, 0xFF8888FF );
                            clicked = ImGui::Selectable( name, m_sampleParents.withInlines && m_sampleParents.symAddr == v.symAddr, ImGuiSelectableFlags_SpanAllColumns );
                            ImGui::PopStyleColor();
                        }
                        else if( m_vd.shortenName == ShortenName::Never )
                        {
                            clicked = ImGui::Selectable( name, m_sampleParents.withInlines && m_sampleParents.symAddr == v.symAddr, ImGuiSelectableFlags_SpanAllColumns );
                        }
                        else
                        {
                            const auto normalized = ShortenZoneName( ShortenName::OnlyNormalize, name );
                            clicked = ImGui::Selectable( "", m_sampleParents.withInlines && m_sampleParents.symAddr == v.symAddr, ImGuiSelectableFlags_SpanAllColumns );
                            ImGui::SameLine( 0, 0 );
                            ImGui::TextUnformatted( normalized );
                            TooltipNormalizedName( name, normalized );
                        }
                        if( clicked ) ShowSampleParents( v.symAddr, !m_statSeparateInlines );
                        ImGui::PopID();
                    }
                    if( parentName )
                    {
                        ImGui::SameLine();
                        if( m_vd.shortenName == ShortenName::Never )
                        {
                            ImGui::TextDisabled( "(%s)", parentName );
                        }
                        else
                        {
                            const auto normalized = ShortenZoneName( ShortenName::OnlyNormalize, parentName );
                            ImGui::TextDisabled( "(%s)", normalized );
                            TooltipNormalizedName( parentName, normalized );
                        }
                    }
                    if( !m_statSeparateInlines && v.count > 0 && v.symAddr != 0 )
                    {
                        ImGui::SameLine();
                        ImGui::TextDisabled( "(+%s)", RealToString( v.count ) );
                    }
                    ImGui::TableNextColumn();
                    float indentVal = 0.f;
                    if( m_statBuzzAnim.Match( v.symAddr ) )
                    {
                        const auto time = m_statBuzzAnim.Time();
                        indentVal = sin( time * 60.f ) * 10.f * time;
                        ImGui::Indent( indentVal );
                    }
                    if( m_statShowAddress )
                    {
                        ImGui::TextDisabled( "0x%" PRIx64, v.symAddr );
                    }
                    else
                    {
                        TextDisabledUnformatted( LocationToString( file, line ) );
                    }
                    if( ImGui::IsItemHovered() )
                    {
                        DrawSourceTooltip( file, line );
                        if( ImGui::IsItemClicked( 1 ) )
                        {
                            if( SourceFileValid( file, m_worker.GetCaptureTime(), *this, m_worker ) )
                            {
                                ViewSymbol( file, line, codeAddr, v.symAddr );
                                if( !m_statSeparateInlines ) m_sourceView->CalcInlineStats( false );
                            }
                            else if( symlen != 0 )
                            {
                                uint32_t len;
                                if( m_worker.GetSymbolCode( codeAddr, len ) )
                                {
                                    ViewSymbol( nullptr, 0, codeAddr, v.symAddr );
                                    if( !m_statSeparateInlines ) m_sourceView->CalcInlineStats( false );
                                }
                                else
                                {
                                    m_statBuzzAnim.Enable( v.symAddr, 0.5f );
                                }
                            }
                            else
                            {
                                m_statBuzzAnim.Enable( v.symAddr, 0.5f );
                            }
                        }
                    }
                    if( indentVal != 0.f )
                    {
                        ImGui::Unindent( indentVal );
                    }
                    ImGui::TableNextColumn();
                    TextDisabledUnformatted( imageName );
                    ImGui::TableNextColumn();
                    const auto baseCnt = cnt;
                    if( cnt > 0 )
                    {
                        char buf[64];
                        if( m_statSampleTime )
                        {
                            const auto t = cnt * period;
                            ImGui::TextUnformatted( TimeToString( t ) );
                            PrintStringPercent( buf, 100. * t / timeRange );
                        }
                        else
                        {
                            ImGui::TextUnformatted( RealToString( cnt ) );
                            PrintStringPercent( buf, cnt * revSampleCount100 );
                        }
                        ImGui::SameLine();
                        TextDisabledUnformatted( buf );
                    }
                    ImGui::TableNextColumn();
                    if( symlen != 0 )
                    {
                        if( m_worker.HasSymbolCode( codeAddr ) )
                        {
                            TextDisabledUnformatted( ICON_FA_DATABASE );
                            ImGui::SameLine();
                        }
                        if( isInline )
                        {
                            TextDisabledUnformatted( "<" );
                            ImGui::SameLine();
                        }
                        TextDisabledUnformatted( MemSizeToString( symlen ) );
                    }

                    if( !m_statSeparateInlines && expand )
                    {
                        assert( v.count > 0 );
                        assert( symlen != 0 );
                        const auto revBaseCnt = 100.0 / baseCnt;
                        auto inSym = m_worker.GetInlineSymbolList( v.symAddr, symlen );
                        assert( inSym != nullptr );
                        const auto symEnd = v.symAddr + symlen;
                        Vector<SymList> inSymList;
                        if( !m_mergeInlines )
                        {
                            while( *inSym < symEnd )
                            {
                                auto sit = inlineMap.find( *inSym );
                                if( sit != inlineMap.end() )
                                {
                                    inSymList.push_back( SymList { *inSym, sit->second.incl, sit->second.excl } );
                                }
                                else
                                {
                                    inSymList.push_back( SymList { *inSym, 0, 0 } );
                                }
                                inSym++;
                            }
                        }
                        else
                        {
                            unordered_flat_map<uint32_t, uint64_t> mergeMap;
                            unordered_flat_map<uint64_t, SymList> outMap;
                            while( *inSym < symEnd )
                            {
                                auto symAddr = *inSym;
                                auto sit = inlineMap.find( symAddr );
                                auto sym = symMap.find( symAddr );
                                assert( sym != symMap.end() );
                                auto mit = mergeMap.find( sym->second.name.Idx() );
                                if( mit == mergeMap.end() )
                                {
                                    mergeMap.emplace( sym->second.name.Idx(), symAddr );
                                }
                                else
                                {
                                    symAddr = mit->second;
                                }
                                if( sit != inlineMap.end() )
                                {
                                    auto oit = outMap.find( symAddr );
                                    if( oit == outMap.end() )
                                    {
                                        outMap.emplace( symAddr, SymList { symAddr, sit->second.incl, sit->second.excl, 1 } );
                                    }
                                    else
                                    {
                                        oit->second.incl += sit->second.incl;
                                        oit->second.excl += sit->second.excl;
                                        oit->second.count++;
                                    }
                                }
                                else
                                {
                                    auto oit = outMap.find( symAddr );
                                    if( oit == outMap.end() )
                                    {
                                        outMap.emplace( symAddr, SymList { symAddr, 0, 0, 1 } );
                                    }
                                    else
                                    {
                                        oit->second.count++;
                                    }
                                }
                                inSym++;
                            }
                            inSymList.reserve( outMap.size() );
                            for( auto& v : outMap )
                            {
                                inSymList.push_back( v.second );
                            }
                        }
                        auto statIt = inlineMap.find( v.symAddr );
                        if( statIt != inlineMap.end() )
                        {
                            inSymList.push_back( SymList { v.symAddr, statIt->second.incl, statIt->second.excl } );
                        }

                        if( accumulationMode == AccumulationMode::SelfOnly )
                        {
                            pdqsort_branchless( inSymList.begin(), inSymList.end(), []( const auto& l, const auto& r ) { return l.excl != r.excl ? l.excl > r.excl : l.symAddr < r.symAddr; } );
                        }
                        else
                        {
                            pdqsort_branchless( inSymList.begin(), inSymList.end(), []( const auto& l, const auto& r ) { return l.incl != l.incl ? l.incl > r.incl : l.symAddr < r.symAddr; } );
                        }

                        ImGui::Indent();
                        for( auto& iv : inSymList )
                        {
                            const auto cnt = accumulationMode == AccumulationMode::SelfOnly ? iv.excl : iv.incl;
                            if( cnt > 0 || showAll )
                            {
                                ImGui::TableNextRow();
                                ImGui::TableNextColumn();
                                auto sit = symMap.find( iv.symAddr );
                                assert( sit != symMap.end() );
                                name = m_worker.GetString( sit->second.name );
                                switch( m_statSampleLocation )
                                {
                                case 0:
                                    file = m_worker.GetString( sit->second.file );
                                    line = sit->second.line;
                                    break;
                                case 1:
                                    file = m_worker.GetString( sit->second.callFile );
                                    line = sit->second.callLine;
                                    break;
                                case 2:
                                    if( sit->second.isInline )
                                    {
                                        file = m_worker.GetString( sit->second.callFile );
                                        line = sit->second.callLine;
                                    }
                                    else
                                    {
                                        file = m_worker.GetString( sit->second.file );
                                        line = sit->second.line;
                                    }
                                    break;
                                default:
                                    assert( false );
                                    break;
                                }

                                const auto sn = iv.symAddr == v.symAddr ? "[ - self - ]" : name;
                                if( m_mergeInlines || iv.excl == 0 )
                                {
                                    if( m_vd.shortenName == ShortenName::Never )
                                    {
                                        ImGui::TextUnformatted( sn );
                                    }
                                    else
                                    {
                                        const auto normalized = ShortenZoneName( ShortenName::OnlyNormalize, sn );
                                        ImGui::TextUnformatted( normalized );
                                        TooltipNormalizedName( sn, normalized );
                                    }
                                }
                                else
                                {
                                    ImGui::PushID( idx++ );
                                    bool clicked;
                                    if( m_vd.shortenName == ShortenName::Never )
                                    {
                                        clicked = ImGui::Selectable( sn, !m_sampleParents.withInlines && m_sampleParents.symAddr == iv.symAddr, ImGuiSelectableFlags_SpanAllColumns );
                                    }
                                    else
                                    {
                                        const auto normalized = ShortenZoneName( ShortenName::OnlyNormalize, sn );
                                        clicked = ImGui::Selectable( "", !m_sampleParents.withInlines && m_sampleParents.symAddr == iv.symAddr, ImGuiSelectableFlags_SpanAllColumns );
                                        ImGui::SameLine( 0, 0 );
                                        ImGui::TextUnformatted( normalized );
                                        TooltipNormalizedName( sn, normalized );
                                    }
                                    if( clicked ) ShowSampleParents( iv.symAddr, false );
                                    ImGui::PopID();
                                }
                                if( iv.count > 1 )
                                {
                                    ImGui::SameLine();
                                    ImGui::TextDisabled( "(\xc3\x97%s)", RealToString( iv.count ) );
                                }
                                ImGui::TableNextColumn();
                                float indentVal = 0.f;
                                if( m_statBuzzAnim.Match( iv.symAddr ) )
                                {
                                    const auto time = m_statBuzzAnim.Time();
                                    indentVal = sin( time * 60.f ) * 10.f * time;
                                    ImGui::Indent( indentVal );
                                }
                                if( m_statShowAddress )
                                {
                                    ImGui::TextDisabled( "0x%" PRIx64, iv.symAddr );
                                }
                                else
                                {
                                    TextDisabledUnformatted( LocationToString( file, line ) );
                                }
                                if( ImGui::IsItemHovered() )
                                {
                                    DrawSourceTooltip( file, line );
                                    if( ImGui::IsItemClicked( 1 ) )
                                    {
                                        if( SourceFileValid( file, m_worker.GetCaptureTime(), *this, m_worker ) )
                                        {
                                            ViewSymbol( file, line, codeAddr, iv.symAddr );
                                            if( !m_statSeparateInlines ) m_sourceView->CalcInlineStats( true );
                                        }
                                        else if( symlen != 0 )
                                        {
                                            uint32_t len;
                                            if( m_worker.GetSymbolCode( codeAddr, len ) )
                                            {
                                                ViewSymbol( nullptr, 0, codeAddr, iv.symAddr );
                                                if( !m_statSeparateInlines ) m_sourceView->CalcInlineStats( true );
                                            }
                                            else
                                            {
                                                m_statBuzzAnim.Enable( iv.symAddr, 0.5f );
                                            }
                                        }
                                        else
                                        {
                                            m_statBuzzAnim.Enable( iv.symAddr, 0.5f );
                                        }
                                    }
                                }
                                if( indentVal != 0.f )
                                {
                                    ImGui::Unindent( indentVal );
                                }
                                ImGui::TableNextColumn();
                                ImGui::TableNextColumn();
                                if( cnt > 0 )
                                {
                                    char buf[64];
                                    if( m_statSampleTime )
                                    {
                                        const auto t = cnt * period;
                                        ImGui::TextUnformatted( TimeToString( t ) );
                                        if( m_relativeInlines )
                                        {
                                            const auto tBase = baseCnt * period;
                                            PrintStringPercent( buf, 100. * t / tBase );
                                        }
                                        else
                                        {
                                            PrintStringPercent( buf, 100. * t / timeRange );
                                        }
                                    }
                                    else
                                    {
                                        ImGui::TextUnformatted( RealToString( cnt ) );
                                        if( m_relativeInlines )
                                        {
                                            PrintStringPercent( buf, cnt * revBaseCnt );
                                        }
                                        else
                                        {
                                            PrintStringPercent( buf, cnt * revSampleCount100 );
                                        }
                                    }
                                    ImGui::SameLine();
                                    TextDisabledUnformatted( buf );
                                }
                            }
                        }
                        ImGui::Unindent();
                        ImGui::TreePop();
                    }
                }
            }
            ImGui::EndTable();
        }
        ImGui::EndChild();

        inlineMap.clear();
    }
}

void View::DrawSampleParents()
{
    bool show = true;
    const auto scale = GetScale();
    ImGui::SetNextWindowSize( ImVec2( 1400 * scale, 500 * scale ), ImGuiCond_FirstUseEver );
    ImGui::Begin( "Sample entry call stacks", &show, ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse );
    if( !ImGui::GetCurrentWindowRead()->SkipItems )
    {
        auto ss = m_worker.GetSymbolStats( m_sampleParents.symAddr );
        auto excl = ss->excl;
        auto stats = ss->parents;

        const auto symbol = m_worker.GetSymbolData( m_sampleParents.symAddr );
        if( !symbol->isInline && m_sampleParents.withInlines )
        {
            const auto symlen = symbol->size.Val();
            auto inSym = m_worker.GetInlineSymbolList( m_sampleParents.symAddr, symlen );
            if( inSym )
            {
                const auto symEnd = m_sampleParents.symAddr + symlen;
                while( *inSym < symEnd )
                {
                    auto istat = m_worker.GetSymbolStats( *inSym++ );
                    if( !istat ) continue;
                    excl += istat->excl;
                    for( auto& v : istat->baseParents )
                    {
                        auto it = stats.find( v.first );
                        if( it == stats.end() )
                        {
                            stats.emplace( v.first, v.second );
                        }
                        else
                        {
                            it->second += v.second;
                        }
                    }
                }
            }
        }
        assert( !stats.empty() );

        const auto symName = m_worker.GetString( symbol->name );
        const char* normalized = m_vd.shortenName != ShortenName::Never ? ShortenZoneName( ShortenName::OnlyNormalize, symName ) : nullptr;
        ImGui::PushFont( m_bigFont );
        TextFocused( "Function:", normalized ? normalized : symName );
        if( normalized )
        {
            ImGui::PopFont();
            TooltipNormalizedName( symName, normalized );
            ImGui::PushFont( m_bigFont );
        }
        if( symbol->isInline )
        {
            ImGui::SameLine();
            TextDisabledUnformatted( "(inline)" );
        }
        else if( !m_sampleParents.withInlines )
        {
            ImGui::SameLine();
            TextDisabledUnformatted( "(without inlines)" );
        }
        ImGui::PopFont();
        TextDisabledUnformatted( "Location:" );
        ImGui::SameLine();
        const auto callFile = m_worker.GetString( symbol->callFile );
        ImGui::TextUnformatted( LocationToString( callFile, symbol->callLine ) );
        if( ImGui::IsItemClicked( 1 ) )
        {
            ViewDispatch( callFile, symbol->callLine, m_sampleParents.symAddr );
        }
        TextDisabledUnformatted( "Entry point:" );
        ImGui::SameLine();
        const auto file = m_worker.GetString( symbol->file );
        ImGui::TextUnformatted( LocationToString( file, symbol->line ) );
        if( ImGui::IsItemClicked( 1 ) )
        {
            ViewDispatch( file, symbol->line, m_sampleParents.symAddr );
        }
        ImGui::SameLine();
        ImGui::Spacing();
        ImGui::SameLine();
        TextDisabledUnformatted( m_worker.GetString( symbol->imageName ) );
        ImGui::Separator();
        ImGui::PushStyleVar( ImGuiStyleVar_FramePadding, ImVec2( 2, 2 ) );
        if( ImGui::RadioButton( ICON_FA_TABLE " List", m_sampleParents.mode == 0 ) ) m_sampleParents.mode = 0;
        ImGui::SameLine();
        ImGui::Spacing();
        ImGui::SameLine();
        if( ImGui::RadioButton( ICON_FA_TREE " Bottom-up tree", m_sampleParents.mode == 1 ) ) m_sampleParents.mode = 1;
        ImGui::SameLine();
        ImGui::Spacing();
        ImGui::SameLine();
        if( ImGui::RadioButton( ICON_FA_TREE " Top-down tree", m_sampleParents.mode == 2 ) ) m_sampleParents.mode = 2;
        ImGui::SameLine();
        ImGui::Spacing();
        ImGui::SameLine();
        ImGui::SeparatorEx( ImGuiSeparatorFlags_Vertical );
        ImGui::SameLine();
        ImGui::Spacing();
        ImGui::SameLine();
        ImGui::Checkbox( ICON_FA_STOPWATCH " Show time", &m_statSampleTime );
        ImGui::PopStyleVar();
        ImGui::Separator();
        ImGui::BeginChild( "##sampleParents" );
        switch( m_sampleParents.mode )
        {
        case 0:
        {
            TextDisabledUnformatted( "Entry call stack:" );
            ImGui::SameLine();
            if( ImGui::SmallButton( " " ICON_FA_CARET_LEFT " " ) )
            {
                m_sampleParents.sel = std::max( m_sampleParents.sel - 1, 0 );
            }
            ImGui::SameLine();
            ImGui::Text( "%s / %s", RealToString( m_sampleParents.sel + 1 ), RealToString( stats.size() ) );
            if( ImGui::IsItemClicked() ) ImGui::OpenPopup( "EntryCallStackPopup" );
            ImGui::SameLine();
            if( ImGui::SmallButton( " " ICON_FA_CARET_RIGHT " " ) )
            {
                m_sampleParents.sel = std::min<int>( m_sampleParents.sel + 1, stats.size() - 1 );
            }
            if( ImGui::BeginPopup( "EntryCallStackPopup" ) )
            {
                int sel = m_sampleParents.sel + 1;
                ImGui::SetNextItemWidth( 120 * scale );
                const bool clicked = ImGui::InputInt( "##entryCallStack", &sel, 1, 100, ImGuiInputTextFlags_EnterReturnsTrue );
                if( clicked ) m_sampleParents.sel = std::min( std::max( sel, 1 ), int( stats.size() ) ) - 1;
                ImGui::EndPopup();
            }
            Vector<decltype(stats.begin())> data;
            data.reserve( stats.size() );
            for( auto it = stats.begin(); it != stats.end(); ++it ) data.push_back( it );
            pdqsort_branchless( data.begin(), data.end(), []( const auto& l, const auto& r ) { return l->second > r->second; } );
            ImGui::SameLine();
            ImGui::TextUnformatted( m_statSampleTime ? TimeToString( m_worker.GetSamplingPeriod() * data[m_sampleParents.sel]->second ) : RealToString( data[m_sampleParents.sel]->second ) );
            ImGui::SameLine();
            char buf[64];
            PrintStringPercent( buf, 100. * data[m_sampleParents.sel]->second / excl );
            TextDisabledUnformatted( buf );
            ImGui::SameLine();
            ImGui::Spacing();
            ImGui::SameLine();
            ImGui::PushStyleVar( ImGuiStyleVar_FramePadding, ImVec2( 0, 0 ) );
            ImGui::TextUnformatted( ICON_FA_AT " Frame location:" );
            ImGui::SameLine();
            ImGui::RadioButton( "Source code", &m_showCallstackFrameAddress, 0 );
            ImGui::SameLine();
            ImGui::RadioButton( "Entry point", &m_showCallstackFrameAddress, 3 );
            ImGui::SameLine();
            ImGui::RadioButton( "Return address", &m_showCallstackFrameAddress, 1 );
            ImGui::SameLine();
            ImGui::RadioButton( "Symbol address", &m_showCallstackFrameAddress, 2 );
            ImGui::PopStyleVar();

            auto& cs = m_worker.GetParentCallstack( data[m_sampleParents.sel]->first );
            ImGui::Separator();
            if( ImGui::BeginTable( "##callstack", 4, ImGuiTableFlags_Resizable | ImGuiTableFlags_Reorderable | ImGuiTableFlags_Hideable | ImGuiTableFlags_Borders | ImGuiTableFlags_ScrollY ) )
            {
                ImGui::TableSetupScrollFreeze( 0, 1 );
                ImGui::TableSetupColumn( "Frame", ImGuiTableColumnFlags_NoHide | ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_NoResize );
                ImGui::TableSetupColumn( "Function" );
                ImGui::TableSetupColumn( "Location" );
                ImGui::TableSetupColumn( "Image" );
                ImGui::TableHeadersRow();

                int fidx = 0;
                int bidx = 0;
                for( auto& entry : cs )
                {
                    auto frameData = entry.custom ? m_worker.GetParentCallstackFrame( entry ) : m_worker.GetCallstackFrame( entry );
                    assert( frameData );
                    const auto fsz = frameData->size;
                    for( uint8_t f=0; f<fsz; f++ )
                    {
                        const auto& frame = frameData->data[f];
                        auto txt = m_worker.GetString( frame.name );
                        bidx++;
                        ImGui::TableNextRow();
                        ImGui::TableNextColumn();
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
                        if( m_sampleParentBuzzAnim.Match( bidx ) )
                        {
                            const auto time = m_sampleParentBuzzAnim.Time();
                            indentVal = sin( time * 60.f ) * 10.f * time;
                            ImGui::Indent( indentVal );
                        }
                        txt = m_worker.GetString( frame.file );
                        switch( m_showCallstackFrameAddress )
                        {
                        case 0:
                            TextDisabledUnformatted( LocationToString( txt, frame.line ) );
                            if( ImGui::IsItemClicked() )
                            {
                                ImGui::SetClipboardText( txt );
                            }
                            break;
                        case 1:
                            if( entry.custom == 0 )
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
                                TextDisabledUnformatted( "unavailable" );
                            }
                            break;
                        case 2:
                            ImGui::TextDisabled( "0x%" PRIx64, frame.symAddr );
                            if( ImGui::IsItemClicked() )
                            {
                                char tmp[32];
                                sprintf( tmp, "0x%" PRIx64, frame.symAddr );
                                ImGui::SetClipboardText( tmp );
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
                                DrawSourceTooltip( txt, frame.line );
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
                                            m_sampleParentBuzzAnim.Enable( bidx, 0.5f );
                                        }
                                    }
                                    else
                                    {
                                        m_sampleParentBuzzAnim.Enable( bidx, 0.5f );
                                    }
                                }
                                else
                                {
                                    if( !ViewDispatch( txt, frame.line, frame.symAddr ) )
                                    {
                                        m_sampleParentBuzzAnim.Enable( bidx, 0.5f );
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
                            TextDisabledUnformatted( m_worker.GetString( frameData->imageName ) );
                        }
                    }
                }
                ImGui::EndTable();
            }
            break;
        }
        case 1:
        {
            SmallCheckbox( ICON_FA_LAYER_GROUP " Group by function name", &m_sampleParents.groupBottomUp );
            auto tree = GetParentsCallstackFrameTreeBottomUp( stats, m_sampleParents.groupBottomUp );
            if( !tree.empty() )
            {
                int idx = 0;
                DrawParentsFrameTreeLevel( tree, idx );
            }
            else
            {
                TextDisabledUnformatted( "No call stacks to show" );
            }

            break;
        }
        case 2:
        {
            SmallCheckbox( ICON_FA_LAYER_GROUP " Group by function name", &m_sampleParents.groupTopDown );
            auto tree = GetParentsCallstackFrameTreeTopDown( stats, m_sampleParents.groupTopDown );
            if( !tree.empty() )
            {
                int idx = 0;
                DrawParentsFrameTreeLevel( tree, idx );
            }
            else
            {
                TextDisabledUnformatted( "No call stacks to show" );
            }
            break;
        }
        default:
            assert( false );
            break;
        }
        ImGui::EndChild();
    }
    ImGui::End();

    if( !show )
    {
        m_sampleParents.symAddr = 0;
    }
}

}
