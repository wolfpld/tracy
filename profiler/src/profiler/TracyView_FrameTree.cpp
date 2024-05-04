#include "TracyImGui.hpp"
#include "TracyPrint.hpp"
#include "TracyView.hpp"

namespace tracy
{

template<class T>
static tracy_force_inline T* GetFrameTreeItemNoGroup( unordered_flat_map<uint64_t, T>& tree, CallstackFrameId idx )
{
    auto it = tree.find( idx.data );
    if( it == tree.end() )
    {
        it = tree.emplace( idx.data, T( idx ) ).first;
    }
    return &it->second;
}

template<class T>
static tracy_force_inline T* GetFrameTreeItemGroup( unordered_flat_map<uint64_t, T>& tree, CallstackFrameId idx, const Worker& worker )
{
    auto frameDataPtr = worker.GetCallstackFrame( idx );
    if( !frameDataPtr ) return nullptr;

    auto& frameData = *frameDataPtr;
    auto& frame = frameData.data[frameData.size-1];
    auto fidx = frame.name.Idx();

    auto it = tree.find( fidx );
    if( it == tree.end() )
    {
        it = tree.emplace( fidx, T( idx ) ).first;
    }
    return &it->second;
}

template<class T>
static tracy_force_inline T* GetParentFrameTreeItemGroup( unordered_flat_map<uint64_t, T>& tree, CallstackFrameId idx, const Worker& worker )
{
    auto frameDataPtr = idx.custom ? worker.GetParentCallstackFrame( idx ) : worker.GetCallstackFrame( idx );
    if( !frameDataPtr ) return nullptr;

    auto& frameData = *frameDataPtr;
    auto& frame = frameData.data[frameData.size-1];
    auto fidx = frame.name.Idx();

    auto it = tree.find( fidx );
    if( it == tree.end() )
    {
        it = tree.emplace( fidx, T( idx ) ).first;
    }
    return &it->second;
}


unordered_flat_map<uint32_t, View::MemPathData> View::GetCallstackPaths( const MemData& mem, MemRange memRange ) const
{
    unordered_flat_map<uint32_t, MemPathData> pathSum;
    pathSum.reserve( m_worker.GetCallstackPayloadCount() );

    const bool hide_inactive = memRange == MemRange::Active;

    if( m_memInfo.range.active )
    {
        auto it = std::lower_bound( mem.data.begin(), mem.data.end(), m_memInfo.range.min, []( const auto& lhs, const auto& rhs ) { return lhs.TimeAlloc() < rhs; } );
        if( it != mem.data.end() )
        {
            auto end = std::lower_bound( mem.data.begin(), mem.data.end(), m_memInfo.range.max, []( const auto& lhs, const auto& rhs ) { return lhs.TimeAlloc() < rhs; } );
            if( memRange != MemRange::Full )
            {
                while( it != end )
                {
                    auto& ev = *it++;
                    if( ev.CsAlloc() == 0 ) continue;
                    const bool is_inactive =  ev.TimeFree() >= 0 && ev.TimeFree() < m_memInfo.range.max;
                    if( hide_inactive == is_inactive ) continue;
                    auto pit = pathSum.find( ev.CsAlloc() );
                    if( pit == pathSum.end() )
                    {
                        pathSum.emplace( ev.CsAlloc(), MemPathData { 1, ev.Size() } );
                    }
                    else
                    {
                        pit->second.cnt++;
                        pit->second.mem += ev.Size();
                    }
                }
            }
            else
            {
                while( it != end )
                {
                    auto& ev = *it++;
                    if( ev.CsAlloc() == 0 ) continue;
                    auto pit = pathSum.find( ev.CsAlloc() );
                    if( pit == pathSum.end() )
                    {
                        pathSum.emplace( ev.CsAlloc(), MemPathData { 1, ev.Size() } );
                    }
                    else
                    {
                        pit->second.cnt++;
                        pit->second.mem += ev.Size();
                    }
                }
            }
        }
    }
    else
    {
        if( memRange != MemRange::Full )
        {
            for( auto& ev : mem.data )
            {
                if( ev.CsAlloc() == 0 ) continue;
                const bool is_inactive =  ev.TimeFree() >= 0;
                if( hide_inactive == is_inactive ) continue;
                auto it = pathSum.find( ev.CsAlloc() );
                if( it == pathSum.end() )
                {
                    pathSum.emplace( ev.CsAlloc(), MemPathData { 1, ev.Size() } );
                }
                else
                {
                    it->second.cnt++;
                    it->second.mem += ev.Size();
                }
            }
        }
        else
        {
            for( auto& ev : mem.data )
            {
                if( ev.CsAlloc() == 0 ) continue;
                auto it = pathSum.find( ev.CsAlloc() );
                if( it == pathSum.end() )
                {
                    pathSum.emplace( ev.CsAlloc(), MemPathData { 1, ev.Size() } );
                }
                else
                {
                    it->second.cnt++;
                    it->second.mem += ev.Size();
                }
            }
        }
    }
    return pathSum;
}

unordered_flat_map<uint64_t, MemCallstackFrameTree> View::GetCallstackFrameTreeBottomUp( const MemData& mem ) const
{
    unordered_flat_map<uint64_t, MemCallstackFrameTree> root;
    auto pathSum = GetCallstackPaths( mem, m_memRangeBottomUp );
    if( m_groupCallstackTreeByNameBottomUp )
    {
        for( auto& path : pathSum )
        {
            auto& cs = m_worker.GetCallstack( path.first );
            auto base = cs.back();
            auto treePtr = GetFrameTreeItemGroup( root, base, m_worker );
            if( treePtr )
            {
                treePtr->count += path.second.cnt;
                treePtr->alloc += path.second.mem;
                treePtr->callstacks.emplace( path.first );
                for( int i = int( cs.size() ) - 2; i >= 0; i-- )
                {
                    treePtr = GetFrameTreeItemGroup( treePtr->children, cs[i], m_worker );
                    if( !treePtr ) break;
                    treePtr->count += path.second.cnt;
                    treePtr->alloc += path.second.mem;
                    treePtr->callstacks.emplace( path.first );
                }
            }
        }
    }
    else
    {
        for( auto& path : pathSum )
        {
            auto& cs = m_worker.GetCallstack( path.first );
            auto base = cs.back();
            auto treePtr = GetFrameTreeItemNoGroup( root, base );
            treePtr->count += path.second.cnt;
            treePtr->alloc += path.second.mem;
            treePtr->callstacks.emplace( path.first );
            for( int i = int( cs.size() ) - 2; i >= 0; i-- )
            {
                treePtr = GetFrameTreeItemNoGroup( treePtr->children, cs[i] );
                treePtr->count += path.second.cnt;
                treePtr->alloc += path.second.mem;
                treePtr->callstacks.emplace( path.first );
            }
        }
    }
    return root;
}

unordered_flat_map<uint64_t, CallstackFrameTree> View::GetCallstackFrameTreeBottomUp( const unordered_flat_map<uint32_t, uint64_t>& stacks, bool group ) const
{
    unordered_flat_map<uint64_t, CallstackFrameTree> root;
    if( group )
    {
        for( auto& path : stacks )
        {
            auto& cs = m_worker.GetCallstack( path.first );
            auto base = cs.back();
            auto treePtr = GetFrameTreeItemGroup( root, base, m_worker );
            if( treePtr )
            {
                treePtr->count += path.second;
                for( int i = int( cs.size() ) - 2; i >= 0; i-- )
                {
                    treePtr = GetFrameTreeItemGroup( treePtr->children, cs[i], m_worker );
                    if( !treePtr ) break;
                    treePtr->count += path.second;
                }
            }
        }
    }
    else
    {
        for( auto& path : stacks )
        {
            auto& cs = m_worker.GetCallstack( path.first );
            auto base = cs.back();
            auto treePtr = GetFrameTreeItemNoGroup( root, base );
            treePtr->count += path.second;
            for( int i = int( cs.size() ) - 2; i >= 0; i-- )
            {
                treePtr = GetFrameTreeItemNoGroup( treePtr->children, cs[i] );
                treePtr->count += path.second;
            }
        }
    }
    return root;
}

unordered_flat_map<uint64_t, CallstackFrameTree> View::GetParentsCallstackFrameTreeBottomUp( const unordered_flat_map<uint32_t, uint32_t>& stacks, bool group ) const
{
    unordered_flat_map<uint64_t, CallstackFrameTree> root;
    if( group )
    {
        for( auto& path : stacks )
        {
            auto& cs = m_worker.GetParentCallstack( path.first );
            auto base = cs.back();
            auto treePtr = GetParentFrameTreeItemGroup( root, base, m_worker );
            if( treePtr )
            {
                treePtr->count += path.second;
                for( int i = int( cs.size() ) - 2; i >= 0; i-- )
                {
                    treePtr = GetParentFrameTreeItemGroup( treePtr->children, cs[i], m_worker );
                    if( !treePtr ) break;
                    treePtr->count += path.second;
                }
            }
        }
    }
    else
    {
        for( auto& path : stacks )
        {
            auto& cs = m_worker.GetParentCallstack( path.first );
            auto base = cs.back();
            auto treePtr = GetFrameTreeItemNoGroup( root, base );
            treePtr->count += path.second;
            for( int i = int( cs.size() ) - 2; i >= 0; i-- )
            {
                treePtr = GetFrameTreeItemNoGroup( treePtr->children, cs[i] );
                treePtr->count += path.second;
            }
        }
    }
    return root;
}


unordered_flat_map<uint64_t, MemCallstackFrameTree> View::GetCallstackFrameTreeTopDown( const MemData& mem ) const
{
    unordered_flat_map<uint64_t, MemCallstackFrameTree> root;
    auto pathSum = GetCallstackPaths( mem, m_memRangeTopDown );
    if( m_groupCallstackTreeByNameTopDown )
    {
        for( auto& path : pathSum )
        {
            auto& cs = m_worker.GetCallstack( path.first );
            auto base = cs.front();
            auto treePtr = GetFrameTreeItemGroup( root, base, m_worker );
            if( treePtr )
            {
                treePtr->count += path.second.cnt;
                treePtr->alloc += path.second.mem;
                treePtr->callstacks.emplace( path.first );
                for( uint16_t i = 1; i < cs.size(); i++ )
                {
                    treePtr = GetFrameTreeItemGroup( treePtr->children, cs[i], m_worker );
                    if( !treePtr ) break;
                    treePtr->count += path.second.cnt;
                    treePtr->alloc += path.second.mem;
                    treePtr->callstacks.emplace( path.first );
                }
            }
        }
    }
    else
    {
        for( auto& path : pathSum )
        {
            auto& cs = m_worker.GetCallstack( path.first );
            auto base = cs.front();
            auto treePtr = GetFrameTreeItemNoGroup( root, base );
            treePtr->count += path.second.cnt;
            treePtr->alloc += path.second.mem;
            treePtr->callstacks.emplace( path.first );
            for( uint16_t i = 1; i < cs.size(); i++ )
            {
                treePtr = GetFrameTreeItemNoGroup( treePtr->children, cs[i] );
                treePtr->count += path.second.cnt;
                treePtr->alloc += path.second.mem;
                treePtr->callstacks.emplace( path.first );
            }
        }
    }
    return root;
}

unordered_flat_map<uint64_t, CallstackFrameTree> View::GetCallstackFrameTreeTopDown( const unordered_flat_map<uint32_t, uint64_t>& stacks, bool group ) const
{
    unordered_flat_map<uint64_t, CallstackFrameTree> root;
    if( group )
    {
        for( auto& path : stacks )
        {
            auto& cs = m_worker.GetCallstack( path.first );
            auto base = cs.front();
            auto treePtr = GetFrameTreeItemGroup( root, base, m_worker );
            if( treePtr )
            {
                treePtr->count += path.second;
                for( uint16_t i = 1; i < cs.size(); i++ )
                {
                    treePtr = GetFrameTreeItemGroup( treePtr->children, cs[i], m_worker );
                    if( !treePtr ) break;
                    treePtr->count += path.second;
                }
            }
        }
    }
    else
    {
        for( auto& path : stacks )
        {
            auto& cs = m_worker.GetCallstack( path.first );
            auto base = cs.front();
            auto treePtr = GetFrameTreeItemNoGroup( root, base );
            treePtr->count += path.second;
            for( uint16_t i = 1; i < cs.size(); i++ )
            {
                treePtr = GetFrameTreeItemNoGroup( treePtr->children, cs[i] );
                treePtr->count += path.second;
            }
        }
    }
    return root;
}

unordered_flat_map<uint64_t, CallstackFrameTree> View::GetParentsCallstackFrameTreeTopDown( const unordered_flat_map<uint32_t, uint32_t>& stacks, bool group ) const
{
    unordered_flat_map<uint64_t, CallstackFrameTree> root;
    if( group )
    {
        for( auto& path : stacks )
        {
            auto& cs = m_worker.GetParentCallstack( path.first );
            auto base = cs.front();
            auto treePtr = GetParentFrameTreeItemGroup( root, base, m_worker );
            if( treePtr )
            {
                treePtr->count += path.second;
                for( uint16_t i = 1; i < cs.size(); i++ )
                {
                    treePtr = GetParentFrameTreeItemGroup( treePtr->children, cs[i], m_worker );
                    if( !treePtr ) break;
                    treePtr->count += path.second;
                }
            }
        }
    }
    else
    {
        for( auto& path : stacks )
        {
            auto& cs = m_worker.GetParentCallstack( path.first );
            auto base = cs.front();
            auto treePtr = GetFrameTreeItemNoGroup( root, base );
            treePtr->count += path.second;
            for( uint16_t i = 1; i < cs.size(); i++ )
            {
                treePtr = GetFrameTreeItemNoGroup( treePtr->children, cs[i] );
                treePtr->count += path.second;
            }
        }
    }
    return root;
}

void View::DrawFrameTreeLevel( const unordered_flat_map<uint64_t, MemCallstackFrameTree>& tree, int& idx )
{
    auto& io = ImGui::GetIO();

    std::vector<unordered_flat_map<uint64_t, MemCallstackFrameTree>::const_iterator> sorted;
    sorted.reserve( tree.size() );
    for( auto it = tree.begin(); it != tree.end(); ++it )
    {
        sorted.emplace_back( it );
    }
    pdqsort_branchless( sorted.begin(), sorted.end(), [] ( const auto& lhs, const auto& rhs ) { return lhs->second.alloc > rhs->second.alloc; } );

    int lidx = 0;
    for( auto& _v : sorted )
    {
        auto& v = _v->second;
        const auto isKernel = ( m_worker.GetCanonicalPointer( v.frame ) >> 63 ) != 0;
        idx++;
        auto frameDataPtr = m_worker.GetCallstackFrame( v.frame );
        if( frameDataPtr )
        {
            auto& frameData = *frameDataPtr;
            auto frame = frameData.data[frameData.size-1];
            bool expand = false;

            const auto frameName = m_worker.GetString( frame.name );
            if( v.children.empty() )
            {
                ImGui::Indent( ImGui::GetTreeNodeToLabelSpacing() );
                if( frameName[0] == '[' )
                {
                    TextDisabledUnformatted( frameName );
                }
                else if( isKernel )
                {
                    TextColoredUnformatted( 0xFF8888FF, frameName );
                }
                else if( m_vd.shortenName == ShortenName::Never )
                {
                    ImGui::TextUnformatted( frameName );
                }
                else
                {
                    const auto normalized = ShortenZoneName( ShortenName::OnlyNormalize, frameName );
                    ImGui::TextUnformatted( normalized );
                    TooltipNormalizedName( frameName, normalized );
                }
                ImGui::Unindent( ImGui::GetTreeNodeToLabelSpacing() );
            }
            else
            {
                ImGui::PushID( lidx++ );
                if( frameName[0] == '[' ) ImGui::PushStyleColor( ImGuiCol_Text, 0x88FFFFFF );
                else if( isKernel ) ImGui::PushStyleColor( ImGuiCol_Text, 0xFF8888FF );
                if( tree.size() == 1 )
                {
                    if( m_vd.shortenName == ShortenName::Never )
                    {
                        expand = ImGui::TreeNodeEx( frameName, ImGuiTreeNodeFlags_DefaultOpen );
                    }
                    else
                    {
                        const auto normalized = ShortenZoneName( ShortenName::OnlyNormalize, frameName );
                        expand = ImGui::TreeNodeEx( normalized, ImGuiTreeNodeFlags_DefaultOpen );
                        TooltipNormalizedName( frameName, normalized );
                    }
                }
                else
                {
                    if( m_vd.shortenName == ShortenName::Never )
                    {
                        expand = ImGui::TreeNode( frameName );
                    }
                    else
                    {
                        const auto normalized = ShortenZoneName( ShortenName::OnlyNormalize, frameName );
                        expand = ImGui::TreeNode( normalized );
                        TooltipNormalizedName( frameName, normalized );
                    }
                }
                if( isKernel || frameName[0] == '[' ) ImGui::PopStyleColor();
                ImGui::PopID();
            }

            if( ImGui::IsItemClicked( 1 ) )
            {
                auto& mem = m_worker.GetMemoryNamed( m_memInfo.pool ).data;
                const auto sz = mem.size();
                m_memInfo.showAllocList = true;
                m_memInfo.allocList.clear();
                for( size_t i=0; i<sz; i++ )
                {
                    if( v.callstacks.find( mem[i].CsAlloc() ) != v.callstacks.end() )
                    {
                        m_memInfo.allocList.emplace_back( i );
                    }
                }
            }

            if( io.KeyCtrl && ImGui::IsItemHovered() )
            {
                ImGui::BeginTooltip();
                TextFocused( "Allocations size:", MemSizeToString( v.alloc ) );
                TextFocused( "Allocations count:", RealToString( v.count ) );
                TextFocused( "Mean allocation size:", MemSizeToString( v.alloc / v.count ) );
                ImGui::SameLine();
                ImGui::EndTooltip();
            }

            if( m_callstackTreeBuzzAnim.Match( idx ) )
            {
                const auto time = m_callstackTreeBuzzAnim.Time();
                const auto indentVal = sin( time * 60.f ) * 10.f * time;
                ImGui::SameLine( 0, ImGui::GetStyle().ItemSpacing.x + indentVal );
            }
            else
            {
                ImGui::SameLine();
            }
            const char* fileName = nullptr;
            if( frame.line == 0 )
            {
                if( frameDataPtr->imageName.Active() ) TextDisabledUnformatted( m_worker.GetString( frameDataPtr->imageName ) );
            }
            else
            {
                fileName = m_worker.GetString( frame.file );
                ImGui::TextDisabled( "%s:%i", fileName, frame.line );
            }
            if( ImGui::IsItemHovered() )
            {
                DrawSourceTooltip( fileName, frame.line );
                if( ImGui::IsItemClicked( 1 ) )
                {
                    if( !ViewDispatch( fileName, frame.line, frame.symAddr ) )
                    {
                        m_callstackTreeBuzzAnim.Enable( idx, 0.5f );
                    }
                }
            }

            ImGui::SameLine();
            if( v.children.empty() )
            {
                ImGui::TextColored( ImVec4( 0.2, 0.8, 0.8, 1.0 ), "%s (%s)", MemSizeToString( v.alloc ), RealToString( v.count ) );
                TooltipIfHovered( "Cost in this node" );
            }
            else
            {
                uint32_t childCost = 0;
                uint64_t childAlloc = 0;
                for( auto& c : v.children )
                {
                    childCost += c.second.count;
                    childAlloc += c.second.alloc;
                }
                const auto rc = v.count - childCost;
                if( rc != 0 )
                {
                    ImGui::TextColored( ImVec4( 0.2, 0.8, 0.8, 1.0 ), "%s (%s)", MemSizeToString( v.alloc - childAlloc ), RealToString( rc ) );
                    TooltipIfHovered( "Cost only in this node" );
                    ImGui::SameLine();
                }
                ImGui::TextColored( ImVec4( 0.8, 0.8, 0.2, 1.0 ), "%s (%s)", MemSizeToString( v.alloc ), RealToString( v.count ) );
                TooltipIfHovered( "Cost in this node and children" );
            }

            if( expand )
            {
                DrawFrameTreeLevel( v.children, idx );
                ImGui::TreePop();
            }
        }
    }
}

void View::DrawFrameTreeLevel( const unordered_flat_map<uint64_t, CallstackFrameTree>& tree, int& idx )
{
    std::vector<unordered_flat_map<uint64_t, CallstackFrameTree>::const_iterator> sorted;
    sorted.reserve( tree.size() );
    for( auto it = tree.begin(); it != tree.end(); ++it )
    {
        sorted.emplace_back( it );
    }
    pdqsort_branchless( sorted.begin(), sorted.end(), [] ( const auto& lhs, const auto& rhs ) { return lhs->second.count > rhs->second.count; } );

    int lidx = 0;
    for( auto& _v : sorted )
    {
        auto& v = _v->second;
        const auto isKernel = ( m_worker.GetCanonicalPointer( v.frame ) >> 63 ) != 0;
        idx++;
        auto frameDataPtr = m_worker.GetCallstackFrame( v.frame );
        if( frameDataPtr )
        {
            auto& frameData = *frameDataPtr;
            auto frame = frameData.data[frameData.size-1];
            bool expand = false;

            const auto frameName = m_worker.GetString( frame.name );
            if( v.children.empty() )
            {
                ImGui::Indent( ImGui::GetTreeNodeToLabelSpacing() );
                if( frameName[0] == '[' )
                {
                    TextDisabledUnformatted( frameName );
                }
                else if( isKernel )
                {
                    TextColoredUnformatted( 0xFF8888FF, frameName );
                }
                else if( m_vd.shortenName == ShortenName::Never )
                {
                    ImGui::TextUnformatted( frameName );
                }
                else
                {
                    const auto normalized = ShortenZoneName( ShortenName::OnlyNormalize, frameName );
                    expand = ImGui::TreeNodeEx( normalized, ImGuiTreeNodeFlags_DefaultOpen );
                    TooltipNormalizedName( frameName, normalized );
                }
                ImGui::Unindent( ImGui::GetTreeNodeToLabelSpacing() );
            }
            else
            {
                ImGui::PushID( lidx++ );
                if( frameName[0] == '[' ) ImGui::PushStyleColor( ImGuiCol_Text, 0x88FFFFFF );
                else if( isKernel ) ImGui::PushStyleColor( ImGuiCol_Text, 0xFF8888FF );
                if( tree.size() == 1 )
                {
                    if( m_vd.shortenName == ShortenName::Never )
                    {
                        expand = ImGui::TreeNodeEx( frameName, ImGuiTreeNodeFlags_DefaultOpen );
                    }
                    else
                    {
                        const auto normalized = ShortenZoneName( ShortenName::OnlyNormalize, frameName );
                        expand = ImGui::TreeNodeEx( normalized, ImGuiTreeNodeFlags_DefaultOpen );
                        TooltipNormalizedName( frameName, normalized );
                    }
                }
                else
                {
                    if( m_vd.shortenName == ShortenName::Never )
                    {
                        expand = ImGui::TreeNode( frameName );
                    }
                    else
                    {
                        const auto normalized = ShortenZoneName( ShortenName::OnlyNormalize, frameName );
                        expand = ImGui::TreeNode( normalized );
                        TooltipNormalizedName( frameName, normalized );
                    }
                }
                if( isKernel || frameName[0] == '[' ) ImGui::PopStyleColor();
                ImGui::PopID();
            }

            if( m_callstackTreeBuzzAnim.Match( idx ) )
            {
                const auto time = m_callstackTreeBuzzAnim.Time();
                const auto indentVal = sin( time * 60.f ) * 10.f * time;
                ImGui::SameLine( 0, ImGui::GetStyle().ItemSpacing.x + indentVal );
            }
            else
            {
                ImGui::SameLine();
            }
            const char* fileName = nullptr;
            if( frame.line == 0 )
            {
                TextDisabledUnformatted( m_worker.GetString( frameDataPtr->imageName ) );
            }
            else
            {
                fileName = m_worker.GetString( frame.file );
                ImGui::TextDisabled( "%s:%i", fileName, frame.line );
            }
            if( ImGui::IsItemHovered() )
            {
                DrawSourceTooltip( fileName, frame.line );
                if( ImGui::IsItemClicked( 1 ) )
                {
                    if( !ViewDispatch( fileName, frame.line, frame.symAddr ) )
                    {
                        m_callstackTreeBuzzAnim.Enable( idx, 0.5f );
                    }
                }
            }

            ImGui::SameLine();
            if( v.children.empty() )
            {
                ImGui::TextColored( ImVec4( 0.2, 0.8, 0.8, 1.0 ), "(%s)", RealToString( v.count ) );
                TooltipIfHovered( "Cost in this node" );
            }
            else
            {
                uint32_t childCost = 0;
                for( auto& c : v.children ) childCost += c.second.count;
                const auto r = v.count - childCost;
                if( r != 0 )
                {
                    ImGui::TextColored( ImVec4( 0.2, 0.8, 0.8, 1.0 ), "(%s)", RealToString( r ) );
                    TooltipIfHovered( "Cost only in this node" );
                    ImGui::SameLine();
                }
                ImGui::TextColored( ImVec4( 0.8, 0.8, 0.2, 1.0 ), "(%s)", RealToString( v.count ) );
                TooltipIfHovered( "Cost in this node and children" );
            }

            if( expand )
            {
                DrawFrameTreeLevel( v.children, idx );
                ImGui::TreePop();
            }
        }
    }
}

void View::DrawParentsFrameTreeLevel( const unordered_flat_map<uint64_t, CallstackFrameTree>& tree, int& idx )
{
    std::vector<unordered_flat_map<uint64_t, CallstackFrameTree>::const_iterator> sorted;
    sorted.reserve( tree.size() );
    for( auto it = tree.begin(); it != tree.end(); ++it )
    {
        sorted.emplace_back( it );
    }
    pdqsort_branchless( sorted.begin(), sorted.end(), [] ( const auto& lhs, const auto& rhs ) { return lhs->second.count > rhs->second.count; } );

    int lidx = 0;
    for( auto& _v : sorted )
    {
        auto& v = _v->second;
        const auto isKernel = ( m_worker.GetCanonicalPointer( v.frame ) >> 63 ) != 0;
        idx++;
        auto frameDataPtr = v.frame.custom ? m_worker.GetParentCallstackFrame( v.frame ) : m_worker.GetCallstackFrame( v.frame );
        if( frameDataPtr )
        {
            auto& frameData = *frameDataPtr;
            auto frame = frameData.data[frameData.size-1];
            bool expand = false;

            const auto frameName = m_worker.GetString( frame.name );
            if( v.children.empty() )
            {
                ImGui::Indent( ImGui::GetTreeNodeToLabelSpacing() );
                if( frameName[0] == '[' )
                {
                    TextDisabledUnformatted( frameName );
                }
                else if( isKernel )
                {
                    TextColoredUnformatted( 0xFF8888FF, frameName );
                }
                else if( m_vd.shortenName == ShortenName::Never )
                {
                    ImGui::TextUnformatted( frameName );
                }
                else
                {
                    const auto normalized = ShortenZoneName( ShortenName::OnlyNormalize, frameName );
                    ImGui::TextUnformatted( normalized );
                    TooltipNormalizedName( frameName, normalized );
                }
                ImGui::Unindent( ImGui::GetTreeNodeToLabelSpacing() );
            }
            else
            {
                ImGui::PushID( lidx++ );
                if( frameName[0] == '[' ) ImGui::PushStyleColor( ImGuiCol_Text, 0x88FFFFFF );
                else if( isKernel ) ImGui::PushStyleColor( ImGuiCol_Text, 0xFF8888FF );
                if( tree.size() == 1 )
                {
                    if( m_vd.shortenName == ShortenName::Never )
                    {
                        expand = ImGui::TreeNodeEx( frameName, ImGuiTreeNodeFlags_DefaultOpen );
                    }
                    else
                    {
                        const auto normalized = ShortenZoneName( ShortenName::OnlyNormalize, frameName );
                        expand = ImGui::TreeNodeEx( normalized, ImGuiTreeNodeFlags_DefaultOpen );
                        TooltipNormalizedName( frameName, normalized );
                    }
                }
                else
                {
                    if( m_vd.shortenName == ShortenName::Never )
                    {
                        expand = ImGui::TreeNode( frameName );
                    }
                    else
                    {
                        const auto normalized = ShortenZoneName( ShortenName::OnlyNormalize, frameName );
                        expand = ImGui::TreeNode( normalized );
                        TooltipNormalizedName( frameName, normalized );
                    }
                }
                if( isKernel || frameName[0] == '[' ) ImGui::PopStyleColor();
                ImGui::PopID();
            }

            if( m_callstackTreeBuzzAnim.Match( idx ) )
            {
                const auto time = m_callstackTreeBuzzAnim.Time();
                const auto indentVal = sin( time * 60.f ) * 10.f * time;
                ImGui::SameLine( 0, ImGui::GetStyle().ItemSpacing.x + indentVal );
            }
            else
            {
                ImGui::SameLine();
            }
            const char* fileName = nullptr;
            if( frame.line == 0 )
            {
                TextDisabledUnformatted( m_worker.GetString( frameDataPtr->imageName ) );
            }
            else
            {
                fileName = m_worker.GetString( frame.file );
                ImGui::TextDisabled( "%s:%i", fileName, frame.line );
            }
            if( ImGui::IsItemHovered() )
            {
                DrawSourceTooltip( fileName, frame.line );
                if( ImGui::IsItemClicked( 1 ) )
                {
                    if( !ViewDispatch( fileName, frame.line, frame.symAddr ) )
                    {
                        m_callstackTreeBuzzAnim.Enable( idx, 0.5f );
                    }
                }
            }

            ImGui::SameLine();
            if( v.children.empty() )
            {
                ImGui::TextColored( ImVec4( 0.2, 0.8, 0.8, 1.0 ), "(%s)", m_statSampleTime ? TimeToString( m_worker.GetSamplingPeriod() * v.count ) : RealToString( v.count ) );
                TooltipIfHovered( "Cost in this node" );
            }
            else
            {
                uint32_t childCost = 0;
                for( auto& c : v.children ) childCost += c.second.count;
                const auto r = v.count - childCost;
                if( r != 0 )
                {
                    ImGui::TextColored( ImVec4( 0.2, 0.8, 0.8, 1.0 ), "(%s)", m_statSampleTime ? TimeToString( m_worker.GetSamplingPeriod() * r ) : RealToString( r ) );
                    TooltipIfHovered( "Cost only in this node" );
                    ImGui::SameLine();
                }
                ImGui::TextColored( ImVec4( 0.8, 0.8, 0.2, 1.0 ), "(%s)", m_statSampleTime ? TimeToString( m_worker.GetSamplingPeriod() * v.count ) : RealToString( v.count ) );
                TooltipIfHovered( "Cost in this node and children" );
            }

            if( expand )
            {
                DrawParentsFrameTreeLevel( v.children, idx );
                ImGui::TreePop();
            }
        }
    }
}

}
