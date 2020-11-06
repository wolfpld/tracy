// Use with instructions.xml retrieved from uops.info

#include <algorithm>
#include <assert.h>
#include <limits>
#include <stdio.h>
#include <string>
#include <string.h>
#include <pugixml.hpp>
#include <unordered_map>
#include <vector>

struct Dictionary
{
    int Get( const std::string& str )
    {
        auto it = str2idx.find( str );
        if( it != str2idx.end() ) return it->second;
        const auto idx = strlist.size();
        str2idx.emplace( str, idx );
        strlist.emplace_back( str );
        return idx;
    }

    int Get( const char* str ) { return Get( std::string( str ) ); }

    const std::string& Get( int idx ) const
    {
        return strlist[idx];
    }

    size_t Size() const { return strlist.size(); }

    std::unordered_map<std::string, int> str2idx;
    std::vector<std::string> strlist;
};

struct ParamDesc
{
    int type;
    int width;
};

struct Variant
{
    std::vector<ParamDesc> desc;
    int isaSet;
    float tp;
    int port, uops, minlat, maxlat;
    bool minbound, maxbound;
};

struct Op
{
    std::vector<Variant> var;
    int desc;
};

struct UArch
{
    std::unordered_map<int, Op> ops;
};

const std::vector<std::pair<const char*, const char*>> LatencyValues = {
    { "cycles", "cycles_is_upper_bound" },
    { "cycles_addr", "cycles_addr_is_upper_bound" },
    { "cycles_addr_same_reg", "cycles_addr_same_reg_is_upper_bound" },
    { "cycles_addr_VSIB", "cycles_addr_VSIB_is_upper_bound" },
    { "cycles_mem", "cycles_mem_is_upper_bound" },
    { "cycles_mem_same_reg", "cycles_mem_same_reg_is_upper_bound" },
    { "cycles_same_reg", "cycles_same_reg_is_upper_bound" },
    { "max_cycles", "max_cycles_is_upper_bound" },
    { "max_cycles_addr", "max_cycles_addr_is_upper_bound" },
    { "min_cycles", "min_cycles_is_upper_bound" },
    { "min_cycles_addr", "min_cycles_addr_is_upper_bound" },
};

int main()
{
    pugi::xml_document doc;
    doc.load_file( "instructions.xml" );
    auto root = doc.child( "root" );

    Dictionary ops;
    Dictionary opsdesc;
    Dictionary uarchs;
    Dictionary ports;
    Dictionary isas;

    std::vector<UArch> uav;

    for( auto& ext : root )
    {
        assert( strcmp( ext.name(), "extension" ) == 0 );
        for( auto& op : ext )
        {
            assert( strcmp( op.name(), "instruction" ) == 0 );
            auto opstr = op.attribute( "asm" ).value();
            auto opdesc = op.attribute( "summary" ).value();
            bool magic = false;
            if( opstr[0] == '{' )
            {
                if( memcmp( opstr, "{load} ", 7 ) == 0 )
                {
                    magic = true;
                    opstr += 7;
                }
                else
                {
                    continue;
                }
            }
            char tmpbuf[64];
            auto opstr2 = op.attribute( "string" ).value();
            const auto strnext = opstr2[strlen(opstr)];
            if( !magic && strnext != ' ' && strnext != '\0' )
            {
                if( memcmp( opstr2, "LEA_", 4 ) == 0 )
                {
                    auto ptr = tmpbuf;
                    opstr = tmpbuf;
                    while( *opstr2 != ' ' ) *ptr++ = *opstr2++;
                    *ptr = '\0';
                }
                else
                {
                    continue;
                }
            }
            const auto opidx = ops.Get( opstr );
            const auto opdescidx = opsdesc.Get( opdesc );

            int isaSet = isas.Get( op.attribute( "isa-set" ).value() );

            std::vector<ParamDesc> desc;
            for( auto& param : op.children( "operand" ) )
            {
                if( !param.attribute( "suppressed" ) )
                {
                    int type = 0;
                    if( strcmp( param.attribute( "type" ).value(), "imm" ) == 0 ) type = 0;
                    else if( strcmp( param.attribute( "type" ).value(), "reg" ) == 0 ) type = 1;
                    else if( strcmp( param.attribute( "type" ).value(), "mem" ) == 0 ) type = 2;
                    else if( strcmp( param.attribute( "type" ).value(), "agen" ) == 0 ) type = 2;
                    desc.emplace_back( ParamDesc { type, atoi( param.attribute( "width" ).value() ) } );
                }
            }

            for( auto& ua : op.children( "architecture" ) )
            {
                auto measurement = ua.child( "measurement" );
                if( measurement )
                {
                    const auto uaidx = uarchs.Get( ua.attribute( "name" ).value() );
                    if( uav.size() <= uaidx ) uav.emplace_back( UArch {} );
                    auto& uai = uav[uaidx];
                    auto& opi = uai.ops[opidx];
                    opi.desc = opdescidx;

                    float tp = -1;
                    if( measurement.attribute( "TP" ) ) tp = atof( measurement.attribute( "TP" ).value() );
                    else if( measurement.attribute( "TP_ports" ) ) tp = atof( measurement.attribute( "TP_ports" ).value() );
                    else if( measurement.attribute( "TP_unrolled" ) ) tp = atof( measurement.attribute( "TP_unrolled" ).value() );

                    int portid = measurement.attribute( "ports" ) ? ports.Get( measurement.attribute( "ports" ).value() ) : -1;
                    int uops = measurement.attribute( "uops" ) ? atoi( measurement.attribute( "uops" ).value() ) : -1;
                    assert( tp != -1 && uops != -1 );

                    int minlat = std::numeric_limits<int>::max();
                    int maxlat = -1;
                    bool minbound = false;
                    bool maxbound = false;

                    for( auto& lat : measurement.children( "latency" ) )
                    {
                        for( auto& v : LatencyValues )
                        {
                            auto attr = lat.attribute( v.first );
                            if( attr )
                            {
                                const auto av = atoi( attr.value() );
                                bool bound = lat.attribute( v.second );
                                if( minlat > av || ( minlat == av && minbound ) )
                                {
                                    minlat = av;
                                    minbound = bound;
                                }
                                if( maxlat < av || ( maxlat == av && maxbound ) )
                                {
                                    maxlat = av;
                                    maxbound = bound;
                                }
                            }
                        }
                    }
                    if( maxlat == -1 ) minlat = -1;

                    opi.var.emplace_back( Variant { desc, isaSet, tp, portid, uops, minlat, maxlat, minbound, maxbound } );
                }
            }
        }
    }

    printf( "#include \"TracyMicroArchitecture.hpp\"\n\n" );

    printf( "namespace tracy\n{\n\n" );

    printf( "const char* MicroArchitectureList[]={\n" );
    for( auto& v : uarchs.strlist )
    {
        printf( "\"%s\",\n", v.c_str() );
    }
    printf( "};\n\n" );

    printf( "const char* PortList[]={\n" );
    for( auto& v : ports.strlist )
    {
        printf( "\"%s\",\n", v.c_str() );
    }
    printf( "};\n\n" );

    printf( "const char* OpsList[]={\n" );
    for( auto& v : ops.strlist )
    {
        printf( "\"%s\",\n", v.c_str() );
    }
    printf( "};\n\n" );

    printf( "const char* IsaList[]={\n" );
    for( auto& v : isas.strlist )
    {
        printf( "\"%s\",\n", v.c_str() );
    }
    printf( "};\n\n" );

    printf( "const char* OpDescList[]={\n" );
    for( auto& v : opsdesc.strlist )
    {
        printf( "\"%s\",\n", v.c_str() );
    }
    printf( "};\n\n" );

    printf( "#define V static constexpr AsmVar\n" );
    printf( "#define A static constexpr AsmVar const*\n\n" );

    int uaidx = 0;
    for( auto& ua : uav )
    {
        for( auto& op: ua.ops )
        {
            int varidx = 0;
            for( auto& var: op.second.var )
            {
                printf( "V z%x_%x_%x={%i,{", uaidx, op.first, varidx++, (int)var.desc.size() );
                bool first = true;
                for( auto& p : var.desc )
                {
                    if( first ) first = false;
                    else printf( "," );
                    printf( "{%i,%i}", p.type, p.width );
                }
                printf( "},%i,%.2ff,%i,%i,%i,%i,%c,%c};\n", var.isaSet, var.tp, var.port, var.uops, var.minlat, var.maxlat, var.minbound ? '1' : '0', var.maxbound ? '1' : '0' );
            }

            varidx = 0;
            printf( "A y%x_%x[]={", uaidx, op.first );
            bool first = true;
            for( auto& var: op.second.var )
            {
                if( first ) first = false;
                else printf( "," );
                printf( "&z%x_%x_%x", uaidx, op.first, varidx++ );
            }
            printf( "};\n" );
        }
        uaidx++;
    }

    printf( "\n\n#define O static constexpr AsmOp\n\n" );

    uaidx = 0;
    for( auto& ua : uav )
    {
        std::vector<decltype(ua.ops.begin())> opsort;
        for( auto it = ua.ops.begin(); it != ua.ops.end(); ++it )
        {
            auto& op = *it;
            printf( "O x%x_%x={%i,%i,%i,y%x_%x};\n", uaidx, op.first, op.first, op.second.desc, (int)op.second.var.size(), uaidx, op.first );
            opsort.emplace_back( it );
        }
        std::sort( opsort.begin(), opsort.end(), []( const auto& l, const auto& r ) { return l->first < r->first; } );
        printf( "static constexpr AsmOp const* w%x[]={", uaidx );
        bool first = true;
        for( auto& op: opsort )
        {
            if( first ) first = false;
            else printf( "," );
            printf( "&x%x_%x", uaidx, op->first );
        }
        printf( "};\n" );
        uaidx++;
    }
    printf( "\n" );

    uaidx = 0;
    for( auto& ua : uav )
    {
        printf( "static constexpr MicroArchitecture v%x={%i,w%x};\n", uaidx, (int)ua.ops.size(), uaidx );
        uaidx++;
    }

    printf( "\nconst MicroArchitecture* const MicroArchitectureData[]={" );
    uaidx = 0;
    bool first = true;
    for( auto& ua : uav )
    {
        if( first ) first = false;
        else printf( "," );
        printf( "&v%x", uaidx++ );
    }
    printf( "};\n\n" );

    printf( "int OpsNum=%i;\nint MicroArchitectureNum=%i;\n", (int)ops.Size(), (int)uarchs.Size() );

    printf( "}\n" );
}
