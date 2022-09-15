#include "tracy_robin_hood.h"
#include "TracyCharUtil.hpp"
#include "TracySourceTokenizer.hpp"

namespace tracy
{

namespace {
static unordered_flat_set<const char*, charutil::Hasher, charutil::Comparator> GetKeywords()
{
    unordered_flat_set<const char*, charutil::Hasher, charutil::Comparator> ret;
    for( auto& v : {
        "alignas", "alignof", "and", "and_eq", "asm", "atomic_cancel", "atomic_commit", "atomic_noexcept",
        "bitand", "bitor", "break", "case", "catch", "class", "compl", "concept", "const", "consteval",
        "constexpr", "constinit", "const_cast", "continue", "co_await", "co_return", "co_yield", "decltype",
        "default", "delete", "do", "dynamic_cast", "else", "enum", "explicit", "export", "extern", "for",
        "friend", "if", "inline", "mutable", "namespace", "new", "noexcept", "not", "not_eq", "operator",
        "or", "or_eq", "private", "protected", "public", "reflexpr", "register", "reinterpret_cast",
        "return", "requires", "sizeof", "static", "static_assert", "static_cast", "struct", "switch",
        "synchronized", "template", "thread_local", "throw", "try", "typedef", "typeid", "typename",
        "union", "using", "virtual", "volatile", "while", "xor", "xor_eq", "override", "final", "import",
        "module", "transaction_safe", "transaction_safe_dynamic" } )
    {
        ret.insert( v );
    }
    return ret;
}
static unordered_flat_set<const char*, charutil::Hasher, charutil::Comparator> GetTypes()
{
    unordered_flat_set<const char*, charutil::Hasher, charutil::Comparator> ret;
    for( auto& v : {
        "bool", "char", "char8_t", "char16_t", "char32_t", "double", "float", "int", "long", "short", "signed",
        "unsigned", "void", "wchar_t", "size_t", "int8_t", "int16_t", "int32_t", "int64_t", "int_fast8_t",
        "int_fast16_t", "int_fast32_t", "int_fast64_t", "int_least8_t", "int_least16_t", "int_least32_t",
        "int_least64_t", "intmax_t", "intptr_t", "uint8_t", "uint16_t", "uint32_t", "uint64_t", "uint_fast8_t",
        "uint_fast16_t", "uint_fast32_t", "uint_fast64_t", "uint_least8_t", "uint_least16_t", "uint_least32_t",
        "uint_least64_t", "uintmax_t", "uintptr_t", "type_info", "bad_typeid", "bad_cast", "type_index",
        "clock_t", "time_t", "tm", "timespec", "ptrdiff_t", "nullptr_t", "max_align_t", "auto",

        "__m64", "__m128", "__m128i", "__m128d", "__m256", "__m256i", "__m256d", "__m512", "__m512i",
        "__m512d", "__mmask8", "__mmask16", "__mmask32", "__mmask64",

        "int8x8_t", "int16x4_t", "int32x2_t", "int64x1_t", "uint8x8_t", "uint16x4_t", "uint32x2_t",
        "uint64x1_t", "float32x2_t", "poly8x8_t", "poly16x4_t", "int8x16_t", "int16x8_t", "int32x4_t",
        "int64x2_t", "uint8x16_t", "uint16x8_t", "uint32x4_t", "uint64x2_t", "float32x4_t", "poly8x16_t",
        "poly16x8_t",

        "int8x8x2_t", "int16x4x2_t", "int32x2x2_t", "int64x1x2_t", "uint8x8x2_t", "uint16x4x2_t",
        "uint32x2x2_t", "uint64x1x2_t", "float32x2x2_t", "poly8x8x2_t", "poly16x4x2_t", "int8x16x2_t",
        "int16x8x2_t", "int32x4x2_t", "int64x2x2_t", "uint8x16x2_t", "uint16x8x2_t", "uint32x4x2_t",
        "uint64x2x2_t", "float32x4x2_t", "poly8x16x2_t", "poly16x8x2_t",

        "int8x8x3_t", "int16x4x3_t", "int32x2x3_t", "int64x1x3_t", "uint8x8x3_t", "uint16x4x3_t",
        "uint32x2x3_t", "uint64x1x3_t", "float32x2x3_t", "poly8x8x3_t", "poly16x4x3_t", "int8x16x3_t",
        "int16x8x3_t", "int32x4x3_t", "int64x2x3_t", "uint8x16x3_t", "uint16x8x3_t", "uint32x4x3_t",
        "uint64x2x3_t", "float32x4x3_t", "poly8x16x3_t", "poly16x8x3_t",

        "int8x8x4_t", "int16x4x4_t", "int32x2x4_t", "int64x1x4_t", "uint8x8x4_t", "uint16x4x4_t",
        "uint32x2x4_t", "uint64x1x4_t", "float32x2x4_t", "poly8x8x4_t", "poly16x4x4_t", "int8x16x4_t",
        "int16x8x4_t", "int32x4x4_t", "int64x2x4_t", "uint8x16x4_t", "uint16x8x4_t", "uint32x4x4_t",
        "uint64x2x4_t", "float32x4x4_t", "poly8x16x4_t", "poly16x8x4_t" } )
    {
        ret.insert( v );
    }
    return ret;
}
static unordered_flat_set<const char*, charutil::Hasher, charutil::Comparator> GetSpecial()
{
    unordered_flat_set<const char*, charutil::Hasher, charutil::Comparator> ret;
    for( auto& v : { "this", "nullptr", "true", "false", "goto", "NULL" } )
    {
        ret.insert( v );
    }
    return ret;
}
static unordered_flat_set<const char*, charutil::Hasher, charutil::Comparator> GetAsmRegs()
{
    unordered_flat_set<const char*, charutil::Hasher, charutil::Comparator> ret;
    for( auto& v : {
        // X86
        "invalid", "rflags", "rip",
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
        "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
        "ax",  "bx",  "cx",  "dx",  "si",  "di",  "bp",  "sp",
        "ah",  "bh",  "ch",  "dh",  "SIL", "DIL", "BPL", "SPL",
        "al",  "bl",  "cl",  "dl",
        "mm0", "mm1", "mm2", "mm3", "mm4", "mm5", "mm6", "mm7",
        "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7", "xmm8", "xmm9",
        "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15", "xmm16", "xmm17", "xmm18", "xmm19",
        "xmm20", "xmm21", "xmm22", "xmm23", "xmm24", "xmm25", "xmm26", "xmm27", "xmm28", "xmm29",
        "xmm30", "xmm31", "k0", "k1", "k2", "k3", "k4", "k5", "k6", "k7",
        // ARM
        "apsr", "apsr_nzcv", "cpsr", "fpexc", "fpinst", "fpscr", "fpscr_nzcv", "fpsid", "itstate",
        "lr", "pc", "sp", "spsr", "d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7", "d8", "d9", "d10",
        "d11", "d12", "d13", "d14", "d15", "d16", "d17", "d18", "d19", "d20", "d21", "d22", "d23",
        "d24", "d25", "d26", "d27", "d28", "d29", "d30", "d31", "fpinst2", "mvfr0", "mvfr1", "mvfr2",
        "q0", "q1", "q2", "q3", "q4", "q5", "q6", "q7", "q8", "q9", "q10", "q11", "q12", "q13", "q14",
        "q15", "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "s0",
        "s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11", "s12", "s13", "s14", "s15",
        "s16", "s17", "s18", "s19", "s20", "s21", "s22", "s23", "s24", "s25", "s26", "s27", "s28", "s29",
        "s30", "s31" })
    {
        ret.insert( v );
    }
    return ret;
}
static unordered_flat_set<const char*, charutil::Hasher, charutil::Comparator> GetAsmSizeDirectives()
{
    unordered_flat_set<const char*, charutil::Hasher, charutil::Comparator> ret;
    for( auto& v : { "byte", "word", "dword", "qword", "xmmword", "ymmword" })
    {
        ret.insert( v );
    }
    return ret;
}
}

Tokenizer::Tokenizer()
    : m_isInComment( false )
    , m_isInPreprocessor( false )
{
}

std::vector<Tokenizer::Token> Tokenizer::Tokenize( const char* begin, const char* end )
{
    std::vector<Token> ret;
    if( m_isInPreprocessor )
    {
        if( begin == end )
        {
            m_isInPreprocessor = false;
            return ret;
        }
        if( *(end-1) != '\\' ) m_isInPreprocessor = false;
        ret.emplace_back( Token { begin, end, TokenColor::Preprocessor } );
        return ret;
    }
    const bool first = !m_isInComment;
    while( begin != end )
    {
        if( m_isInComment )
        {
            const auto pos = begin;
            for(;;)
            {
                while( begin != end && *begin != '*' ) begin++;
                begin++;
                if( begin < end )
                {
                    if( *begin == '/' )
                    {
                        begin++;
                        ret.emplace_back( Token { pos, begin, TokenColor::Comment } );
                        m_isInComment = false;
                        break;
                    }
                }
                else
                {
                    ret.emplace_back( Token { pos, end, TokenColor::Comment } );
                    return ret;
                }
            }
        }
        else
        {
            while( begin != end && isspace( (uint8_t)*begin ) ) begin++;
            if( first && begin < end && *begin == '#' )
            {
                if( *(end-1) == '\\' ) m_isInPreprocessor = true;
                ret.emplace_back( Token { begin, end, TokenColor::Preprocessor } );
                return ret;
            }
            const auto pos = begin;
            const auto col = IdentifyToken( begin, end );
            ret.emplace_back( Token { pos, begin, col } );
        }
    }
    return ret;
}

static bool TokenizeNumber( const char*& begin, const char* end )
{
    const bool startNum = *begin >= '0' && *begin <= '9';
    if( *begin != '+' && *begin != '-' && !startNum ) return false;
    begin++;
    bool hasNum = startNum;
    while( begin < end && ( ( *begin >= '0' && *begin <= '9' ) || *begin == '\'' ) )
    {
        hasNum = true;
        begin++;
    }
    if( !hasNum ) return false;
    bool isFloat = false, isBinary = false;
    if( begin < end )
    {
        if( *begin == '.' )
        {
            isFloat = true;
            begin++;
            while( begin < end && ( ( *begin >= '0' && *begin <= '9' ) || *begin == '\'' ) ) begin++;
        }
        else if( *begin == 'x' || *begin == 'X' )
        {
            // hexadecimal
            begin++;
            while( begin < end && ( ( *begin >= '0' && *begin <= '9' ) || ( *begin >= 'a' && *begin <= 'f' ) || ( *begin >= 'A' && *begin <= 'F' ) || *begin == '\'' ) ) begin++;
        }
        else if( *begin == 'b' || *begin == 'B' )
        {
            isBinary = true;
            begin++;
            while( begin < end && ( ( *begin == '0' || *begin == '1' ) || *begin == '\'' ) ) begin++;
        }
    }
    if( !isBinary )
    {
        if( begin < end && ( *begin == 'e' || *begin == 'E' || *begin == 'p' || *begin == 'P' ) )
        {
            isFloat = true;
            begin++;
            if( begin < end && ( *begin == '+' || *begin == '-' ) ) begin++;
            bool hasDigits = false;
            while( begin < end && ( ( *begin >= '0' && *begin <= '9' ) || ( *begin >= 'a' && *begin <= 'f' ) || ( *begin >= 'A' && *begin <= 'F' ) || *begin == '\'' ) )
            {
                hasDigits = true;
                begin++;
            }
            if( !hasDigits ) return false;
        }
        if( begin < end && ( *begin == 'f' || *begin == 'F' || *begin == 'l' || *begin == 'L' ) ) begin++;
    }
    if( !isFloat )
    {
        while( begin < end && ( *begin == 'u' || *begin == 'U' || *begin == 'l' || *begin == 'L' ) ) begin++;
    }
    return true;
}

Tokenizer::TokenColor Tokenizer::IdentifyToken( const char*& begin, const char* end )
{
    static const auto s_keywords = GetKeywords();
    static const auto s_types = GetTypes();
    static const auto s_special = GetSpecial();

    if( *begin == '"' )
    {
        begin++;
        while( begin < end )
        {
            if( *begin == '"' )
            {
                begin++;
                break;
            }
            begin += 1 + ( *begin == '\\' && end - begin > 1 && *(begin+1) == '"' );
        }
        return TokenColor::String;
    }
    if( *begin == '\'' )
    {
        begin++;
        if( begin < end && *begin == '\\' ) begin++;
        if( begin < end ) begin++;
        if( begin < end && *begin == '\'' ) begin++;
        return TokenColor::CharacterLiteral;
    }
    if( ( *begin >= 'a' && *begin <= 'z' ) || ( *begin >= 'A' && *begin <= 'Z' ) || *begin == '_' )
    {
        const char* tmp = begin;
        begin++;
        while( begin < end && ( ( *begin >= 'a' && *begin <= 'z' ) || ( *begin >= 'A' && *begin <= 'Z' ) || ( *begin >= '0' && *begin <= '9' ) || *begin == '_' ) ) begin++;
        if( begin - tmp <= 24 )
        {
            char buf[25];
            memcpy( buf, tmp, begin-tmp );
            buf[begin-tmp] = '\0';
            if( s_keywords.find( buf ) != s_keywords.end() ) return TokenColor::Keyword;
            if( s_types.find( buf ) != s_types.end() ) return TokenColor::Type;
            if( s_special.find( buf ) != s_special.end() ) return TokenColor::Special;
        }
        return TokenColor::Default;
    }
    const char* tmp = begin;
    if( TokenizeNumber( begin, end ) ) return TokenColor::Number;
    begin = tmp;
    if( *begin == '/' && end - begin > 1 )
    {
        if( *(begin+1) == '/' )
        {
            begin = end;
            return TokenColor::Comment;
        }
        if( *(begin+1) == '*' )
        {
            begin += 2;
            for(;;)
            {
                while( begin < end && *begin != '*' ) begin++;
                if( begin == end )
                {
                    m_isInComment = true;
                    return TokenColor::Comment;
                }
                begin++;
                if( begin < end && *begin == '/' )
                {
                    begin++;
                    return TokenColor::Comment;
                }
            }
        }
    }
    while( begin < end )
    {
        switch( *begin )
        {
        case '[':
        case ']':
        case '{':
        case '}':
        case '!':
        case '%':
        case '^':
        case '&':
        case '*':
        case '(':
        case ')':
        case '-':
        case '+':
        case '=':
        case '~':
        case '|':
        case '<':
        case '>':
        case '?':
        case ':':
        case '/':
        case ';':
        case ',':
        case '.':
            begin++;
            break;
        default:
            goto out;
        }
    }
out:
    if( begin != tmp ) return TokenColor::Punctuation;
    begin = end;
    return TokenColor::Default;
}

std::vector<Tokenizer::AsmToken> Tokenizer::TokenizeAsm( const char* begin, const char* end )
{
    std::vector<AsmToken> ret;
    while( begin != end )
    {
        while( begin != end && isspace( (uint8_t)*begin ) ) begin++;
        const auto pos = begin;
        const auto col = IdentifyAsmToken( begin, end );
        ret.emplace_back( AsmToken { pos, begin, col } );
    }
    return ret;
}

Tokenizer::AsmTokenColor Tokenizer::IdentifyAsmToken( const char*& begin, const char* end )
{
    static const auto s_regs = GetAsmRegs();
    static const auto s_sizes = GetAsmSizeDirectives();

    begin = end;
    return AsmTokenColor::Default;
}

}
