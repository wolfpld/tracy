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

}
