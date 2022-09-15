#ifndef __TRACYSOURCETOKENIZER_HPP__
#define __TRACYSOURCETOKENIZER_HPP__

#include <stdint.h>
#include <vector>

namespace tracy
{

class Tokenizer
{
public:
    enum class TokenColor : uint8_t
    {
        Default,
        Comment,
        Preprocessor,
        String,
        CharacterLiteral,
        Keyword,
        Number,
        Punctuation,
        Type,
        Special
    };

    struct Token
    {
        const char* begin;
        const char* end;
        TokenColor color;
    };

    struct Line
    {
        const char* begin;
        const char* end;
        std::vector<Token> tokens;
    };

    enum class AsmTokenColor : uint8_t
    {
        Label,          // no-op, padding
        Default,        // '+', '[', '*', etc
        SizeDirective,  // byte, word, dword, etc
        Register,       // rax, rip, etc
        Literal,        // 0x04, etc
    };

    struct AsmToken
    {
        const char* begin;
        const char* end;
        AsmTokenColor color;
    };

    Tokenizer();

    std::vector<Token> Tokenize( const char* begin, const char* end );
    std::vector<AsmToken> TokenizeAsm( const char* begin, const char* end );

private:
    TokenColor IdentifyToken( const char*& begin, const char* end );
    AsmTokenColor IdentifyAsmToken( const char*& begin, const char* end );

    bool m_isInComment;
    bool m_isInPreprocessor;
};

}

#endif
