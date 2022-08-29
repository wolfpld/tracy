#ifndef __TRACYSOURCETOKENIZER_HPP__
#define __TRACYSOURCETOKENIZER_HPP__

#include <stdint.h>
#include <cstdint>
#include <vector>
#include <string>

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

    enum class AsmTokenColor : uint8_t
    {
        Mnemonic,       // no-op, padding
        Label,          // no-op, padding
        Default,        // '+', '[', '*', etc
        SizeDirective,   // byte, word, dword, etc
        Register,       // rax, rip, etc
        Literal,        // 0x04, etc
    };

    struct Token
    {
        const char* begin;
        const char* end;
        TokenColor color;
    };

    struct AsmToken
    {
        uint8_t beginIdx;
        uint8_t endIdx;
        AsmTokenColor color;
    };

    struct Line
    {
        const char* begin;
        const char* end;
        std::vector<Token> tokens;
    };

    struct AsmOperand
    {
        std::string string;
        std::vector<AsmToken> tokens;
    };

    Tokenizer();

    std::vector<Token> Tokenize( const char* begin, const char* end );
    AsmOperand TokenizeAsmOperand( const char assemblyText[160] );

private:
    TokenColor IdentifyToken( const char*& begin, const char* end );

    bool m_isInComment;
    bool m_isInPreprocessor;
};

}

#endif
