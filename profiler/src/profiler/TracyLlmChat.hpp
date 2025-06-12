#ifndef __TRACYLLMCHAT_HPP__
#define __TRACYLLMCHAT_HPP__

#include <string>

struct MD_PARSER;

namespace tracy
{

class TracyLlmChat
{
public:
    static constexpr const char* ForgetMsg = "<tool_output>\n...";

    enum class TurnRole
    {
        User,
        UserDebug,
        Assistant,
        AssistantDebug,
        Error,
        // virtual roles below
        Trash,
        None,
    };

    TracyLlmChat();
    ~TracyLlmChat();

    void Begin();
    void End();

    bool Turn( TurnRole role, const std::string& content );

private:
    void NormalScope();
    void ThinkScope();

    void PrintMarkdown( const char* str, size_t size );
    void PrintThink( const char* str, size_t size );
    void PrintToolCall( const char* str, size_t size );

    float* m_width;
    float m_maxWidth;

    TurnRole m_role;
    bool m_thinkActive;
    bool m_thinkOpen;
    int m_thinkIdx;
    int m_subIdx;
    int m_roleIdx;

    MD_PARSER* m_parser;
};

}

#endif
