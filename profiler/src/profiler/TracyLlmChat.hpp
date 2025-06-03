#ifndef __TRACYLLMCHAT_HPP__
#define __TRACYLLMCHAT_HPP__

#include <string>

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
        None
    };

    TracyLlmChat();
    ~TracyLlmChat();

    void Begin();
    void End();

    void Turn( TurnRole role, const std::string& content );

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
};

}

#endif
