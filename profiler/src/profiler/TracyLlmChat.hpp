#ifndef __TRACYLLMCHAT_HPP__
#define __TRACYLLMCHAT_HPP__

#include <string>

#include "TracyMarkdown.hpp"

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
        Attachment,
        Assistant,
        AssistantDebug,
        Error,
        // virtual roles below
        Trash,
        Regenerate,
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

    Markdown m_markdown;
};

}

#endif
