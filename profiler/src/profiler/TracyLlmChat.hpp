#ifndef __TRACYLLMCHAT_HPP__
#define __TRACYLLMCHAT_HPP__

#include <nlohmann/json.hpp>

#include "TracyMarkdown.hpp"

namespace tracy
{

class TracyLlmChat
{
public:
    static constexpr const char* ForgetMsg = "...";

    enum class TurnRole
    {
        User,
        Attachment,
        Assistant,
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

    bool Turn( TurnRole role, const nlohmann::json& json );

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
