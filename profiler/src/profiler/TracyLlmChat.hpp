#ifndef __TRACYLLMCHAT_HPP__
#define __TRACYLLMCHAT_HPP__

#include <nlohmann/json.hpp>
#include <vector>

#include "TracyMarkdown.hpp"

namespace tracy
{

struct LlmSkill;
class View;
class Worker;

class TracyLlmChat
{
public:
    static constexpr const char* ForgetMsg = "<removed to save context>";

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

    enum class Think
    {
        Hide,
        Show,
        ToolCall
    };

    TracyLlmChat( View& view, Worker& worker, const std::vector<LlmSkill>& skills );
    ~TracyLlmChat();

    void Begin();
    void End();

    bool Turn( TurnRole role, std::vector<nlohmann::json>::iterator it, const std::vector<nlohmann::json>::iterator& end, Think think, bool last, bool fadeout );
    void SetModelTimeLabel( const char* model, uint64_t duration_ns );

private:
    void NormalScope();
    void ThinkScope( bool spacing = false );

    void PrintThink( const char* str, size_t size );

    [[nodiscard]] std::string ToolCallDescription( const nlohmann::json& json ) const;

    float* m_width;
    float m_maxWidth;

    TurnRole m_role;
    bool m_thinkActive;
    bool m_thinkOpen;
    int m_thinkIdx;
    int m_roleIdx;

    Markdown m_markdown;
    std::string m_label;

    const std::vector<LlmSkill>& m_skills;
    const Worker& m_worker;
    View& m_view;
};

}

#endif
