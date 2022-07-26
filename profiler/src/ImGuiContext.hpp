#ifndef __IMGUICONTEXT_HPP__
#define __IMGUICONTEXT_HPP__

#include <string>

class ImGuiTracyContext
{
public:
    ImGuiTracyContext();
    ~ImGuiTracyContext();

private:
    std::string m_iniFilename;
};

#endif
