#ifndef __CONNECTIONHISTORY_HPP__
#define __CONNECTIONHISTORY_HPP__

#include <stdint.h>
#include <string>
#include <unordered_map>
#include <vector>

class ConnectionHistory
{
public:
    ConnectionHistory();
    ~ConnectionHistory();

    const std::string& Name( size_t idx ) const { return m_connHistVec[idx]->first; }

    void Count( const char* name );
    void Erase( size_t idx );

    bool empty() const { return m_connHistVec.empty(); }
    size_t size() const { return m_connHistVec.size(); }

private:
    void Rebuild();

    std::string m_fn;

    std::unordered_map<std::string, uint64_t> m_connHistMap;
    std::vector<std::unordered_map<std::string, uint64_t>::const_iterator> m_connHistVec;
};

#endif
