#ifndef __HISTORY_HPP__
#define __HISTORY_HPP__

#include <stddef.h>
#include <stdint.h>
#include <string>
#include <unordered_map>
#include <vector>

// Persisted "recently used" lists, stored together in a single history.json
// in the profiler's save directory.
class History
{
public:
    History();
    ~History();

    // Client addresses, most used first.
    size_t ConnectionCount() const { return m_connectionsVec.size(); }
    const std::string& ConnectionName( size_t idx ) const { return m_connectionsVec[idx]->first; }
    void CountConnection( const std::string& address );
    void EraseConnection( size_t idx );

    // Trace files that were opened or saved, most recent first.
    const std::vector<std::string>& RecentTraces() const { return m_recentTraces; }
    void RecordTrace( const char* path );

private:
    void Load();
    void Save() const;
    void Rebuild();

    std::string m_fn;

    std::unordered_map<std::string, uint64_t> m_connectionsMap;
    std::vector<std::unordered_map<std::string, uint64_t>::const_iterator> m_connectionsVec;
    std::vector<std::string> m_recentTraces;
};

#endif
