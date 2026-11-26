#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <iterator>
#include <limits.h>

#include "TracyLlmBm25.hpp"

namespace tracy
{

namespace
{

// Porter stemmer, following the original 1980 algorithm.

bool IsConsonant( const std::string& s, size_t i )
{
    switch( s[i] )
    {
    case 'a': case 'e': case 'i': case 'o': case 'u':
        return false;
    case 'y':
        return i == 0 ? true : !IsConsonant( s, i-1 );
    }
    return true;
}

int StemMeasure( const std::string& s )
{
    int m = 0;
    size_t i = 0, n = s.size();
    while( i < n && IsConsonant( s, i ) ) i++;
    if( i >= n ) return 0;
    while( i < n )
    {
        while( i < n && !IsConsonant( s, i ) ) i++;
        if( i >= n ) break;
        while( i < n && IsConsonant( s, i ) ) i++;
        m++;
    }
    return m;
}

bool HasVowel( const std::string& s )
{
    for( size_t i = 0; i < s.size(); i++ )
    {
        if( !IsConsonant( s, i ) ) return true;
    }
    return false;
}

bool EndsDouble( const std::string& s )
{
    return s.size() >= 2 && s[s.size()-1] == s[s.size()-2] && IsConsonant( s, s.size()-1 );
}

bool EndsCvc( const std::string& s )
{
    if( s.size() < 3 ) return false;
    const size_t n = s.size();
    if( !IsConsonant( s, n-1 ) || IsConsonant( s, n-2 ) || !IsConsonant( s, n-3 ) ) return false;
    const char c = s[n-1];
    return c != 'w' && c != 'x' && c != 'y';
}

bool EndsWith( const std::string& s, const char* suf, size_t& len )
{
    len = strlen( suf );
    return s.size() >= len && memcmp( s.data() + s.size() - len, suf, len ) == 0;
}

struct StemRule
{
    const char* from;
    const char* to;
    int minM;
};

// the step ends at the first suffix that matches, whether or not its condition passes
void ApplyStemRules( std::string& s, const StemRule* rules, size_t count )
{
    for( size_t i = 0; i < count; i++ )
    {
        auto& r = rules[i];
        size_t len;
        if( !EndsWith( s, r.from, len ) ) continue;
        const std::string base = s.substr( 0, s.size() - len );
        if( StemMeasure( base ) > r.minM ) s = base + r.to;
        return;
    }
}

void StemStep1a( std::string& s )
{
    size_t len;
    if( EndsWith( s, "sses", len ) ) { s.resize( s.size()-2 ); return; }
    if( EndsWith( s, "ies", len ) )  { s.resize( s.size()-2 ); return; }
    if( EndsWith( s, "ss", len ) )   { return; }
    if( EndsWith( s, "s", len ) )    { s.resize( s.size()-1 ); }
}

void StemStep1b( std::string& s )
{
    size_t len;
    if( EndsWith( s, "eed", len ) )
    {
        if( StemMeasure( s.substr( 0, s.size()-3 ) ) > 0 ) s.resize( s.size()-1 );
        return;
    }
    bool hit = false;
    if( EndsWith( s, "ed", len ) && HasVowel( s.substr( 0, s.size()-2 ) ) ) { s.resize( s.size()-2 ); hit = true; }
    else if( EndsWith( s, "ing", len ) && HasVowel( s.substr( 0, s.size()-3 ) ) ) { s.resize( s.size()-3 ); hit = true; }
    if( hit )
    {
        if( EndsWith( s, "at", len ) || EndsWith( s, "bl", len ) || EndsWith( s, "iz", len ) )
        {
            s += 'e';
        }
        else if( EndsDouble( s ) )
        {
            const char c = s.back();
            if( c != 'l' && c != 's' && c != 'z' ) s.pop_back();
        }
        else if( StemMeasure( s ) == 1 && EndsCvc( s ) )
        {
            s += 'e';
        }
    }
}

void StemStep1c( std::string& s )
{
    size_t len;
    if( EndsWith( s, "y", len ) && HasVowel( s.substr( 0, s.size()-1 ) ) ) s.back() = 'i';
}

void StemStep2( std::string& s )
{
    static const StemRule rules[] = {
        { "ational", "ate", 0 }, { "tional", "tion", 0 }, { "enci", "ence", 0 }, { "anci", "ance", 0 },
        { "izer", "ize", 0 }, { "abli", "able", 0 }, { "alli", "al", 0 }, { "entli", "ent", 0 },
        { "eli", "e", 0 }, { "ousli", "ous", 0 }, { "ization", "ize", 0 }, { "ation", "ate", 0 },
        { "ator", "ate", 0 }, { "alism", "al", 0 }, { "iveness", "ive", 0 }, { "fulness", "ful", 0 },
        { "ousness", "ous", 0 }, { "aliti", "al", 0 }, { "iviti", "ive", 0 }, { "biliti", "ble", 0 },
    };
    ApplyStemRules( s, rules, std::size( rules ) );
}

void StemStep3( std::string& s )
{
    static const StemRule rules[] = {
        { "icate", "ic", 0 }, { "ative", "", 0 }, { "alize", "al", 0 }, { "iciti", "ic", 0 },
        { "ical", "ic", 0 }, { "ful", "", 0 }, { "ness", "", 0 },
    };
    ApplyStemRules( s, rules, std::size( rules ) );
}

void StemStep4( std::string& s )
{
    static const char* suf[] = {
        "al", "ance", "ence", "er", "ic", "able", "ible", "ant", "ement", "ment", "ent",
        "ion", "ou", "ism", "ate", "iti", "ous", "ive", "ize"
    };
    for( auto sp : suf )
    {
        const size_t len = strlen( sp );
        if( s.size() <= len ) continue;
        if( memcmp( s.data() + s.size() - len, sp, len ) != 0 ) continue;
        if( strcmp( sp, "ion" ) == 0 )
        {
            const char t = s[ s.size() - len - 1 ];
            if( t != 's' && t != 't' ) continue;
        }
        if( StemMeasure( s.substr( 0, s.size() - len ) ) > 1 ) s.resize( s.size() - len );
        return;
    }
}

void StemStep5a( std::string& s )
{
    size_t len;
    if( EndsWith( s, "e", len ) )
    {
        const std::string base = s.substr( 0, s.size()-1 );
        const int m = StemMeasure( base );
        if( m > 1 || ( m == 1 && !EndsCvc( base ) ) ) s = base;
    }
}

void StemStep5b( std::string& s )
{
    if( StemMeasure( s ) > 1 && EndsDouble( s ) && s.back() == 'l' ) s.pop_back();
}

std::string Stem( std::string s )
{
    if( s.size() < 3 ) return s;
    StemStep1a( s ); StemStep1b( s ); StemStep1c( s ); StemStep2( s );
    StemStep3( s ); StemStep4( s ); StemStep5a( s ); StemStep5b( s );
    return s;
}

int EditDistance( const std::string& a, const std::string& b, int maxDist )
{
    if( std::abs( (int)a.size() - (int)b.size() ) > maxDist ) return maxDist + 1;
    const size_t n = a.size(), m = b.size();
    std::vector<int> prev( m+1 ), cur( m+1 );
    for( size_t j = 0; j <= m; j++ ) prev[j] = (int)j;
    for( size_t i = 1; i <= n; i++ )
    {
        cur[0] = (int)i;
        int rowMin = cur[0];
        for( size_t j = 1; j <= m; j++ )
        {
            const int cost = a[i-1] == b[j-1] ? 0 : 1;
            cur[j] = std::min( { prev[j]+1, cur[j-1]+1, prev[j-1]+cost } );
            rowMin = std::min( rowMin, cur[j] );
        }
        if( rowMin > maxDist ) return maxDist + 1;
        std::swap( prev, cur );
    }
    return prev[m];
}

constexpr double Bm25K1 = 1.4;
constexpr double Bm25B = 0.75;
constexpr double HeaderBoost = 2.0;
constexpr double ProximityAlpha = 1.0;

}

void TracyLlmBm25::Tokenize( std::string_view text, std::vector<std::string>& out )
{
    std::string tok;
    auto flush = [&]() {
        if( tok.empty() ) return;
        if( tok.size() > 1 ) out.push_back( tok );
        for( char sep : { '_', '-' } )
        {
            if( tok.find( sep ) == std::string::npos ) continue;
            size_t p = 0;
            while( p < tok.size() )
            {
                size_t e = tok.find( sep, p );
                if( e == std::string::npos ) e = tok.size();
                if( e > p && e - p > 1 ) out.push_back( tok.substr( p, e-p ) );
                p = e + 1;
            }
        }
        tok.clear();
    };
    for( char c : text )
    {
        if( ( c >= 'a' && c <= 'z' ) || ( c >= '0' && c <= '9' ) || c == '_' || c == '-' )
        {
            tok += c;
        }
        else if( c >= 'A' && c <= 'Z' )
        {
            tok += c - 'A' + 'a';
        }
        else
        {
            flush();
        }
    }
    flush();
}

TracyLlmBm25::TracyLlmBm25( std::vector<Doc>&& docs )
{
    m_numDocs = (int)docs.size();
    long total = 0;
    for( int d = 0; d < m_numDocs; d++ )
    {
        std::vector<std::string> raw;
        Tokenize( docs[d].header, raw );
        std::vector<std::string> header;
        header.reserve( raw.size() );
        for( auto& t : raw ) header.emplace_back( Stem( t ) );

        std::vector<std::string> tok;
        Tokenize( docs[d].text, tok );

        // boosted header tokens also inflate the document length, so that the
        // boost doesn't turn into a free win over longer documents
        m_docLen.push_back( (int)header.size() + (int)tok.size() + (int)header.size() * (int)( HeaderBoost - 1.0 ) );
        total += m_docLen.back();

        unordered_flat_map<std::string, std::vector<int32_t>> tpos;
        for( size_t i = 0; i < header.size(); i++ )
        {
            for( int b = 0; b < (int)HeaderBoost; b++ ) tpos[header[i]].push_back( (int32_t)i );
        }
        for( size_t i = 0; i < tok.size(); i++ )
        {
            tpos[Stem( tok[i] )].push_back( (int32_t)( header.size() + i ) );
        }
        for( auto& [term, positions] : tpos )
        {
            m_postings[term].push_back( Posting { (uint32_t)d, std::move( positions ) } );
        }
    }
    m_avgdl = total / (double)m_numDocs;

    for( auto& [term, plist] : m_postings )
    {
        std::sort( plist.begin(), plist.end(), []( const auto& a, const auto& b ) { return a.doc < b.doc; } );
        m_df[term] = (uint32_t)plist.size();
        m_vocab.emplace_back( term );
    }
    std::sort( m_vocab.begin(), m_vocab.end() );
}

std::vector<TracyLlmBm25::Result> TracyLlmBm25::Search( const std::string& query, size_t k ) const
{
    std::vector<std::string> raw;
    Tokenize( query, raw );
    std::vector<std::string> stems;
    stems.reserve( raw.size() );
    for( auto& t : raw ) stems.emplace_back( Stem( t ) );
    std::sort( stems.begin(), stems.end() );
    stems.erase( std::unique( stems.begin(), stems.end() ), stems.end() );

    struct QueryTerm
    {
        std::vector<std::pair<std::string, double>> expand;
        bool content = false;
    };

    const int contentDfMax = std::max( 2, m_numDocs / 8 );
    std::vector<QueryTerm> terms;
    terms.reserve( stems.size() );
    unordered_flat_set<std::string> claimed;
    for( auto& st : stems )
    {
        QueryTerm t;
        auto it = m_df.find( st );
        if( it != m_df.end() )
        {
            t.expand.emplace_back( st, 1.0 );
            claimed.insert( st );
            t.content = it->second <= (uint32_t)contentDfMax;
        }
        else if( st.size() >= 4 )
        {
            const int maxDist = st.size() <= 5 ? 1 : 2;
            std::vector<std::pair<int, std::string>> cand;
            for( auto& v : m_vocab )
            {
                const int d = EditDistance( st, v, maxDist );
                if( d <= maxDist ) cand.emplace_back( d, v );
            }
            std::sort( cand.begin(), cand.end(), [this]( const auto& a, const auto& b ) {
                if( a.first != b.first ) return a.first < b.first;
                return m_df.at( a.second ) > m_df.at( b.second );
            } );
            std::vector<std::pair<std::string, double>> picked;
            double wsum = 0;
            for( auto& [d, v] : cand )
            {
                if( picked.size() >= 3 ) break;
                if( claimed.contains( v ) ) continue;
                const double w = d == 1 ? 0.6 : 0.3;
                picked.emplace_back( v, w );
                wsum += w;
            }
            for( auto& [v, w] : picked )
            {
                t.expand.emplace_back( v, w / std::max( 1.0, wsum ) );
                claimed.insert( v );
            }
            if( !t.expand.empty() ) t.content = m_df.at( t.expand[0].first ) <= (uint32_t)contentDfMax;
        }
        terms.emplace_back( std::move( t ) );
    }

    unordered_flat_map<int, double> scores;
    unordered_flat_map<int, std::vector<std::vector<int32_t>>> posSets;

    size_t nContent = 0;
    for( auto& t : terms ) if( t.content ) nContent++;

    for( size_t ti = 0; ti < terms.size(); ti++ )
    {
        auto& t = terms[ti];
        for( auto& [term, w] : t.expand )
        {
            const uint32_t df = m_df.at( term );
            const double idf = std::log( 1.0 + ( m_numDocs - df + 0.5 ) / ( df + 0.5 ) );
            if( idf <= 0 ) continue;
            auto it = m_postings.find( term );
            if( it == m_postings.end() ) continue;
            for( auto& p : it->second )
            {
                const double tf = (double)p.positions.size();
                const double norm = tf * ( Bm25K1 + 1 ) / ( tf + Bm25K1 * ( 1.0 - Bm25B + Bm25B * m_docLen[p.doc] / m_avgdl ) );
                scores[p.doc] += w * idf * norm;
                if( t.content )
                {
                    auto& ps = posSets[p.doc];
                    if( ps.empty() ) ps.resize( terms.size() );
                    auto& v = ps[ti];
                    v.insert( v.end(), p.positions.begin(), p.positions.end() );
                }
            }
        }
    }

    if( nContent >= 2 )
    {
        for( auto& [doc, ps] : posSets )
        {
            int nSlots = 0;
            for( auto& v : ps ) if( !v.empty() ) nSlots++;
            if( (size_t)nSlots < nContent ) continue;

            struct Ev { int32_t pos; int term; };
            std::vector<Ev> ev;
            for( size_t ti = 0; ti < ps.size(); ti++ )
            {
                for( auto p : ps[ti] ) ev.push_back( { p, (int)ti } );
            }
            std::sort( ev.begin(), ev.end(), []( const auto& a, const auto& b ) { return a.pos < b.pos; } );

            std::vector<int> cnt( ps.size(), 0 );
            int have = 0;
            int best = INT32_MAX;
            size_t l = 0;
            for( size_t r = 0; r < ev.size(); r++ )
            {
                if( cnt[ev[r].term]++ == 0 ) have++;
                while( have == nSlots )
                {
                    best = std::min( best, ev[r].pos - ev[l].pos );
                    if( --cnt[ev[l].term] == 0 ) have--;
                    l++;
                }
            }
            if( best != INT32_MAX )
            {
                scores[doc] *= 1.0 + ProximityAlpha * 10.0 / ( 10.0 + best );
            }
        }
    }

    std::vector<Result> hits;
    hits.reserve( scores.size() );
    for( auto& [doc, s] : scores ) hits.push_back( { (uint32_t)doc, (float)s } );
    std::sort( hits.begin(), hits.end(), []( const auto& a, const auto& b ) { return a.score > b.score; } );
    if( hits.size() > k ) hits.resize( k );
    return hits;
}

}
