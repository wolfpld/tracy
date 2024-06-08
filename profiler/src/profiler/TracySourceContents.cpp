#include "TracySourceContents.hpp"
#include "TracyView.hpp"
#include "TracyWorker.hpp"

namespace tracy
{

SourceContents::SourceContents()
    : m_file( nullptr )
    , m_fileStringIdx( 0 )
    , m_data( nullptr )
    , m_dataBuf( nullptr )
    , m_dataSize( 0 )
{
}

SourceContents::~SourceContents()
{
    delete[] m_dataBuf;
}

void SourceContents::Parse( const char* fileName, const Worker& worker, const View& view )
{
    if( m_file == fileName ) return;

    m_file = fileName;
    m_fileStringIdx = worker.FindStringIdx( fileName );
    m_lines.clear();
    if( fileName )
    {
        uint32_t sz;
        const auto srcCache = worker.GetSourceFileFromCache( fileName );
        if( srcCache.data != nullptr )
        {
            m_data = srcCache.data;
            m_dataSize = srcCache.len;
            sz = srcCache.len;
        }
        else
        {
            FILE* f = fopen( view.SourceSubstitution( fileName ), "rb" );
            if( f )
            {
                fseek( f, 0, SEEK_END );
                sz = ftell( f );
                fseek( f, 0, SEEK_SET );
                if( sz > m_dataSize )
                {
                    delete[] m_dataBuf;
                    m_dataBuf = new char[sz];
                    m_dataSize = sz;
                }
                fread( m_dataBuf, 1, sz, f );
                m_data = m_dataBuf;
                fclose( f );
            }
            else
            {
                m_file = nullptr;
            }
        }

        if( m_file ) Tokenize( m_data, sz );
    }
}

void SourceContents::Parse( const char* source )
{
    if( source == m_data ) return;

    const size_t len = strlen( source );

    m_file = nullptr;
    m_fileStringIdx = 0;
    m_data = source;
    m_dataBuf = nullptr;
    m_dataSize = len;
    Tokenize( source, len );
}

void SourceContents::Tokenize( const char* txt, size_t sz )
{
    Tokenizer tokenizer;
    for(;;)
    {
        auto end = txt;
        while( *end != '\n' && *end != '\r' && end - m_data < sz ) end++;
        m_lines.emplace_back( Tokenizer::Line { txt, end, tokenizer.Tokenize( txt, end ) } );
        if( end - m_data == sz ) break;
        if( *end == '\n' )
        {
            end++;
            if( end - m_data < sz && *end == '\r' ) end++;
        }
        else if( *end == '\r' )
        {
            end++;
            if( end - m_data < sz && *end == '\n' ) end++;
        }
        if( end - m_data == sz ) break;
        txt = end;
    }
}

}
