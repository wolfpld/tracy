// Loads a .tracy file and prints, for each GPU context, whether it is
// named and how many GPU zones it recorded. Used to verify that a
// late-connecting client correctly received the deferred GpuNewContext
// (and, downstream, actual GPU zone data) rather than the connection
// having crashed the server before any capture was possible.
//
// Usage: ./check_gpu_zones trace.tracy
// Expected output: "GPU context 0: line_scan_processing_cuda, 100 zones"

#include <cstdio>
#include <cstdlib>
#include "server/TracyFileRead.hpp"
#include "server/TracyWorker.hpp"

int main( int argc, char** argv )
{
    if( argc != 2 )
    {
        fprintf( stderr, "Usage: %s <trace.tracy>\n", argv[0] );
        return 1;
    }

    try
    {
        auto f = std::unique_ptr<tracy::FileRead>( tracy::FileRead::Open( argv[1] ) );
        if( !f )
        {
            fprintf( stderr, "Cannot open %s\n", argv[1] );
            return 1;
        }

        tracy::Worker worker( *f, tracy::EventType::None, false );

        const auto& gpuData = worker.GetGpuData();
        if( gpuData.empty() )
        {
            printf( "No GPU contexts found.\n" );
            return 2;
        }

        bool all_good = true;
        for( size_t i = 0; i < gpuData.size(); i++ )
        {
            const auto& ctx = gpuData[i];
            const bool has_name = ctx->name.Active() && worker.GetString( ctx->name )[0] != '\0';
            const char* name = has_name ? worker.GetString( ctx->name ) : "(unnamed)";
            printf( "GPU context %zu: %s, %lu zones\n", i, name, (unsigned long)ctx->count );
            if( !has_name || ctx->count == 0 ) all_good = false;
        }

        return all_good ? 0 : 2;
    }
    catch( const std::exception& e )
    {
        fprintf( stderr, "Error: %s\n", e.what() );
        return 1;
    }
}
