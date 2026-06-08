// Loads a .tracy file and prints the GPU context names.
// Used to verify that on-demand profiling correctly defers the
// GpuContextName message so late-connecting clients see the name.
//
// Usage: ./check_gpu_ctx_name trace.tracy
// Expected output: "GPU context 0: rocprofv3"
// If name is missing: "GPU context 0: (unnamed)"

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
            return 1;
        }

        bool all_named = true;
        for( size_t i = 0; i < gpuData.size(); i++ )
        {
            const auto& ctx = gpuData[i];
            if( ctx->name.Active() )
            {
                const char* name = worker.GetString( ctx->name );
                bool has_name = name && name[0] != '\0';
                printf( "GPU context %zu: %s\n", i, has_name ? name : "(unnamed)" );
                if( !has_name ) all_named = false;
            }
            else
            {
                printf( "GPU context %zu: (unnamed)\n", i );
                all_named = false;
            }
        }

        return all_named ? 0 : 2;
    }
    catch( const std::exception& e )
    {
        fprintf( stderr, "Error: %s\n", e.what() );
        return 1;
    }
}
