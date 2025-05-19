#pragma once

#include <memory>
#include <stddef.h>
#include <stdint.h>

#define Unembed( name ) std::make_shared<EmbedData>( Embed::name##Size, Embed::name##Lz4Size, Embed::name##Data )

class EmbedData
{
public:
    EmbedData( size_t size, size_t lz4Size, const uint8_t* data );
    ~EmbedData();

    [[nodiscard]] const char* data() const { return m_data; }
    [[nodiscard]] size_t size() const { return m_size; }

private:
    char* m_data;
    size_t m_size;
};
