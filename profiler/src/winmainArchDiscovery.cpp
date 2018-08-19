#ifdef _WIN32
namespace tracy
{
    bool DiscoveryAVX()
    {
#ifdef __AVX__
        return true;
#else
        return false;
#endif
    }

    bool DiscoveryAVX2()
    {
#ifdef __AVX2__
        return true;
#else
        return false;
#endif
    }
}
#endif
