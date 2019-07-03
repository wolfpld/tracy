namespace tracy
{

static const char* DecodeArmImplementer( uint32_t v )
{
    static char buf[16];
    switch( v )
    {
    case 0x41: return "ARM";
    case 0x42: return "Broadcom";
    case 0x43: return "Cavium";
    case 0x44: return "DEC";
    case 0x46: return "Fujitsu";
    case 0x48: return "HiSilicon";
    case 0x4d: return "Motorola";
    case 0x4e: return "Nvidia";
    case 0x50: return "Applied Micro";
    case 0x51: return "Qualcomm";
    case 0x53: return "Samsung";
    case 0x54: return "Texas Instruments";
    case 0x56: return "Marvell";
    case 0x61: return "Apple";
    case 0x66: return "Faraday";
    case 0x68: return "HXT";
    case 0x69: return "Intel";
    default: break;
    }
    sprintf( buf, "0x%x", v );
    return buf;
}

static const char* DecodeArmPart( uint32_t impl, uint32_t part )
{
    static char buf[16];
    switch( impl )
    {
    case 0x41:
        switch( part )
        {
        case 0x810: return "810";
        case 0x920: return "920";
        case 0x922: return "922";
        case 0x926: return "926";
        case 0x940: return "940";
        case 0x946: return "946";
        case 0x966: return "966";
        case 0xa20: return "1020";
        case 0xa22: return "1022";
        case 0xa26: return "1026";
        case 0xb02: return "11 MPCore";
        case 0xb36: return "1136";
        case 0xb56: return "1156";
        case 0xb76: return "1176";
        case 0xc05: return " Cortex-A5";
        case 0xc07: return " Cortex-A7";
        case 0xc08: return " Cortex-A8";
        case 0xc09: return " Cortex-A9";
        case 0xc0c: return " Cortex-A12";
        case 0xc0d: return " Rockchip RK3288";
        case 0xc0f: return " Cortex-A15";
        case 0xc0e: return " Cortex-A17";
        case 0xc14: return " Cortex-R4";
        case 0xc15: return " Cortex-R5";
        case 0xc17: return " Cortex-R7";
        case 0xc18: return " Cortex-R8";
        case 0xc20: return " Cortex-M0";
        case 0xc21: return " Cortex-M1";
        case 0xc23: return " Cortex-M3";
        case 0xc24: return " Cortex-M4";
        case 0xc27: return " Cortex-M7";
        case 0xc60: return " Cortex-M0+";
        case 0xd00: return " AArch64 simulator";
        case 0xd01: return " Cortex-A32";
        case 0xd03: return " Cortex-A53";
        case 0xd04: return " Cortex-A35";
        case 0xd05: return " Cortex-A55";
        case 0xd06: return " Cortex-A65";
        case 0xd07: return " Cortex-A57";
        case 0xd08: return " Cortex-A72";
        case 0xd09: return " Cortex-A73";
        case 0xd0a: return " Cortex-A75";
        case 0xd0b: return " Cortex-A76";
        case 0xd0c: return " Neoverse N1";
        case 0xd0d: return " Cortex-A77";
        case 0xd0e: return " Cortex-A76AE";
        case 0xd0f: return " AEMv8";
        case 0xd13: return " Cortex-R52";
        case 0xd20: return " Cortex-M23";
        case 0xd21: return " Cortex-M33";
        case 0xd4a: return " Neoverse E1";
        default: break;
        }
    case 0x42:
        switch( part )
        {
        case 0xf: return " Brahma B15";
        case 0x100: return " Brahma B53";
        case 0x516: return " ThunderX2";
        default: break;
        }
    case 0x43:
        switch( part )
        {
        case 0xa0: return " ThunderX";
        case 0xa1: return " ThunderX 88XX";
        case 0xa2: return " ThunderX 81XX";
        case 0xa3: return " ThunderX 83XX";
        case 0xaf: return " ThunderX2 99xx";
        default: break;
        }
    case 0x44:
        switch( part )
        {
        case 0xa10: return " SA110";
        case 0xa11: return " SA1100";
        default: break;
        }
    case 0x46:
        switch( part )
        {
        case 0x1: return " A64FX";
        default: break;
        }
    case 0x48:
        switch( part )
        {
        case 0xd01: return " TSV100";
        case 0xd40: return " Kirin 980";
        default: break;
        }
    case 0x4e:
        switch( part )
        {
        case 0x0: return " Denver";
        case 0x3: return " Denver 2";
        case 0x4: return " Carmel";
        default: break;
        }
    case 0x50:
        switch( part )
        {
        case 0x0: return " X-Gene";
        default: break;
        }
    case 0x51:
        switch( part )
        {
        case 0xf: return " Scorpion";
        case 0x2d: return " Scorpion";
        case 0x4d: return " Krait";
        case 0x6f: return " Krait";
        case 0x200: return " Kryo";
        case 0x201: return " Kryo Silver (Snapdragon 821)";
        case 0x205: return " Kryo Gold";
        case 0x211: return " Kryo Silver (Snapdragon 820)";
        case 0x800: return " Kryo 260 / 280 Gold";
        case 0x801: return " Kryo 260 / 280 Silver";
        case 0x802: return " Kryo 385 Gold";
        case 0x803: return " Kryo 385 Silver";
        case 0x804: return " Kryo 485 Gold";
        case 0xc00: return " Falkor";
        case 0xc01: return " Saphira";
        default: break;
        }
    case 0x53:
        switch( part )
        {
        case 0x1: return " Exynos M1/M2";
        case 0x2: return " Exynos M3";
        default: break;
        }
    case 0x56:
        switch( part )
        {
        case 0x131: return " Feroceon 88FR131";
        case 0x581: return " PJ4 / PJ4B";
        case 0x584: return " PJ4B-MP / PJ4C";
        default: break;
        }
    case 0x61:
        switch( part )
        {
        case 0x1: return " Cyclone";
        case 0x2: return " Typhoon";
        case 0x3: return " Typhoon/Capri";
        case 0x4: return " Twister";
        case 0x5: return " Twister/Elba/Malta";
        case 0x6: return " Hurricane";
        case 0x7: return " Hurricane/Myst";
        default: break;
        }
    case 0x66:
        switch( part )
        {
        case 0x526: return " FA526";
        case 0x626: return " FA626";
        default: break;
        }
    case 0x68:
        switch( part )
        {
        case 0x0: return " Phecda";
        default: break;
        }
    default: break;
    }
    sprintf( buf, " 0x%x", part );
    return buf;
}

}
