struct vs2ps
{
    float2 uv : TEXCOORD0;
    float4 pos : SV_Position;
};

vs2ps main(uint vid : SV_VertexID)
{
    vs2ps o;
    o.uv = float2((vid << 1) & 2, vid & 2);
    o.pos = float4(o.uv * float2(2, 2) + float2(-1, -1), 0, 1);
    return o;
}
