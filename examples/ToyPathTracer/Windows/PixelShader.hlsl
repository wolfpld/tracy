float3 LinearToSRGB(float3 rgb)
{
    rgb = max(rgb, float3(0, 0, 0));
    return max(1.055 * pow(rgb, 0.416666667) - 0.055, 0.0);
}

Texture2D tex : register(t0);
SamplerState smp : register(s0);

float4 main(float2 uv : TEXCOORD0) : SV_Target
{
    float3 col = tex.Sample(smp, uv).rgb;
    col = LinearToSRGB(col);
    return float4(col, 1.0f);
}
