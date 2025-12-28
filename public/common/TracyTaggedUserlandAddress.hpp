#ifndef __TRACYTAGGEDPTR_HPP__
#define __TRACYTAGGEDPTR_HPP__

#include <stdint.h>
#include <assert.h>

namespace tracy
{

class TaggedUserlandAddress
{
	uint64_t m_storage;
	// So far no kernel seems to allow userspace address with more than 56bits userspace VAs since now hardware support it. See https://docs.kernel.org/next/x86/x86_64/mm.html and https://www.kernel.org/doc/html/v5.8/arm64/memory.html#bit-userspace-vas
	static constexpr uint64_t kUserspaceVABits = 56;
	static constexpr uint64_t kKernelOnlyBits = 64 - kUserspaceVABits;
	static constexpr uint64_t kKernelOnlyBitMask = ( ( uint64_t(1) << kKernelOnlyBits ) - uint64_t(1) ) << kUserspaceVABits;
public:
	
	TaggedUserlandAddress() = default;
	explicit TaggedUserlandAddress( uint64_t address, uint8_t tag = 0 )
	{
		assert( ( address & kKernelOnlyBitMask ) == 0 );
		assert( ( (uint64_t)tag & ~( kKernelOnlyBitMask >> kUserspaceVABits ) ) == 0 );
		m_storage = address | ( (uint64_t)tag << kUserspaceVABits );
	}

	void SetPackedValue(uint64_t value) { m_storage = value; }
	uint64_t GetPackedValue() const { return m_storage; }

	void SetAddress( uint64_t address)
	{
		assert( ( address & kKernelOnlyBitMask ) == 0 );
		m_storage = ( m_storage & kKernelOnlyBitMask ) | address;
	}
	uint64_t GetAddress() const { return m_storage & ( ~kKernelOnlyBitMask ); }

	void SetTag( uint8_t tag )
	{
		assert( ( (uint64_t)tag & ~( kKernelOnlyBitMask >> kUserspaceVABits ) ) == 0 );
		m_storage = ( (uint64_t)tag << kUserspaceVABits ) | ( m_storage & ( ~kKernelOnlyBitMask ) );
	}
	uint8_t GetTag() const { return (uint8_t)( ( m_storage & kKernelOnlyBitMask ) >> kUserspaceVABits ); }
};

}

#endif
