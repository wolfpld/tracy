#ifndef __TRACYTAGGEDPTR_HPP__
#define __TRACYTAGGEDPTR_HPP__

#include <stdint.h>

namespace tracy
{

class TaggedUserlandAddress
{
	uint64_t m_storage;
	// So far no kernel seems to allow userspace address with more than 52bits userspace VAs (not supported by ARM/x86 HW)
	static constexpr uint64_t kUserspaceVABits = 52;
	static constexpr uint64_t kKernelOnlyBits = 64 - kUserspaceVABits;
	static constexpr uint64_t kKernelOnlyBitMask = ( ( uint64_t(1) << kKernelOnlyBits ) - uint64_t(1) ) << kUserspaceVABits;
public:
	// Trivial constructor and copy
	TaggedUserlandAddress() = default;
	TaggedUserlandAddress(const TaggedUserlandAddress&) = default;
	TaggedUserlandAddress(TaggedUserlandAddress&&) = default;
	
	explicit TaggedUserlandAddress( uint64_t address, uint16_t tag = 0 )
	{
		SetAddress( address );
		SetTag( tag );
	}
	// We want a trivial copy
	TaggedUserlandAddress& operator=(const TaggedUserlandAddress&) = default;
	TaggedUserlandAddress& operator=(TaggedUserlandAddress&&) = default;

	void SetPackedValue(uint64_t value) { m_storage = value; }
	uint64_t GetPackedValue() const { return m_storage; }

	void SetAddress( uint64_t address)
	{
		assert( ( address & kKernelOnlyBitMask ) == 0 );
		m_storage = ( m_storage & kKernelOnlyBitMask ) | address;
	}
	uint64_t GetAddress() const { return m_storage & ( ~kKernelOnlyBitMask ); }

	void SetTag( uint16_t tag )
	{
		assert( ( (uint64_t)tag & ~( kKernelOnlyBitMask >> kUserspaceVABits ) ) == 0 );
		m_storage = ( (uint64_t)tag << kUserspaceVABits ) | ( m_storage & ( ~kKernelOnlyBitMask ) );
	}
	uint16_t GetTag() const { return (uint16_t)( ( m_storage & kKernelOnlyBitMask ) >> kUserspaceVABits ); }
};

}

#endif
