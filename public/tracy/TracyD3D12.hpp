#ifndef __TRACYD3D12_HPP__
#define __TRACYD3D12_HPP__

#ifndef TRACY_ENABLE

#define TracyD3D12Context(device, queue) nullptr
#define TracyD3D12Destroy(ctx)
#define TracyD3D12ContextName(ctx, name, size)

#define TracyD3D12NewFrame(ctx)

#define TracyD3D12Zone(ctx, cmdList, name)
#define TracyD3D12ZoneC(ctx, cmdList, name, color)
#define TracyD3D12NamedZone(ctx, varname, cmdList, name, active)
#define TracyD3D12NamedZoneC(ctx, varname, cmdList, name, color, active)
#define TracyD3D12ZoneTransient(ctx, varname, cmdList, name, active)

#define TracyD3D12ZoneS(ctx, cmdList, name, depth)
#define TracyD3D12ZoneCS(ctx, cmdList, name, color, depth)
#define TracyD3D12NamedZoneS(ctx, varname, cmdList, name, depth, active)
#define TracyD3D12NamedZoneCS(ctx, varname, cmdList, name, color, depth, active)
#define TracyD3D12ZoneTransientS(ctx, varname, cmdList, name, depth, active)

#define TracyD3D12Collect(ctx)

namespace tracy
{
	class D3D12ZoneScope {};
}

using TracyD3D12Ctx = void*;

#else

#include "Tracy.hpp"
#include "../client/TracyProfiler.hpp"
#include "../client/TracyCallstack.hpp"

#include <cstdlib>
#include <cassert>
#include <d3d12.h>
#include <dxgi.h>
#include <wrl/client.h>
#include <queue>

namespace tracy
{

	struct D3D12QueryPayload
	{
		uint32_t m_queryIdStart = 0;
		uint32_t m_queryCount = 0;
	};

	// Command queue context.
	class D3D12QueueCtx
	{
		friend class D3D12ZoneScope;

		static constexpr uint32_t MaxQueries = 64 * 1024;  // Queries are begin and end markers, so we can store half as many total time durations. Must be even!

		bool m_initialized = false;

		ID3D12Device* m_device = nullptr;
		ID3D12CommandQueue* m_queue = nullptr;
		uint8_t m_context;
		Microsoft::WRL::ComPtr<ID3D12QueryHeap> m_queryHeap;
		Microsoft::WRL::ComPtr<ID3D12Resource> m_readbackBuffer;

		// In-progress payload.
		uint32_t m_queryLimit = MaxQueries;
		std::atomic<uint32_t> m_queryCounter = 0;
		uint32_t m_previousQueryCounter = 0;

		uint32_t m_activePayload = 0;
		Microsoft::WRL::ComPtr<ID3D12Fence> m_payloadFence;
		std::queue<D3D12QueryPayload> m_payloadQueue;

		int64_t m_prevCalibration = 0;
		int64_t m_qpcToNs = int64_t{ 1000000000 / GetFrequencyQpc() };

	public:
		D3D12QueueCtx(ID3D12Device* device, ID3D12CommandQueue* queue)
			: m_device(device)
			, m_queue(queue)
			, m_context(GetGpuCtxCounter().fetch_add(1, std::memory_order_relaxed))
		{
			// Verify we support timestamp queries on this queue.

			if (queue->GetDesc().Type == D3D12_COMMAND_LIST_TYPE_COPY)
			{
				D3D12_FEATURE_DATA_D3D12_OPTIONS3 featureData{};

				bool Success = SUCCEEDED(device->CheckFeatureSupport(D3D12_FEATURE_D3D12_OPTIONS3, &featureData, sizeof(featureData)));
				assert(Success && featureData.CopyQueueTimestampQueriesSupported && "Platform does not support profiling of copy queues.");
			}

			uint64_t timestampFrequency;

			if (FAILED(queue->GetTimestampFrequency(&timestampFrequency)))
			{
				assert(false && "Failed to get timestamp frequency.");
			}

			uint64_t cpuTimestamp;
			uint64_t gpuTimestamp;

			if (FAILED(queue->GetClockCalibration(&gpuTimestamp, &cpuTimestamp)))
			{
				assert(false && "Failed to get queue clock calibration.");
			}

			// Save the device cpu timestamp, not the profiler's timestamp.
			m_prevCalibration = cpuTimestamp * m_qpcToNs;

			cpuTimestamp = Profiler::GetTime();

			D3D12_QUERY_HEAP_DESC heapDesc{};
			heapDesc.Type = queue->GetDesc().Type == D3D12_COMMAND_LIST_TYPE_COPY ? D3D12_QUERY_HEAP_TYPE_COPY_QUEUE_TIMESTAMP : D3D12_QUERY_HEAP_TYPE_TIMESTAMP;
			heapDesc.Count = m_queryLimit;
			heapDesc.NodeMask = 0;  // #TODO: Support multiple adapters.

			while (FAILED(device->CreateQueryHeap(&heapDesc, IID_PPV_ARGS(&m_queryHeap))))
			{
				m_queryLimit /= 2;
				heapDesc.Count = m_queryLimit;
			}

			// Create a readback buffer, which will be used as a destination for the query data.

			D3D12_RESOURCE_DESC readbackBufferDesc{};
			readbackBufferDesc.Alignment = 0;
			readbackBufferDesc.Dimension = D3D12_RESOURCE_DIMENSION_BUFFER;
			readbackBufferDesc.Width = m_queryLimit * sizeof(uint64_t);
			readbackBufferDesc.Height = 1;
			readbackBufferDesc.DepthOrArraySize = 1;
			readbackBufferDesc.Format = DXGI_FORMAT_UNKNOWN;
			readbackBufferDesc.Layout = D3D12_TEXTURE_LAYOUT_ROW_MAJOR;  // Buffers are always row major.
			readbackBufferDesc.MipLevels = 1;
			readbackBufferDesc.SampleDesc.Count = 1;
			readbackBufferDesc.SampleDesc.Quality = 0;
			readbackBufferDesc.Flags = D3D12_RESOURCE_FLAG_NONE;

			D3D12_HEAP_PROPERTIES readbackHeapProps{};
			readbackHeapProps.Type = D3D12_HEAP_TYPE_READBACK;
			readbackHeapProps.CPUPageProperty = D3D12_CPU_PAGE_PROPERTY_UNKNOWN;
			readbackHeapProps.MemoryPoolPreference = D3D12_MEMORY_POOL_UNKNOWN;
			readbackHeapProps.CreationNodeMask = 0;
			readbackHeapProps.VisibleNodeMask = 0;  // #TODO: Support multiple adapters.

			if (FAILED(device->CreateCommittedResource(&readbackHeapProps, D3D12_HEAP_FLAG_NONE, &readbackBufferDesc, D3D12_RESOURCE_STATE_COPY_DEST, nullptr, IID_PPV_ARGS(&m_readbackBuffer))))
			{
				assert(false && "Failed to create query readback buffer.");
			}

			if (FAILED(device->CreateFence(0, D3D12_FENCE_FLAG_NONE, IID_PPV_ARGS(&m_payloadFence))))
			{
				assert(false && "Failed to create payload fence.");
			}

			auto* item = Profiler::QueueSerial();
			MemWrite(&item->hdr.type, QueueType::GpuNewContext);
			MemWrite(&item->gpuNewContext.cpuTime, cpuTimestamp);
			MemWrite(&item->gpuNewContext.gpuTime, gpuTimestamp);
			memset(&item->gpuNewContext.thread, 0, sizeof(item->gpuNewContext.thread));
			MemWrite(&item->gpuNewContext.period, 1E+09f / static_cast<float>(timestampFrequency));
			MemWrite(&item->gpuNewContext.context, m_context);
			MemWrite(&item->gpuNewContext.flags, GpuContextCalibration);
			MemWrite(&item->gpuNewContext.type, GpuContextType::Direct3D12);

#ifdef TRACY_ON_DEMAND
			GetProfiler().DeferItem(*item);
#endif

			Profiler::QueueSerialFinish();

			m_initialized = true;
		}

		void NewFrame()
		{
			uint32_t queryCounter = m_queryCounter.exchange(0);
			m_payloadQueue.emplace(D3D12QueryPayload{ m_previousQueryCounter, queryCounter });
			m_previousQueryCounter += queryCounter;

			if (m_previousQueryCounter >= m_queryLimit)
			{
				m_previousQueryCounter -= m_queryLimit;
			}

			m_queue->Signal(m_payloadFence.Get(), ++m_activePayload);
		}

		void Name( const char* name, uint16_t len )
		{
			auto ptr = (char*)tracy_malloc( len );
			memcpy( ptr, name, len );

			auto item = Profiler::QueueSerial();
			MemWrite( &item->hdr.type, QueueType::GpuContextName );
			MemWrite( &item->gpuContextNameFat.context, m_context );
			MemWrite( &item->gpuContextNameFat.ptr, (uint64_t)ptr );
			MemWrite( &item->gpuContextNameFat.size, len );
#ifdef TRACY_ON_DEMAND
			GetProfiler().DeferItem( *item );
#endif
			Profiler::QueueSerialFinish();
		}

		void Collect()
		{
			ZoneScopedC(Color::Red4);

#ifdef TRACY_ON_DEMAND
			if (!GetProfiler().IsConnected())
			{
				m_queryCounter = 0;

				return;
			}
#endif

			// Find out what payloads are available.
			const auto newestReadyPayload = m_payloadFence->GetCompletedValue();
			const auto payloadCount = m_payloadQueue.size() - (m_activePayload - newestReadyPayload);

			if (!payloadCount)
			{
				return;  // No payloads are available yet, exit out.
			}

			D3D12_RANGE mapRange{ 0, m_queryLimit * sizeof(uint64_t) };

			// Map the readback buffer so we can fetch the query data from the GPU.
			void* readbackBufferMapping = nullptr;

			if (FAILED(m_readbackBuffer->Map(0, &mapRange, &readbackBufferMapping)))
			{
				assert(false && "Failed to map readback buffer.");
			}

			auto* timestampData = static_cast<uint64_t*>(readbackBufferMapping);

			for (uint32_t i = 0; i < payloadCount; ++i)
			{
				const auto& payload = m_payloadQueue.front();

				for (uint32_t j = 0; j < payload.m_queryCount; ++j)
				{
					const auto counter = (payload.m_queryIdStart + j) % m_queryLimit;
					const auto timestamp = timestampData[counter];
					const auto queryId = counter;

					auto* item = Profiler::QueueSerial();
					MemWrite(&item->hdr.type, QueueType::GpuTime);
					MemWrite(&item->gpuTime.gpuTime, timestamp);
					MemWrite(&item->gpuTime.queryId, static_cast<uint16_t>(queryId));
					MemWrite(&item->gpuTime.context, m_context);

					Profiler::QueueSerialFinish();
				}

				m_payloadQueue.pop();
			}

			m_readbackBuffer->Unmap(0, nullptr);

			// Recalibrate to account for drift.

			uint64_t cpuTimestamp;
			uint64_t gpuTimestamp;

			if (FAILED(m_queue->GetClockCalibration(&gpuTimestamp, &cpuTimestamp)))
			{
				assert(false && "Failed to get queue clock calibration.");
			}

			cpuTimestamp *= m_qpcToNs;

			const auto cpuDelta = cpuTimestamp - m_prevCalibration;
			if (cpuDelta > 0)
			{
				m_prevCalibration = cpuTimestamp;
				cpuTimestamp = Profiler::GetTime();

				auto* item = Profiler::QueueSerial();
				MemWrite(&item->hdr.type, QueueType::GpuCalibration);
				MemWrite(&item->gpuCalibration.gpuTime, gpuTimestamp);
				MemWrite(&item->gpuCalibration.cpuTime, cpuTimestamp);
				MemWrite(&item->gpuCalibration.cpuDelta, cpuDelta);
				MemWrite(&item->gpuCalibration.context, m_context);

				Profiler::QueueSerialFinish();
			}
		}

	private:
		tracy_force_inline uint32_t NextQueryId()
		{
			uint32_t queryCounter = m_queryCounter.fetch_add(2);
			assert(queryCounter < m_queryLimit && "Submitted too many GPU queries! Consider increasing MaxQueries.");

			const uint32_t id = (m_previousQueryCounter + queryCounter) % m_queryLimit;

			return id;
		}

		tracy_force_inline uint8_t GetId() const
		{
			return m_context;
		}
	};

	class D3D12ZoneScope
	{
		const bool m_active;
		D3D12QueueCtx* m_ctx = nullptr;
		ID3D12GraphicsCommandList* m_cmdList = nullptr;
		uint32_t m_queryId = 0;  // Used for tracking in nested zones.

	public:
		tracy_force_inline D3D12ZoneScope(D3D12QueueCtx* ctx, ID3D12GraphicsCommandList* cmdList, const SourceLocationData* srcLocation, bool active)
#ifdef TRACY_ON_DEMAND
			: m_active(active && GetProfiler().IsConnected())
#else
			: m_active(active)
#endif
		{
			if (!m_active) return;

			m_ctx = ctx;
			m_cmdList = cmdList;

			m_queryId = ctx->NextQueryId();
			cmdList->EndQuery(ctx->m_queryHeap.Get(), D3D12_QUERY_TYPE_TIMESTAMP, m_queryId);

			auto* item = Profiler::QueueSerial();
			MemWrite(&item->hdr.type, QueueType::GpuZoneBeginSerial);
			MemWrite(&item->gpuZoneBegin.cpuTime, Profiler::GetTime());
			MemWrite(&item->gpuZoneBegin.srcloc, reinterpret_cast<uint64_t>(srcLocation));
			MemWrite(&item->gpuZoneBegin.thread, GetThreadHandle());
			MemWrite(&item->gpuZoneBegin.queryId, static_cast<uint16_t>(m_queryId));
			MemWrite(&item->gpuZoneBegin.context, ctx->GetId());

			Profiler::QueueSerialFinish();
		}

		tracy_force_inline D3D12ZoneScope(D3D12QueueCtx* ctx, ID3D12GraphicsCommandList* cmdList, const SourceLocationData* srcLocation, int depth, bool active)
#ifdef TRACY_ON_DEMAND
			: m_active(active&& GetProfiler().IsConnected())
#else
			: m_active(active)
#endif
		{
			if (!m_active) return;

			m_ctx = ctx;
			m_cmdList = cmdList;

			m_queryId = ctx->NextQueryId();
			cmdList->EndQuery(ctx->m_queryHeap.Get(), D3D12_QUERY_TYPE_TIMESTAMP, m_queryId);

			auto* item = Profiler::QueueSerialCallstack(Callstack(depth));
			MemWrite(&item->hdr.type, QueueType::GpuZoneBeginCallstackSerial);
			MemWrite(&item->gpuZoneBegin.cpuTime, Profiler::GetTime());
			MemWrite(&item->gpuZoneBegin.srcloc, reinterpret_cast<uint64_t>(srcLocation));
			MemWrite(&item->gpuZoneBegin.thread, GetThreadHandle());
			MemWrite(&item->gpuZoneBegin.queryId, static_cast<uint16_t>(m_queryId));
			MemWrite(&item->gpuZoneBegin.context, ctx->GetId());

			Profiler::QueueSerialFinish();
		}

		tracy_force_inline D3D12ZoneScope(D3D12QueueCtx* ctx, uint32_t line, const char* source, size_t sourceSz, const char* function, size_t functionSz, const char* name, size_t nameSz, ID3D12GraphicsCommandList* cmdList, bool active)
#ifdef TRACY_ON_DEMAND
			: m_active(active&& GetProfiler().IsConnected())
#else
			: m_active(active)
#endif
		{
			if (!m_active) return;

			m_ctx = ctx;
			m_cmdList = cmdList;

			m_queryId = ctx->NextQueryId();
			cmdList->EndQuery(ctx->m_queryHeap.Get(), D3D12_QUERY_TYPE_TIMESTAMP, m_queryId);

			const auto sourceLocation = Profiler::AllocSourceLocation(line, source, sourceSz, function, functionSz, name, nameSz);

			auto* item = Profiler::QueueSerial();
			MemWrite(&item->hdr.type, QueueType::GpuZoneBeginAllocSrcLocSerial);
			MemWrite(&item->gpuZoneBegin.cpuTime, Profiler::GetTime());
			MemWrite(&item->gpuZoneBegin.srcloc, sourceLocation);
			MemWrite(&item->gpuZoneBegin.thread, GetThreadHandle());
			MemWrite(&item->gpuZoneBegin.queryId, static_cast<uint16_t>(m_queryId));
			MemWrite(&item->gpuZoneBegin.context, ctx->GetId());

			Profiler::QueueSerialFinish();
		}

		tracy_force_inline D3D12ZoneScope(D3D12QueueCtx* ctx, uint32_t line, const char* source, size_t sourceSz, const char* function, size_t functionSz, const char* name, size_t nameSz, ID3D12GraphicsCommandList* cmdList, int depth, bool active)
#ifdef TRACY_ON_DEMAND
			: m_active(active&& GetProfiler().IsConnected())
#else
			: m_active(active)
#endif
		{
			if (!m_active) return;

			m_ctx = ctx;
			m_cmdList = cmdList;

			m_queryId = ctx->NextQueryId();
			cmdList->EndQuery(ctx->m_queryHeap.Get(), D3D12_QUERY_TYPE_TIMESTAMP, m_queryId);

			const auto sourceLocation = Profiler::AllocSourceLocation(line, source, sourceSz, function, functionSz, name, nameSz);

			auto* item = Profiler::QueueSerialCallstack(Callstack(depth));
			MemWrite(&item->hdr.type, QueueType::GpuZoneBeginAllocSrcLocCallstackSerial);
			MemWrite(&item->gpuZoneBegin.cpuTime, Profiler::GetTime());
			MemWrite(&item->gpuZoneBegin.srcloc, sourceLocation);
			MemWrite(&item->gpuZoneBegin.thread, GetThreadHandle());
			MemWrite(&item->gpuZoneBegin.queryId, static_cast<uint16_t>(m_queryId));
			MemWrite(&item->gpuZoneBegin.context, ctx->GetId());

			Profiler::QueueSerialFinish();
		}

		tracy_force_inline ~D3D12ZoneScope()
		{
			if (!m_active) return;

			const auto queryId = m_queryId + 1;  // Our end query slot is immediately after the begin slot.
			m_cmdList->EndQuery(m_ctx->m_queryHeap.Get(), D3D12_QUERY_TYPE_TIMESTAMP, queryId);

			auto* item = Profiler::QueueSerial();
			MemWrite(&item->hdr.type, QueueType::GpuZoneEndSerial);
			MemWrite(&item->gpuZoneEnd.cpuTime, Profiler::GetTime());
			MemWrite(&item->gpuZoneEnd.thread, GetThreadHandle());
			MemWrite(&item->gpuZoneEnd.queryId, static_cast<uint16_t>(queryId));
			MemWrite(&item->gpuZoneEnd.context, m_ctx->GetId());

			Profiler::QueueSerialFinish();

			m_cmdList->ResolveQueryData(m_ctx->m_queryHeap.Get(), D3D12_QUERY_TYPE_TIMESTAMP, m_queryId, 2, m_ctx->m_readbackBuffer.Get(), m_queryId * sizeof(uint64_t));
		}
	};

	static inline D3D12QueueCtx* CreateD3D12Context(ID3D12Device* device, ID3D12CommandQueue* queue)
	{
		auto* ctx = static_cast<D3D12QueueCtx*>(tracy_malloc(sizeof(D3D12QueueCtx)));
		new (ctx) D3D12QueueCtx{ device, queue };

		return ctx;
	}

	static inline void DestroyD3D12Context(D3D12QueueCtx* ctx)
	{
		ctx->~D3D12QueueCtx();
		tracy_free(ctx);
	}

}

using TracyD3D12Ctx = tracy::D3D12QueueCtx*;

#define TracyD3D12Context(device, queue) tracy::CreateD3D12Context(device, queue);
#define TracyD3D12Destroy(ctx) tracy::DestroyD3D12Context(ctx);
#define TracyD3D12ContextName(ctx, name, size) ctx->Name(name, size);

#define TracyD3D12NewFrame(ctx) ctx->NewFrame();

#if defined TRACY_HAS_CALLSTACK && defined TRACY_CALLSTACK
#  define TracyD3D12Zone(ctx, cmdList, name) TracyD3D12NamedZoneS(ctx, ___tracy_gpu_zone, cmdList, name, TRACY_CALLSTACK, true)
#  define TracyD3D12ZoneC(ctx, cmdList, name, color) TracyD3D12NamedZoneCS(ctx, ___tracy_gpu_zone, cmdList, name, color, TRACY_CALLSTACK, true)
#  define TracyD3D12NamedZone(ctx, varname, cmdList, name, active) static constexpr tracy::SourceLocationData TracyConcat(__tracy_gpu_source_location, __LINE__) { name, __FUNCTION__, __FILE__, (uint32_t)__LINE__, 0 }; tracy::D3D12ZoneScope varname{ ctx, cmdList, &TracyConcat(__tracy_gpu_source_location, __LINE__), TRACY_CALLSTACK, active };
#  define TracyD3D12NamedZoneC(ctx, varname, cmdList, name, color, active) static constexpr tracy::SourceLocationData TracyConcat(__tracy_gpu_source_location, __LINE__) { name, __FUNCTION__, __FILE__, (uint32_t)__LINE__, color }; tracy::D3D12ZoneScope varname{ ctx, cmdList, &TracyConcat(__tracy_gpu_source_location, __LINE__), TRACY_CALLSTACK, active };
#  define TracyD3D12ZoneTransient(ctx, varname, cmdList, name, active) TracyD3D12ZoneTransientS(ctx, varname, cmdList, name, TRACY_CALLSTACK, active)
#else
#  define TracyD3D12Zone(ctx, cmdList, name) TracyD3D12NamedZone(ctx, ___tracy_gpu_zone, cmdList, name, true)
#  define TracyD3D12ZoneC(ctx, cmdList, name, color) TracyD3D12NamedZoneC(ctx, ___tracy_gpu_zone, cmdList, name, color, true)
#  define TracyD3D12NamedZone(ctx, varname, cmdList, name, active) static constexpr tracy::SourceLocationData TracyConcat(__tracy_gpu_source_location, __LINE__) { name, __FUNCTION__, __FILE__, (uint32_t)__LINE__, 0 }; tracy::D3D12ZoneScope varname{ ctx, cmdList, &TracyConcat(__tracy_gpu_source_location, __LINE__), active };
#  define TracyD3D12NamedZoneC(ctx, varname, cmdList, name, color, active) static constexpr tracy::SourceLocationData TracyConcat(__tracy_gpu_source_location, __LINE__) { name, __FUNCTION__, __FILE__, (uint32_t)__LINE__, color }; tracy::D3D12ZoneScope varname{ ctx, cmdList, &TracyConcat(__tracy_gpu_source_location, __LINE__), active };
#  define TracyD3D12ZoneTransient(ctx, varname, cmdList, name, active) tracy::D3D12ZoneScope varname{ ctx, __LINE__, __FILE__, strlen(__FILE__), __FUNCTION__, strlen(__FUNCTION__), name, strlen(name), cmdList, active };
#endif

#ifdef TRACY_HAS_CALLSTACK
#  define TracyD3D12ZoneS(ctx, cmdList, name, depth) TracyD3D12NamedZoneS(ctx, ___tracy_gpu_zone, cmdList, name, depth, true)
#  define TracyD3D12ZoneCS(ctx, cmdList, name, color, depth) TracyD3D12NamedZoneCS(ctx, ___tracy_gpu_zone, cmdList, name, color, depth, true)
#  define TracyD3D12NamedZoneS(ctx, varname, cmdList, name, depth, active) static constexpr tracy::SourceLocationData TracyConcat(__tracy_gpu_source_location, __LINE__) { name, __FUNCTION__, __FILE__, (uint32_t)__LINE__, 0 }; tracy::D3D12ZoneScope varname{ ctx, cmdList, &TracyConcat(__tracy_gpu_source_location, __LINE__), depth, active };
#  define TracyD3D12NamedZoneCS(ctx, varname, cmdList, name, color, depth, active) static constexpr tracy::SourceLocationData TracyConcat(__tracy_gpu_source_location, __LINE__) { name, __FUNCTION__, __FILE__, (uint32_t)__LINE__, color }; tracy::D3D12ZoneScope varname{ ctx, cmdList, &TracyConcat(__tracy_gpu_source_location, __LINE__), depth, active };
#  define TracyD3D12ZoneTransientS(ctx, varname, cmdList, name, depth, active) tracy::D3D12ZoneScope varname{ ctx, __LINE__, __FILE__, strlen(__FILE__), __FUNCTION__, strlen(__FUNCTION__), name, strlen(name), cmdList, depth, active };
#else
#  define TracyD3D12ZoneS(ctx, cmdList, name, depth) TracyD3D12Zone(ctx, cmdList, name)
#  define TracyD3D12ZoneCS(ctx, cmdList, name, color, depth) TracyD3D12Zone(ctx, cmdList, name, color)
#  define TracyD3D12NamedZoneS(ctx, varname, cmdList, name, depth, active) TracyD3D12NamedZone(ctx, varname, cmdList, name, active)
#  define TracyD3D12NamedZoneCS(ctx, varname, cmdList, name, color, depth, active) TracyD3D12NamedZoneC(ctx, varname, cmdList, name, color, active)
#  define TracyD3D12ZoneTransientS(ctx, varname, cmdList, name, depth, active) TracyD3D12ZoneTransient(ctx, varname, cmdList, name, active)
#endif

#define TracyD3D12Collect(ctx) ctx->Collect();

#endif

#endif
