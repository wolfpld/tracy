#ifdef _WIN32
#  include <windows.h>
#else
#  include <unistd.h>
#endif

#include <chrono>
#include <iostream>
#include <thread>
#include <vector>
#include <cassert>
#include <optional>
#include <deque>
#include <unordered_map>

#include "../../public/common/TracyAlign.hpp"
#include "../../public/common/tracy_lz4.hpp"
#include "../../public/common/TracyProtocol.hpp"
#include "../../public/common/TracyQueue.hpp"
#include "../../public/common/TracySocket.hpp"

class PacketList
{
	std::basic_string<uint8_t> buffer;
	std::basic_string<uint32_t> offsets;

	public:

	bool ready;

  	PacketList() : ready(false) {}

	void append(const uint8_t* ptr, uint32_t sz)
	{
		auto n = buffer.size();
		buffer.resize(n + sz);
		memcpy(buffer.data() + n, ptr, sz);
		offsets.push_back(n);
	}

	void clear()
	{
		buffer.clear();
		offsets.clear();
	}

	uint32_t length()
	{
		return offsets.length();
	}

	bool empty()
	{
		return offsets.empty();
	}

	std::pair<const uint8_t*, uint32_t> operator[](uint32_t pos)
	{
		uint32_t n = offsets.length();
		if (n == 0 || pos >= n) return {nullptr, 0};
		if (pos == n - 1)
		{
			return {
				buffer.data() + offsets[pos],
				buffer.length() - offsets[pos],
			};
		}
		else
		{
			return {
				buffer.data() + offsets[pos],
				offsets[pos+1] - offsets[pos],
			};
		}
	}

	std::pair<const uint8_t*, uint32_t> front()
	{
		return (*this)[0];
	}

	std::pair<const uint8_t*, uint32_t> back()
	{
		return (*this)[this->length()-1];
	}

	const std::basic_string<uint8_t>* data()
	{
		return &buffer;
	}

	void pop()
	{
		uint32_t offset = offsets.back();
		buffer.resize(offset);
		offsets.pop_back();
	}
};

class PacketQueue
{
	PacketList packetLists[2];
	uint32_t readIdx;
	uint8_t readList;

	public:

	PacketQueue()
	{
		readIdx = 0;
		readList = 1;
	}

	void push(const uint8_t* ptr, uint32_t sz)
	{
		packetLists[!readList].append(ptr, sz);
	}

	void pop_front()
	{
		if (packetLists[0].empty() && packetLists[1].empty()) return;
		if (packetLists[readList].empty())
		{
			readList = !readList;
			readIdx = 0;
		}
		readIdx++;
		if (readIdx >= packetLists[readList].length())
		{
			packetLists[readList].clear();
			readList = !readList;
			readIdx = 0;
		}
	}

	void pop_back()
	{
		if (packetLists[0].empty() && packetLists[1].empty()) return;

		if (packetLists[!readList].empty())
		{
			packetLists[readList].pop();
			if (readIdx >= packetLists[readList].length())
			{
				packetLists[readList].clear();
				readIdx = 0;
			}
		}
		else
		{
			packetLists[!readList].pop();
		}
	}

	std::pair<const uint8_t*, uint32_t> operator[](uint32_t pos)
	{
		uint16_t remPackets = packetLists[readList].length() - readIdx;
		if (pos < remPackets)
		{
			return packetLists[readList][readIdx + pos];
		}
		else
		{
			return packetLists[!readList][pos - remPackets];
		}
	}

	std::pair<const uint8_t*, uint32_t> front()
	{
		if (packetLists[readList].empty())
		{
			return packetLists[!readList].front();
		}
		else
		{
			return packetLists[readList][readIdx];
		}
	}

	std::pair<const uint8_t*, uint32_t> back()
	{
		if (packetLists[!readList].empty())
		{
			return packetLists[readList].back();
		}
		else
		{
			return packetLists[!readList].back();
		}
	}

	uint32_t length()
	{
		return packetLists[0].length() + packetLists[1].length() - readIdx;
	}

	bool empty()
	{
		return this->length() == 0;
	}
};

class OutputBuffer
{
	tracy::LZ4_stream_t* stream;
	char* buffer;
	char* compressed;
	int start;
	int offset;

	public:

	OutputBuffer()
	: start(0)
	, offset(0)
	{
		stream = tracy::LZ4_createStream();
		buffer = new char[tracy::TargetFrameSize*3];
		compressed = new char[tracy::LZ4Size + sizeof(tracy::lz4sz_t)];
		LZ4_resetStream(stream);
	}

	~OutputBuffer()
	{
		tracy::LZ4_freeStream(stream);
		delete buffer;
		delete compressed;
	}

	bool empty()
	{
		return offset == start;
	}

	uint32_t space()
	{
		return tracy::TargetFrameSize - (offset - start);
	}

	void append(const uint8_t* ptr, uint32_t sz)
	{
		memcpy(buffer + offset, ptr, sz);
		offset += sz;
	}

	bool commit(tracy::Socket* outSock)
	{
		const tracy::lz4sz_t lz4sz = LZ4_compress_fast_continue(
			stream,
			buffer + start,
			compressed + sizeof(tracy::lz4sz_t),
			offset - start,
			tracy::LZ4Size,
			1
		);
		memcpy(compressed, &lz4sz, sizeof(lz4sz));

		if (outSock->Send(compressed, lz4sz + sizeof(tracy::lz4sz_t)) == -1)
		{
			std::cout << "Failed to send data to server" << std::endl;
			return false;
		}

		if (offset > tracy::TargetFrameSize * 2) offset = 0;
		start = offset;

		return true;
	}
};

struct UnresolvedRequest
{
	tracy::ServerQueryPacket request;
	std::unordered_map<uint64_t, PacketList> responses;
};

struct ClientConnection
{
	uint64_t id;
	std::unique_ptr<tracy::Socket> socket;
	std::unique_ptr<tracy::LZ4_streamDecode_t> stream;
	std::unique_ptr<char[]> buffer;
	int bufferOffset;
	PacketQueue queue;
	int threadContexts;
	bool terminated;
	bool hasCallstacks;
	int callstackFrames;
	tracy::WelcomeMessage welcome;
	PacketList* activeCallstackList;
	int64_t timer;
	int64_t timerSerial;
};

struct BroadcastClient
{
	uint64_t id;
	uint64_t pid;
	uint32_t protoVer;
	char addr[17];
	uint16_t listenPort;
	char name[tracy::WelcomeMessageProgramNameSize];
};

bool serverConnection = false;
std::optional<tracy::WelcomeMessage> welcome = std::nullopt;
std::vector<ClientConnection> clientConnections;
std::deque<UnresolvedRequest> unresolvedRequests;
std::deque<UnresolvedRequest> unresolvedPriorityRequests;
PacketQueue outQueue;
uint32_t outActiveThread = 0;
uint64_t topologyClient = 0;

bool IsQueryPrio(tracy::ServerQuery type)
{
	return type < tracy::ServerQuery::ServerQueryDisconnect;
}

std::optional<tracy::WelcomeMessage> execute_server_handshake(tracy::Socket* socket)
{
	socket->Send(tracy::HandshakeShibboleth, tracy::HandshakeShibbolethSize);
	uint32_t protocolVersion = tracy::ProtocolVersion;
	socket->Send(&protocolVersion, sizeof(protocolVersion));

	tracy::HandshakeStatus handshake;
	if (!socket->Read(&handshake, sizeof(handshake), 10))
	{
		std::cout << "Failed to read client handshake status" << std::endl;
		return std::nullopt;
	}

	switch (handshake)
	{
	case tracy::HandshakeWelcome:
		break;
	case tracy::HandshakeProtocolMismatch:
		std::cout << "HandshakeProtocolMismatch" << std::endl;
		return std::nullopt;
	case tracy::HandshakeNotAvailable:
		std::cout << "HandshakeNotAvailable" << std::endl;
		return std::nullopt;
	default:
		std::cout << "Unexpected handshake state" << std::endl;
		return std::nullopt;
	}

	tracy::WelcomeMessage w;
	if (!socket->Read(&w, sizeof(w), 10))
	{
		std::cout << "Failed to read client welcome message" << std::endl;
		return std::nullopt;
	}

	std::cout << "Welcome message:" << std::endl;
	std::cout << "\ttimerMul: " << +w.timerMul << std::endl;
	std::cout << "\tinitBegin: " << +w.initBegin << std::endl;
	std::cout << "\tinitEnd: " << +w.initEnd << std::endl;
	std::cout << "\tdelay: " << +w.delay << std::endl;
	std::cout << "\tresolution: " << +w.resolution << std::endl;
	std::cout << "\tepoch: " << +w.epoch << std::endl;
	std::cout << "\texectime: " << +w.exectime << std::endl;
	std::cout << "\tpid: " << +w.pid << std::endl;
	std::cout << "\tsamplingPeriod: " << +w.samplingPeriod << std::endl;
	std::cout << "\tflags: " << +w.flags << std::endl;
	std::cout << "\tcpuArch: " << +w.cpuArch << std::endl;
	std::cout << "\tcpuId: " << +w.cpuId << std::endl;

	if (w.flags & tracy::WelcomeFlag::OnDemand)
	{
		std::cout << "On demand mode" << std::endl;
		tracy::OnDemandPayloadMessage onDemand;
		if (!socket->Read(&onDemand, sizeof(onDemand), 10))
		{
			std::cout << "Failed to read on demand payload" << std::endl;
			return std::nullopt;
		}
	}

	return std::make_optional(w);
}

bool execute_client_handshake(tracy::Socket* socket)
{
	if (!welcome)
	{
		std::cout << "Error: Server does not have a welcome message" << std::endl;
		return false;
	}

	char shibboleth[tracy::HandshakeShibbolethSize];
	auto res = socket->ReadRaw(shibboleth, tracy::HandshakeShibbolethSize, 2000);
	if (!res || memcmp(shibboleth, tracy::HandshakeShibboleth, tracy::HandshakeShibbolethSize) != 0)
	{
		std::cout << "Failed to read handshake magic string" << std::endl;
		return false;
	}

	uint32_t protocolVersion;
	res = socket->ReadRaw(&protocolVersion, sizeof( protocolVersion ), 2000);
	if (!res)
	{
		std::cout << "Failed to read protocol version" << std::endl;
		return false;
	}

	if (protocolVersion != tracy::ProtocolVersion) {
		tracy::HandshakeStatus status = tracy::HandshakeProtocolMismatch;
		socket->Send(&status, sizeof(status));

		std::cout << "Mismatched protocol versions. Multiplexer: " << tracy::ProtocolVersion << "; Server: " << protocolVersion << std::endl;
		return false;
	}

	tracy::HandshakeStatus handshake = tracy::HandshakeWelcome;
	socket->Send(&handshake, sizeof(handshake));

	socket->Send(&welcome.value(), sizeof(welcome.value()));

	return true;
}

bool handle_server_request(tracy::Socket* socket)
{
	tracy::ServerQueryPacket payload;
	if (!socket->Read(&payload, sizeof(payload), 10))
	{
		std::cout << "Server request socket read fail" << std::endl;
		return false;
	}

	if (payload.type == tracy::ServerQueryDisconnect ||
	    payload.type == tracy::ServerQueryTerminate)
	{
		for (auto& connection : clientConnections)
		{
			connection.socket->Send(&payload, tracy::ServerQueryPacketSize);
		}
		return payload.type == tracy::ServerQueryTerminate;
	}

	UnresolvedRequest unresolvedRequest;
	memcpy(&unresolvedRequest.request, &payload, sizeof(payload));
	unresolvedRequest.responses.reserve(clientConnections.size());

	for (auto& connection : clientConnections)
	{
		unresolvedRequest.responses.insert({connection.id, PacketList()});
		connection.socket->Send(&payload, tracy::ServerQueryPacketSize);
	}

	if (IsQueryPrio(payload.type))
	{
		unresolvedPriorityRequests.push_back(std::move(unresolvedRequest));
	}
	else
	{
		unresolvedRequests.push_back(std::move(unresolvedRequest));
	}

	return true;
}

bool receive_client_broadcast(tracy::UdpListen* socket, BroadcastClient* out)
{
	tracy::IpAddress addr;
	size_t msgLen;
	auto msg = socket->Read(msgLen, addr, 0);
	if (!msg) return false;
	if (msgLen < sizeof(uint16_t))
	{
		std::cout << "Received too short broadcast message" << std::endl;
		return false;
	}

	uint16_t broadcastVersion;
	memcpy(&broadcastVersion, msg, sizeof(uint16_t));
	if (broadcastVersion > tracy::BroadcastVersion)
	{
		std::cout << "Received broadcast message with unsupported version: " << broadcastVersion << std::endl;
		return false;
	}

	switch (broadcastVersion)
	{
	case 3:
	{
		if (msgLen > sizeof(tracy::BroadcastMessage))
		{
			std::cout << "Received unexpected size broadcast v2 message" << std::endl;
			return false;
		}
		tracy::BroadcastMessage bm;
		memcpy(&bm, msg, msgLen);
		out->protoVer = bm.protocolVersion;
		strcpy(out->name, bm.programName);
		out->listenPort = bm.listenPort;
		out->pid = bm.pid;
		break;
	}
	case 2:
	{
		if (msgLen > sizeof(tracy::BroadcastMessage_v2))
		{
			std::cout << "Received unexpected size broadcast v2 message" << std::endl;
			return false;
		}
		tracy::BroadcastMessage_v2 bm;
		memcpy(&bm, msg, msgLen);
		out->protoVer = bm.protocolVersion;
		strcpy(out->name, bm.programName);
		out->listenPort = bm.listenPort;
		out->pid = 0;
		break;
	}
	case 1:
	{
		if (msgLen > sizeof(tracy::BroadcastMessage_v1))
		{
			std::cout << "Received unexpected size broadcast v1 message" << std::endl;
			return false;
		}
		tracy::BroadcastMessage_v1 bm;
		memcpy(&bm, msg, msgLen);
		out->protoVer = bm.protocolVersion;
		strcpy(out->name, bm.programName);
		out->listenPort = bm.listenPort;
		out->pid = 0;
		break;
	}
	case 0:
	{
		if (msgLen > sizeof(tracy::BroadcastMessage_v0))
		{
			std::cout << "Received unexpected size broadcast v0 message" << std::endl;
			return false;
		}
		tracy::BroadcastMessage_v0 bm;
		memcpy(&bm, msg, msgLen);
		out->protoVer = bm.protocolVersion;
		strcpy(out->name, bm.programName);
		out->listenPort = 8086;
		out->pid = 0;
		break;
	}
	}

	memcpy(out->addr, addr.GetText(), 17);
	out->id = uint64_t(addr.GetNumber()) | (uint64_t(out->listenPort) << 32);
	return true;
}

uint32_t get_event_size(const tracy::QueueItem& ev, const char*& ptr)
{
	uint32_t result = tracy::QueueDataSize[ev.hdr.idx];

	if (ev.hdr.type == tracy::QueueType::FrameImageData ||
	    ev.hdr.type == tracy::QueueType::SymbolCode ||
	    ev.hdr.type == tracy::QueueType::SourceCode)
	{
		uint32_t sz;
		memcpy(&sz, ptr + result, sizeof(sz));
		result += sizeof(sz) + sz;
	}
	else if (ev.hdr.idx >= (int)tracy::QueueType::StringData ||
	         ev.hdr.type == tracy::QueueType::SingleStringData ||
	         ev.hdr.type == tracy::QueueType::SecondStringData)
	{
		uint16_t sz;
		memcpy(&sz, ptr + result, sizeof(sz));
		result += sizeof(sz) + sz;
	}

	return result;
}

bool handle_client_response(ClientConnection& connection, const tracy::QueueItem* ev, uint32_t sz)
{
	switch (ev->hdr.type)
	{
	case tracy::QueueType::SourceLocation:
		// Order dependant request
		for (auto& req : unresolvedPriorityRequests)
		{
			if (req.request.type != tracy::ServerQuerySourceLocation) continue;
			auto match = req.responses.find(connection.id);
			if (match == req.responses.end()) continue;
			if (!match->second.empty()) continue;

			match->second.append((const uint8_t*)ev, sz);
			match->second.ready = true;
			return true;
		}
		std::cout << "Error: SourceLocation response without matching request" << std::endl;
		return true;
	case tracy::QueueType::CallstackFrameSize:
		connection.hasCallstacks = true;
		for (auto& req : unresolvedRequests)
		{
			if (req.request.type != tracy::ServerQuery::ServerQueryCallstackFrame) continue;
			if (req.request.ptr != ev->callstackFrameSize.ptr) continue;
			auto match = req.responses.find(connection.id);
			if (match == req.responses.end()) continue;
			if (match->second.ready) continue;

			auto imagePtrSz = connection.queue.back();
			match->second.append(imagePtrSz.first, imagePtrSz.second);
			connection.queue.pop_back();

			connection.callstackFrames = ev->callstackFrameSize.size;
			connection.activeCallstackList = &match->second;

			match->second.append((const uint8_t*)ev, sz);
			return true;
		}
		std::cout << "Error: CallstackFrameSize response without matching request: " << ev->callstackFrameSize.ptr << std::endl;
		return true;
	case tracy::QueueType::CallstackFrame:
	{
		if (connection.activeCallstackList == nullptr)
		{
			std::cout << "Error: Unexpected CallstackFrame" << std::endl;
			return true;
		}

		auto namePtrSz = connection.queue[connection.queue.length() - 2];
		auto filePtrSz = connection.queue[connection.queue.length() - 1];

		connection.activeCallstackList->append(namePtrSz.first, namePtrSz.second);
		connection.activeCallstackList->append(filePtrSz.first, filePtrSz.second);

		connection.queue.pop_back();
		connection.queue.pop_back();

		connection.activeCallstackList->append((const uint8_t*)ev, sz);

		connection.callstackFrames--;

		if (connection.callstackFrames == 0)
		{
			connection.activeCallstackList->ready = true;
			connection.activeCallstackList = nullptr;
		}
		return true;
	}
	case tracy::QueueType::SymbolInformation:
		connection.hasCallstacks = true;
		for (auto& req : unresolvedRequests)
		{
			if (req.request.type != tracy::ServerQuery::ServerQuerySymbol) continue;
			if (req.request.ptr != ev->symbolInformation.symAddr) continue;
			auto match = req.responses.find(connection.id);
			if (match == req.responses.end()) break;

			auto filePtrSz = connection.queue.back();
			match->second.append(filePtrSz.first, filePtrSz.second);
			connection.queue.pop_back();

			match->second.append((const uint8_t*)ev, sz);
			match->second.ready = true;
			return true;
		}
		std::cout << "Error: SymbolInformation response without matching request" << std::endl;
		return true;
	case tracy::QueueType::AckSourceCodeNotAvailable:
		for (auto& req : unresolvedRequests)
		{
			if (req.request.type != tracy::ServerQuery::ServerQuerySourceCode) continue;
			if (req.request.ptr != ev->sourceCodeNotAvailable.id) continue;
			auto match = req.responses.find(connection.id);
			if (match == req.responses.end()) break;

			match->second.append((const uint8_t*)ev, sz);
			match->second.ready = true;
			return true;
		}
		std::cout << "Error: AckSourceCodeNotAvailable(" << ev->sourceCodeNotAvailable.id << ") response without matching request" << std::endl;
		return true;
	case tracy::QueueType::AckSymbolCodeNotAvailable:
		for (auto& req : unresolvedRequests)
		{
			if (req.request.type != tracy::ServerQuery::ServerQuerySymbolCode) continue;
			auto match = req.responses.find(connection.id);
			if (match == req.responses.end()) break;
			if (match->second.ready) continue;

			match->second.append((const uint8_t*)ev, sz);
			match->second.ready = true;
			return true;
		}
		std::cout << "Error: AckSourceCodeNotAvailable(" << ev->sourceCodeNotAvailable.id << ") response without matching request" << std::endl;
		return true;
	case tracy::QueueType::AckServerQueryNoop:
		for (auto& req : unresolvedPriorityRequests)
		{
			if (req.request.type != tracy::ServerQueryParameter) continue;
			auto match = req.responses.find(connection.id);
			if (match == req.responses.end()) continue;
			if (match->second.ready) continue;
			if (!match->second.empty()) continue;

			match->second.append((const uint8_t*)ev, sz);
			match->second.ready = true;
			return true;
		}

		for (auto& req : unresolvedRequests)
		{
			switch (req.request.type)
			{
			case tracy::ServerQueryCallstackFrame:
			case tracy::ServerQuerySymbol:
				if (connection.hasCallstacks) continue;
				break;
			case tracy::ServerQueryDataTransfer:
			case tracy::ServerQueryDataTransferPart:
				break;
			default:
				continue;
			}
			auto match = req.responses.find(connection.id);
			if (match == req.responses.end()) continue;
			if (match->second.ready) continue;
			if (!match->second.empty()) continue;

			match->second.append((const uint8_t*)ev, sz);
			match->second.ready = true;
			return true;
		}

		std::cout << "Error: AckServerQueryNoop response without matching request" << std::endl;
		return true;
	default:
		assert(ev->hdr.idx >= (int)tracy::QueueType::StringData);
		for (auto& req : unresolvedPriorityRequests)
		{
			switch (req.request.type)
			{
			case tracy::ServerQuery::ServerQueryString:
			case tracy::ServerQuery::ServerQueryThreadString:
			case tracy::ServerQuery::ServerQueryPlotName:
			case tracy::ServerQuery::ServerQueryFrameName:
			case tracy::ServerQuery::ServerQueryFiberName:
			case tracy::ServerQuery::ServerQuerySourceCode:
			case tracy::ServerQuery::ServerQuerySymbolCode:
			case tracy::ServerQuery::ServerQueryExternalName:
				break;
			default:
				continue;
			}
			if (req.request.ptr != ev->stringTransfer.ptr) continue;
			auto match = req.responses.find(connection.id);
			if (match == req.responses.end()) break;

			match->second.append((const uint8_t*)ev, sz);
			if (req.request.type == tracy::ServerQuery::ServerQueryExternalName)
			{
				match->second.ready = ev->hdr.type == tracy::QueueType::ExternalName;
			}
			else
			{
				match->second.ready = true;
			}
			return true;
		}

		for (auto& req : unresolvedRequests)
		{
			switch (req.request.type)
			{
			case tracy::ServerQuery::ServerQuerySourceCode:
			case tracy::ServerQuery::ServerQuerySymbolCode:
			case tracy::ServerQuery::ServerQueryExternalName:
				break;
			default:
				continue;
			}
			if (req.request.ptr != ev->stringTransfer.ptr) continue;
			auto match = req.responses.find(connection.id);
			if (match == req.responses.end()) break;

			match->second.append((const uint8_t*)ev, sz);
			if (req.request.type == tracy::ServerQuery::ServerQueryExternalName)
			{
				match->second.ready = ev->hdr.type == tracy::QueueType::ExternalName;
			}
			else
			{
				match->second.ready = true;
			}
			return true;
		}

		return false;
	}
}

enum class TimeType {
	None,
	Timestamp,
	Delta,
	SerialDelta,
	ThreadDelta,
};

std::pair<TimeType, int64_t*> get_time_type_and_field(tracy::QueueItem* ev)
{
	switch(ev->hdr.type)
	{
	// Non-serial delta
	case tracy::QueueType::CallstackSample:
	case tracy::QueueType::CallstackSampleContextSwitch:
		return std::make_pair(TimeType::Delta, &ev->callstackSample.time);
	case tracy::QueueType::ContextSwitch:
		return std::make_pair(TimeType::Delta, &ev->contextSwitch.time);
	case tracy::QueueType::ThreadWakeup:
		return std::make_pair(TimeType::Delta, &ev->threadWakeup.time);
	// Serial delta
	case tracy::QueueType::LockWait:
	case tracy::QueueType::LockSharedWait:
		return std::make_pair(TimeType::SerialDelta, &ev->lockWait.time);
	case tracy::QueueType::LockObtain:
	case tracy::QueueType::LockSharedObtain:
		return std::make_pair(TimeType::SerialDelta, &ev->lockObtain.time);
	case tracy::QueueType::LockRelease:
	case tracy::QueueType::LockSharedRelease:
		return std::make_pair(TimeType::SerialDelta, &ev->lockRelease.time);
	case tracy::QueueType::GpuZoneBeginSerial:
	case tracy::QueueType::GpuZoneBeginCallstackSerial:
	case tracy::QueueType::GpuZoneBeginAllocSrcLocSerial:
	case tracy::QueueType::GpuZoneBeginAllocSrcLocCallstackSerial:
		return std::make_pair(TimeType::SerialDelta, &ev->gpuZoneBegin.cpuTime);
	case tracy::QueueType::GpuZoneEndSerial:
		return std::make_pair(TimeType::SerialDelta, &ev->gpuZoneEnd.cpuTime);
	case tracy::QueueType::MemAlloc:
	case tracy::QueueType::MemAllocNamed:
	case tracy::QueueType::MemAllocCallstack:
	case tracy::QueueType::MemAllocCallstackNamed:
		return std::make_pair(TimeType::SerialDelta, &ev->memAlloc.time);
	case tracy::QueueType::MemFree:
	case tracy::QueueType::MemFreeNamed:
	case tracy::QueueType::MemFreeCallstack:
	case tracy::QueueType::MemFreeCallstackNamed:
		return std::make_pair(TimeType::SerialDelta, &ev->memFree.time);
	// Thread delta
	case tracy::QueueType::ZoneBegin:
	case tracy::QueueType::ZoneBeginCallstack:
	case tracy::QueueType::ZoneBeginAllocSrcLoc:
	case tracy::QueueType::ZoneBeginAllocSrcLocCallstack:
		return std::make_pair(TimeType::ThreadDelta, &ev->zoneBegin.time);
	case tracy::QueueType::ZoneEnd:
		return std::make_pair(TimeType::ThreadDelta, &ev->zoneEnd.time);
	case tracy::QueueType::FiberEnter:
		return std::make_pair(TimeType::ThreadDelta, &ev->fiberEnter.time);
	case tracy::QueueType::FiberLeave:
		return std::make_pair(TimeType::ThreadDelta, &ev->fiberLeave.time);
	case tracy::QueueType::PlotDataInt:
	case tracy::QueueType::PlotDataFloat:
	case tracy::QueueType::PlotDataDouble:
		return std::make_pair(TimeType::ThreadDelta, &ev->plotDataInt.time);
	case tracy::QueueType::GpuZoneBegin:
	case tracy::QueueType::GpuZoneBeginCallstack:
	case tracy::QueueType::GpuZoneBeginAllocSrcLoc:
	case tracy::QueueType::GpuZoneBeginAllocSrcLocCallstack:
		return std::make_pair(TimeType::ThreadDelta, &ev->gpuZoneBegin.cpuTime);
	case tracy::QueueType::GpuZoneEnd:
		return std::make_pair(TimeType::ThreadDelta, &ev->gpuZoneEnd.cpuTime);
	// Timestamp
	case tracy::QueueType::FrameMarkMsg:
	case tracy::QueueType::FrameMarkMsgStart:
	case tracy::QueueType::FrameMarkMsgEnd:
		return std::make_pair(TimeType::Timestamp, &ev->frameMark.time);
	case tracy::QueueType::FrameVsync:
		return std::make_pair(TimeType::Timestamp, &ev->frameVsync.time);
	case tracy::QueueType::LockAnnounce:
		return std::make_pair(TimeType::Timestamp, &ev->lockAnnounce.time);
	case tracy::QueueType::LockTerminate:
		return std::make_pair(TimeType::Timestamp, &ev->lockTerminate.time);
	case tracy::QueueType::Message:
	case tracy::QueueType::MessageCallstack:
		return std::make_pair(TimeType::Timestamp, &ev->message.time);
	case tracy::QueueType::GpuNewContext:
		return std::make_pair(TimeType::Timestamp, &ev->gpuNewContext.cpuTime);
	case tracy::QueueType::GpuCalibration:
		return std::make_pair(TimeType::Timestamp, &ev->gpuCalibration.cpuTime);
	case tracy::QueueType::GpuTimeSync:
		return std::make_pair(TimeType::Timestamp, &ev->gpuTimeSync.cpuTime);
	case tracy::QueueType::CrashReport:
		return std::make_pair(TimeType::Timestamp, &ev->crashReport.time);
	case tracy::QueueType::SysTimeReport:
		return std::make_pair(TimeType::Timestamp, &ev->sysTime.time);
	case tracy::QueueType::SysPowerReport:
		return std::make_pair(TimeType::Timestamp, &ev->sysPower.time);
	case tracy::QueueType::HwSampleCpuCycle:
	case tracy::QueueType::HwSampleInstructionRetired:
	case tracy::QueueType::HwSampleCacheReference:
	case tracy::QueueType::HwSampleCacheMiss:
	case tracy::QueueType::HwSampleBranchRetired:
	case tracy::QueueType::HwSampleBranchMiss:
		return std::make_pair(TimeType::Timestamp, &ev->hwSample.time);
	default:
		return std::make_pair(TimeType::None, nullptr);
	}
}

void normalise_time(ClientConnection& connection, tracy::QueueItem* ev)
{
	if (!welcome) return;

	auto eventTypeField = get_time_type_and_field(ev);
	TimeType tType = eventTypeField.first;
	int64_t* field = eventTypeField.second;

	if (tType == TimeType::None) return;

	double mult = connection.welcome.timerMul;
	auto dt = tracy::MemRead<int64_t>(field);

	switch (tType)
	{
	case TimeType::SerialDelta:
		connection.timerSerial += dt * mult;
		dt = connection.timerSerial;
		break;
	case TimeType::Delta:
		connection.timer += dt * mult;
		dt = connection.timer;
		break;
	case TimeType::ThreadDelta:
	case TimeType::Timestamp:
		dt *= mult;
		break;
	case TimeType::None:
		return;
	}

	tracy::MemWrite(field, dt);
}

uint64_t outTimer = 0;
uint64_t outTimerSerial = 0;
void adjust_time(tracy::QueueItem* ev)
{
	if (!welcome) return;

	auto eventTypeField = get_time_type_and_field(ev);
	TimeType tType = eventTypeField.first;
	int64_t* field = eventTypeField.second;

	switch (tType)
	{
	case TimeType::SerialDelta:
	case TimeType::Delta:
		break;
	default:
		return;
	}

	auto t = tracy::MemRead<int64_t>(field);
	int64_t dt;

	switch (tType)
	{
	case TimeType::SerialDelta:
		dt = t - outTimerSerial;
		outTimerSerial = t;
		break;
	case TimeType::Delta:
		dt = t - outTimer;
		outTimer = t;
		break;
	default:
		return;
	}

	tracy::MemWrite(field, dt);
}

bool process_server_query_responses(std::deque<UnresolvedRequest>* queue)
{
	for (auto& req : *queue)
	{
		bool allReady = true;
		for (auto& resp : req.responses)
		{
			if (resp.second.ready) continue;

			ClientConnection* conMatch = nullptr;
			for (auto& con : clientConnections)
			{
				if (con.id != resp.first) continue;
				conMatch = &con;
				break;
			}
			if (conMatch == nullptr)
			{
				req.responses.erase(resp.first);
				continue;
			}

			allReady = false;
			break;
		}
		if (!allReady) break;

		// Are there no responses left?
		if (req.responses.empty())
		{
			// Consider providing default response in this case
			queue->pop_front();
			continue;
		}

		// Is it a named thread?
		if (req.request.type == tracy::ServerQuery::ServerQueryThreadString)
		{
			uint8_t sizeOffset = tracy::QueueDataSize[(int)tracy::QueueType::ThreadName];
			uint8_t strOffset = sizeOffset + sizeof(uint16_t);

			auto genericName = std::to_string(req.request.ptr);
			bool resolved = false;
			for (auto & response : req.responses)
			{
				auto* respStr = response.second.data()->c_str() + strOffset;
				if (strcmp((const char*)respStr, genericName.c_str()) == 0) continue;

				for (uint32_t i=0; i<response.second.length(); ++i)
				{
					auto ptrSz = response.second[i];
					if (((const tracy::QueueItem*)ptrSz.first)->hdr.type == tracy::QueueType::ThreadName)
					{
						// Append thread ID for unique name
						std::basic_string<uint8_t> tmp;
						tmp.reserve(ptrSz.second + 2 + genericName.length());
						tmp.append(ptrSz.first, ptrSz.second);

						uint16_t size;
						memcpy(&size, (const char*)(tmp.data() + sizeOffset), sizeof(size));
						size += 2 + genericName.length();
						memcpy((char*)(tmp.data() + sizeOffset), &size, sizeof(size));

						tmp.push_back('(');
						tmp.append((const uint8_t*)genericName.c_str(), genericName.length());
						tmp.push_back(')');

						outQueue.push(tmp.data(), tmp.length());
					}
					else
					{
						outQueue.push(ptrSz.first, ptrSz.second);
					}
				}


				queue->pop_front();
				resolved = true;
				break;
			}

			if (resolved) continue;
		}

		// Are all responses same?
		bool allSame = true;
		const std::basic_string<uint8_t>* previousResp = nullptr;
		for (auto& resp : req.responses)
		{
			if (previousResp == nullptr)
			{
				previousResp = resp.second.data();
				continue;
			}
			if ((*previousResp) == (*resp.second.data())) continue;
			allSame = false;
			break;
		}
		if (allSame)
		{
			auto& resp = req.responses.begin()->second;
			for (uint32_t i=0; i<resp.length(); ++i)
			{
				auto ptrSz = resp[i];
				outQueue.push(ptrSz.first, ptrSz.second);
			}
			queue->pop_front();
			continue;
		}

		if (req.responses.size() > 2)
		{
			// Is one different?
			PacketList* different = nullptr;
			for (auto resp=req.responses.begin(); resp != req.responses.end(); resp++)
			{
				bool unique = true;
				for (auto other=std::next(resp); other != req.responses.end(); other++)
				{
					if (*resp->second.data() != *other->second.data()) continue;
					unique = false;
					break;
				}

				if (!unique) continue;
				different = &resp->second;
			}

			if (different)
			{
				for (uint32_t i=0; i<different->length(); ++i)
				{
					auto ptrSz = (*different)[i];
					outQueue.push(ptrSz.first, ptrSz.second);
				}
				queue->pop_front();
				continue;
			}
		}

		// Otherwise...

		std::cout << "Error: Can't resolve responses of server request: " << (uint64_t)req.request.type << std::endl;
		for (auto& resp : req.responses)
		{
			std::cout << "Client: " << resp.first << ", response: ";
			const std::basic_string<uint8_t>* s = resp.second.data();
			for (uint8_t ch : *s)
			{
				if (ch < 32) std::cout << "\\" << (uint32_t)ch;
				else std::cout << ch;
			}
			std::cout << std::endl;
		}
		return false;
	}

	return true;
}

int main()
{
	tracy::UdpListen broadListen =
		tracy::UdpListen();
	if (!broadListen.Listen(8086)) {
		std::cout << "Failed to listen to UDP broadcast on port 8086" << std::endl;
		return 1;
	}

	tracy::ListenSocket outListen;
	if (!outListen.Listen(8085, 4)) {
		outListen.Close();
		std::cout << "Failed to listen to TCP port 8085" << std::endl;
		return 1;
	}

	std::cout << "Starting Tracy multiplexer on port 8085" << std::endl <<
		"Listening for client UDP broadcast messages..." << std::endl;

	tracy::Socket *outSock = nullptr;
	OutputBuffer outBuffer;
	auto inCompressed = std::unique_ptr<char[]>(new char[tracy::LZ4Size]);

	for(;;)
	{
		// Accept new client connections
		BroadcastClient client;
		while (receive_client_broadcast(&broadListen, &client))
		{
			bool existingConnection = false;
			for (auto & clientConnection : clientConnections)
			{
				if (clientConnection.id != client.id) continue;
				existingConnection = true;
				break;
			}
			if (existingConnection) continue;

			std::cout << "Connecting to a client:" << std::endl <<
				"\tName: " << client.name << std::endl <<
				"\tID: "  << client.id << std::endl <<
				"\tAddress: " << client.addr << std::endl <<
				"\tPort: " << client.listenPort << std::endl;

			if (tracy::ProtocolVersion != client.protoVer)
			{
				std::cout << "Failed, mismatched protocol versions. Multiplexer: " << tracy::ProtocolVersion << "; Client: " << client.protoVer << std::endl;
				continue;
			}

			ClientConnection connection;
			connection.id = client.id;
			connection.socket = std::make_unique<tracy::Socket>();
			connection.stream = std::unique_ptr<tracy::LZ4_streamDecode_t>(tracy::LZ4_createStreamDecode());
			connection.buffer = std::unique_ptr<char[]>(new char[tracy::TargetFrameSize*3 + 1]);
			connection.bufferOffset = 0;
			connection.queue = PacketQueue();
			connection.threadContexts = 0;
			connection.terminated = false;
			connection.hasCallstacks = false;
			connection.callstackFrames = 0;
			connection.welcome = tracy::WelcomeMessage();
			connection.activeCallstackList = nullptr;
			connection.timer = 0;
			connection.timerSerial = 0;


			if (!connection.socket->ConnectBlocking(client.addr, client.listenPort))
			{
				std::cout << "Failed to connect to the client" << std::endl;
				continue;
			}

			auto optWelcome = execute_server_handshake(connection.socket.get());

			if (!optWelcome)
			{
				std::cout << "Failed to initiate handshake with the client" << std::endl;
				continue;
			}

			optWelcome.value().initBegin = optWelcome.value().timerMul;
			optWelcome.value().initEnd = optWelcome.value().timerMul;

			connection.welcome = optWelcome.value();

			// Steal first client's identity
			if (!welcome)
			{
				welcome = optWelcome;
				welcome->timerMul = 1;
			}

			LZ4_setStreamDecode(connection.stream.get(), nullptr, 0);

			clientConnections.push_back( std::move(connection) );
			std::cout << "Connected to client successfuly" << std::endl << std::endl;
		}

		// Process client sockets
		for (uint32_t idx=0; idx<clientConnections.size(); ++idx)
		{
			auto& connection = clientConnections[idx];
			while (connection.socket->HasData())
			{
				tracy::lz4sz_t lz4sz;
				if (!connection.socket->Read(&lz4sz, sizeof(lz4sz), 10))
				{
					std::cout << "Error: Failed to read client lz4 size" << std::endl;
					clientConnections.erase(clientConnections.begin() + idx);
					break;
				}
				if (!connection.socket->Read(inCompressed.get(), lz4sz, 10))
				{
					std::cout << "Error: Failed to read client lz4 buffer" << std::endl;
					clientConnections.erase(clientConnections.begin() + idx);
					break;
				}

				auto buf = &connection.buffer[connection.bufferOffset];
				auto sz = tracy::LZ4_decompress_safe_continue( connection.stream.get(), inCompressed.get(), buf, lz4sz, tracy::TargetFrameSize);
				assert(sz >= 0);

				connection.bufferOffset += sz;
				if (connection.bufferOffset > tracy::TargetFrameSize * 2) connection.bufferOffset = 0;

				const char* ptr = buf;
				const char* end = ptr + sz;

				while (ptr < end)
				{
					auto ev = (tracy::QueueItem*)ptr;
					auto sz = get_event_size(*ev, ptr);
					ptr += sz;

					switch (ev->hdr.type)
					{
						case tracy::QueueType::Terminate:
							connection.terminated = true;
							break;
						case tracy::QueueType::ThreadContext:
							connection.threadContexts++;
							break;
						case tracy::QueueType::CpuTopology:
							if (topologyClient == connection.id || topologyClient == 0)
							{
								topologyClient = connection.id;
							}
							else
							{
								continue;
							}
							break;
						default:
							break;
					}

					if (handle_client_response(connection, ev, sz))
					{
						continue;
					}

					connection.queue.push((const uint8_t*)ev, sz);
					normalise_time(connection, (tracy::QueueItem*)connection.queue.back().first);
				}
			}
		}

		// Process server query responses
		if (!process_server_query_responses(&unresolvedPriorityRequests)) return 1;
		if (!process_server_query_responses(&unresolvedRequests)) return 1;

		// Schedule client packets
		for (uint32_t idx=0; idx<clientConnections.size(); ++idx)
		{
			auto& con = clientConnections[idx];
			if (con.terminated)
			{
				while (!con.queue.empty())
				{
					auto ptrSz = con.queue.front();
					outQueue.push(ptrSz.first, ptrSz.second);
					con.queue.pop_front();
				}

				clientConnections.erase(clientConnections.begin() + idx);
				continue;
			}

			while (con.threadContexts > 1)
			{
				bool firstThreadContext = true;
				while(true)
				{
					auto ptrSz = con.queue.front();
					auto ev = (const tracy::QueueItem*)ptrSz.first;
					if (ev->hdr.type == tracy::QueueType::ThreadContext
					    && !firstThreadContext)
					{
						break;
					}
					outQueue.push(ptrSz.first, ptrSz.second);
					if (ev->hdr.type == tracy::QueueType::ThreadContext)
					{
						firstThreadContext = false;
					}
					con.queue.pop_front();
				}
				con.threadContexts--;
			}
		}

		// Process server socket
		if (serverConnection)
		{
			// Send data to server
			while (!outQueue.empty())
			{
				auto packet = outQueue.front();
				auto ptr = packet.first;
				auto sz = packet.second;
		        assert( sz <= tracy::TargetFrameSize );

				if (sz > outBuffer.space())
				{
					if (!outBuffer.commit(outSock)) return 1;
				}

				adjust_time((tracy::QueueItem*)ptr);

				outBuffer.append(ptr, sz);
				outQueue.pop_front();
			}

			if (!outBuffer.empty())
			{
				if (!outBuffer.commit(outSock)) return 1;
			}

			// Receive data from server
			while (outSock->HasData())
			{
				if (!handle_server_request(outSock)) return 0;
			}
		}
		else
		{
			if (!outSock) outSock = outListen.Accept();

			if (outSock)
			{
				if (!welcome)
				{
					std::cout << "Error: Multiplexer has no welcome message, launch the first client" << std::endl;
			        std::this_thread::sleep_for( std::chrono::seconds( 1 ) );
			        continue;
				}

				if (!execute_client_handshake(outSock))
				{
					std::cout << "Failed to connect to the server" << std::endl;
					return 1;
				}
				serverConnection = true;
			}
		}

        std::this_thread::sleep_for( std::chrono::milliseconds( 4 ) );
	}

	return 0;
}
