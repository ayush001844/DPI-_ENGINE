#ifndef IPACKET_READER_H
#define IPACKET_READER_H

#include <cstdint>
#include <string>
#include <vector>

namespace PacketAnalyzer {

// PCAP Global Header (24 bytes)
struct PcapGlobalHeader {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
};

// PCAP Packet Header (16 bytes)
struct PcapPacketHeader {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
};

// Represents a single captured packet
struct RawPacket {
    PcapPacketHeader header;
    std::vector<uint8_t> data;
};

// Interface for reading packets
class IPacketReader {
public:
    virtual ~IPacketReader() = default;
    
    // Read the next packet, returns false if no more packets
    virtual bool readNextPacket(RawPacket& packet) = 0;
    
    // Get the global header info
    virtual const PcapGlobalHeader& getGlobalHeader() const = 0;
};

} // namespace PacketAnalyzer

#endif // IPACKET_READER_H
