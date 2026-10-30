#ifndef PCAP_READER_H
#define PCAP_READER_H

#include <cstdint>
#include <string>
#include <vector>
#include <fstream>

#include "ipacket_reader.h"
#include <fstream>

namespace PacketAnalyzer {

// Class to read PCAP files
class PcapReader : public IPacketReader {
public:
    PcapReader() = default;
    ~PcapReader() override;

    // Open a pcap file for reading
    bool open(const std::string& filename);
    
    // Close the file
    void close();
    
    // Read the next packet, returns false if no more packets
    bool readNextPacket(RawPacket& packet) override;
    
    // Get the global header info
    const PcapGlobalHeader& getGlobalHeader() const override { return global_header_; }
    
    // Check if file is open
    bool isOpen() const { return file_.is_open(); }
    
    // Check if we need to swap byte order
    bool needsByteSwap() const { return needs_byte_swap_; }

private:
    std::ifstream file_;
    PcapGlobalHeader global_header_;
    bool needs_byte_swap_ = false;
    
    // Helper to swap bytes if needed
    uint16_t maybeSwap16(uint16_t value);
    uint32_t maybeSwap32(uint32_t value);
};

} // namespace PacketAnalyzer

#endif // PCAP_READER_H
