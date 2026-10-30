#ifndef LIVE_PCAP_READER_H
#define LIVE_PCAP_READER_H

#include "ipacket_reader.h"
#include <string>
#include <pcap.h>

namespace PacketAnalyzer {

class LivePcapReader : public IPacketReader {
public:
    LivePcapReader();
    ~LivePcapReader() override;

    // Open a live interface for reading
    bool open(const std::string& device);
    
    // Close the interface
    void close();
    
    // Read the next packet, returns false on error or EOF
    bool readNextPacket(RawPacket& packet) override;
    
    // Get the mock global header info
    const PcapGlobalHeader& getGlobalHeader() const override { return global_header_; }
    
    // Check if device is open
    bool isOpen() const { return handle_ != nullptr; }

private:
    pcap_t* handle_;
    PcapGlobalHeader global_header_;
};

} // namespace PacketAnalyzer

#endif // LIVE_PCAP_READER_H
