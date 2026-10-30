#include "live_pcap_reader.h"
#include <iostream>
#include <cstring>
#include <chrono>

namespace PacketAnalyzer {

LivePcapReader::LivePcapReader() : handle_(nullptr) {
    std::memset(&global_header_, 0, sizeof(global_header_));
}

LivePcapReader::~LivePcapReader() {
    close();
}

bool LivePcapReader::open(const std::string& device) {
    close();

    char errbuf[PCAP_ERRBUF_SIZE];
    
    // Open the device in promiscuous mode, 65535 snaplen, 1000ms timeout
    handle_ = pcap_open_live(device.c_str(), 65535, 1, 1000, errbuf);
    
    if (handle_ == nullptr) {
        std::cerr << "Error: Could not open device " << device << ": " << errbuf << std::endl;
        return false;
    }

    // Check link-layer header type
    int datalink = pcap_datalink(handle_);
    // Most likely it's DLT_EN10MB (Ethernet) or DLT_NULL (Loopback on BSD/macOS)
    
    // Construct a mock global header
    global_header_.magic_number = 0xa1b2c3d4;
    global_header_.version_major = 2;
    global_header_.version_minor = 4;
    global_header_.thiszone = 0;
    global_header_.sigfigs = 0;
    global_header_.snaplen = 65535;
    
    // Map DLT to PCAP network type (1 = Ethernet)
    // In libpcap DLT_EN10MB is 1. We just use the DLT directly.
    global_header_.network = datalink;

    std::cout << "Opened live capture on device: " << device << std::endl;
    std::cout << "  Link type: " << global_header_.network << std::endl;

    return true;
}

void LivePcapReader::close() {
    if (handle_) {
        pcap_close(handle_);
        handle_ = nullptr;
    }
}

bool LivePcapReader::readNextPacket(RawPacket& packet) {
    if (!handle_) {
        return false;
    }

    struct pcap_pkthdr* header;
    const u_char* data;
    int res = pcap_next_ex(handle_, &header, &data);

    if (res == 1) {
        // Read successful
        packet.header.ts_sec = header->ts.tv_sec;
        packet.header.ts_usec = header->ts.tv_usec;
        packet.header.incl_len = header->caplen;
        packet.header.orig_len = header->len;
        
        packet.data.assign(data, data + header->caplen);
        return true;
    } else if (res == 0) {
        // Timeout expired, no packet available right now
        // We can just sleep/retry, but for a blocking read it's best to retry immediately or return false
        // returning false will end the loop, so we should actually wait for the packet if it's a live capture.
        // Wait, pcap_next_ex returning 0 means timeout. If we return false, the loop might terminate.
        // Let's retry internally until we get a packet, an error, or EOF.
        // But we shouldn't loop indefinitely without yielding.
        // Let's use a retry loop.
        while (res == 0) {
            res = pcap_next_ex(handle_, &header, &data);
            if (res == 1) {
                packet.header.ts_sec = header->ts.tv_sec;
                packet.header.ts_usec = header->ts.tv_usec;
                packet.header.incl_len = header->caplen;
                packet.header.orig_len = header->len;
                packet.data.assign(data, data + header->caplen);
                return true;
            }
        }
    }

    if (res == -1) {
        std::cerr << "Error reading packet: " << pcap_geterr(handle_) << std::endl;
    }
    
    // EOF or error
    return false;
}

} // namespace PacketAnalyzer
