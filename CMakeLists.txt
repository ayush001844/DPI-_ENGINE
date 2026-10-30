cmake_minimum_required(VERSION 3.16)
project(PacketAnalyzer VERSION 1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Source files
set(SOURCES
    src/main.cpp
    src/pcap_reader.cpp
    src/live_pcap_reader.cpp
    src/packet_parser.cpp
)

# Header files location
include_directories(${CMAKE_SOURCE_DIR}/include)

# Create the executables
add_executable(packet_analyzer ${SOURCES})

# DPI Engine multi-threaded
set(DPI_SOURCES
    src/dpi_mt.cpp
    src/pcap_reader.cpp
    src/live_pcap_reader.cpp
    src/packet_parser.cpp
    src/sni_extractor.cpp
    src/types.cpp
)
add_executable(dpi_engine ${DPI_SOURCES})

# Link libpcap
target_link_libraries(packet_analyzer pcap)
target_link_libraries(dpi_engine pcap pthread)

# For macOS, we might need to link against system libraries later
if(APPLE)
    # Add any macOS-specific settings here
endif()
