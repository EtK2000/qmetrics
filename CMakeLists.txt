cmake_minimum_required(VERSION 3.16)
project(sniffer)

set(CMAKE_CXX_STANDARD 20)

find_package(Threads REQUIRED)
add_executable(sniffer main.cpp qmetrics/NetworkHelper.hpp qmetrics/QMetrics.cpp qmetrics/SipParser.cpp)
target_link_libraries(sniffer ${CMAKE_THREAD_LIBS_INIT} pcap)