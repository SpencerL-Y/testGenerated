#ifndef EtherSender_hpp
#define EtherSender_hpp


#include <stdlib.h>
#include <iostream>
#include <memory.h>
#include <pcap.h>
#include <string>
#include "packet.hpp"
class EtherSender
{
private:
    /* data */
    ushort smac[6];
public:
    int sendEtherBroadcast(u_char* data, int length, int identify);
    int sendEtherPacketWithDevice(u_char* data, int length, int identify,  ushort dmac[6], char* if_name, pcap_if_t* selectedIf);
    pcap_if_t* getDevice();
    ushort* getSmac();
    EtherSender(ushort smac[6]);
    ~EtherSender();
};

#endif