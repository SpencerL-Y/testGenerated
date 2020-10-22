#include "../include/EtherSender.hpp"
pcap_if_t* EtherSender::getDevice()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    char *if_name = pcap_lookupdev(errbuf);
    pcap_if_t* selectedIf = nullptr;
    pcap_if_t* alldevs;
    pcap_if_t* d;
    pcap_findalldevs(&alldevs, errbuf);
    for(d = alldevs; d; d = d->next)
    {
        if(!strcmp(if_name, d->name))
        {
            selectedIf = d;
            break;
        }
    }
    return selectedIf;
}
int EtherSender::sendEtherBroadcast(u_char* data, int length, int identify)
{
    
    std::cout << "here" << std::endl;
    char errbuf[PCAP_ERRBUF_SIZE];
    std::cout << "lookup " << std::endl;
    char* if_name = pcap_lookupdev(errbuf);
    std::cout << "lookup end" << std::endl;
    ushort dmac[6];
    for(int i = 0; i < 6; i ++)
    {
        dmac[i] = 0xff;
    }
    std::cout << "getDevice" << std::endl;
    pcap_if_t* selectedIf = this->getDevice();
    std::cout << "getDevice end" << std::endl;
    std::cout << "sendEtherPacket" << std::endl;
    int result = this->sendEtherPacketWithDevice(data, length, identify, dmac, if_name, selectedIf);
    std::cout << "sendEtherPacket end" << std::endl;
    return result;
}
EtherSender::EtherSender(ushort smac[6])
{
    memcpy(this->smac, smac, 6);
}


EtherSender::~EtherSender()
{

}
int EtherSender::sendEtherPacketWithDevice(u_char* data, int length, int identify, ushort dmac[6], char* if_name, pcap_if_t* selectedIf)
{
    
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* selectedAdp = pcap_open_live(if_name, 65536, 1, 1000, errbuf);
    ether_header eh;
	for (int i = 0; i < 6; i++) {
		eh.h_dest[i] = dmac[i];
		// set to broadcast
		eh.h_source[i] = this->getSmac()[i];
	}
    if(selectedAdp == nullptr){
        std::cout << "No device selected" << std::endl;
    }
	eh.type = htons(0x888f);
    char sndBuf[1000];
	int index = 0;
	memcpy(sndBuf, &eh, sizeof(eh));
	index = sizeof(eh);
    int res_length = htonl((length + sizeof(int)));
    memcpy(&sndBuf[index], &res_length, sizeof(int));
    index += sizeof(res_length);
    int id = htonl(identify);
    memcpy(&sndBuf[index], &id, sizeof(int));
    index += sizeof(id);
	memcpy(&sndBuf[index], data, length);
	index += length;
    std::cout << "Send ether packet: " << "length = " << length << ", from = " << smac << ", to = " << dmac << std::endl;
    return pcap_sendpacket(selectedAdp, (u_char*)sndBuf, index);
}



ushort* EtherSender::getSmac()
{
    return this->smac;
}


