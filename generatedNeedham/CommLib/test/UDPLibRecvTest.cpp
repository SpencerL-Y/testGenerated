#include "../NetComm/include/UDPReceiver.hpp"

int main(){
    UDPReceiver receiver;
    u_char* dst = (u_char*)malloc(1000*sizeof(u_char));
    receiver.receivePacket("210.77.2.231", 8888);
    dst = receiver.getDstData();
    std::cout << "data receive: " << dst << std::endl;
    return 0;
}