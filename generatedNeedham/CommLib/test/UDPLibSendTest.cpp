#include "../NetComm/include/UDPSender.hpp"

int main(){
    UDPSender sender;
    std::string data = "what the f**k";
    sender.sendPacket((u_char*)data.c_str(), data.length(), "210.77.2.231", 8888);
    std::cout << "send over" << std::endl;
    return 0;
}