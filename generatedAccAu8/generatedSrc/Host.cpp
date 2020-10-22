#include "../generatedHeader/Host.h"
static void dataHandlerHostreceive(u_char* param, const struct pcap_pkthdr* header, const u_char* packetData){
	ether_header* eh;
	eh = (ether_header*)packetData;
	/*Configure your own protocol number of ethernet frame*/
	
	if(ntohs(eh->type) == 0x888f){
		int* length = (int*)((char*)packetData + sizeof(ether_header));
		int converted_length = ntohl(*length);
		std::cout << "enter loop condition: length " << converted_length  << std::endl;
		if(tempDataHost != NULL){
			free(tempDataHost);
		}
		tempDataHost = (char*)malloc(sizeof(char)*(converted_length));
		memcpy(tempDataHost, ((char*)packetData + sizeof(ether_header) + sizeof(int)),  converted_length);
		std::cout << "loop break" << std::endl;
		tempDataHostStr = tempDataHost;
		pcap_breakloop(devHost);
		std::cout << "loop break over" << std::endl;
		return;
	}
}
int Host::receive(ByteVec msg){
	/*Configure your own implementation of length_*/
	int length_ = 0;
	u_char* data_ = (u_char*)malloc(length_*sizeof(u_char));
	u_char* dst_;	/*Add MAC Address here*/
	ushort mac[6];
	EtherReceiver er;
	pcap_if_t* dev = er.getDevice();
	char errbuf[500];
	pcap_t* selectedAdp = pcap_open_live(dev->name, 65536, 1, 1000, errbuf);
	devHost = selectedAdp;
	/*Add self defined dataHandler to handle data received*/
	/*parameters: u_char* param, const struct pcap_pkthdr* header, const u_char* packetData*/
	er.listenWithHandler(devHost, dataHandlerHostreceive, data_);
	/*Add your own data processing logic here*/
	free(data_);
	int result;
	return result;

}
int Host::send(ByteVec msg){
	/*Configure your own implementation of length_*/
	std::string data = msg.getData();

	u_char* data_ = (u_char*)malloc(data.size()*sizeof(u_char));
	memcpy(data_, data.c_str(), data.size());
	ushort mac[6];
	for(int i = 0; i < 6; i++){
		mac[i] = 0x11;
	}
	EtherSender snd(mac);
	snd.getDevice();
	/*add your identifier of the sender*/
	std::cout << "send ether broadcast" << std::endl;
	int success =snd.sendEtherBroadcast(data_, data.size());
	free(data_);
	int result;
	return result;

}
ByteVec Host::SymEnc(ByteVec msg, int key){
ByteVec result;
	return result;

}
ByteVec Host::SymDec(ByteVec msg, int key){
ByteVec result;
	return result;

}
ByteVec Host::Sign(ByteVec msg, int skey){
	Signature sig;
	memset(sig.sig,  0, 128);
	return sig;

}
bool Host::Verify(ByteVec msg, int pkey){
bool result;
	return true;

}
void Host::SMLMainHost(){
	while(__currentState != -100) {
		switch(__currentState){
			case STATE___init:{
				std::cout << "--------------------STATE___init" << std::endl;
				
					authReqMsg.head.msgType = 2;
					authReqMsg.head.timeStamp.time = 1;
					authReqMsg.host = hostId;
					authReqMsg.gateway = gateway;
					std::cout << "sign" << std::endl;
					authReqMsg.signature = Sign(authReqMsg,hostIdSk);
					std::cout << "sign over" << std::endl;
				__currentState = STATE__reqMsgCreated;
				
				break;}
			case STATE___final:{
				__currentState = -100;
				std::cout << "--------------------STATE___final" << std::endl;
				break;}
			case STATE__reqMsgCreated:{
				std::cout << "--------------------STATE__reqMsgCreated" << std::endl;
					std::ostringstream reqMsgCreatedOs;
					boost::archive::text_oarchive reqMsgCreateOA(reqMsgCreatedOs);
					reqMsgCreateOA << authReqMsg;
					SendStr sendStr;
					sendStr.data = reqMsgCreatedOs.str();
					std::cout << "send: " << sendStr.data << std::endl;
					send(sendStr);
				__currentState = STATE__reqSent;
				
				break;}
			case STATE__reqSent:{
				std::cout << "--------------------STATE__reqSent" << std::endl;
				
					receive(authQueMsg);


				std::cout << "authQueMsg packet received" << std::endl;
				std::istringstream reqSentIs(tempDataHostStr);
				boost::archive::text_iarchive reqSentIA(reqSentIs);
				reqSentIA >> authQueMsg;
				__currentState = STATE__queRecieved;
				
				break;}
			case STATE__queRecieved:{
				std::cout << "--------------------STATE__queRecieved" << std::endl;
				if(!Verify(authQueMsg,serverPk)){
				__currentState = STATE__verifyAuthQueFailed;
				}
				else if(Verify(authQueMsg,serverPk)){
					nonce = authQueMsg.nonce;
					queRespMsg.head.msgType = 5;
					queRespMsg.head.timeStamp.time = authQueMsg.head.timeStamp.time+1;
					queRespMsg.nonce = nonce;
					queRespMsg.host = hostId;
					queRespMsg.signature = Sign(queRespMsg,hostIdSk);
				__currentState = STATE__queRespCreated;
				}
				break;}
			case STATE__queRespCreated:{
				std::cout << "--------------------STATE__queRespCreated" << std::endl;
					SendStr sndmsg;
					std::ostringstream queRespCreatedOs;
					boost::archive::text_oarchive queRespCreatedOA(queRespCreatedOs);
					queRespCreatedOA << queRespMsg;
					sndmsg.data = queRespCreatedOs.str();
					send(sndmsg);
				__currentState = STATE__queRespSent;
				
				break;}
			case STATE__verifyAuthQueFailed:{
				std::cout << "--------------------STATE__verifyAuthQueFailed" << std::endl;
				
				__currentState = STATE___final;
				
				break;}
			case STATE__queRespSent:{
				std::cout << "--------------------STATE__queRespSent" << std::endl;
				
					receive(authRespMsg);
				__currentState = STATE__respRecved;
				
				break;}
			case STATE__respRecved:{
				std::cout << "--------------------STATE__respRecved" << std::endl;
				if(Verify(authRespMsg,serverPk)){
					hostIp = authRespMsg.hostIp;
					//hostIpSk = SymDec(authRespMsg.secHostIpSk,hostIdSk);
				__currentState = STATE___final;
				}
				else if(!Verify(authRespMsg,serverPk)){
				__currentState = STATE__verifyAuthRespFailed;
				}
				break;}
			case STATE__verifyAuthRespFailed:{
				std::cout << "--------------------STATE__verifyAuthRespFailed" << std::endl;
				
				__currentState = STATE___final;
				
				break;}
			default: break;
		}
	}
}

