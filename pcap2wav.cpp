/*************************************************************************
2014-10-24 yinli

linux version  pcap2wav:
deal with the pcap file ,change it to the wav file,
according the payload type in the rtp data,using the G711u¡¢G711a¡¢G729 decoder respectively.


two import parameters:(1) source pcap file path and file name  (2)destination path;
all success:retrun 0;
error:error information and retrun -1

***************************************************************************/


#include <iostream>
#include<memory.h>
#include<string>
#include <vector>

#ifdef WIN32
#include <WinSock2.h>
#define S_ISREG(m) (((m) & 0170000) == (0100000))
#define S_ISDIR(m) (((m) & 0170000) == (0040000))
#else
#include<netinet/in.h>       //linux
#endif

#ifndef WIN32
#include <unistd.h>
#else
#include <io.h>
#endif

#include<sys/stat.h>
#include"pcap_header.h"
#include "pcm2wav.h"

#include "typedef.h"
#include "codecParameters.h"
#include "utils.h"
#include "decoder.h"

using namespace std;

//function to compare the ip address
bool compareIP(uint8_t* firstIP,uint8_t* secondIP,int index)
{
	for (int i = 0; i < index; i++) {
		if (firstIP[i] != secondIP[i]) {
			return false;
		}
    }
	return true;
}

//g711u_decoder
int G711_Decode_ulaw(short* pRawData, const unsigned char* pBuffer, int32_t nBufferSize)
{
	for (int i = 0; i < nBufferSize; i++)
	{
		pRawData[i] = pBuffer[i];
		pRawData[i] ^= 0xff;  // u-law has all bits inverted for transmission

		int linear = pRawData[i] & 0x0f;
		linear <<= 3;
		linear |= 0x84;  // Set MSB (0x80) and a 'half' bit (0x04) to place PCM value in middle of range

		uint8_t shift = pRawData[i] >> 4;
		shift &= 7;
		linear <<= shift;

		linear -= 0x84; // Subract uLaw bias

		if (pRawData[i] & 0x80)
			pRawData[i] = -linear;
		else
			pRawData[i] = linear;

	}

	return nBufferSize * 2;
}

 //g711a_decoder
int G711_Decode_alaw(short* pRawData, const unsigned char* pBuffer, int32_t nBufferSize)
{
	for (int i = 0; i < nBufferSize; i++)
	{
		pRawData[i] = pBuffer[i];
		pRawData[i] ^= 0x55;  // A-law has alternate bits inverted for transmission

		uint8_t sign = pRawData[i] & 0x80;
		int linear = pRawData[i] & 0x1f;
		linear <<= 4;
		linear += 8;  // Add a 'half' bit (0x08) to place PCM value in middle of range

		pRawData[i] &= 0x7f;
		if (pRawData[i] >= 0x20)
		{
			linear |= 0x100;  // Put in MSB
			uint8_t shift = (pRawData[i] >> 4) - 1;
			linear <<= shift;
		}

		if (!sign)
			pRawData[i] = -linear;
		else
			pRawData[i] = linear;

	}

	return nBufferSize * 2;
}

int32_t decodeG729(std::vector<int16_t> & dest, const std::vector<unsigned char> & src)
{
	uint8_t inputBuffer[10] = { 0 };
	//create the decoder 
	bcg729DecoderChannelContextStruct* Decoder = NULL;
	Decoder = initBcg729DecoderChannel();    //initialization of the decoder   

	int framesize = 0;
	uint32_t decodesize = 0;
	if (src.size() - decodesize < 8) {
		framesize = 2;
	}
	else {
		framesize = 10;
	}

	while (decodesize < src.size())
	{
		memcpy(inputBuffer, src.data() + decodesize, framesize);
		decodesize += framesize;
		if (src.size() - decodesize < 8) {
			framesize = 2;
		}
		else {
			framesize = 10;
		}


		uint8_t frameErasureFlag1 = 0;
		if ((uint8_t)inputBuffer[0] == 0) //frame has been erased
		{
			frameErasureFlag1 = 1;
		}

		int16_t tempoutpuBuffer[L_FRAME] = { 0 };
		bcg729Decoder(Decoder, inputBuffer, frameErasureFlag1, tempoutpuBuffer);
		dest.insert(dest.end(), tempoutpuBuffer, tempoutpuBuffer + L_FRAME);

	}
	//release decoder
	closeBcg729DecoderChannel(Decoder);
	return dest.size();
}

int main(int argc, char* argv[])
{
	if (argc < 3) {
		printf("please import the correct source file and destination path!!!\n");
		return -1;
	}

	if (access(argv[1], 0) != 0 || access(argv[2], 0) != 0) {
		printf("please import the correct source file and destination path!!!\n");
		return -1;
	}

	struct stat info;
	stat(argv[1], &info);
	if (S_ISDIR(info.st_mode)) {
		printf("please import the correct source file and destination path!!!\n");
		return -1;
	}

	stat(argv[2], &info);
	if (!S_ISDIR(info.st_mode)) {
		printf("please import the correct source file and destination path!!!\n");
		return -1;
	}

	int playtype = 0;
	if (argc >3){
		playtype = stoi(argv[3]);
	}

	std::string strpath = argv[1];

	//get the filename:except the path and the extension 
	std::string strfilename;
#ifdef WIN32
	char split = '\\';
#else
	char split = '/';
#endif
	strfilename = strpath.substr(strpath.rfind(split) + 1);
	strfilename = strfilename.substr(0, strfilename.length() - 5);

	FILE* pFile = fopen(strpath.c_str(), "rb");
	if (pFile == NULL) {
		printf("The pcap file is opened failed!!");
		return -1;
	}

	fseek(pFile, 0, SEEK_END);
	const long iFileLen = ftell(pFile);
	fseek(pFile, 0, SEEK_SET);
	std::vector<char> pcapBuffer(iFileLen, 0);    //set buffer  the same with the file
	fread(pcapBuffer.data(), 1, iFileLen, pFile);   //read FILE to buffer
	fclose(pFile);


	struct __file_header* file_header;
	file_header = (__file_header*)pcapBuffer.data();

	printf("iLinkType:%d\n", file_header->iLinkType);

	int offset_to_ip;     //set  offset_to_ip based on linktype

	switch (file_header->iLinkType)
	{
	case 1:
		offset_to_ip = 14;
		break;
	case 101:
		offset_to_ip = 0;
		break;
	case 113:
		offset_to_ip = 16;
		break;
	default:
		printf("Unknown interface type\n");
		return -1;
	}


	int iNo = 1;

	//to keep the sip IP address
	uint8_t sip_srcaddr[4] = "";
	uint8_t sip_desaddr[4] = "";

	uint8_t buffer1_srcaddr[4] = "";
	uint8_t buffer1_desaddr[4] = "";

	uint8_t buffer2_srcaddr[4] = "";
	uint8_t buffer2_desaddr[4] = "";

	int port_times = 1;

	//to keep the SIP port
	uint16_t sip_srcport;
	uint16_t sip_desport;

	std::vector<unsigned char> pcmBuffer1;
	pcmBuffer1.reserve(iFileLen);
	std::vector<unsigned char> pcmBuffer2;
	pcmBuffer2.reserve(iFileLen);

	//to keep the payload data
	uint8_t  payload_type = 1;

	//////////////////deal with the data packet one by one based on adding the size

	int32_t iIndex = sizeof(struct __file_header);
	while (iIndex < iFileLen)
	{
		struct __pkthdr* data = (__pkthdr*)(pcapBuffer.data() + iIndex);
		iNo++;

		uint8_t* pkt_data = (uint8_t*)data + sizeof(struct __pkthdr);
		struct iphdr* ip_header = (iphdr*)(pkt_data + offset_to_ip);

		if (iNo-1 == 1) {
			//record the first sip IP direction
			memcpy(sip_srcaddr, &ip_header->saddr, 4);
			memcpy(sip_desaddr, &ip_header->daddr, 4);
		}

#pragma region UDP
		/*take the part of UDP out , according the protocol=17*/
		if (ip_header->protocol == 17)
		{

			struct udphdr* udp_header = (udphdr*)((uint8_t*)ip_header + sizeof(struct iphdr));

			uint16_t srcport = htons(udp_header->source_port);
			uint16_t desport = htons(udp_header->dest_port);

			if (port_times == 1)
			{
				sip_srcport = srcport;
				sip_desport = desport;
			}
			port_times++;

			// whether RTP stream or not based on the UDP header information£¬¡ê?the source and destination ports are not sip port or the same ports 
			if (srcport == sip_srcport || desport == sip_desport || srcport == sip_desport || desport == sip_srcport || srcport == desport)
			{
				iIndex = iIndex + sizeof(struct __pkthdr) + data->iPLength;    //read one whole data packet every time
				continue;   //skip to next data packet
			}

		}
#pragma endregion UDP
		/*take the part of TCP out , according the protocol=6*/
#pragma region TCP
		else if (ip_header->protocol == 6)
		{

			struct tcphdr* tcp_header = (tcphdr*)((uint8_t*)ip_header + sizeof(struct iphdr));

			uint16_t srcport = htons(tcp_header->source_port);
			uint16_t desport = htons(tcp_header->dest_port);

			if (port_times == 1){
				sip_srcport = srcport;
				sip_desport = desport;
			}
			port_times++;

			//with tcp,the port has three situations:all are not rtp stream
			if (srcport == sip_srcport || desport == sip_desport || srcport == sip_desport || desport == sip_srcport)   //sip port
			{
				iIndex = iIndex + sizeof(struct __pkthdr) + data->iPLength;    //read one whole data packet every time
				continue;   //skip to next data packet
			}
			else if (srcport == desport)    //UDP hesder port
			{
				iIndex = iIndex + sizeof(struct __pkthdr) + data->iPLength;    //read one whole data packet every time
				continue;   //skip to next data packet
			}
			else    //sip port changed
			{
				iIndex = iIndex + sizeof(struct __pkthdr) + data->iPLength;    //read one whole data packet every time
				continue;
			}
		}
#pragma endregion TCP

		//to keep the rtp IP address
		uint8_t srcaddr[4];
		uint8_t desaddr[4];
		memcpy(srcaddr, &ip_header->saddr, 4);
		memcpy(desaddr, &ip_header->daddr, 4);

		struct udphdr* udp_header = (udphdr*)((uint8_t*)ip_header + sizeof(struct iphdr));
		//delete the RTP header based on the size of the RTP header
		struct rtphdr* rtp_header = (rtphdr*)((uint8_t*)udp_header + sizeof(struct udphdr));


		//////////////////////////take out the payload data//////////////////
		uint8_t* rtp_data = (uint8_t*)rtp_header + sizeof(struct rtphdr);

		if (rtp_header->pt != playtype)     //remove the situation of that the payload_type is 101: the protol is RTP EVENT
		{
			iIndex = iIndex + sizeof(struct __pkthdr) + data->iPLength;
			continue;
		}

		payload_type = rtp_header->pt;    //based on the payload type to decide use which wav head

		if (buffer1_srcaddr[0] == 0) {
			memcpy(buffer1_srcaddr,srcaddr,4);
			memcpy(buffer1_desaddr,desaddr,4);
			memcpy(buffer2_srcaddr,desaddr,4);
			memcpy(buffer2_desaddr,srcaddr,4);
		}
		///////////////delete all header information£¬take out of the payload data,basing on the different IP direction to save file: ip12ip2.pcm  ip22ip1.pcm  input.pcm
		uint32_t datasize = data->iPLength - offset_to_ip - sizeof(iphdr) - sizeof(udphdr) - sizeof(rtphdr);
		if (compareIP(srcaddr, buffer1_srcaddr, 4) && compareIP(desaddr, buffer1_desaddr, 4))
		{
			//when the IP direction is IP12IP2,add the payload data to pcmBuffer1
			uint32_t pos = pcmBuffer1.size();
			pcmBuffer1.resize(pcmBuffer1.size() + datasize, 0);
			memcpy(pcmBuffer1.data() + pos, rtp_data, datasize);
		}
		if (compareIP(srcaddr, buffer2_srcaddr, 4) && compareIP(desaddr, buffer2_desaddr, 4))
		{
			//when the IP direction is iP22IP1,add the payload data to pcmBuffer2
			uint32_t pos = pcmBuffer2.size();
			pcmBuffer2.resize(pcmBuffer2.size() + datasize, 0);
			memcpy(pcmBuffer2.data() + pos, rtp_data, datasize);
		}

		//set the begin position of the next data packet
		iIndex = iIndex + sizeof(struct __pkthdr) + data->iPLength;
	}


	std::string destpath = argv[2];

	std::string strpath1;
	std::string strpath2;
	std::string strpathall;


	if (buffer1_srcaddr[0] == 0 && buffer1_srcaddr[1] == 0 && buffer1_srcaddr[2] == 0 && buffer1_srcaddr[3] == 0 
		&& buffer1_desaddr[0] == 0 && buffer1_desaddr[1] == 0 && buffer1_desaddr[2] == 0 && buffer1_desaddr[3] == 0) {
		memcpy(buffer1_srcaddr,sip_srcaddr,4);
		memcpy(buffer1_desaddr,sip_desaddr,4);
	}

	if (buffer2_srcaddr[0] == 0 && buffer2_srcaddr[1] == 0 && buffer2_srcaddr[2] == 0 && buffer2_srcaddr[3] == 0
		&& buffer2_desaddr[0] == 0 && buffer2_desaddr[1] == 0 && buffer2_desaddr[2] == 0 && buffer2_desaddr[3] == 0) {
		memcpy(buffer2_srcaddr, sip_desaddr, 4);
		memcpy(buffer2_desaddr, sip_srcaddr, 4);
	}

	char buffer[256] = "";
	sprintf(buffer, "%s%s_%d.%d.%d.%d_2_%d.%d.%d.%d.wav", destpath.c_str(), strfilename.c_str(), 
		(int)buffer1_srcaddr[0], (int)buffer1_srcaddr[1], (int)buffer1_srcaddr[2], (int)buffer1_srcaddr[3],
		(int)buffer1_desaddr[0], (int)buffer1_desaddr[1], (int)buffer1_desaddr[2], (int)buffer1_desaddr[3]);
	strpath1 = buffer;
	
	sprintf(buffer, "%s%s_%d.%d.%d.%d_2_%d.%d.%d.%d.wav", destpath.c_str(), strfilename.c_str(), 
		(int)buffer2_srcaddr[0], (int)buffer2_srcaddr[1], (int)buffer2_srcaddr[2], (int)buffer2_srcaddr[3],
		(int)buffer2_desaddr[0], (int)buffer2_desaddr[1], (int)buffer2_desaddr[2], (int)buffer2_desaddr[3]);
	strpath2 = buffer;

	
	sprintf(buffer, "%s%s.wav", destpath.c_str(), strfilename.c_str());
	strpathall = buffer;

	if (pcmBuffer1.size() == 0 && pcmBuffer2.size() == 0)
	{
		return 0;
	}

#pragma  region PCMU
	/* codec G711:pcmu*/
	if (payload_type == 0)      //codec G711:pcmu // add G711 decode
	{
		std::vector<short>pRawData1(pcmBuffer1.size(), 0);
		std::vector<short>pRawData2(pcmBuffer2.size(), 0);
		std::vector<short>pRawDataAll;

		if (pcmBuffer1.size() != 0) {
			int size1 = G711_Decode_ulaw(pRawData1.data(), pcmBuffer1.data(), pcmBuffer1.size());
			pcm2wav(strpath1.c_str(), (unsigned char *)pRawData1.data(), size1, 1, 8000, 16000, 2, 16);
		}

		if (pcmBuffer2.size() != 0) {
			int size2 = G711_Decode_ulaw(pRawData2.data(), pcmBuffer2.data(),pcmBuffer2.size());
			pcm2wav(strpath2.c_str(), (unsigned char*)pRawData2.data(), size2, 1, 8000, 16000, 2, 16);
		}

		if (pRawData1.size() < pRawData2.size())
		{
			pRawDataAll = pRawData2;

			for (uint32_t i = (pRawData2.size() - pRawData1.size()); i < pRawData2.size(); i++)
			{
				pRawDataAll[i] = pRawData2[i] + pRawData1[i - (pRawData2.size() - pRawData1.size())];
			}

			pcm2wav(strpathall.c_str(), (unsigned char *)pRawDataAll.data(), pRawDataAll.size()*2, 1, 8000, 16000, 2, 16);   //different parameter affact the audio

		}
		else if (pRawData1.size() >= pRawData2.size())
		{
			pRawDataAll = pRawData1;
			for (uint32_t i = (pRawData1.size() - pRawData2.size()); i < pRawData1.size(); i++)
			{
				pRawDataAll[i] = pRawData1[i] + pRawData2[i - (pRawData1.size() - pRawData2.size())];
			}

			pcm2wav(strpathall.c_str(), (unsigned char *)pRawDataAll.data(), pRawDataAll.size()*2, 1, 8000, 16000, 2, 16);   //different parameter affact the audio
		}

     }
#pragma endregion PCMU
#pragma region PCMA
	/*  codec G711:pcma*/
	else if (payload_type == 8)     //codec G711:pcma
	{
		std::vector<short>pRawData1(pcmBuffer1.size(), 0);
		std::vector<short>pRawData2(pcmBuffer2.size(), 0);
		std::vector<short>pRawDataAll;

		if (pcmBuffer1.size() != 0) {
			int size1 = G711_Decode_alaw(pRawData1.data(), pcmBuffer1.data(), pcmBuffer1.size());
			pcm2wav(strpath1.c_str(), (unsigned char *)pRawData1.data(), size1, 1, 8000, 16000, 2, 16);
		}

		if (pcmBuffer2.size() != 0) {
			int size2 = G711_Decode_alaw(pRawData2.data(), pcmBuffer2.data(), pcmBuffer2.size());
			pcm2wav(strpath2.c_str(), (unsigned char *)pRawData2.data(), size2, 1, 8000, 16000, 2, 16);
		}

		if (pRawData1.size() < pRawData2.size())
		{
			pRawDataAll = pRawData2;

			for (uint32_t i = (pRawData2.size() - pRawData1.size()); i < pRawData2.size(); i++)
			{
				pRawDataAll[i] = pRawData2[i] + pRawData1[i - (pRawData2.size() - pRawData1.size())];
			}

			pcm2wav(strpathall.c_str(), (unsigned char *)pRawDataAll.data(), pRawDataAll.size() * 2, 1, 8000, 16000, 2, 16);   //different parameter affact the audio

		}
		else if (pRawData1.size() >= pRawData2.size())
		{
			pRawDataAll = pRawData1;
			for (uint32_t i = (pRawData1.size() - pRawData2.size()); i < pRawData1.size(); i++)
			{
				pRawDataAll[i] = pRawData1[i] + pRawData2[i - (pRawData1.size() - pRawData2.size())];
			}

			pcm2wav(strpathall.c_str(), (unsigned char *)pRawDataAll.data(), pRawDataAll.size() * 2, 1, 8000, 16000, 2, 16);   //different parameter affact the audio
		}

	 }
#pragma endregion PCMA

#pragma region G729A
	/* codecG729a*/
	else if (payload_type == 18)   //codecG729a
	{
		std::vector<int16_t> pRawData1;
		pRawData1.reserve(L_FRAME * 1000);
		std::vector<int16_t> pRawData2;
		pRawData2.reserve(L_FRAME * 1000);
		std::vector<int16_t> pRawDataAll;
		pRawDataAll.reserve(L_FRAME * 1000);

		decodeG729(pRawData1, pcmBuffer1);
		decodeG729(pRawData2, pcmBuffer2);

		pcm2wav(strpath1.c_str(), (unsigned char *)pRawData1.data(), pRawData1.size() * 2, 1, 8000, 16000, 2, 16);
		pcm2wav(strpath2.c_str(), (unsigned char *)pRawData2.data(), pRawData2.size() * 2, 1, 8000, 16000, 2, 16);
		
		if (pRawData1.size() < pRawData2.size())
		{
			pRawDataAll = pRawData2;

			for (uint32_t i = (pRawData2.size() - pRawData1.size()); i < pRawData2.size(); i++)
			{
				pRawDataAll[i] = pRawData2[i] + pRawData1[i - (pRawData2.size() - pRawData1.size())];
			}

			pcm2wav(strpathall.c_str(), (unsigned char *)pRawDataAll.data(), pRawDataAll.size() * 2, 1, 8000, 16000, 2, 16);   //different parameter affact the audio

		}
		else if (pRawData1.size() >= pRawData2.size())
		{
			pRawDataAll = pRawData1;
			for (uint32_t i = (pRawData1.size() - pRawData2.size()); i < pRawData1.size(); i++)
			{
				pRawDataAll[i] = pRawData1[i] + pRawData2[i - (pRawData1.size() - pRawData2.size())];
			}

			pcm2wav(strpathall.c_str(), (unsigned char *)pRawDataAll.data(), pRawDataAll.size() * 2, 1, 8000, 16000, 2, 16);   //different parameter affact the audio
		}
		
	}
#pragma endregion G729
     return 0;
}
 


