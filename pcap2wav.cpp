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
#include<stdio.h>
#include<memory.h>
#include<stdlib.h>
#include<math.h>
#include<string>

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
int compareIP(uint8_t* firstIP,uint8_t* secondIP,int index)
{
    for(int i =0;i<=index;i++)
    {
        if(firstIP[i] == secondIP[i])
        {
           if(i == index)
            {
             return 1;
            }
           continue;
        }
        else
        {
            return 0;
        }
        
    }
	return 1;
}

//g711u_decoder
 int G711_Decode_ulaw(short* pRawData,const unsigned char* pBuffer,int32_t nBufferSize)
	{

	 for(int i=0; i<nBufferSize; i++)   
     {  
	  
      pRawData[i] = pBuffer[i];  

	  pRawData[i] ^= 0xff;  // u-law has all bits inverted for transmission

	int linear = pRawData[i]&0x0f;
	linear <<= 3;
	linear |= 0x84;  // Set MSB (0x80) and a 'half' bit (0x04) to place PCM value in middle of range

	uint8_t shift = pRawData[i]>>4;
	shift &= 7;
	linear <<= shift;

	linear -= 0x84; // Subract uLaw bias

	if(pRawData[i]&0x80)
		pRawData[i] = -linear;
	else
		pRawData[i] = linear;
	
     }   
	
     return nBufferSize*2;
	}

 //g711a_decoder
 int G711_Decode_alaw(short* pRawData,const unsigned char* pBuffer,int32_t nBufferSize)
 {
	
	for(int i=0; i<nBufferSize; i++)   
    {  

      pRawData[i] = pBuffer[i];  
	  pRawData[i] ^= 0x55;  // A-law has alternate bits inverted for transmission

	  uint8_t sign = pRawData[i]&0x80;
	  int linear = pRawData[i]&0x1f;
	  linear <<= 4;
	  linear += 8;  // Add a 'half' bit (0x08) to place PCM value in middle of range

	  pRawData[i] &= 0x7f;
	  if(pRawData[i]>=0x20)
	  {
		linear |= 0x100;  // Put in MSB
		uint8_t shift = (pRawData[i]>>4)-1;
		linear <<= shift;
	   }

	  if(!sign)
		pRawData[i] = -linear;
	  else
		pRawData[i] = linear;

    }   

	return nBufferSize*2; 
 }


int main(int argc,char* argv[])

{

      if(argc!=3)
     {
       printf("please import the correct source file and destination path!!!\n");
       return -1;
     }

     if(access(argv[1],0)!=0 || access(argv[2],0)!=0)
      {
        printf("please import the correct source file and destination path!!!\n");
        return -1;
       }

        struct stat info;
         stat(argv[1],&info);
         if(S_ISDIR(info.st_mode))
           {
             printf("please import the correct source file and destination path!!!\n");
             return -1;
            }
         stat(argv[2],&info);
         if(!S_ISDIR(info.st_mode))
           {
             printf("please import the correct source file and destination path!!!\n");
             return -1;
            }  

     struct __pkthdr* data;

	 const char *strpath = argv[1];  

	//get the filename:except the path and the extension 
	char *strfilename = new char[251]();
        int strpath_size = strlen(strpath);
	int lastsplit_position = 0;
	for(int i = strpath_size;i>=0;i--)
	{
        char strpath_letter = strpath[i];
#ifdef WIN32
		char split = '\\';
#else
		char split = '/';
#endif
		if (strpath_letter == split)
		{
			lastsplit_position = i;
			lastsplit_position++;
			break;
		}
	}
	memcpy(strfilename,(char*)strpath+lastsplit_position,strpath_size-lastsplit_position-5);

	
    FILE* pFile = fopen(strpath,"rb");
    if( pFile ==NULL)
    {
        printf( "The pcap file is opened failed!!");
        return -1;
    }

    fseek( pFile, 0, SEEK_END);
    const long iFileLen = ftell( pFile);
    fseek( pFile, 0, SEEK_SET);
    char* pBuffer = (char*)malloc( iFileLen);    //set buffer  the same with the file
    fread( (void*)pBuffer, 1, iFileLen, pFile);   //read FILE to buffer
    fclose( pFile);
  
    int32_t iIndex = sizeof(struct __file_header);

    struct __file_header* file_header;
	file_header=(__file_header*)pBuffer;

  //  printf("%d\n",file_header->iLinkType);
	
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

	//to keep the rtp IP address
    uint8_t srcaddr[4] = "";
    uint8_t desaddr[4] = "";
	 
    int ip_times = 1;
	int port_times = 1;

 //to keep the SIP port
	uint16_t sip_srcport;
	uint16_t sip_desport;

//    int offset_to_ip=16;     //set  offset_to_ip based on linktype
    int ipsize = sizeof(struct iphdr);   
    int udpsize = sizeof(struct udphdr);
    int rtpsize = sizeof(struct rtphdr);

    uint8_t pkt_data1[10240] = "";
	uint8_t rtp_data1[200] = "";
	uint8_t* pkt_data = pkt_data1 ;
	uint8_t* rtp_data  = rtp_data1;

    uint8_t  payload_type = 1;
	uint8_t final_payloadtype =1;
    //count the num of the session in defined ip address direction
  
    int block_count1 = 0;
    int block_count2 = 0;
	int payloadlen1 = 0 ;
	int payloadlen2 = 0;

	 //to keep the payload data
    char* pcmBuffer1 = new char[iFileLen]();
    char* pcmBuffer2 = new char[iFileLen]();
  

	//////////////////deal with the data packet one by one based on adding the size
    while(iIndex < iFileLen)     
    {
    
        data = (__pkthdr*)(pBuffer + iIndex);
       
		iNo++;
        int cursession_num = iNo-1;
    
        int32_t rtpFileLen = sizeof(struct __pkthdr) + data->iPLength;   //the whole size of the data packet
        //////////////////////////////separate the information of every block from the pcap data packet//////////////////////
       
		pkt_data = (uint8_t*)pBuffer + iIndex +sizeof(struct __pkthdr);
		struct iphdr* ip_header;
        ip_header = (iphdr*)(pkt_data+offset_to_ip);
   
		if (cursession_num == 1)
		{
			//record the first sip IP direction

			for (int i = 0; i <= 3; i++)
			{
				sip_srcaddr[i] = pkt_data[offset_to_ip + 12 + i];
				sip_desaddr[i] = pkt_data[offset_to_ip + 16 + i];
			}
		}
        
     /*take the part of UDP out , according the protocol=17*/   
		if (ip_header->protocol == 17)
		{

			struct udphdr* udp_header;
			udp_header = (udphdr*)(pkt_data + offset_to_ip + ipsize);

			uint16_t srcport = htons(udp_header->source_port);
			uint16_t desport = htons(udp_header->dest_port);

			if (port_times == 1)
			{
				sip_srcport = srcport;
				sip_desport = desport;
			}
			port_times++;

			uint16_t udplen = htons(udp_header->len);
			// whether RTP stream or not based on the UDP header information£¬¡ê?the source and destination ports are not sip port or the same ports 
			if (srcport == sip_srcport || desport == sip_desport || srcport == sip_desport || desport == sip_srcport || srcport == desport)
			{

				iIndex = iIndex + sizeof(struct __pkthdr) + data->iPLength;    //read one whole data packet every time
				continue;   //skip to next data packet
			}
			//delete the RTP header based on the size of the RTP header
			struct rtphdr* rtp_header;
			rtp_header = (rtphdr*)(pkt_data + offset_to_ip + ipsize + udpsize);

			payload_type = rtp_header->pt;    //based on the payload type to decide use which wav head

			uint16_t tempsequence_number;
			if (cursession_num >= 5)
			{
				tempsequence_number = htons(rtp_header->sequence_number);    //have been tested:right

			}

			//////////////////////////take out the payload data//////////////////
			rtp_data = (uint8_t*)rtp_header + rtpsize;


		}
	    /*take the part of TCP out , according the protocol=6*/
		else if (ip_header->protocol == 6)
		{

			struct tcphdr* tcp_header;
			tcp_header = (tcphdr*)(pkt_data + offset_to_ip + ipsize);

			uint16_t srcport = htons(tcp_header->source_port);
			uint16_t desport = htons(tcp_header->dest_port);

			if (port_times == 1)
			{
				sip_srcport = srcport;
				sip_desport = desport;
			}
			port_times++;

			uint16_t tcplen = htons(tcp_header->hdr_len);

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

		//record the first rtp IP direction
		uint8_t ip1[4];
        uint8_t ip2[4];
        
        for(int i = 0;i<=3;i++)
        {
         ip1[i] = pkt_data[offset_to_ip+12+i];    
         ip2[i] = pkt_data[offset_to_ip+16+i];    
        }
    /////////record the first ip information ,to distiguish the payload data
        if (ip_times == 1)
        {
            for (int i=0;i<=3;i++)
            {
               srcaddr[i] = ip1[i];
               desaddr[i] = ip2[i];
            }  
        }
       ip_times++;
	     
	   if(/*payload_type!=0 && payload_type!=8 && */payload_type!=18)     //remove the situation of that the payload_type is 101: the protol is RTP EVENT
	   {
		   iIndex = iIndex + sizeof(struct __pkthdr) + data->iPLength; 
		   continue;
	   }
	   else
	   {
		   final_payloadtype = payload_type;
	   }

 ///////////////delete all header information£¬take out of the payload data,basing on the different IP direction to save file: ip12ip2.pcm  ip22ip1.pcm  input.pcm
        if( compareIP(srcaddr,ip1,3) && compareIP(desaddr,ip2,3))
        {
            //when the IP direction is IP12IP2,add the payload data to pcmBuffer1
           memcpy((pcmBuffer1+payloadlen1),(rtp_data),( data->iPLength - offset_to_ip - ipsize - udpsize -rtpsize));
           payloadlen1 += (data->iPLength - offset_to_ip - ipsize - udpsize -rtpsize);
		   block_count1++;            
        }
        if(compareIP(desaddr,ip1,3) && compareIP(srcaddr,ip2,3))
        {
            //when the IP direction is iP22IP1,add the payload data to pcmBuffer2
            memcpy((pcmBuffer2+payloadlen2),(rtp_data),( data->iPLength - offset_to_ip - ipsize - udpsize -rtpsize));
            payloadlen2 += (data->iPLength - offset_to_ip - ipsize - udpsize -rtpsize);
			block_count2++;
        }    
    
        strcpy((char*)pkt_data,"");
        strcpy((char*)rtp_data,"");

        //set the begin position of the next data packet
        iIndex = iIndex + sizeof(struct __pkthdr) + data->iPLength;
    }

	free(pBuffer);
   
	const char *finalpath = argv[2];

	char strpath1[151] = "";
	FILE* pcmfile1;

	char strpath2[151] = "";
	FILE* pcmfile2;

	char strpathall[151] = "";
	FILE* pcmfileall;

	if (srcaddr[0]==0 && srcaddr[1]==0 && srcaddr[2]==0 && srcaddr[3]==0 && desaddr[0]==0 && desaddr[1]==0 && desaddr[2]==0 && desaddr[3]==0 )
	{
		//char strpath1[151] = "";
		sprintf(strpath1,"%s%s_%d.%d.%d.%d2%d.%d.%d.%d.wav",finalpath,strfilename,(int)sip_srcaddr[0],(int)sip_srcaddr[1],(int)sip_srcaddr[2],(int)sip_srcaddr[3],(int)sip_desaddr[0],(int)sip_desaddr[1],(int)sip_desaddr[2],(int)sip_desaddr[3]);
		strpath1[150] = '\0';
		//FILE* pcmfile1 = fopen(strpath1,"wb");
		pcmfile1 = fopen(strpath1,"wb");
		if (pcmfile1==NULL)
		{
			return -1;
		}
		fclose(pcmfile1);

		// char strpath2[151] = "";
		sprintf(strpath2,"%s%s_%d.%d.%d.%d2%d.%d.%d.%d.wav",finalpath,strfilename,(int)sip_desaddr[0],(int)sip_desaddr[1],(int)sip_desaddr[2],(int)sip_desaddr[3],(int)sip_srcaddr[0],(int)sip_srcaddr[1],(int)sip_srcaddr[2],(int)sip_srcaddr[3]);
		strpath2[150] = '\0';
		//FILE* pcmfile2 = fopen(strpath2,"wb");
		pcmfile2 = fopen(strpath2,"wb");
		if (pcmfile2==NULL)
		{
			return -1;
		}
		fclose(pcmfile2);

		// char strpathall[151] = "";
		sprintf(strpathall,"%s%s_all.wav",finalpath,strfilename);
		strpathall[150] = '\0';
		//FILE* pcmfileall = fopen(strpathall,"wb");
		pcmfileall = fopen(strpathall,"wb");
		if (pcmfileall==NULL)
		{
			return -1;
		}
		fclose(pcmfileall);

	}
	else
	{
		//char strpath1[151] = "";
		sprintf(strpath1,"%s%s_%d.%d.%d.%d_2_%d.%d.%d.%d.wav",finalpath,strfilename,(int)srcaddr[0],(int)srcaddr[1],(int)srcaddr[2],(int)srcaddr[3],(int)desaddr[0],(int)desaddr[1],(int)desaddr[2],(int)desaddr[3]);
		strpath1[150] = '\0';
		//FILE* pcmfile1 = fopen(strpath1,"wb");
		pcmfile1 = fopen(strpath1,"wb");
		if (pcmfile1==NULL)
		{
			return -1;
		}
		fclose(pcmfile1);

		//char strpath2[151] = "";
		sprintf(strpath2,"%s%s_%d.%d.%d.%d_2_%d.%d.%d.%d.wav",finalpath,strfilename,(int)desaddr[0],(int)desaddr[1],(int)desaddr[2],(int)desaddr[3],(int)srcaddr[0],(int)srcaddr[1],(int)srcaddr[2],(int)srcaddr[3]);
		strpath2[150] = '\0';
		//FILE* pcmfile2 = fopen(strpath2,"wb");
		pcmfile2 = fopen(strpath2,"wb");
		if (pcmfile2==NULL)
		{
			return -1;
		}
		fclose(pcmfile2);

		//char strpathall[151] = "";
		sprintf(strpathall,"%s%s.wav",finalpath,strfilename);
		strpathall[150] = '\0';
		//FILE* pcmfileall = fopen(strpathall,"wb");
		pcmfileall = fopen(strpathall,"wb");
		if (pcmfileall==NULL)
		{
			return -1;
		}
		fclose(pcmfileall);

	}
	delete [] strfilename;


	if (block_count1==0 && block_count2==0)
	 {
           delete [] pcmBuffer1;
           delete [] pcmBuffer2;	
		   return 0;
	  }

	payload_type = final_payloadtype;

	/* codec G711:pcmu*/
     if(payload_type == 0)      //codec G711:pcmu // add G711 decode
     {
	
	      if (block_count1!=0 && block_count2!=0)
	       {
              
	            int nBufferSize1 = payloadlen1;
	            short* pRawData1 = new short[iFileLen]();
                int size1 = G711_Decode_ulaw(pRawData1, (unsigned char*)pcmBuffer1, nBufferSize1);  
                pcm2wav(strpath1,(char*)pRawData1,size1,1,8000,16000,2,16);
	       
	           int nBufferSize2 = payloadlen2;
	           short* pRawData2 = new short[iFileLen](); 
	        
               int size2 = G711_Decode_ulaw(pRawData2,(unsigned char*)pcmBuffer2, nBufferSize2);
               pcm2wav(strpath2,(char*)pRawData2,size2,1,8000,16000,2,16);
 
	           int sizeall = 0;
	           if (nBufferSize1<nBufferSize2)
	           {
                   for (int i = 0;i<(nBufferSize2-nBufferSize1);i++ )
		           {
			            pRawData2[i] = pRawData2[i];
		            }

		            for (int i =(nBufferSize2-nBufferSize1);i<nBufferSize2;i++ )
		            {
			           pRawData2[i] = pRawData2[i]+ pRawData1[i-(nBufferSize2-nBufferSize1)];
		            }

	                sizeall = size2;
		            pcm2wav(strpathall,(char*)pRawData2,sizeall,1,8000,16000,2,16);   //different parameter affact the audio

	            }
	            else if (nBufferSize1>=nBufferSize2)
	            {
		            for (int i = 0;i<(nBufferSize1-nBufferSize2);i++ )
		            {
			           pRawData1[i] = pRawData1[i];
		            }
			
					
		            for (int i =(nBufferSize1-nBufferSize2);i<nBufferSize1;i++ )     
		            {

			          pRawData1[i] = pRawData1[i]+ pRawData2[i-(nBufferSize1-nBufferSize2)]; 
		              
					}

		            sizeall = size1;
		            pcm2wav(strpathall,(char*)pRawData1,sizeall,1,8000,16000,2,16);   //different parameter affact the audio
	             }
      
	            delete [] pRawData1;
	            delete [] pRawData2;     
	            delete [] pcmBuffer1;
                delete [] pcmBuffer2;	
	         }

		   if(block_count1==0 && block_count2!=0)
	        {

	            
		         int nBufferSize2 = payloadlen2;
	             short* pRawData2 = new short[iFileLen](); 
                 int size2 = G711_Decode_ulaw(pRawData2,(unsigned char*)pcmBuffer2, nBufferSize2);

                  pcm2wav(strpath2,(char*)pRawData2,size2,1,8000,16000,2,16);
		          pcm2wav(strpathall,(char*)pRawData2,size2,1,8000,16000,2,16);
	    
		          delete [] pcmBuffer1;
		          delete [] pRawData2;   
		          delete [] pcmBuffer2;
		
	          }

	         if(block_count1!=0 && block_count2==0)
	          {

	              
		           int nBufferSize1 = payloadlen1;
	               short* pRawData1 = new short[iFileLen](); 
                   int size1 = G711_Decode_ulaw(pRawData1,(unsigned char*)pcmBuffer1, nBufferSize1);

                   pcm2wav(strpath1,(char*)pRawData1,size1,1,8000,16000,2,16);
		           pcm2wav(strpathall,(char*)pRawData1,size1,1,8000,16000,2,16);
	    
		           delete [] pcmBuffer1;
		           delete [] pRawData1;   
		           delete [] pcmBuffer2;	
	            }

     }
 
	/*  codec G711:pcma*/
    else if (payload_type == 8)     //codec G711:pcma
	{      
	       if (block_count1!=0 && block_count2!=0)
	       {
            
	            int nBufferSize1 = payloadlen1;
	            short* pRawData1 = new short[iFileLen]();
                int size1 = G711_Decode_alaw(pRawData1, (unsigned char*)pcmBuffer1, nBufferSize1);  
                pcm2wav(strpath1,(char*)pRawData1,size1,1,8000,16000,2,16);
	        
	           int nBufferSize2 = payloadlen2;
	           short* pRawData2 = new short[iFileLen](); 
	        
               int size2 = G711_Decode_alaw(pRawData2,(unsigned char*)pcmBuffer2, nBufferSize2);
               pcm2wav(strpath2,(char*)pRawData2,size2,1,8000,16000,2,16);
 
	           int sizeall = 0;
	           if (nBufferSize1<nBufferSize2)
	           {
                   for (int i = 0;i<(nBufferSize2-nBufferSize1);i++ )
		           {
			            pRawData2[i] = pRawData2[i];
		            }

		            for (int i =(nBufferSize2-nBufferSize1);i<nBufferSize2;i++ )
		            {
			           pRawData2[i] = pRawData2[i]+ pRawData1[i-(nBufferSize2-nBufferSize1)];
		            }

	                sizeall = size2;
		            pcm2wav(strpathall,(char*)pRawData2,sizeall,1,8000,16000,2,16);   //different parameter affact the audio

	            }
	            else if (nBufferSize1>=nBufferSize2)
	            {
		            for (int i = 0;i<(nBufferSize1-nBufferSize2);i++ )
		            {
			           pRawData1[i] = pRawData1[i];
		            }
			
					
		            for (int i =(nBufferSize1-nBufferSize2);i<nBufferSize1;i++ )     
		            {

			          pRawData1[i] = pRawData1[i]+ pRawData2[i-(nBufferSize1-nBufferSize2)];   
		              
					}

		            sizeall = size1;
		            pcm2wav(strpathall,(char*)pRawData1,sizeall,1,8000,16000,2,16);   //different parameter affact the audio
	             }
      
	            delete [] pRawData1;
	            delete [] pRawData2;    
	            delete [] pcmBuffer1;
                delete [] pcmBuffer2;	
	         }

		   if(block_count1==0 && block_count2!=0)
	        {

		         int nBufferSize2 = payloadlen2;
	             short* pRawData2 = new short[iFileLen](); 
                 int size2 = G711_Decode_alaw(pRawData2,(unsigned char*)pcmBuffer2, nBufferSize2);

                  pcm2wav(strpath2,(char*)pRawData2,size2,1,8000,16000,2,16);
		          pcm2wav(strpathall,(char*)pRawData2,size2,1,8000,16000,2,16);
	    
		          delete [] pcmBuffer1;
		          delete [] pRawData2;    
		          delete [] pcmBuffer2;
		
	          }

	         if(block_count1!=0 && block_count2==0)
	          {

		           int nBufferSize1 = payloadlen1;
	               short* pRawData1 = new short[iFileLen](); 
                   int size1 = G711_Decode_alaw(pRawData1,(unsigned char*)pcmBuffer1, nBufferSize1);

                   pcm2wav(strpath1,(char*)pRawData1,size1,1,8000,16000,2,16);
		           pcm2wav(strpathall,(char*)pRawData1,size1,1,8000,16000,2,16);
	    
		           delete [] pcmBuffer1;
		           delete [] pRawData1;    
		           delete [] pcmBuffer2;	
	            }

	 }


	/* codecG729a*/
	else if (payload_type == 18)   //codecG729a
	{

		if (block_count1 != 0 && block_count2 != 0)
		{

			uint8_t inputBuffer1[10] = { 0 };
			int16_t outputBuffer1[L_FRAME] = { 0 };

			int framesNbr1 = 0;


			pcmfile1 = fopen(strpath1, "wb");
			if (pcmfile1 == NULL)
			{
				return -1;
			}

			//create the decoder 
			bcg729DecoderChannelContextStruct* Decoder1 = NULL;
			Decoder1 = initBcg729DecoderChannel();    //initialization of the decoder   

			int framesize1 = 0;
			int decodesize1 = 0;
			if ((payloadlen1 - decodesize1) < 8)
			{
				framesize1 = 2;
			}
			else
			{
				framesize1 = 10;
			}

			while (memcpy(inputBuffer1, pcmBuffer1 + decodesize1, framesize1))
			{

				framesNbr1++;
				decodesize1 += framesize1;
				if ((payloadlen1 - decodesize1) < 8)
				{
					framesize1 = 2;
				}
				else
				{
					framesize1 = 10;
				}


				uint8_t frameErasureFlag1 = 0;
				if ((uint8_t)inputBuffer1[0] == 0) //frame has been erased
				{
					frameErasureFlag1 = 1;
				}

				bcg729Decoder(Decoder1, inputBuffer1, frameErasureFlag1, outputBuffer1);

				fwrite(outputBuffer1, sizeof(int16_t), L_FRAME, pcmfile1);

				if (decodesize1 >= payloadlen1)
				{
					break;
				}

			}


			//release decoder
			closeBcg729DecoderChannel(Decoder1);


			fclose(pcmfile1);
			delete[] pcmBuffer1;

			uint8_t inputBuffer2[10] = { 0 };
			int16_t outputBuffer2[L_FRAME] = { 0 };

			int framesNbr2 = 0;


			pcmfile2 = fopen(strpath2, "wb");
			if (pcmfile2 == NULL)
			{
				return -1;
			}

			/*create the decoder */
			bcg729DecoderChannelContextStruct* Decoder2 = NULL;
			Decoder2 = initBcg729DecoderChannel();    //initialization of the decoder

			int framesize2 = 0;
			int decodesize2 = 0;
			if ((payloadlen2 - decodesize2) < 8)
			{
				framesize2 = 2;
			}
			else
			{
				framesize2 = 10;
			}

			while (memcpy(inputBuffer2, pcmBuffer2 + decodesize2, framesize2))
			{ /* input buffer contains the parameters and in [15] the frame erasure flag */

				framesNbr2++;
				decodesize2 += framesize2;
				if ((payloadlen2 - decodesize2) < 8)
				{
					framesize2 = 2;
				}
				else
				{
					framesize2 = 10;
				}

				uint8_t frameErasureFlag2 = 0;
				if ((uint8_t)inputBuffer2[0] == 0) //frame has been erased
				{
					frameErasureFlag2 = 1;
				}

				bcg729Decoder(Decoder2, inputBuffer2, frameErasureFlag2, outputBuffer2);


				/* write the output to the output files (only on first loop of perf measurement)*/
				fwrite(outputBuffer2, sizeof(int16_t), L_FRAME, pcmfile2);


				if (decodesize2 >= payloadlen2)
				{
					break;
				}

			}
			/*release decoder*/
			closeBcg729DecoderChannel(Decoder2);

			fclose(pcmfile2);
			delete[] pcmBuffer2;


			/*change the two direction pcm file to the wav file*/
			pcmfile1 = fopen(strpath1, "rb");
			if (pcmfile1 == NULL)
			{
				return -1;
			}
			fseek(pcmfile1, 0, SEEK_END);
			const long pcmfileout1_len = ftell(pcmfile1);
			fseek(pcmfile1, 0, SEEK_SET);
			char* tempBuffer1 = (char*)malloc(pcmfileout1_len);    //set buffer  the same with the file
			fread((void*)tempBuffer1, 1, pcmfileout1_len, pcmfile1);   //read FILE to buffer
			fclose(pcmfile1);
			pcm2wav(strpath1, tempBuffer1, pcmfileout1_len, 1, 8000, 16000, 2, 16);

			pcmfile2 = fopen(strpath2, "rb");
			if (pcmfile2 == NULL)
			{
				return -1;
			}
			fseek(pcmfile2, 0, SEEK_END);
			const long pcmfileout2_len = ftell(pcmfile2);
			fseek(pcmfile2, 0, SEEK_SET);
			char* tempBuffer2 = (char*)malloc(pcmfileout2_len);    //set buffer  the same with the file
			fread((void*)tempBuffer2, 1, pcmfileout2_len, pcmfile2);   //read FILE to buffer
			fclose(pcmfile2);
			pcm2wav(strpath2, tempBuffer2, pcmfileout2_len, 1, 8000, 16000, 2, 16);

			//add the two direction pcm file together,change it to the wav file
			int pcmfileoutall_len = 0;
			if (pcmfileout1_len <= pcmfileout2_len)
			{

				for (int i = 0; i < (pcmfileout2_len - pcmfileout1_len); i++)
				{
					tempBuffer2[i] = tempBuffer2[i];
				}

				for (int i = (pcmfileout2_len - pcmfileout1_len); i <= pcmfileout2_len - 1; i++)
				{
					tempBuffer2[i] = tempBuffer2[i] + tempBuffer1[i - (pcmfileout2_len - pcmfileout1_len)];
				}


				pcmfileoutall_len = pcmfileout2_len;
				pcm2wav(strpathall, tempBuffer2, pcmfileoutall_len, 1, 8000, 16000, 2, 16);   //different parameter affact the audio

			}
			else if (pcmfileout1_len > pcmfileout2_len)
			{
				for (int i = 0; i < (pcmfileout1_len - pcmfileout2_len); i++)
				{
					tempBuffer1[i] = tempBuffer1[i];
				}

				for (int i = (pcmfileout1_len - pcmfileout2_len); i <= pcmfileout1_len - 1; i++)
				{
					tempBuffer1[i] = tempBuffer1[i] + tempBuffer2[i - (pcmfileout1_len - pcmfileout2_len)];
				}
				pcmfileoutall_len = pcmfileout1_len;
				pcm2wav(strpathall, tempBuffer1, pcmfileoutall_len, 1, 8000, 16000, 2, 16);   //different parameter affact the audio
			}

			if (tempBuffer1 != NULL)
			{
				free(tempBuffer1);

				tempBuffer1 = NULL;
			}

			if (tempBuffer2 != NULL)
			{
				free(tempBuffer2);
				tempBuffer2 = NULL;
			}

		}


		else if (block_count1 != 0 && block_count2 == 0)
		{
			delete[] pcmBuffer2;
			uint8_t inputBuffer1[10] = { 0 };
			int16_t outputBuffer1[L_FRAME] = { 0 };

			int framesNbr1 = 0;

			pcmfile1 = fopen(strpath1, "wb");
			if (pcmfile1 == NULL)
			{
				return -1;
			}

			//create the decoder 
			bcg729DecoderChannelContextStruct* Decoder1 = NULL;
			Decoder1 = initBcg729DecoderChannel();    //initialization of the decoder   

			int framesize1 = 0;
			int decodesize1 = 0;
			if ((payloadlen1 - decodesize1) < 8)
			{
				framesize1 = 2;
			}
			else
			{
				framesize1 = 10;
			}

			while (memcpy(inputBuffer1, pcmBuffer1 + decodesize1, framesize1))
			{

				framesNbr1++;
				decodesize1 += framesize1;
				if ((payloadlen1 - decodesize1) < 8)
				{
					framesize1 = 2;
				}
				else
				{
					framesize1 = 10;
				}

				uint8_t frameErasureFlag1 = 0;
				if ((uint8_t)inputBuffer1[0] == 0) //frame has been erased
				{
					frameErasureFlag1 = 1;
				}

				bcg729Decoder(Decoder1, inputBuffer1, frameErasureFlag1, outputBuffer1);

				// write the output to the output files (only on first loop of per measurement)	
				fwrite(outputBuffer1, sizeof(int16_t), L_FRAME, pcmfile1);

				if (decodesize1 >= payloadlen1)
				{
					break;
				}

			}

			//release decoder
			closeBcg729DecoderChannel(Decoder1);

			fclose(pcmfile1);
			delete[] pcmBuffer1;

			/*change the two direction pcm file to the wav file*/
			pcmfile1 = fopen(strpath1, "rb");
			if (pcmfile1 == NULL)
			{
				return -1;
			}
			fseek(pcmfile1, 0, SEEK_END);
			const long pcmfileout1_len = ftell(pcmfile1);
			fseek(pcmfile1, 0, SEEK_SET);
			char* tempBuffer1 = (char*)malloc(pcmfileout1_len);    //set buffer  the same with the file
			fread((void*)tempBuffer1, 1, pcmfileout1_len, pcmfile1);   //read FILE to buffer
			fclose(pcmfile1);
			pcm2wav(strpath1, tempBuffer1, pcmfileout1_len, 1, 8000, 16000, 2, 16);

			pcm2wav(strpathall, tempBuffer1, pcmfileout1_len, 1, 8000, 16000, 2, 16);


		}

		else if (block_count1 == 0 && block_count2 != 0)
		{
			delete[] pcmBuffer1;

			uint8_t inputBuffer2[10] = { 0 };
			int16_t outputBuffer2[L_FRAME] = { 0 };

			int framesNbr2 = 0;

			pcmfile2 = fopen(strpath2, "wb");
			if (pcmfile2 == NULL)
			{
				return -1;
			}

			/*create the decoder */
			bcg729DecoderChannelContextStruct* Decoder2 = NULL;
			Decoder2 = initBcg729DecoderChannel();    //initialization of the decoder

			int framesize2 = 0;
			int decodesize2 = 0;
			if ((payloadlen2 - decodesize2) < 8)
			{
				framesize2 = 2;
			}
			else
			{
				framesize2 = 10;
			}

			while (memcpy(inputBuffer2, pcmBuffer2 + decodesize2, framesize2))
			{ /* input buffer contains the parameters and in [15] the frame erasure flag */

				framesNbr2++;
				decodesize2 += framesize2;
				if ((payloadlen2 - decodesize2) < 8)
				{
					framesize2 = 2;
				}
				else
				{
					framesize2 = 10;
				}

				uint8_t frameErasureFlag2 = 0;
				if ((uint8_t)inputBuffer2[0] == 0) //frame has been erased
				{
					frameErasureFlag2 = 1;
				}

				bcg729Decoder(Decoder2, inputBuffer2, frameErasureFlag2, outputBuffer2);


				/* write the output to the output files (only on first loop of perf measurement)*/
				fwrite(outputBuffer2, sizeof(int16_t), L_FRAME, pcmfile2);
				if (decodesize2 >= payloadlen2)
				{
					break;
				}

			}
			/*release decoder*/
			closeBcg729DecoderChannel(Decoder2);

			fclose(pcmfile2);
			delete[] pcmBuffer2;

			pcmfile2 = fopen(strpath2, "rb");
			if (pcmfile2 == NULL)
			{
				return -1;
			}
			fseek(pcmfile2, 0, SEEK_END);
			const long pcmfileout2_len = ftell(pcmfile2);
			fseek(pcmfile2, 0, SEEK_SET);
			char* tempBuffer2 = (char*)malloc(pcmfileout2_len);    //set buffer  the same with the file
			fread((void*)tempBuffer2, 1, pcmfileout2_len, pcmfile2);   //read FILE to buffer
			fclose(pcmfile2);
			pcm2wav(strpath2, tempBuffer2, pcmfileout2_len, 1, 8000, 16000, 2, 16);

			pcm2wav(strpathall, tempBuffer2, pcmfileout2_len, 1, 8000, 16000, 2, 16);

		}
		remove(strpath1);
		remove(strpath2);

	}

     return 0;
}
 


