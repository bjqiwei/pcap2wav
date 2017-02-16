#pragma pack( push, 1)
// 为了保证在windows和linux下都能正常编译，放弃使用INT64或者_int_64

typedef signed char int8_t; 
typedef short int int16_t;
typedef  int  int32_t;
typedef unsigned char uint8_t;
typedef unsigned short int uint16_t;
typedef unsigned int uint32_t;
//typedef char Byte;
//typedef unsigned long in_addr_t;



// Pcap文件头    24byte
struct __file_header
{
	int32_t    iMagic;
	int16_t    iMaVersion;
	int16_t    iMiVersion;
	int32_t    iTimezone;
	int32_t    iSigFlags;
	int32_t    iSnapLen;
	int32_t    iLinkType;
};

// 数据包头  16byte
struct __pkthdr
{
	int32_t        iTimeSecond;
	int32_t        iTimeSS;
	int32_t        iPLength;
	int32_t        iLength;
};

//frame information   14byte
struct framehdr{
	uint8_t DesMAC[6];
	uint8_t SrcMAC[6];
	uint16_t frametype;
};

//ip header 20byte
struct iphdr {
	uint8_t	version:4;
	uint8_t	tos;
	uint16_t	tot_len;
	uint16_t	id;
	uint16_t	frag_off;
	uint8_t	ttl;
	uint8_t	protocol;
	uint16_t	check;
	uint32_t	saddr;
	uint32_t	daddr;
	//uint8_t ip1[4];
	//uint8_t ip2[4];
	/*The options start here. */
};

//udp        //8byte
struct udphdr {

	uint16_t	source_port;
	uint16_t	dest_port;
	uint16_t	len;
	uint16_t	check;
};

//tcp          //32byte
struct tcphdr{
	uint16_t	source_port;
	uint16_t	dest_port;
	uint32_t sequence_number;  
	uint32_t ack_number; 
	uint8_t hdr_len;
	uint8_t flags;
	uint16_t fact;
	uint16_t  check;
	uint16_t urgent_pointer;
	uint16_t type;
	uint8_t kind;
	uint8_t length;
	uint32_t timestamp; 
	uint32_t timestamp_echo;
};

//rtphrd  12byte
struct rtphdr{  
	     // uint16_t sequence_number;
	    int8_t v;   //when windows and linux ,change the position of pt and v for the big_endian and the little_endian
	    int8_t pt;
           // uint8_t v;
          //  uint16_t v_pt; 
	    uint16_t sequence_number;  
	    uint32_t timestamp;  
	    uint32_t ssrc;  
	};  

//struct in_addr{     
//	in_addr_t s_addr; }; 

/*
typedef struct in_addr {
        union {
                struct { uint8_t s_b1,s_b2,s_b3,s_b4; } S_un_b;
                struct { uint16_t s_w1,s_w2; } S_un_w;
                uint32_t S_addr;
        } S_un;
#define s_addr  S_un.S_addr  //can be used for most tcp & ip code 
#define s_host  S_un.S_un_b.s_b2    // host on imp
#define s_net   S_un.S_un_b.s_b1    // network
#define s_imp   S_un.S_un_w.s_w2    // imp
#define s_impno S_un.S_un_b.s_b4    // imp #
#define s_lh    S_un.S_un_b.s_b3    // logical host
};
*/


//得到链路层是DLT_EN10MB时候对应的带宽数据
#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif


//struct ether_header
//{
//  uint8_t  ether_dhost[ETH_ALEN];	/* destination eth addr	*/
 // uint8_t  ether_shost[ETH_ALEN];	/* source ether addr	*/
 // uint16_t ether_type;		        /* packet type ID field	*/
//} __attribute__ ((__packed__));  


//void pcm2wav(char *file, char *buffer, int32_t size, int32_t speed);


//int compareIP(uint8_t* firstIP,uint8_t* secondIP,int index);

#pragma pack( pop)
