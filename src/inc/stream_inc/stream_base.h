#ifndef _APP_STREAM_BASE_H_
#define _APP_STREAM_BASE_H_ 

#define STREAM_BASE_H_VERSION		(20160901)

#include <sys/types.h>
#include <netinet/in.h>            
#include <netinet/ip.h>            
#include <netinet/ip6.h>   
#include <netinet/tcp.h>   
#include <netinet/udp.h>   
#include <stdlib.h>
#include <string.h>

#ifndef UINT8
typedef unsigned char		UINT8;
#endif
#ifndef UCHAR
typedef unsigned char		UCHAR;
#endif
#ifndef UINT16
typedef unsigned short		UINT16;
#endif

#ifndef UINT32
typedef unsigned int			UINT32;
#endif
#ifndef UINT64
typedef unsigned long long	UINT64;
#endif

/* CHN : ���ķ����� */
/* ENG : stream direction definition*/
#define DIR_C2S 			0x01
#define DIR_S2C 			0x02
#define DIR_DOUBLE 			0x03

/* CHN : ����ײ㴫�䷽����,����ģʽ������ */
/* ENG : network topology route direction, is valid in serial mode */
#define DIR_ROUTE_UP		0x00
#define DIR_ROUTE_DOWN 		0x01

/* CHN : ���������Ͷ��� */
/* ENG : single packet type definition */
#define PKT_TYPE_NORMAL  			(0x0)	/* normal, common */
#define PKT_TYPE_IPREBUILD 			(1<<0)  /* ip frag reassembled packet;  ip��Ƭ���鱨�� */
#define PKT_TYPE_TCPUNORDER 		(1<<1)  /* TCP out of order packet;  TCP������ */
#define PKT_TYPE_TCPREORDER 		(1<<2)  /* TCP sequential packet;  TCP��������õ����ݰ� */ 
#define PKT_TYPE_TCPRETRANS 		(1<<3)  /* TCP retransmit packet;  TCP�ش����� */
#define PKT_TYPE_IP_FRAG			(1<<4)  /* IP frag packet;  IP��Ƭ�� */

/* CHN : ��ַ���Ͷ���, ��ͨ������ addr_type_to_string() ת���ַ�����ʽ. */
/* ENG : address type, transform to string mode by call addr_type_to_string(). */
enum addr_type_t{
	__ADDR_TYPE_INIT = 0,
	ADDR_TYPE_IPV4,				/* 1, struct stream_tuple4_v4 */
	ADDR_TYPE_IPV6,				/* 2, struct stream_tuple4_v6 */
	ADDR_TYPE_VLAN,				/* 3 */
	ADDR_TYPE_MAC,				/* 4 */
	ADDR_TYPE_ARP = 5,			/* 5 */
	ADDR_TYPE_GRE,				/* 6 */
	ADDR_TYPE_MPLS,				/* 7 */
	ADDR_TYPE_PPPOE_SES,		/* 8 */
	ADDR_TYPE_TCP,				/* 9 */
	ADDR_TYPE_UDP = 10,			/* 10 */
	ADDR_TYPE_L2TP,				/* 11 */
	__ADDR_TYPE_IP_PAIR_V4,		/* 12, ipv4 layer in tunnel mode */
	__ADDR_TYPE_IP_PAIR_V6,		/* 13, ipv6 layer in tunnel mode */
	ADDR_TYPE_PPP,				/* 14 */
	__ADDR_TYPE_MAX,			/* 15 */
};

#define TCP_TAKEOVER_STATE_FLAG_OFF	0
#define TCP_TAKEOVER_STATE_FLAG_ON	1


/* CHN : Ӧ�ò㿴��������״̬���� */
/* ENG : stream state for protocol or business plug*/
#define OP_STATE_PENDING   0
#define OP_STATE_REMOVE_ME 1
#define OP_STATE_CLOSE     2
#define OP_STATE_DATA      3

/* CHN : Ӧ�ò㷵�ؽ������ */
/* ENG : return value of plug */
#define APP_STATE_GIVEME   0x00
#define APP_STATE_DROPME   0x01
#define APP_STATE_FAWPKT   0x00
#define APP_STATE_DROPPKT  0x10

/* CHN : �������Ͷ��� */
/* ENG : stream type */
enum stream_type_t{
	STREAM_TYPE_NON = 0, /* No stream concept indeed, such as vlan, IP, etc.;  �����ĸ���, ��VLAN, IP��� */
	STREAM_TYPE_TCP,
	STREAM_TYPE_UDP,	 /* there is no stream of UDP in RFC, but in MESA platform, we build a UDP stream with same tuple4 packet */
	STREAM_TYPE_VLAN,
	STREAM_TYPE_SOCKS4,
	STREAM_TYPE_SOCKS5,
	STREAM_TYPE_HTTP_PROXY,
	STREAM_TYPE_PPPOE,
	STREAM_TYPE_L2TP,
};

/*
   CHN: ���ĵײ�����������, ��ͬ��stream_type_t, ���統ǰ��ΪSTREAM_TYPE_TCP, ���ײ����������STREAM_TUNNLE_PPTP.
        ��Ϊ��������Ƕ��ֲ�ͬ����Ƕ�����, ֻ��¼��ײ���������.
*/
enum stream_carry_tunnel_t{
	STREAM_TUNNLE_NON = 0, 	/* default is 0, not tunnel; Ĭ��Ϊ0, �����; */
	STREAM_TUNNLE_6OVER4 	= 1,
	STREAM_TUNNLE_GRE			= 2,
	STREAM_TUNNLE_IP_IN_IP	= 4,
	STREAM_TUNNLE_PPTP		= 8,
	STREAM_TUNNLE_L2TP		= 16,
	STREAM_TUNNLE_TEREDO		= 32,
};

typedef struct raw_ipfrag_list{
    void *frag_packet;
    int pkt_len;
    int type; /* IPv4 or IPv6 */
    struct raw_ipfrag_list *next;
}raw_ipfrag_list_t;


#ifndef STRUCT_TUPLE4_DEFINED
#define STRUCT_TUPLE4_DEFINED (1)
/* compat for start, papp;  ����start, papp */
struct tuple4 {
  u_int saddr;
  u_int daddr;
  u_short source;
  u_short dest;
};
#endif

struct tuple6
{
	UCHAR saddr[16] ;
	UCHAR daddr[16] ;
	UINT16 source;
	UINT16 dest;
};

/* network-order */
struct stream_tuple4_v4{
	UINT32 saddr;	/* network order */
	UINT32 daddr;	/* network order */
	UINT16 source;	/* network order */
	UINT16 dest;	/* network order */
};


#ifndef IPV6_ADDR_LEN
#define IPV6_ADDR_LEN	(sizeof(struct in6_addr))
#endif

struct stream_tuple4_v6
{
	UCHAR saddr[IPV6_ADDR_LEN] ;
	UCHAR daddr[IPV6_ADDR_LEN] ;
	UINT16 source;	/* network order */
	UINT16 dest;	/* network order */
};


#define GRE_TAG_LEN 		(4)
struct layer_addr_gre
{
	UINT16 gre_id;
};


#define VLAN_ID_MASK		(0x0FFF)
#define VLAN_TAG_LEN 		(4)
struct layer_addr_vlan
{
	UINT16 vlan_id;	/* network order */
};

#define VLAN_ID_LEN 4
struct tuplevlan
{
	UCHAR vlan_id[VLAN_ID_LEN];
};

struct layer_addr_pppoe_session
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned int ver:4;   
	unsigned int type:4;  
#endif
#if __BYTE_ORDER == __BIG_ENDIAN
	unsigned int type:4; 
	unsigned int ver:4; 
#endif
  	unsigned char code;
	unsigned short session_id;
};

#ifndef MAC_ADDR_LEN
#define MAC_ADDR_LEN		(6)
#endif

struct layer_addr_mac
{
	UCHAR dst_mac[MAC_ADDR_LEN]; /* network order */
	UCHAR src_mac[MAC_ADDR_LEN]; /* network order */
};

struct layer_addr_ipv4
{
	UINT32 saddr; 	/* network order */
	UINT32 daddr; 	/* network order */
	/* 2014-04-21 lijia add, 
	   Ϊ�˽�Լ�ڴ�ռ䡢�ʹ���Ч��, ��ǿ�ư�Э���δ���,
	   IP���TCP����Ϊһ����,
	   ����������IP, �˿���ϢΪ0;
	*/
	UINT16 source;	/* network order */
	UINT16 dest;		/* network order */
};

struct layer_addr_ipv6
{
	UCHAR saddr[IPV6_ADDR_LEN] ; /* network order */
	UCHAR daddr[IPV6_ADDR_LEN] ; /* network order */
	/* 2014-04-21 lijia add, 
	   Ϊ�˽�Լ�ڴ�ռ䡢�ʹ���Ч��, ��ǿ�ư�Э���δ���,
	   IP���TCP����Ϊһ����,
	   ����������IP, �˿���ϢΪ0;
	*/
	UINT16 source;/* network order */
	UINT16 dest;/* network order */
};

struct layer_addr_tcp
{
	UINT16 source; /* network order */
	UINT16 dest;    /* network order */
};

struct layer_addr_udp
{
	UINT16 source; /* network order */
	UINT16 dest;    /* network order */
};


struct layer_addr_l2tp_v2_t{
	UINT16 tunnelid_C2S; /* network order, �Դ���㴴�����ķ���Ϊ׼ */
	UINT16 tunnelid_S2C; /* network order, �Դ���㴴�����ķ���Ϊ׼ */
	UINT16 sessionlid_C2S; /* network order, �Դ���㴴�����ķ���Ϊ׼ */
	UINT16 sessionlid_S2C; /* network order, �Դ���㴴�����ķ���Ϊ׼ */
};

struct layer_addr_l2tp_v3_t{
	UINT32 sessionlid; /* network order */
};
		
struct layer_addr_l2tp
{
	UCHAR version; /* v2 or v3 */
	union
	{	
 		struct layer_addr_l2tp_v2_t l2tp_addr_v2;
		struct layer_addr_l2tp_v3_t l2tp_addr_v3;
	}l2tpun;
};

struct layer_addr_mpls
{
	unsigned int mpls_pkt;
};


struct layer_addr
{
	UCHAR addrtype; /*  definition in enum addr_type_t */
	UCHAR addrlen;	
	UCHAR pkttype;	   	/* packet special features, definition in MACRO PKT_TYPE_xxx */
	UCHAR pktipfragtype;	/* ip frag packetfeatures, definition in MACRO PKT_TYPE_xxx */
	
	UCHAR __pad[4]; /* pad for alignment */
	union
	{
		struct stream_tuple4_v4 *tuple4_v4;
		struct stream_tuple4_v6 *tuple4_v6;
		struct layer_addr_ipv4	*ipv4;
		struct layer_addr_ipv6	*ipv6;
		struct layer_addr_vlan	*vlan;
		struct layer_addr_mac	*mac;
		struct layer_addr_gre	*gre;
		struct layer_addr_tcp	*tcp;
		struct layer_addr_udp	*udp;
		struct layer_addr_pppoe_session *pppoe_ses;		
		struct layer_addr_l2tp	*l2tp;
		void 					*paddr;
	};

};

/* CHN : �����˽ṹ���ں�papp����, ����ָ��ʱ, ����struct layer_addrǿת */
/* ENG : compat for papp, can be transform to struct layer_addr pointer */
struct ipaddr
{
	UCHAR addrtype; /*  definition in enum addr_type_t */
	UCHAR addrlen;
	UCHAR  pkttype;	  /* packet special features, definition in MACRO PKT_TYPE_xxx */
	UCHAR  pktipfragtype;	   		/* ip frag packetfeatures, definition in MACRO PKT_TYPE_xxx */
	UCHAR __pad[4]; /* pad for alignment */
	union
	{
		struct stream_tuple4_v4 *v4;
		struct stream_tuple4_v6 *v6;
		void *paddr;
	};

};

struct tcpdetail
{
	void  *pdata;		 
	UINT32 datalen;		
	UINT32 lostlen;		/* lost data len, not accumulated, current procedure */
	UINT32 serverpktnum; 	/* this value indicate TCP-ALL packet, include syn, ack, rst, if want get tcp data status, use stream_project.h : struct tcp_flow_stat */
	UINT32 clientpktnum;  	/* this value indicate TCP-ALL packet, include syn, ack, rst, if want get tcp data status, use stream_project.h : struct tcp_flow_stat */
	UINT32 serverbytes;   	/* this value indicate TCP-ALL packet, include syn, ack, rst, if want get tcp data status, use stream_project.h : struct tcp_flow_stat */
	UINT32 clientbytes;     /* this value indicate TCP-ALL packet, include syn, ack, rst, if want get tcp data status, use stream_project.h : struct tcp_flow_stat */
	UINT64 createtime; 
	UINT64 lastmtime;
};

struct udpdetail
{
 	void *pdata;		     
 	UINT32 datalen;			 
	UINT32 pad;			
	UINT32 serverpktnum; 	 /* you should better use stream_project.h : struct udp_flow_stat */
	UINT32 clientpktnum;	/* you should better use stream_project.h : struct udp_flow_stat */
	UINT32 serverbytes;	/* you should better use stream_project.h : struct udp_flow_stat */
	UINT32 clientbytes;	/* you should better use stream_project.h : struct udp_flow_stat */
	UINT64 createtime; 
	UINT64 lastmtime;
};

struct streaminfo
{
	struct layer_addr addr;      
	struct streaminfo *pfather; /* this stream's carry layer stream; �ϲ����ṹ�� */
	UCHAR type;			/* stream type, definition in enum stream_type_t */
	UCHAR threadnum;	     
	UCHAR  dir;           	/*  valid in all stream life, current stream direction state, 0x01:c-->s; 0x02:s-->c; 0x03 c<-->s; */
	UCHAR  curdir;         /* valid in current procedure, current packet direction, 0x01:c-->s;  0x02:s-->c */
	UCHAR  opstate;		/* stream state, definition in MACRO OP_STATE_xxx */
	UCHAR  pktstate;	/* for TCPALL plug, stream state, definition in MACRO OP_STATE_xxx */
	UCHAR  routedir;	     /* network topology route direction, is valid in serial mode */
	UCHAR  stream_state;	/* stream management state, for example, in TCP stream, maybe SYN, DATA, NOUSE */
	UINT32 hash_index;		/* stream hash index, maybe reduplicate with other stream when hash algorithm collide */      
	UINT32 stream_index;    /* stream global index per thread  */	
	union
	{
		struct tcpdetail *ptcpdetail;
		struct udpdetail *pudpdetail;
		void   *pdetail;
	};
 };



#ifdef __cplusplus
extern "C" {
#endif

/* CHN : �ڴ������غ���, ����ƽ̨�Ĳ������ʹ�ô��ຯ��������ͷ��ڴ� */
/* ENG : memory management function, plugs must call these functions instead of malloc, free in <stdlib.h> */
void *dictator_malloc(int thread_seq,size_t size);
void dictator_free(int thread_seq,void *pbuf);
void *dictator_realloc(int thread_seq, void* pbuf, size_t size);

/* CHN : ��ȡ��ǰϵͳ���еĲ��������߳����� */
/* ENG : get current total thread of platfomr */
int get_thread_count(void);

/* CHN : ����enum addr_type_tַ����ת���ɿɴ�ӡ���ַ�����ʽ */
/* ENG : transform binary addr_type_t to string mode */
const char *addr_type_to_string(enum addr_type_t type);

/*
	ENG : transform tuple4 to string mode, muse used in packet process thread context;
	CHN : ��layer_addr��ַת�����ַ�����ʽ, �������ڰ������߳�.
*/
const char *printaddr (const struct layer_addr *paddrinfo, int threadindex);

/*
	ENG : a reentrant version of printaddr, thread safe;
	CHN : printaddr�Ŀ�����汾, ���̰߳�ȫ��.
*/
const char *printaddr_r(const struct layer_addr *paddrinfo, char *out_buf, int out_buf_len);

/* 
	ENG : duplicate a same layer_addr struct, memory obtained with malloc(3);
	CHN : ����һ����ȫ��ͬ��layer_addr�ṹ��, �ڴ�ͨ��malloc(3)��ȡ.
*/
struct layer_addr * layer_addr_dup(const struct layer_addr *paddrinfo);

/* 
	ENG: used to free all memory of paddrinfo;
	CHN: �����ͷ�paddrinfo�ڴ�.
*/
void layer_addr_free(struct layer_addr *paddrinfo);


/* 
	ENG : duplicate a same streaminfo list, memory obtained with malloc(3);
	CHN : ����һ����ȫ��ͬ��streaminfo�ṹ�弰�����ṹ, �ڴ�ͨ��malloc(3)��ȡ.
*/
struct streaminfo *streaminfo_dup(const struct streaminfo *stream);

/* 
	ENG: used to free all memory of streaminfo;
	CHN: �����ͷŽṹ�弰�����ṹ���ڴ�.
*/
void streaminfo_free(struct streaminfo *stream);


/* 
	addr list transform function, like inet_ntop(), inet_pton(),
	use '<' as delimitation between layer,
	if direction is double, for ip, port, use '-' as delimitation between source and destination,
	
	for example:
		"T4T:6005-1673<IP4:61.147.112.53-11.215.62.23<MAC:0000ea60040d-0200000003b6"

	args:
		pstream	: stream info;
		dst		: buf to store result;
		size		: dst buf's size;
		addr_list_str: addr list string;
		thread_index : thread index;

	����ֵ:
		>0:ת����Ľ��ʵ��ռ���ڴ泤��, stream_addr_list_ntop()�������ַ���ĩβ��'\0';
		-1:dst����ռ䳤�Ȳ���;
		-2:��ʽ����;
		-3:��������;
*/
int stream_addr_list_ntop(const struct streaminfo *pstream, char *dst, int size);
int stream_addr_list_pton(const char *addr_list_str, void *dst, int size, int thread_index);


#ifdef __cplusplus
}
#endif

#endif

