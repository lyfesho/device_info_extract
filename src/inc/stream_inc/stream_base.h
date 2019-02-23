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

/* CHN : 流的方向定义 */
/* ENG : stream direction definition*/
#define DIR_C2S 			0x01
#define DIR_S2C 			0x02
#define DIR_DOUBLE 			0x03

/* CHN : 网络底层传输方向定义,串联模式有意义 */
/* ENG : network topology route direction, is valid in serial mode */
#define DIR_ROUTE_UP		0x00
#define DIR_ROUTE_DOWN 		0x01

/* CHN : 单包的类型定义 */
/* ENG : single packet type definition */
#define PKT_TYPE_NORMAL  			(0x0)	/* normal, common */
#define PKT_TYPE_IPREBUILD 			(1<<0)  /* ip frag reassembled packet;  ip碎片重组报文 */
#define PKT_TYPE_TCPUNORDER 		(1<<1)  /* TCP out of order packet;  TCP乱序报文 */
#define PKT_TYPE_TCPREORDER 		(1<<2)  /* TCP sequential packet;  TCP乱序排序好的数据包 */ 
#define PKT_TYPE_TCPRETRANS 		(1<<3)  /* TCP retransmit packet;  TCP重传报文 */
#define PKT_TYPE_IP_FRAG			(1<<4)  /* IP frag packet;  IP分片包 */

/* CHN : 地址类型定义, 可通过函数 addr_type_to_string() 转成字符串形式. */
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


/* CHN : 应用层看到的链接状态定义 */
/* ENG : stream state for protocol or business plug*/
#define OP_STATE_PENDING   0
#define OP_STATE_REMOVE_ME 1
#define OP_STATE_CLOSE     2
#define OP_STATE_DATA      3

/* CHN : 应用层返回结果定义 */
/* ENG : return value of plug */
#define APP_STATE_GIVEME   0x00
#define APP_STATE_DROPME   0x01
#define APP_STATE_FAWPKT   0x00
#define APP_STATE_DROPPKT  0x10

/* CHN : 流的类型定义 */
/* ENG : stream type */
enum stream_type_t{
	STREAM_TYPE_NON = 0, /* No stream concept indeed, such as vlan, IP, etc.;  无流的概念, 如VLAN, IP层等 */
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
   CHN: 流的底层承载隧道类型, 不同于stream_type_t, 比如当前流为STREAM_TYPE_TCP, 但底层隧道类型是STREAM_TUNNLE_PPTP.
        因为隧道可能是多种不同类型嵌套组合, 只记录最底层的隧道类型.
*/
enum stream_carry_tunnel_t{
	STREAM_TUNNLE_NON = 0, 	/* default is 0, not tunnel; 默认为0, 非隧道; */
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
/* compat for start, papp;  兼容start, papp */
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
	   为了节约内存空间、和处理效率, 不强制按协议层次处理,
	   IP层和TCP层做为一个层,
	   对于隧道外层IP, 端口信息为0;
	*/
	UINT16 source;	/* network order */
	UINT16 dest;		/* network order */
};

struct layer_addr_ipv6
{
	UCHAR saddr[IPV6_ADDR_LEN] ; /* network order */
	UCHAR daddr[IPV6_ADDR_LEN] ; /* network order */
	/* 2014-04-21 lijia add, 
	   为了节约内存空间、和处理效率, 不强制按协议层次处理,
	   IP层和TCP层做为一个层,
	   对于隧道外层IP, 端口信息为0;
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
	UINT16 tunnelid_C2S; /* network order, 以传输层创建流的方向为准 */
	UINT16 tunnelid_S2C; /* network order, 以传输层创建流的方向为准 */
	UINT16 sessionlid_C2S; /* network order, 以传输层创建流的方向为准 */
	UINT16 sessionlid_S2C; /* network order, 以传输层创建流的方向为准 */
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

/* CHN : 保留此结构用于和papp兼容, 用作指针时, 可与struct layer_addr强转 */
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
	struct streaminfo *pfather; /* this stream's carry layer stream; 上层流结构体 */
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

/* CHN : 内存管理相关函数, 基于平台的插件必须使用此类函数申请或释放内存 */
/* ENG : memory management function, plugs must call these functions instead of malloc, free in <stdlib.h> */
void *dictator_malloc(int thread_seq,size_t size);
void dictator_free(int thread_seq,void *pbuf);
void *dictator_realloc(int thread_seq, void* pbuf, size_t size);

/* CHN : 获取当前系统运行的并发处理线程总数 */
/* ENG : get current total thread of platfomr */
int get_thread_count(void);

/* CHN : 将地enum addr_type_t址类型转换成可打印的字符串形式 */
/* ENG : transform binary addr_type_t to string mode */
const char *addr_type_to_string(enum addr_type_t type);

/*
	ENG : transform tuple4 to string mode, muse used in packet process thread context;
	CHN : 将layer_addr地址转换成字符串形式, 必须用在包处理线程.
*/
const char *printaddr (const struct layer_addr *paddrinfo, int threadindex);

/*
	ENG : a reentrant version of printaddr, thread safe;
	CHN : printaddr的可重入版本, 是线程安全的.
*/
const char *printaddr_r(const struct layer_addr *paddrinfo, char *out_buf, int out_buf_len);

/* 
	ENG : duplicate a same layer_addr struct, memory obtained with malloc(3);
	CHN : 复制一个完全相同的layer_addr结构体, 内存通过malloc(3)获取.
*/
struct layer_addr * layer_addr_dup(const struct layer_addr *paddrinfo);

/* 
	ENG: used to free all memory of paddrinfo;
	CHN: 用于释放paddrinfo内存.
*/
void layer_addr_free(struct layer_addr *paddrinfo);


/* 
	ENG : duplicate a same streaminfo list, memory obtained with malloc(3);
	CHN : 复制一个完全相同的streaminfo结构体及父流结构, 内存通过malloc(3)获取.
*/
struct streaminfo *streaminfo_dup(const struct streaminfo *stream);

/* 
	ENG: used to free all memory of streaminfo;
	CHN: 用于释放结构体及父流结构的内存.
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

	返回值:
		>0:转换后的结果实际占用内存长度, stream_addr_list_ntop()包含了字符串末尾的'\0';
		-1:dst缓存空间长度不足;
		-2:格式错误;
		-3:其他错误;
*/
int stream_addr_list_ntop(const struct streaminfo *pstream, char *dst, int size);
int stream_addr_list_pton(const char *addr_list_str, void *dst, int size, int thread_index);


#ifdef __cplusplus
}
#endif

#endif

