#ifndef _APP_STREAM_CONTROL_H_
#define _APP_STREAM_CONTROL_H_ 

#ifdef __cplusplus
extern "C" {
#endif

#define STREAM_CONTROL_H_VERSION		(20160726)

#define TCP_CTEAT_LINK_BYSYN   			0x01
#define TCP_CTEAT_LINK_BYDATA 			0x02

/*
	option of stream, 

	MSO_IGNORE_RST_FIN: will not be terminated by RST, FIN packet, only if timeout or in LRU tail, it will be eliminated. 
*/
enum MESA_stream_opt{
	__MSO_PAD			=	0,
	MSO_MAX_UNORDER	=	1,  	/* opt_val type must be struct max_unorder_opt */
	MSO_NEED_ACK,				/* opt_val type must be unsigned char */
	MSO_TAKEOVER,				/* opt_val type must be int */
	MSO_TIMEOUT,				/* opt_val type must be unsigned short */
	MSO_IGNORE_RST_FIN, 		/* opt_val type must be unsigned char */
	MSO_TCP_CREATE_LINK_MODE,  /* opt_val must be unsigned char, refer to TCP_CTEAT_LINK_xxx */
	MSO_TCP_ISN_C2S, /* Host-order, opt_val type must be unsigned int */
	MSO_TCP_ISN_S2C, /* Host-order, opt_val type must be unsigned int */
	MSO_TCP_SYN_OPT, /* opt_val must be struct tcp_option **, opt_val_len [OUT} is struct tcp_option number, valid only if SYN packet is captured */
	MSO_TCP_SYNACK_OPT, /* opt_val must be struct tcp_option **, opt_val_len [OUT} is struct tcp_option number, valid only if SYN/ACK packet is captured */
	MSO_STREAM_TUNNEL_TYPE,  /* opt_val must be unsigned short, refer to enum stream_carry_tunnel_t */
	__MSO_MAX,
};

/* for MSO_MAX_UNORDER  */
struct max_unorder_opt{
	unsigned short stream_dir; /* refer to stream_base.h, DIR_C2S, DIR_S2C, DIR_DOUBLE */
	unsigned short max_unorder_val;
};

#define MAX_TCP_OPT_LEN	(38) /* TCP头部长度最长为60字节, 去除标准头部剩余选项部分最长40字节, 选项数据部分最长38字节 */
#define MAX_TCP_OPT_NUM	(20) /* 单个TCP包最大选项数量 */

enum tcp_option_value{
	TCP_OPT_EOL = 0,
	TCP_OPT_NOP = 1,
	TCP_OPT_MSS = 2,
	TCP_OPT_WIN_SCALE = 3,
	TCP_OPT_SACK = 4,
	TCP_OPT_TIME_STAMP = 8,	/* refer to struct tcp_option_ts */
	TCP_OPT_MD5 = 19,
};

struct tcp_option_ts{
	unsigned int ts_self;
	unsigned int ts_echo_reply;	
};

struct tcp_option{
	unsigned char type;
	unsigned char len;
	union{
		unsigned char char_value;
		unsigned short short_value;
		unsigned int int_value;
		unsigned long long long_value;
		char *variable_value;
		struct tcp_option_ts opt_ts_val;
	};	
} __attribute__((packed, aligned(1)));

/*
	plug call MESA_set_stream_opt() to set feature of specified stream.
		opt: option type, refer to enum MESA_stream_opt;
		opt_val: option value, depend on opt type;
		opt_val_len: opt_val size;
	
	return value:
		0 :OK;
		<0:error;
*/
int MESA_set_stream_opt(const struct streaminfo *pstream, enum MESA_stream_opt opt, void *opt_val, int opt_val_len);


/*
	plug call MESA_get_stream_opt() to get feature of specified stream.
		opt: option type, refer to enum MESA_stream_opt;
		opt_val: option value, depend on opt type;
		opt_val_len: value-result argment, IN:opt_val buf size, OUT:opt_val actual size;
	
	return value:
		0 :OK;
		<0:error;
*/
int MESA_get_stream_opt(const struct streaminfo *pstream, enum MESA_stream_opt opt, void *opt_val, int *opt_val_len);


/*
	Get options from tcphdr, and store them in raw_result.
	return value:
		= 0: no option;
		> 0: opt number;
		< 0: error.	
*/
int MESA_get_tcp_pkt_opts(const struct tcphdr *tcphdr, struct tcp_option *raw_result, int res_num);

/****************************************************************************************
	CHN : 因为历史遗留问题,此类函数保留仅为向后兼容,请使用新接口:MESA_set_stream_opt().
	ENG : for compat old version, keep these functions, but we suggest you use new API MESA_set_stream_opt().
*****************************************************************************************/
int tcp_set_single_stream_max_unorder(const struct streaminfo *stream, UCHAR dir, unsigned short unorder_num);
int tcp_set_single_stream_needack(const struct streaminfo *pstream);
int tcp_set_single_stream_takeoverflag(const struct streaminfo *pstream,int flag);
int stream_set_single_stream_timeout(const struct streaminfo *pstream,unsigned short timeout);
/****************************************************************************************
****************************************************************************************
****************************************************************************************/

#ifdef __cplusplus
}
#endif

#endif

