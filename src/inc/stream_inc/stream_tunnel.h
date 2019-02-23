#ifndef _APP_STREAM_TUNNEL_H_
#define _APP_STREAM_TUNNEL_H_ 1 

#define STREAM_TUNNEL_H_VERSION		(20160830)

#ifdef __cplusplus
extern "C" {
#endif

enum tunnel_link_type_t{
	TUNNEL_LINK_TYPE_CONTROL = 1, /* 隧道协议控制连接 */
	TUNNEL_LINK_TYPE_DATA 	= 2, /* 隧道协议数据连接 */
};

struct pptp_info{
	int link_type;
	int encryt_pro;
	int authentication_pro;
};


struct l2tp_info{
	int link_type;
	int encryt_pro;
};

struct isakmp_info{
	unsigned long long init_cookie;
	unsigned long long resp_cookie;
	unsigned short encry_algo;
	unsigned short hash_algo;
	unsigned short auth_method;
	unsigned char major_version;
	unsigned char minor_version;
};

typedef enum{
	IPSEC_OPT_IKE_VERSION,  	/* opt_val type must be char ** */
}ipsec_opt_t;

typedef enum{
	PPTP_OPT_LINK_TYPE,		/* opt_val type must be char ** */
	PPTP_OPT_ENCRY_PRO,		/* opt_val type must be char ** */
	PPTO_OPT_AUTHEN_PRO,		/* opt_val type must be char ** */
}pptp_opt_t;

typedef enum{
	L2TP_OPT_LINK_TYPE,		/* opt_val type must be char ** */
	L2TP_OPT_ENCRY_PRO,		/* opt_val type must be char ** */
}l2tp_opt_t;

int soq_get_ipsec_info(const struct isakmp_info *ikp_info, ipsec_opt_t opt, void *opt_val, int *opt_val_len);

int soq_get_pptp_info(const struct pptp_info *pptp_info, pptp_opt_t opt, void *opt_val, int *opt_val_len);

int soq_get_l2tp_info(const struct l2tp_info *l2tp_info, l2tp_opt_t opt, void *opt_val, int *opt_val_len);

#ifdef __cplusplus
}
#endif

#endif
