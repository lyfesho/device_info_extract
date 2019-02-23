#ifndef _APP_STREAM_INJECT_H_
#define _APP_STREAM_INJECT_H_ 

#include <sys/types.h>
#include "stream_base.h"

#ifdef __cplusplus
extern "C" {
#endif

#define STREAM_INJECT_H_VERSION		(20161010)


/* 
	CHN : ����GK��غ��� 
	ENG : to force terminate a stream;

	MESA_kill_tcp: use RST to terminate a TCP stream;
	MESA_kill_tcp_synack: send phony SYN/ACK packet to cheat client and server.
	MESA_kill_connection: for non-TCP stream, such as UDP stream, only available in serial mode.

    return value:
		>= 0: success.
		-1  : error.
*/
int MESA_kill_tcp(struct streaminfo *stream, const void *raw_pkt);
int MESA_kill_tcp_synack(struct streaminfo *stream, const void *raw_pkt);
int MESA_kill_connection(struct streaminfo *stream, const void *ext_raw_pkt);

/*
	���������ܵ�MESA_kill_xxxϵ�к���.
	���ӹ���Ϊ: 
	    ��ʵ�ʷ��͵����ݰ�copy��feedback_buf�ռ���, ������feedback_buf_lenΪʵ�����ݰ�����.

	ע��: feedback_buf_lenΪ���봫����, �����ʾfeedback_buf����, ������ʾʵ�ʷ��͵����ݰ�����.

    return value:
		>= 0: success.
		-1  : error.	
		-2  : feedback_buf or feedback_buf_len error.
*/
int MESA_kill_tcp_feedback(struct streaminfo *stream, const void *raw_pkt, char *feedback_buf, int *feedback_buf_len);
int MESA_kill_tcp_synack_feedback(struct streaminfo *stream, const void *raw_pkt, char *feedback_buf, int *feedback_buf_len);
int MESA_kill_connection_feedback(struct streaminfo *stream, const void *raw_pkt, char *feedback_buf, int *feedback_buf_len);

/* 
	CHN : ����route_dir����, Ϊ�˼���papp;
	ENG : compat for papp, dir reverse.
 */
unsigned char MESA_dir_reverse(unsigned char raw_route_dir);

/*
	ARG:
		stream: ���ṹ��ָ��;
		payload: Ҫ���͵�����ָ��;
		payload_len: Ҫ���͵����ݸ��س���;
		raw_pkt: ԭʼ��ָ��;
		snd_routedir: Ҫ�������ݵ�route����, 
			 ��������͵İ��뵱ǰ��ͬ��, snd_routedir = stream->routedir, 
			 ��������͵İ��뵱ǰ������, snd_routedir = MESA_dir_reverse(stream->routedir).
	return value:
		-1: error.
		>0: ���͵����ݰ�ʵ���ܳ���(payload_len + �ײ��ͷ����);
*/
int MESA_inject_pkt(struct streaminfo *stream, const char *payload, int payload_len, const void *raw_pkt, UCHAR snd_routedir);


/*
	���������ܵ�MESA_inject_pkt_feedback����, ����ͬMESA_inject_pkt().
	��ʵ�ʷ��͵����ݰ�copy��feedback_buf�ռ���, ������feedback_buf_lenΪʵ�����ݰ�����.

	ע��: feedback_buf_lenΪ���봫����, �����ʾfeedback_buf����, ������ʾʵ�ʷ��͵����ݰ�����.

    return value:
		>= 0: success.
		-1  : error.	
		-2  : feedback_buf or feedback_buf_len error.
*/
int MESA_inject_pkt_feedback(struct streaminfo *stream, const char *payload, int payload_len, 
						const void *ext_raw_pkt, UCHAR snd_routedir,
						char *feedback_buf, int *feedback_buf_len);
						
int MESA_sendpacket_ethlayer(int thread_index,const char *buf, int buf_len, unsigned int target_id);//papp online, shuihu

/* �����ѹ���õ�����IP��, У��͵Ⱦ�������߼��� */
int MESA_sendpacket_iplayer(int thread_index,const char *buf,  int buf_len, __uint8_t dir);

/* ����ָ������IP��, ��ָ����������, У�����ƽ̨�Զ�����,
   sip, dipΪ������. */
int MESA_fakepacket_send_ipv4(int thread_index,__uint8_t ttl,__uint8_t protocol,
							u_int32_t sip_host_order, u_int32_t dip_host_order, 
							const char *payload, int payload_len,__uint8_t dir);

/* ����ָ������TCP��, ��ָ����������, У�����ƽ̨�Զ�����,
   sip, dip,sport,dport,sseq,sack��Ϊ������. */
int MESA_fakepacket_send_tcp(int thread_index,u_int sip_host_order,u_int dip_host_order,
							u_short sport_host_order,u_short dport_host_order,
							u_int sseq_host_order,u_int sack_host_order,
							u_char control,const char* payload,int payload_len, u_int8_t dir);

/* ����ָ������UDP��, ��ָ����������, У�����ƽ̨�Զ�����,
   sip, dip,sport,dport��Ϊ������. */
int MESA_fakepacket_send_udp(int thread_index, u_int sip_host_order, u_int dip_host_order, 
							u_short sport_host_order,u_short dport_host_order, 
							const char *payload, int payload_len,u_int8_t dir);
							

#ifdef __cplusplus
}
#endif

#endif

