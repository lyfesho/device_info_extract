#ifndef DEVICE_INFO_EXTRACT_H_
#define DEVICE_INFO_EXTRACT_H_

#include <MESA/MESA_htable.h>
#include <MESA/stream.h>

#define CONF_NAME "./conf/option_info.conf"
#define CONF_MODULE   "DEVICE_INFO_EXTRACT"

#define MAC_ADDR_LEN 6
#define MAX_LINE_SIZE 256

#define DHCP_MAGIC_NUM 0x63825363

typedef struct{
	char mac[MAC_ADDR_LEN];
	unsigned short sport;
	unsigned short dport;
}base_info_t;

typedef struct{
	UINT8 option_num;
	char * option_name;
	char * option_value;
}dhcp_info_t;

typedef struct{
	char dhcp_option_htable[256][MAX_LINE_SIZE];
	char dhcpv6_option_htable[144][MAX_LINE_SIZE];
	char oui_htable[][MAX_LINE_SIZE];
}g_info_t;

typedef struct{
	int dhcp_discover_num;
	int dhcp_request_num;
	int dhcpv6_pkt_num;
	int mdns_pkt_num;
	int ssdp_search_pkt_num;
	int ssdp_notify_pkt_num;

	MESA_htable_handle dhcp_discover_htable;
	MESA_htable_handle dhcp_request_htable;
	MESA_htable_handle dhcpv6_pkt_htable;
	MESA_htable_handle mdns_pkt_htable;
	MESA_htable_handle llmnr_qname_htable;
	MESA_htable_handle smb_srcname_htable;
	MESA_htable_handle nbns_qname_htable;
	MESA_htable_handle ssdp_search_htable;
	MESA_htable_handle ssdp_notify_htable;
	MESA_htable_handle udp_devname_htable;
}device_info_context_t;

#endif