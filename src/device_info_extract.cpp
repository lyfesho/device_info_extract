#include "cJSON.h"
#include "device_info_extract.h"

const char * mdns_dipv4 = "224.0.0.251";
const char * mdns_dipv6 = "ff02::fb";
const char * llmnr_dipv4 = "224.0.0.252";
const char * llmnr_dipv6 = "ff02::1:3";
const char * smb_nbns_dipv4 = "192.168.255.255";
const char * ssdp_dipv4 = "239.255.255.250";

cJSON * json_root = cJSON_CreateArray();
g_info_t g_info;

int file2hash(){
	const char * dhcp_option_path = "./support/options.txt";
	const char * dhcpv6_option_path = "./support/dhcpv6_options.txt";
	//char oui_path[] = "./support/oui.txt";
	
	FILE * dhcp_option_file;
	FILE * dhcpv6_option_file;
	//FILE * oui_file;

	dhcp_option_file = fopen(dhcp_option_path, "r");
	dhcpv6_option_file = fopen(dhcpv6_option_path, "r");
	//oui_file = fopen(oui_path, "r");
	
	if (!dhcp_option_file && !dhcpv6_option_file){
		printf("file_open_failed");
		return -1;
	}

	char line[MAX_LINE_SIZE] = {0};

	while(!feof(dhcp_option_file)){
		memset(line, 0, sizeof(line));
		fgets(line, sizeof(line), dhcp_option_file);

		for(int i = 0; i < 256; i ++){
			memcpy(g_info.dhcp_option_htable[i], line, sizeof(line));
		}
	}

	while(!feof(dhcpv6_option_file)){
		memset(line, 0, sizeof(line));
		fgets(line, sizeof(line), dhcpv6_option_file);

		for(int i = 0; i < 144; i ++){
			memcpy(g_info.dhcpv6_option_htable[i], line, sizeof(line));
		}
	}

#if 0
	//need to think the way to store oui key-value pair
	while(!feof(oui_file)){
		memset(line, 0, sizeof(line));
		fgets(line, sizeof(line), oui_file);

		int add_ret;
		add_ret = MESA_htable_add(g_info.oui_htable, (const unsigned char *)line, sizeof(line), NULL);
		if(add_ret <= 0){
			printf("oui_htable add failed");
			return -1;
		}
	}
#endif

	fclose(dhcp_option_file);
	fclose(dhcpv6_option_file);
	//fclose(oui_file);

	return 1;
}

int init_device_info_context(device_info_context_t ** param){
	device_info_context_t * device_info_context = (device_info_context_t *)calloc(1, sizeof(device_info_context_t));
	device_info_context->dhcp_discover_num = 0;
	device_info_context->dhcp_request_num = 0;
	device_info_context->dhcpv6_pkt_num = 0;
	device_info_context->mdns_pkt_num = 0;
	device_info_context->ssdp_search_pkt_num = 0;
	device_info_context->ssdp_notify_pkt_num = 0;

	//hashtable create
	device_info_context->dhcp_discover_htable = MESA_htable_born();
	MESA_htable_mature(device_info_context->dhcp_discover_htable);
	device_info_context->dhcp_request_htable= MESA_htable_born();
	MESA_htable_mature(device_info_context->dhcp_request_htable);
	device_info_context->dhcpv6_pkt_htable = MESA_htable_born();
	MESA_htable_mature(device_info_context->dhcpv6_pkt_htable);
	device_info_context->mdns_pkt_htable= MESA_htable_born();
	MESA_htable_mature(device_info_context->mdns_pkt_htable);
	device_info_context->llmnr_qname_htable= MESA_htable_born();
	MESA_htable_mature(device_info_context->llmnr_qname_htable);
	device_info_context->smb_srcname_htable= MESA_htable_born();
	MESA_htable_mature(device_info_context->smb_srcname_htable);
	device_info_context->nbns_qname_htable= MESA_htable_born();
	MESA_htable_mature(device_info_context->nbns_qname_htable);
	device_info_context->ssdp_search_htable= MESA_htable_born();
	MESA_htable_mature(device_info_context->ssdp_search_htable);
	device_info_context->ssdp_notify_htable= MESA_htable_born();
	MESA_htable_mature(device_info_context->ssdp_notify_htable);
	device_info_context->udp_devname_htable= MESA_htable_born();
	MESA_htable_mature(device_info_context->udp_devname_htable);
	
	*param = pme;
	return 0;
}

void handle_dhcp(const void * pdata, UINT32 datalen, cJSON * dhcp_val_arr, device_info_context_t * device_info_context){
	UINT32 magic_num = 0;
	memcpy(&magic_num, (UINT8 *)pdata + 236, 4);
	if(magic_num == htol(DHCP_MAGIC_NUM)){
		UINT8 len = 0;
		UINT8 id = 0;
		UINT8 * temp = (UINT8 *)pdata + 240;

		//extract the first option_id, option_len and option_val
		memcpy(&id, temp, 1);
		memcpy(&len, temp+1, 1);
		int msg_type = 0;
		if(53 == id){
			memcpy(&msg_type, temp + 2, len);                 //id_value_int
		}

		//if dhcp option is not discover nor request
		if(1 != msg_type || 3 != msg_type){
			return;
		}

		//dhcp option is discover/request -->analyze
		const char * comma = ",";
		UINT32 opt_size = datalen;
		char * opt_str = (char *)calloc(1, opt_size);
		char * opt_tmp = opt_str;
		
		while(255 != id){
			memcpy(&len, temp+1, 1);
			memcpy(opt_tmp, temp, 1);  //copy option_num
			memcpy(opt_tmp+1, comma, 1); //copy comma
			
			if(55 == id){
				temp += 2;
				opt_tmp += 2;
				for(int i = 0; i < len; i ++){
					memcpy(opt_tmp, temp, 1);
					memcpy(opt_tmp+1, comma, 1);
					temp += 1;
					opt_tmp += 2;
				}
			}else{
				memcpy(opt_tmp+2, temp+2, len);//copy option_val
				memcpy(opt_tmp+2+len, comma, 1);//copy comma

				opt_tmp += 2+len+1;
				temp += 2 + len;
			}
			memcpy(&id, temp, 1);
		}

		char type_pkt_key[20] = {0};
		if(1 == id){
			//------TODO:check discover_hash_table
			//if not duplicate

			//how to count the num of pkt in remove duplicate case?????
			device_info_context->dhcp_discover_num += 1;
			snprintf(type_pkt_key, "discover_%d", device_info_context->dhcp_discover_num);			
		}
		else if(3 == id){
			device_info_context->dhcp_request_num += 1;
			snprintf(type_pkt_key, "request_%d", device_info_context->dhcp_request_num);
		}
		//if not duplicate
		cJSON * pkt_obj = cJSON_CreateObject();
		cJSON_AddItemToArray(dhcp_val_arr, pkt_obj);
		cJSON_AddItemToObject(pkt_obj, type_pkt_key, cJSON_CreateString(opt_str));
		
		free(opt_str);
		

#if 0
		cJSON * option; //discover or request
		cJSON * opt_type;
		cJSON * opt_val_obj;
		char opt_type_str[10] = {0};
		if(1 == id){
			opt_type_str = "discover";
		}
		else if(3 == id){
			opt_type_str = "request";
		}

		if(0 != dhcp_arr_size){
			for(int i = 0; i < dhcp_arr_size; i ++){
				option = cJSON_GetArrayItem(dhcp_val_arr, i);
				opt_type = cJSON_GetObjectItem(option, opt_type_str);
				if(NULL != opt_type){
					break;
				}
			}
		}
		if(0 == dhcp_arr_size || NULL == opt_type){
			opt_type = cJSON_CreateObject();
			cJSON_AddItemToArray(dhcp_val_arr,opt_type); //add discover obj to dhcp_val_arr
			opt_val_obj = cJSON_CreateObject();
			cJSON_AddItemToObject(opt_type, opt_type_str, opt_val_obj); //add discover_val to discover obj
		}

		//extract option name and value; then add to opt_val_obj
		while(id != 255){
			len = *(temp + 1);
			char * id_val = (char *)calloc(1, len + 1);
			memcpy(id_val, temp + 2, len);

			//if opt_val_obj do not have certain id
			if(NULL == cJSON_GetObjectItem(opt_val_obj, g_info.dhcp_option_htable[id])){
				cJSON_AddStringToObject(opt_val_obj, g_info.dhcp_option_htable, id_val);
			}

			id = *(temp + 2 + len);
			temp = temp + 2 + len;
		}
#endif
	}
}

void handle_dhcpv6(const void * pdata, UINT32 datalen, cJSON * dhcpv6_arr, device_info_context_t * device_info_context){
	UINT8 * temp = (UINT8 *)pdata + 4;
	UINT16 id = 0;
	memcpy(&id, temp, 2);

	//extract dhcpv6_val
	const char * comma = ",";
	const char * nak = "nak";
	UINT16 len = 0;
	UINT32 opt_size = datalen;
	char * opt_str = (char *)calloc(1, opt_size);
	char * opt_tmp = opt_str;

	UINT32 remain_size = datalen - 4;
	while(remain_size != 0){
		memcpy(&len, temp+2, 2);
		memcpy(opt_tmp, temp, 2);  //copy option_num
		memcpy(opt_tmp+2, comma, 1); //copy comma

		if(0x0027 == id){
			//extract FQDN
			memcpy(opt_tmp+3, temp+4, len);
			memcpy(opt_tmp+3+len, comma, 1);
			opt_tmp += 3 + len + 1; //opt_num:2bytes; comma:1byte; len; comma:1byte
			temp += 4 + len;
		}
		else if(0x0006 == id){
			//extract request list
			opt_tmp += 3;
			temp += 4;
			for(int i = 0; i < len/2; i ++){
				memcpy(opt_tmp, temp, 2);
				memcpy(opt_tmp+2, comma, 1);
				temp += 2;
				opt_tmp += 3;
			}
		}
		else{
			memcpy(opt_tmp+3, nak, 3);
			memcpy(opt_tmp+6, comma, 1);
			opt_tmp += 7; //opt_num:2bytes; comma:1byte; nak:3bytes; comma:1byte
			temp += 4 + len; //opt_num:2bytes; len:2bytes; len_val
		}

		memcpy(&id, temp, 2);
	}

	char pkt_key[10] = {0};
	//------TODO:check discover_hash_table
	//if not duplicate

	//how to count the num of pkt in remove duplicate case?????
	device_info_context->dhcpv6_pkt_num += 1;
	snprintf(pkt_key, "pkt_%d", device_info_context->dhcpv6_pkt_num);			
	//if not duplicate
	cJSON * pkt_obj = cJSON_CreateObject();
	cJSON_AddItemToArray(dhcpv6_arr, pkt_obj);
	cJSON_AddItemToObject(pkt_obj, pkt_key, cJSON_CreateString(opt_str));

	free(opt_str);

#if 0
	UINT16 id = 0;
	id = *temp;
	int len = *(temp + 2);
	while(0 != datalen){
		const char * nak = "nak";
		len = *(temp + 2);
		if(NULL == cJSON_GetObjectItem(dhcpv6_val_obj, g_info.dhcpv6_option_htable[id])){
			cJSON_AddStringToObject(dhcpv6_val_obj, g_info.dhcpv6_option_htable, nak);
		}

		id = *(temp + 4 + len);
		temp = temp + 4 + len;
		datalen = datalen - 4 - len;
	}
#endif
	
}

//using pointer and len to extract part of name
void extract_part_name_from_rr(const void * pdata, int offset, char * part_name){
	UINT8 * temp = (UINT8 *)pdata + offset;
	UINT8 len = 0;
	memcpy(&len, temp, 1);
	memcpy(part_name, temp+1, len);
}

void extract_rr_from_mdns(const void * pdata, cJSON * rr_val_arr, int num, UINT32 pdatalen){
	UINT8 * head = (UINT8 *)pdata;
	UINT8 * temp = NULL;

	char name[256] = {0}; //!!!-----assume name is smaller than 256 bytes 
	char part_name[256] = {0}; //save part of name
	UINT32 offset = 12;

	int rr_cnt = 1;

	while((offset < pdatalen) && (rr_cnt <= num)){

		char rr[512] = {0};
		//char rr_key[10] = {0};
		//snprintf(rr_key, "rr_%d", rr_cnt)
		
		UINT8 len = 0;
		UINT8 old_len = 0;
		old_len = len;
		memcpy(&len, head+offset, 1);
		memset(name, 0, sizeof(name));
	
		while(0x00 != len){
			if(0xc0 == len){
				temp = head+offset+1;
				memcpy(&offset, head+offset+1, 1);
			}
			memcpy(&len, head+offset, 1);
			extract_part_name_from_rr(pdata, offset, part_name);
			memcpy(&name[old_len], part_name, len);
			name[old_len+len] = '.';

			offset = offset + 1 + len;
			old_len = old_len + len + 1; //name's position
			memcpy(&len, head+offset, 1);
		}

		//TYPE
		UINT16 type = 0;
		if(NULL != temp){
			offset = temp;
		}
		memcpy(&type, head+offset+1, 2);  //c0£ºjump c039->39; normal: jump 00

		//CLASS
		UINT16 class_flag = 0;
		offset = offset + 2;
		memcpy(&class_flag, head+offset, 2);

		rr_cnt = rr_cnt + 1;
		offset = offset + 2; //point to the sec record

		snprintf(rr, "%s,%d,%d", name, type, class_flag);

		//cJSON * rr_obj = cJSON_CreateObject();
		//cJSON_AddItemToArray(rr_val_arr, rr_obj);
		cJSON_AddItemToArray(rr_val_arr, cJSON_CreateString(rr));

	}
}


void handle_mdns(const void * pdata, cJSON * mdns_val_arr, int mdns_pkt_num, UINT32 pdatalen){
	char pkt_key[20] = {0};
	snprintf(pkt_key, "pkt_%d", mdns_pkt_num);
	
	cJSON * pkt_obj = cJSON_CreateObject();
	cJSON_AddItemToArray(mdns_val_arr, pkt_obj);
	cJSON * pkt_val_arr = cJSON_CreateArray();
	cJSON_AddItemToObject(pkt_obj, pkt_key, pkt_val_arr); //{"packet_1":[...]}

	UINT8 * temp = (UINT8 *)pdata + 2; //transaction id : 0x0000
	UINT16 flag = 0;
	memcpy(&flag, temp, 2); //flags: 0x0000(query); 0x8400(resposne)
	temp = temp + 2;

	UINT16 question_num = 0;
	UINT16 answer_num = 0;
	UINT16 authority_num = 0;
	UINT16 additional_num = 0;
	memcpy(&question_num, temp, 2);
	memcpy(&answer_num, temp+2, 2);
	memcpy(&authority_num, temp+4, 2);
	memcpy(&additional_num, temp+6, 2);
	temp = temp + 8;

	//query
	if(question_num != 0){
		cJSON * query_obj = cJSON_CreateObject();
		cJSON_AddItemToArray(pkt_val_arr, query_obj);
		cJSON * query_val_arr = cJSON_CreateArray();
		cJSON_AddItemToObject(query_obj, "query", query_val_arr);
		
		extract_rr_from_mdns(pdata, query_val_arr, question_num, pdatalen);
	}

	//answer
	if(answer_num != 0){
		cJSON * answer_obj = cJSON_CreateObject();
		cJSON_AddItemToArray(pkt_val_arr, answer_obj);
		cJSON * answer_val_arr = cJSON_CreateArray();
		cJSON_AddItemToObject(answer_obj, "answer", answer_val_arr);

		extract_rr_from_mdns(pdata, answer_val_arr, answer_num, pdatalen);
	}

	//authority
	if(authority_num != 0){
		cJSON * auth_obj = cJSON_CreateObject();
		cJSON_AddItemToArray(pkt_val_arr, auth_obj);
		cJSON * auth_val_arr = cJSON_CreateArray();
		cJSON_AddItemToObject(auth_obj, "authority", auth_val_arr);

		extract_rr_from_mdns(pdata, auth_val_arr, authority_num, pdatalen);
	}

	//additional
	if(additional_num != 0){
		cJSON * add_obj = cJSON_CreateObject();
		cJSON_AddItemToArray(pkt_val_arr, add_obj);
		cJSON * add_val_arr = cJSON_CreateArray();
		cJSON_AddItemToObject(add_obj, "additional", add_val_arr);

		extract_rr_from_mdns(pdata, add_val_arr, additional_num, pdatalen);
	}

}

void handle_llmnr(const void * pdata, cJSON * llmnr_val_arr){
	UINT8 * head = (UINT8 *)pdata;
	char name[256] = {0}; //!!!---assume name do not have _
	int offset = 0;
	UINT8 len = 0;
	//name
	memcpy(&len, head+offset, 1);
	extract_part_name_from_rr(pdata, offset, name);

	cJSON_AddItemToArray(llmnr_val_arr, cJSON_CreateString(name));
}

void name_decode(char * encoded_name, char * name){
	for(int i = 0; i < 16; i ++){
		name[i] = (encoded_name[2*i]-0x41)<<4 + (encoded_name[2*i+1]-0x41);
	}
}

void handle_smb(const void * pdata, cJSON * smb_arr){
	UINT8 * head = (UINT8 *)pdata;
	char name[32] = {0};
	int offset = 14; //head+offset points to source_name
	UINT8 len = 0;
	memcpy(&len, head+offset, 1);
	offset += 1;
	
	if(len != 0x20){
		printf("warning:smb sourcename more than 16 byte!");
	}
	else{
		char encoded_name[32] = {0};
		memcpy(encoded_name, head+offset, len);
		name_decode(encoded_name, name);
		cJSON_AddItemToArray(smb_arr, cJSON_CreateString(name));
	}
}

void handle_nbns(const void * pdata, cJSON * nbns_arr, int query_num){
	UINT8 * head = (UINT8 *)pdata;
	int offset = 12; //head+offset points to query_rr
	char rr[512] = {0};
	char name[32] = {0};

	UINT8 len = 0;
	memcpy(&len, head+offset, 1);
	offset += 1;
	if(len != 0x20){
		printf("warning:nbns sourcename more than 16 byte!");
	}
	else{
		char encoded_name[32] = {0};
		memcpy(encoded_name, head+offset, len);
		name_decode(encoded_name, name);
		cJSON_AddItemToArray(nbns_arr, cJSON_CreateString(name));
	}	
}

void handle_ssdp(const void * pdata, cJSON * ssdp_arr, device_info_context_t * device_info_context){
	UINT8 * head = (UINT8 *)pdata;
	cJSON * type_obj = cJSON_CreateObject(void);
	//search or notify
	UINT8 flag = 0; //using to classify M(-SEARCH) and N(otify), 4D=M;4E=N
	flag = *pdata;
	if(0x4d == flag){
		device_info_context->ssdp_search_pkt_num += 1;
		char search_key[20] = {0};
		snprintf(search_key, "search_%d", device_info_context->ssdp_search_pkt_num);
		cJSON * search_obj = cJSON_CreateObject();
		cJSON_AddItemToArray(ssdp_arr, search_obj);
		cJSON * search_arr = cJSON_CreateArray();
		cJSON_AddItemToObject(search_obj; search_key, search_arr);
	}
	else if(0x4e == flag){
		device_info_context->ssdp_notify_pkt_num += 1;
		char notify_key[20] = {0};
		snprintf(notify_key, "notify_%d", device_info_context->ssdp_notify_pkt_num);
		cJSON * notify_obj = cJSON_CreateObject();
		cJSON_AddItemToArray(ssdp_arr, notify_obj);
		cJSON * notify_arr = cJSON_CreateArray();
		cJSON_AddItemToObject(notify_obj, notify_key, notify_arr);
	}
	
	
}

void extract_protocol(const struct steaminfo * a_udp, char * protocol, const void * ip_hdr){
	int ret;
	UINT8 * eth_hdr = NULL;
	ret = get_opt_from_rawpkt(a_udp, RAW_PKT_GET_DATA, &eth_hdr);
	if(0 != ret){
		printf("eth_hdr get error");
	}

	memset(protocol, 0, sizeof(protocol));

	UINT16 type = 0;
	memcpy(&type, eth_hdr+12, 2);

	switch(type){
		case 0x0806:
			const char * arp_str = "arp";
			memcpy(protocol, arp_str, 3);
			break;
		case 0x0800:
			type = 0;
			memcpy(&type, ip_hdr+9, 1);
			if(0x02 == type){	
				const char * igmp_str = "igmp";
				memcpy(protocol, igmp_str, 4);
			}else if(0x01 == type){
				const char * icmp_str = "icmp";
				memcpy(protocol, icmp_str, 4);
			}
			break;
		case 0x86dd:
			type = 0;
			memcpy(&type, ip_hdr+16, 1);
			if(0x3a == type){
				//ICMPv6
				const char * icmpv6_str = "icmpv6";
				memcpy(protocol, icmpv6_str, 6);
			}
			break;	
	}
}

int DEVICE_INFO_EXTRACT_ENTRY(const struct streaminfo * a_udp, void ** param, int thread_seq, const void * ip_hdr){
	device_info_context_t * device_info_context = (device_info_context_t *) * param;

	if (0 > init_device_info_context(&device_info_context)){
		printf("context init error");
	}
	
	//is UDP pkt
	if(a_udp->type == 2){
		*param = pme;
		//extract base info
		base_info_t * base_info = (base_info_t*)calloc(1, sizeof(base_info_t));
		if(a_udp->addr.addrtype == ADDR_TYPE_IPV4){
			base_info->sport = ntohs(a_udp->addr.tuple4_v4->source);
			base_info->dport = ntohs(a_udp->addr.tuple4_v4->dest);
		}
		else if(a_udp->addr.addrtype == ADDR_TYPE_IPV6){
			base_info->sport = ntohs(a_udp->addr.tuple4_v6->source);
			base_info->dport = ntohs(a_udp->addr.tuple4_v6->dest);
		}
		memcpy(base_info->mac, a_udp->addr.mac->src_mac, MAC_ADDR_LEN);

		//obtain mac_info_obj
		cJSON * mac_info_obj;
		bool found = 0;
		int mac_num = cJSON_GetArraySize(json_root);
		if(0 != mac_num){
			for(int i = 0; i < mac_num; i ++){
				mac_info_obj = cJSON_GetArrayItem(json_root, i);
				cJSON * mac_string = cJSON_GetObjectItem(mac_info_obj, "mac");
				if(0 == strcmp(mac_string->valuestring, base_info->mac)){
					found = 1;
					break; //certain mac_info exists
				}
			}			
		}
		//if certain mac_info not exists
		if(0 == mac_num || 0 == found){
			mac_info_obj = cJSON_CreateObject();
			cJSON_AddItemToArray(json_root, mac_info_obj);         //create mac_info_obj
			cJSON_AddItemToObject(mac_info_obj, "mac", cJSON_CreateString(base_info->mac)); //add mac to mac_info_obj
		}

		//extract protocol
		char protocol[10] = {0};
		extract_protocol(a_udp, protocol, ip_hdr);

		//different protocol
		switch(base_info->dport){
			case 67:
				if (68 == base_info->sport){ //dhcp protocol
					cJSON * dhcp_arr;
					dhcp_arr = cJSON_GetObjectItem(mac_info_obj, "dhcp");
					if(NULL == dhcp_arr){ //do not have dhcp value
						dhcp_arr = cJSON_CreateArray();
						cJSON_AddItemToObject(mac_info_obj, "dhcp", dhcp_arr);
					}
					handle_dhcp(a_udp->pudpdetail->pdata, a_udp->pudpdetail->datalen, dhcp_arr, device_info_context);
				}
				else{
					printf("dhcp error");
				}
				break;
			case 547:
				if (546 == base_info->sport){ //dhcpv6 protocol
					cJSON * dhcpv6_arr;
					dhcpv6_arr = cJSON_GetObjectItem(mac_info_obj, "dhcpv6");
					if(NULL == dhcpv6_arr){
						dhcpv6_arr = cJSON_CreateArray();
						cJSON_AddItemToObject(mac_info_obj, "dhcpv6", dhcpv6_arr);
					}
					handle_dhcpv6(a_udp->pudpdetail->pdata, a_udp->pudpdetail->datalen, dhcpv6_arr, device_info_context);
				}
				else{
					printf("dhcpv6 error");
				}
				break;
			case 5353:
				if ((a_udp->addr.addrtype == ADDR_TYPE_IPV4 && 0 != strcmp(mdns_dipv4, a_udp->addr.tuple4_v4->daddr))
					|| (a_udp->addr.addrtype == ADDR_TYPE_IPV6 && 0 != strcmp(mdns_dipv6, a_udp->addr.tuple4_v6->daddr))){ //mdns protocol
					//count for mdns_pkt_num
					device_info_context->mdns_pkt_num += 1;

					cJSON * mdns_arr;
					mdns_arr = cJSON_GetObjectItem(mac_info_obj, "mdns");
					if(NULL == mdns_arr){
						mdns_arr = cJSON_CreateArray();
						cJSON_AddItemToObject(mac_info_obj, "mdns", mdns_arr);
					}
					handle_mdns(a_udp->pudpdetail->pdata, mdns_arr, device_info_context->mdns_pkt_num, a_udp->pudpdetail->datalen);
				}
				else{
					printf("mdns error");
				}
				break;
			case 5355:
				if ((a_udp->addr.addrtype == ADDR_TYPE_IPV4 && 0 != strcmp(llmnr_dipv4, a_udp->addr.tuple4_v4->daddr))
					|| (a_udp->addr.addrtype == ADDR_TYPE_IPV6 && 0 != strcmp(llmnr_dipv6, a_udp->addr.tuple4_v6->daddr))){ //llmnr protocol

					cJSON * llmnr_arr;
					llmnr_arr = cJSON_GetObjectItem(mac_info_obj, "llmnr");
					if(NULL == llmnr_arr){
						llmnr_arr = cJSON_CreateArray();
						cJSON_AddItemToObject(mac_info_obj, "llmnr", llmnr_arr);
					}

					handle_llmnr(a_udp->pudpdetail->pdata, llmnr_arr);
				}
				else{
					printf("llmnr error");
				}
				break;
			case 138:
				if (a_udp->addr.addrtype == ADDR_TYPE_IPV4 && 0 != strcmp(smb_nbns_dipv4, a_udp->addr.tuple4_v4->daddr)){ //smb protocol

					cJSON * smb_arr;
					smb_arr = cJSON_GetObjectItem(mac_info_obj, "smb");
					if(NULL == smb_arr){
						smb_arr = cJSON_CreateArray();
						cJSON_AddItemToObject(mac_info_obj, "smb", smb_arr);
					}
					
					handle_smb(a_udp->pudpdetail->pdata, smb_arr);
				}
				else{
					printf("smb error");
				}
				break;
			case 137:
				if (a_udp->addr.addrtype == ADDR_TYPE_IPV4 && 0 != strcmp(smb_nbns_dipv4, a_udp->addr.tuple4_v4->daddr)){ //nbns protocol
					//whether is a query pkt
					UINT16 query_num = 0;
					memcpy(&query_num, (UINT8 *)a_udp->pudpdetail->pdata+4, 2);
					if(0 != query_num){
						cJSON * nbns_arr;
						nbns_arr = cJSON_GetObjectItem(mac_info_obj, "nbns");
						if(NULL == nbns_arr){
							nbns_arr = cJSON_CreateArray();
							cJSON_AddItemToObject(mac_info_obj, "nbns", nbns_arr);
						}

						handle_nbns(a_udp->pudpdetail->pdata, nbns_arr, query_num);
					}
				}
				else{
					printf("nbns error");
				}
				break;
			case 1900:
				if (a_udp->addr.addrtype == ADDR_TYPE_IPV4 && 0 != strcmp(ssdp_dipv4, a_udp->addr.tuple4_v4->daddr)){ //ssdp protocol
					//!!!---Assume all types of ssdp pkts are {search, notify}.  if not, arr of ssdp val will be NULL
					cJSON * ssdp_arr;
					ssdp_arr = cJSON_GetObjectItem(mac_info_obj, "ssdp");
					if(NULL == ssdp_arr){
						ssdp_arr = cJSON_CreateArray();
						cJSON_AddItemToObject(mac_info_obj, "ssdp", ssdp_arr);
					}
					
					handle_ssdp(a_udp->pudpdetail->pdata, ssdp_arr, device_info_context);
				}
				else{
					printf("ssdp error");
				}
				break;
			default:
				UINT8 * head = (UINT8 *)a_udp->pudpdetail->pdata;
				UINT8 * device_name_offset = NULL;
				device_name_offset = (UINT8 *)strstr(head, "DEVICE_NAME=");
				//if "DEVICE_NAME" in udp data
				if(NULL != device_name_offset){

					device_name_offset += 12; //get device name val
					
					//obtain string val
					UINT8 flag = 0;   //whether 0a
					UINT8 * tmp = device_name_offset;
					int device_name_len = 0;
					char device_name[128] = {0};
					memcpy(&flag, head+tmp, 1);
					while(0x0a != flag){
						device_name_len += 1;
						tmp += 1;
						memcpy(&flag, head+tmp, 1);
					}

					memcpy(device_name, head+device_name_offset, device_name_len);

					//add to json obj
					cJSON * device_name_arr = cJSON_GetObjectItem(mac_info_obj, "udp");   //!!!---assume only one device name
					if(NULL == device_name_arr){
						device_name_arr = cJSON_CreateArray();
						cJSON_AddItemToArray(device_name_arr, device_name);
					}
				}
		}

		
	}
}

int DEVICE_INFO_EXTRACT_INIT(){

	file2hash();
	
	return 0;
}

void DEVICE_INFO_EXTRACT_DESTROY(){}
