#include "cJSON.h"
#include "device_info_extract.h"

const char * mdns_dipv4 = "224.0.0.251";
const char * mdns_dipv6 = "ff02::fb";
const char * llmnr_dipv4 = "224.0.0.252";
const char * llmnr_dipv6 = "ff02::1:3";
const char * smb_nbns_dipv4 = "192.168.255.255";
const char * ssdp_dipv4 = "239.255.255.250";

const char * np = "_nextpacket_";  //12bytes
const char * nr = "_nextRR_";  //8bytes

cJSON * json_root = cJSON_CreateArray();

void add_series_2_json(cJSON * ptcl_obj, char * series){
	char * series_sub_ptr = NULL;
	cJSON * exist_series = cJSON_GetObjectItem(ptcl_obj, "series");
	if(NULL == exist_series){
		cJSON_AddItemToObject(ptcl_obj, "series", exist_series);
	}
	else{
		//check whether value of certain have id_str
		series_sub_ptr = memmem(exist_series->valuestring, strlen(exist_series->valuestring), series, strlen(series);
		if(NULL == series_sub_ptr || '_' != *(series_sub_ptr+strlen(series)) || 0 != *(series_sub_ptr+strlen(series))){
			//certain existed_id_val do not have id_val
			char * new_str = (char *)calloc(1, strlen(exist_series->valuestring) + strlen(series) + 16);
			snprintf(new_str, "%s%s%s", exist_series->valuestring, np, cJSON_CreateString(series));

			//replace old to new
			cJSON_ReplaceItemInObject(ptcl_obj, "series", new_str);
			free(new_str);
		}
	}
}

void handle_dhcp(const void * pdata, UINT32 datalen, cJSON * dhcp_obj){
	UINT32 magic_num = 0;
	const char * comma = ",";
	memcpy(&magic_num, (UINT8 *)pdata + 236, 4);
	if(magic_num == htol(DHCP_MAGIC_NUM)){
		UINT8 len = 0;
		UINT8 id = 0;
		char id_str[4] = {0};
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

		//dhcp option is discover/request -> execute
		cJSON * type_obj = NULL;
		char * series = (char *)calloc(1, (datalen-240)*sizeof(char));
		char * series_tmp = series;
		
		if(1 == id){
			type_obj = cJSON_GetObjectItem(type_obj, "discover");
			if(NULL == type_obj){
				type_obj = cJSON_CreateObject();
				cJSON_AddItemToObject(dhcp_obj, "discover", type_obj);
			}
		}
		else if(3 == id){
			type_obj = cJSON_GetObjectItem(dhcp_obj, "request");
			if(NULL == type_obj){
				type_obj = cJSON_CreateObject();
				cJSON_AddItemToObject(dhcp_obj, "request", type_obj);
			}
		}

		//extract option name and value; then add to opt_val_obj
		while(id != 255){
			//write to series
			memcpy(series_tmp, temp, 1);
			memcpy(series_tmp+1, comma, 1);
			series_tmp += 2;
			
			len = *(temp + 1);

			//extract id_val
			char * req_list = (char *)calloc(1, 64*sizeof(char));
			char * req_ptr = req_list;
			if(55 == id){
				temp += 2;
				for(int i = 0; i < len; i ++){
					memcpy(req_list, temp, 1);
					memcpy(req_list+1, comma, 1);
					temp += 1;
					req_list += 2;
				}
			}
			char * id_val = (char *)calloc(1, len + 1);
			if(55 != id){
				memcpy(id_val, temp + 2, len);        
			}
			
			//judge if is duplicated
			cJSON * exist_id;
			exist_id = cJSON_GetObjectItem(type_obj, id_str);
			char * substr_ptr = NULL;
			//if type_obj do not have certain id: add key-value
			if(NULL == exist_id){
				cJSON_AddItemToObject(type_obj, id_str, cJSON_CreateString(id_val));
			}
			else{
				//check whether value of certain have id_str
				substr_ptr == memmem(exist_id->valuestring, strlen(exist_id->valuestring), id_val, strlen(id_val));
				if(NULL == substr_ptr){
					//certain existed_id_val do not have id_val
					char * new_id_str = (char *)calloc(1, strlen(exist_id->valuestring) + strlen(id_val) + 16);
					snprintf(new_id_str, "%s%s%s", exist_id->valuestring, np, cJSON_CreateString(id_val));

					//replace old to new
					cJSON_ReplaceItemInObject(type_obj, id_str, new_id_str);
					free(new_id_str);
				}
				else if(55 == id){
					if('_' != *(substr_ptr+strlen(id_val)) || 0 != *(substr_ptr+strlen(id_val))){
						//not duplicated, need to be added
						char * new_id_str = (char *)calloc(1, strlen(exist_id->valuestring) + strlen(req_list) + 16);
						snprintf(new_id_str, "%s%s%s", exist_id->valuestring, np, req_list);

						//replace old to new
						cJSON_ReplaceItemInObject(type_obj, id_str, cJSON_CreateString(new_id_str));
					}
				}
			}			

			free(req_list);
			free(id_val);
			
			id = *(temp + 2 + len);
			temp = temp + 2 + len;

			if(255 == id){
				memcpy(series_tmp, temp, 1);
			}
		}

		add_series_2_json(type_obj, series)
		free(series);

	}
}

void handle_dhcpv6(const void * pdata, UINT32 datalen, cJSON * dhcpv6_obj){
	UINT8 * temp = (UINT8 *)pdata + 4;
	UINT16 id = 0;
	char id_str[5] = {0};
	memcpy(&id, temp, 2);

	//extract dhcpv6_val
	const char * comma = ",";
	const char * nak = "nak";
	UINT16 len = 0;
	UINT32 opt_size = datalen;

	char * para_list = (char *)calloc(1, opt_size);
	char * para_tmp = para_list;

	char * fqdn = (char *)calloc(1, opt_size);

	char * series = (char *)calloc(1, opt_size);
	char * series_tmp = series;

	UINT32 remain_size = datalen - 4;
	while(remain_size != 0){
		memcpy(&len, temp+2, 2);
		memcpy(id_str, temp, 2);  //copy option_num to id_str

		//write to series
		memcpy(series_tmp, temp, 2);
		memcpy(series_tmp+2, comma, 1);
		series_tmp += 3;

		if(0x0027 == id){
			//extract FQDN
			memcpy(fqdn, temp+4, len);
			memcpy(fqdn+len, comma, 1);
			temp += 4 + len;
			remain_size = remain_size - 4 - len;

			//add to json
			cJSON * exist_fqdn = cJSON_GetObjectItem(dhcpv6_obj, id_str);
			if(NULL == exist_fqdn){
				cJSON_AddItemToObject(dhcpv6_obj, id_str, fqdn);
			}
			else{
				//check whether value of certain have id_str
				if(NULL == memmem(exist_fqdn->valuestring, strlen(exist_fqdn->valuestring), fqdn, strlen(fqdn)){
					//certain existed_id_val do not have id_val
					char * new_id_str = (char *)calloc(1, strlen(exist_fqdn->valuestring) + strlen(fqdn) + 16);
					snprintf(new_id_str, "%s%s%s", exist_fqdn->valuestring, np, cJSON_CreateString(fqdn));

					//replace old to new
					cJSON_ReplaceItemInObject(dhcpv6_obj, id_str, new_id_str);
					free(new_id_str);
				}
			}
		}
		else if(0x0006 == id){
			//extract request list
			temp += 4;
			remain_size -= 4;
			for(int i = 0; i < len/2; i ++){
				memcpy(para_tmp, temp, 2);
				memcpy(para_tmp+2, comma, 1);
				temp += 2;
				remain_size -= 4;
				para_tmp += 3;
			}

			char * substr_ptr = NULL;
			//add to json
			cJSON * exist_para_list = cJSON_GetObjectItem(dhcpv6_obj, id_str);
			if(NULL == exist_para_list){
				cJSON_AddItemToObject(dhcpv6_obj, id_str, para_list);
			}
			else{
				//check whether value of certain have id_str
				substr_ptr = memmem(exist_para_list->valuestring, strlen(exist_para_list->valuestring), para_list, strlen(para_list);
				if(NULL == substr_ptr || '_' == *(substr_ptr+strlen(para_list)) || 0 == *(substr_ptr+strlen(para_list))){
					//certain existed_id_val do not have id_val
					char * new_str = (char *)calloc(1, strlen(exist_para_list->valuestring) + strlen(para_list) + 16);
					snprintf(new_str, "%s%s%s", exist_para_list->valuestring, np, cJSON_CreateString(para_list));

					//replace old to new
					cJSON_ReplaceItemInObject(dhcpv6_obj, id_str, new_str);
					free(new_str);
				}
			}
		}
		else{
			cJSON_AddItemToObject(dhcpv6_obj, id_str, cJSON_CreateString(nak));
			temp += 4 + len; //opt_num:2bytes; len:2bytes; len_val
			remain_size  = remain_size - 4 - len;
		}

		memcpy(&id, temp, 2);

		if(0 == remain_size){
			memcpy(series_tmp, temp, 2);
		}
	}

	add_series_2_json(dhcpv6_obj, series)
	free(para_list);
	free(fqdn);
	free(series);
	
}

//using pointer and len to extract part of name
void extract_part_name_from_rr(const void * pdata, int offset, char * part_name){
	UINT8 * temp = (UINT8 *)pdata + offset;
	UINT8 len = 0;
	memcpy(&len, temp, 1);
	memcpy(part_name, temp+1, len);
}

void extract_rr_from_mdns(const void * pdata, cJSON * type_obj, int num, UINT32 pdatalen){
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

		if(offset == pdatalen){
			snprintf(rr, "%s,%d,%d", name, type, class_flag);
		}
		else if(offset < pdatalen){
			snprintf(rr, "%s,%d,%d%s", name, type, class_flag, nr);
		}
	
	}
}


void handle_mdns(const void * pdata, cJSON * mdns_obj, UINT32 pdatalen){
	UINT8 * temp = (UINT8 *)pdata + 2; //transaction id : 0x0000
	UINT16 flag = 0;
	memcpy(&flag, temp, 2); //flags: 0x0000(query); 0x8400(resposne)
	temp = temp + 2;

	cJSON * type_obj;
	if(0x0000 == flag){
		type_obj = cJSON_GetObjectItem(mdns_obj, "query");
		if(NULL == type_obj){
			type_obj = cJSON_CreateObject();
			cJSON_AddItemToObject(mdns_obj, "query", type_obj);
		}
	}
	else if(0x8400 == flag){
		type_obj = cJSON_GetObjectItem(mdns_obj, "response");
		if(NULL == type_obj){
			type_obj = cJSON_CreateObject();
			cJSON_AddItemToObject(mdns_obj, "response", type_obj);
		}
	}

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
		extract_rr_from_mdns(pdata, type_obj, question_num, pdatalen);
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

void handle_llmnr(const void * pdata, cJSON * mac_info_obj){
	UINT8 * head = (UINT8 *)pdata;
	int offset = 12;
	char name[64] = {0};   //!!!---assume do not have _
	//name
	extract_part_name_from_rr(pdata, offset, name);

	cJSON * llmnr_val;
	llmnr_val = cJSON_GetObjectItem(mac_info_obj, "llmnr");
	if(NULL == llmnr_val){
		cJSON_AddItemToObject(mac_info_obj, "llmnr", cJSON_CreateString(name));
	}
	else{
		//if not duplicated:
		if(NULL == memmem(llmnr_val->valuestring, strlen(llmnr_val->valuestring), name, sizeof(name))){
			char * new_llmnr_str = (char *)calloc(1, strlen(llmnr_val->valuestring)+sizeof(name)+16);
			snprintf(new_llmnr_str, "%s%s%s", llmnr_val->valuestring, np, name);
			cJSON_ReplaceItemInObject(mac_info_obj, "llmnr", cJSON_CreateString(new_llmnr_str));
			free(new_llmnr_str);
		}
	}
}

//Input:encoded name; Output:decoded name
void name_decode(char * encoded_name, char * name){
	for(int i = 0; i < 16; i ++){
		name[i] = (encoded_name[2*i]-0x41)<<4 + (encoded_name[2*i+1]-0x41);
	}
}

void handle_smb(const void * pdata, cJSON * mac_info_obj){
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
	}

	//add to cjson
	cJSON * smb_val;
	smb_val = cJSON_GetObjectItem(mac_info_obj, "smb");
	if(NULL == smb_val){
		cJSON_AddItemToObject(mac_info_obj, "smb", cJSON_CreateString(name));
	}
	else{
		//if not duplicated->replace
		if(NULL == memmem(smb_val->valuestring, strlen(smb_val->valuestring), name, sizeof(name))){
			char * new_smb_str = (char *)calloc(1, strlen(smb_val->valuestring)+sizeof(name)+16);
			snprintf(new_smb_str, "%s%s%s", smb_val->valuestring, np, name);
			cJSON_ReplaceItemInObject(mac_info_obj, "smb", cJSON_CreateString(new_smb_str));
			free(new_smb_str);
		}
	}
}

void handle_nbns(const void * pdata, cJSON * mac_info_obj){
	UINT8 * head = (UINT8 *)pdata;
	int offset = 12; //head+offset points to query_rr
	char rr[512] = {0};
	char name[32] = {0}; //!!!---Assume ssdp only 1 queryname

	UINT8 len = 0;
	memcpy(&len, head+offset, 1);
	offset += 1;
	if(len != 0x20){
		printf("warning:nbns queryname more than 16 byte!");
	}
	else{
		char encoded_name[32] = {0};
		memcpy(encoded_name, head+offset, len);
		name_decode(encoded_name, name);
	}	

	//add to cjson
	cJSON * nbns_val;
	nbns_val = cJSON_GetObjectItem(mac_info_obj, "nbns");
	if(NULL == nbns_val){
		cJSON_AddItemToObject(mac_info_obj, "nbns", cJSON_CreateString(name));
	}
	else{
		//if not duplicated->replace
		if(NULL == memmem(nbns_val->valuestring, strlen(nbns_val->valuestring), name, sizeof(name))){
			char * new_nbns_str = (char *)calloc(1, strlen(nbns_val->valuestring)+sizeof(name)+16);
			snprintf(new_nbns_str, "%s%s%s", nbns_val->valuestring, np, name);
			cJSON_ReplaceItemInObject(mac_info_obj, "nbns", cJSON_CreateString(new_nbns_str));
			free(new_nbns_str);
		}
	}
}

void handle_ssdp(const void * pdata, UINT32 datalen, cJSON * ssdp_obj){
	UINT8 * head = (UINT8 *)pdata;
	cJSON * type_obj;
	//search or notify
	UINT8 flag = 0; //using to classify M(-SEARCH) and N(otify), 4D=M;4E=N
	flag = *pdata;

	//val item extract: split by 0d0a
	char * val = (char *)calloc(1, datalen*sizeof(char)+1);
	memcpy(val, head, datalen);
	char * p_item = strtok(val, "\r\n");
	while(p_item != NULL){
		
	}
	free(val);
	
	if(0x4d == flag){ //search
		type_obj = cJSON_GetObjectItem(ssdp_obj, "search");
		if(NULL == type_obj){
			type_obj = cJSON_CreateObject();
			cJSON_AddItemToObject(type_obj, "search", type_obj);
		}
		else{
			
		}
		
		device_info_context->ssdp_search_pkt_num += 1;
		char search_key[20] = {0};
		snprintf(search_key, "search_%d", device_info_context->ssdp_search_pkt_num);
		cJSON * search_obj = cJSON_CreateObject();
		cJSON_AddItemToArray(ssdp_arr, search_obj);
		cJSON * search_arr = cJSON_CreateArray();
		cJSON_AddItemToObject(search_obj; search_key, search_arr);
	}
	else if(0x4e == flag){ //notify
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
					cJSON * dhcp_obj;
					dhcp_obj = cJSON_GetObjectItem(mac_info_obj, "dhcp");
					if(NULL == dhcp_obj){ //do not have dhcp value
						dhcp_obj = cJSON_CreateObject();
						cJSON_AddItemToObject(mac_info_obj, "dhcp", dhcp_obj);
					}
					handle_dhcp(a_udp->pudpdetail->pdata, a_udp->pudpdetail->datalen, dhcp_obj);
				}
				else{
					printf("dhcp error");
				}
				break;
			case 547:
				if (546 == base_info->sport){ //dhcpv6 protocol
					cJSON * dhcpv6_obj;
					dhcpv6_obj = cJSON_GetObjectItem(mac_info_obj, "dhcpv6");
					if(NULL == dhcpv6_obj){
						dhcpv6_obj = cJSON_CreateObject();
						cJSON_AddItemToObject(mac_info_obj, "dhcpv6", dhcpv6_obj);
					}
					handle_dhcpv6(a_udp->pudpdetail->pdata, a_udp->pudpdetail->datalen, dhcpv6_obj);
				}
				else{
					printf("dhcpv6 error");
				}
				break;
			case 5353:
				if ((a_udp->addr.addrtype == ADDR_TYPE_IPV4 && 0 != strcmp(mdns_dipv4, a_udp->addr.tuple4_v4->daddr))
					|| (a_udp->addr.addrtype == ADDR_TYPE_IPV6 && 0 != strcmp(mdns_dipv6, a_udp->addr.tuple4_v6->daddr))){ //mdns protocol

					cJSON * mdns_obj;
					mdns_obj = cJSON_GetObjectItem(mac_info_obj, "mdns");
					if(NULL == mdns_obj){
						mdns_obj = cJSON_CreateObject();
						cJSON_AddItemToObject(mac_info_obj, "mdns", mdns_obj);
					}
					handle_mdns(a_udp->pudpdetail->pdata, mdns_obj, a_udp->pudpdetail->datalen);
				}
				else{
					printf("mdns error");
				}
				break;
			case 5355:
				if ((a_udp->addr.addrtype == ADDR_TYPE_IPV4 && 0 != strcmp(llmnr_dipv4, a_udp->addr.tuple4_v4->daddr))
					|| (a_udp->addr.addrtype == ADDR_TYPE_IPV6 && 0 != strcmp(llmnr_dipv6, a_udp->addr.tuple4_v6->daddr))){ //llmnr protocol

					handle_llmnr(a_udp->pudpdetail->pdata, mac_info_obj);
				}
				else{
					printf("llmnr error");
				}
				break;
			case 138:
				if (a_udp->addr.addrtype == ADDR_TYPE_IPV4 && 0 != strcmp(smb_nbns_dipv4, a_udp->addr.tuple4_v4->daddr)){ //smb protocol

					handle_smb(a_udp->pudpdetail->pdata, mac_info_obj);
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
						handle_nbns(a_udp->pudpdetail->pdata, mac_info_obj, query_num);
					}
				}
				else{
					printf("nbns error");
				}
				break;
			case 1900:
				if (a_udp->addr.addrtype == ADDR_TYPE_IPV4 && 0 != strcmp(ssdp_dipv4, a_udp->addr.tuple4_v4->daddr)){ //ssdp protocol
					//!!!---Assume all types of ssdp pkts are {search, notify}.  if not, arr of ssdp val will be NULL
					cJSON * ssdp_obj;
					ssdp_obj = cJSON_GetObjectItem(mac_info_obj, "ssdp");
					if(NULL == ssdp_obj){
						ssdp_obj = cJSON_CreateObject();
						cJSON_AddItemToObject(mac_info_obj, "ssdp", ssdp_obj);
					}
					
					handle_ssdp(a_udp->pudpdetail->pdata, a_udp->pudpdetail->datalen, ssdp_obj);
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
					cJSON * udp_val = cJSON_GetObjectItem(mac_info_obj, "udp");   //!!!---assume only one device name
					
					//add to cjson
					if(NULL == udp_val){
						cJSON_AddItemToObject(mac_info_obj, "udp", cJSON_CreateString(device_name));
					}
					else{
						//if not duplicated->replace
						if(NULL == memmem(udp_val->valuestring, strlen(udp_val->valuestring), device_name, sizeof(device_name))){
							char * new_udp_str = (char *)calloc(1, strlen(udp_val->valuestring)+sizeof(device_name)+16);
							snprintf(new_udp_str, "%s%s%s", udp_val->valuestring, np, device_name);
							cJSON_ReplaceItemInObject(mac_info_obj, "udp", cJSON_CreateString(device_name));
							free(new_udp_str);
						}
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
