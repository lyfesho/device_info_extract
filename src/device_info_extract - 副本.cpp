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
	char dhcp_option_path[] = "./support/options.txt";
	char dhcpv6_option_path[] = "./support/dhcpv6_options.txt";
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
	device_info_context_t * pme = (device_info_context_t *)calloc(1, sizeof(device_info_context_t));
	pme->mac = cJSON_CreateObject();
	*param = pme;
	return 0;
}

void handle_dhcp(const void * pdata, cJSON * dhcp_val_arr){
	uint32_t magic_num = 0;
	memcpy(&magic_num, (UINT8 *)pdata + 236, 4);
	if(magic_num == htol(DHCP_MAGIC_NUM)){
		int len = 0;
		UINT8 id = 0;
		UINT8 * temp = (UINT8 *)pdata + 240;

		//extract the first option_id, option_len and option_val
		id = *temp;
		len = *(temp + 1);
		int msg_type = 0;
		if(53 == id){
			memcpy(&msg_type, temp + 2, len);                 //id_value_int
		}

		//if dhcp option is not discover nor request
		if(1 != msg_type || 3 != msg_type){
			return;
		}

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
		int dhcp_arr_size = cJSON_GetArraySize(dhcp_val_arr);
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
	}
}

void handle_dhcpv6(const void * pdata, cJSON * dhcpv6_val_obj, UINT32 datalen){
	UINT8 * temp = (UINT8 *)pdata + 4;
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
	
}

void extract_rr_from_mdns1(const void * pdata, cJSON * rr_val_obj, int num){
	UINT8 * temp = (UINT8 *)pdata + 12;
	for(int i = 0; i < num; i ++){
		UINT8 compress_flag = 0;
		memcpy(&compress_flag, temp, 1);

		UINT8 offset = 0;
		//name being compressed from the beginning
		if (0xc0 == compress_flag){
			memcpy(&offset, temp+1, 1);
			temp = temp + 2;      //make temp point to type
		}
		//name not being compressed from the beginning
		else{ 
			offset = temp;        //if not compressed, then offset is the same as temp; using offset to extract name

			char name[256] = {0}; //!!!-----assume name is smaller than 256 bytes 
			UINT8 len = 0;
			UINT8 old_len = 0;
			old_len = len;   //used for len record
			memcpy(&len, offset, 1);

			while(0x00 != len){
				memcpy(&name[old_len], offset+1, len);
				name[len] = '.';
				
				offset = offset + 1 + len;
				old_len = len + 1;   //name's position
				memcpy(&len, offset, 1);
			}
			
			
		}
	}
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
	snprintf(pkt_key, "packet_%d", mdns_pkt_num);
	
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
	char rr[512] = {0};
	char name[256] = {0}; //!!!---assume name do not have _
	int offset = 0;
	UINT8 len = 0;
	//name
	memcpy(&len, head+offset, 1);
	extract_part_name_from_rr(pdata, offset, name);
	offset = offset + 1 + len + 1; // len string 00
	
	//type
	UINT16 type = 0;
	memcpy(&type, head+offset, 2);  //c0£ºjump c039->39; normal: jump 00
	offset = offset + 2;

	//CLASS
	UINT16 class_flag = 0;
	memcpy(&class_flag, head+offset, 2);

	snprintf(rr, "%s,%d,%d", name, type, class_flag);
	cJSON_AddItemToArray(llmnr_val_arr, cJSON_CreateString(rr));
}

int DEVICE_INFO_EXTRACT_ENTRY(const struct streaminfo * a_udp, void ** param, int thread_seq, const void * raw_pkt){
	device_info_context_t * device_info_context = (device_info_context_t *) * param;

	if (0 > init_device_info_context(&device_info_context)){
		printf("mac layer json init error");
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

		//different protocol
		switch(base_info->dport){
			case 67:
				if (68 == base_info->sport){ //dhcp protocol
					cJSON * protocol;
					cJSON * dhcp;
					cJSON * dhcp_val_arr;
					if(0 != mac_arr_size){
						//iterate all mac_val(i.e. protocols) to find out whether dhcp protocol exists
						for(int i = 0; i < mac_arr_size; i ++){
							protocol = cJSON_GetArrayItem(mac_val_arr, i);
							dhcp = cJSON_GetObjectItem(protocol, "dhcp");
							if(dhcp != NULL){
								break;
							}
						}
					}
					//if dhcp obj not exists
					if (0 == mac_arr_size || NULL == dhcp){
						dhcp = cJSON_CreateObject();
						cJSON_AddItemToArray(mac_val_arr,dhcp); //add dhcp obj to mac_val_arr
						dhcp_val_arr = cJSON_CreateArray();
						cJSON_AddItemToObject(dhcp,"dhcp",dhcp_val_arr); //add dhcp_val_arr to dhcp obj
					}
					handle_dhcp(a_udp->pudpdetail->pdata, dhcp_val_arr);
				}
				else{
					printf("dhcp error");
				}
				break;
			case 547:
				if (546 == base_info->sport){ //dhcpv6 protocol
					cJSON * protocol;
					cJSON * dhcpv6;
					cJSON * dhcpv6_val_obj;
					if(0 != mac_arr_size){
						//find dhcpv6 protocol
						for(int i = 0; i < mac_arr_size; i ++){
							protocol = cJSON_GetArrayItem(mac_arr_size, i);
							dhcpv6 = cJSON_GetObjectItem(protocol, "dhcpv6");
							if(dhcpv6 != NULL){
								break;
							}
						}
					}
					//if dhcpv6 obj not exists
					if(0 == mac_arr_size || NULL == dhcpv6){
						dhcpv6 = cJSON_CreateObject();
						cJSON_AddItemToArray(mac_val_arr, dhcpv6); //add dhcpv6 obj to mac_val_arr
						dhcpv6_val_obj = cJSON_CreateObject();
						cJSON_AddItemToObject(dhcpv6_val_obj, "dhcpv6", dhcpv6_val_obj);
					}
					handle_dhcpv6(a_udp->pudpdetail->pdata, dhcpv6_val_obj, a_udp->pudpdetail->datalen);
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
					
					cJSON * protocol;
					cJSON * mdns;
					cJSON * mdns_val_arr;
					if(0 != mac_arr_size){
						//find mdns protocol from json
						for(int i = 0; i < mac_arr_size; i ++){
							protocol = cJSON_GetArrayItem(mac_val_arr, i);
							mdns = cJSON_GetObjectItem(protocol, "mdns");
							if(mdns != NULL){
								break;
							}
						}
					}
					//if mdns obj is not exists
					if(0 == mac_arr_size || NULL == mdns){
						mdns = cJSON_CreateObject();
						cJSON_AddItemToArray(mac_val_arr, mdns);
						mdns_val_arr = cJSON_CreateArray();
						cJSON_AddItemToObject(mdns, "mdns", mdns_val_arr);
					}
					handle_mdns(a_udp->pudpdetail->pdata, mdns_val_arr, device_info_context->mdns_pkt_num, a_udp->pudpdetail->datalen);
				}
				else{
					printf("mdns error");
				}
				break;
			case 5355:
				if ((a_udp->addr.addrtype == ADDR_TYPE_IPV4 && 0 != strcmp(llmnr_dipv4, a_udp->addr.tuple4_v4->daddr))
					|| (a_udp->addr.addrtype == ADDR_TYPE_IPV6 && 0 != strcmp(llmnr_dipv6, a_udp->addr.tuple4_v6->daddr))){ //llmnr protocol

					cJSON * protocol;
					cJSON * llmnr;
					cJSON * llmnr_val_arr;

					if(0 != mac_arr_size){
						//find llmnr protocol from json
						for(int i = 0; i < mac_arr_size; i ++){
							protocol = cJSON_GetArrayItem(mac_val_arr, i);
							llmnr_val_arr = cJSON_GetObjectItem(protocol, "llmnr");
							if(llmnr_val_arr != NULL){
								break;
							}
						}
					}
					//if llmnr obj is not exists
					if(0 == mac_arr_size || NULL == llmnr){
						llmnr = cJSON_CreateObject();
						cJSON_AddItemToArray(mac_val_arr, llmnr);
						llmnr_val_arr = cJSON_CreateArray();
						cJSON_AddItemToObject(llmnr, "llmnr", llmnr_val_arr);
					}

					handle_llmnr(a_udp->pudpdetail->pdata, llmnr_val_arr);
				}
				else{
					printf("llmnr error");
				}
				break;
			case 138:
				if (a_udp->addr.addrtype == ADDR_TYPE_IPV4 && 0 != strcmp(smb_nbns_dipv4, a_udp->addr.tuple4_v4->daddr)){ //smb protocol

					handle_smb(const void * a_udp->pudpdetail->pdata);
				}
				else{
					printf("smb error");
				}
				break;
			case 137:
				if (a_udp->addr.addrtype == ADDR_TYPE_IPV4 && 0 != strcmp(smb_nbns_dipv4, a_udp->addr.tuple4_v4->daddr)){
					handle_nbns(const void * a_udp->pudpdetail->pdata);
				}
				else{
					printf("nbns error");
				}
				break;
			case 1900:
				if (a_udp->addr.addrtype == ADDR_TYPE_IPV4 && 0 != strcmp(ssdp_dipv4, a_udp->addr.tuple4_v4->daddr)){
					handle_ssdp(const void * a_udp->pudpdetail->pdata);
				}
				else{
					printf("ssdp error");
				}
				break;
			default:
				handle_udp(const void * a_udp->pudpdetail->pdata);
		}
	}
}

int DEVICE_INFO_EXTRACT_INIT(){
	//create three htable
	g_info->dhcp_option_htable = MESA_htable_born();
	MESA_htable_mature(g_info->dhcp_option_htable);

	g_info->dhcpv6_option_htable = MESA_htable_born();
	MESA_htable_mature(g_info->dhcpv6_option_htable);

	g_info->oui_htable = MESA_htable_born();
	MESA_htable_mature(g_info->oui_htable);

	file2hash();
	
	return 0;
}

void DEVICE_INFO_EXTRACT_DESTROY(){}
