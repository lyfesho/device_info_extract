import json
import re
import pandas as pd
import csv
import os

seperator = '|'
file_name = './pcap_data/0324-fugang-royalhotel'
csv_file = './support/knowledge.csv'
output_json_name = 'train_data671.json'
output_csv_name = 'result671.csv'

#read files from dir
def iter_dir():
    path = ""

def find_mac_obj(json_root_arr, mac):
    for json_pkt_obj in json_root_arr:
        if(json_pkt_obj['mac'] == mac):
            return json_pkt_obj
    #create mac_obj and add to json_root_arr
    json_pkt_obj = {}
    json_pkt_obj['mac'] = mac
    json_root_arr.append(json_pkt_obj)
    return json_pkt_obj

def extract_ptcl(layer_obj):
    frame_obj = layer_obj['frame']
    ptcl_str = frame_obj['frame.protocols']
    ptcl = ptcl_str.split(':')[-1]
    if ('data' == ptcl) and ('udp' in layer_obj):
        dst_port = layer_obj['udp']['udp.dstport']
        ptcl = 'udp_' + dst_port
    elif ('data' == ptcl):
        ptcl = ptcl_str.split(':')[-2]
    return ptcl

def gene_ptcl_obj(json_pkt_obj, ptcl):
    if 'protocol' in json_pkt_obj:
        ptcl_str = json_pkt_obj['protocol']
        json_pkt_obj['protocol'] = ptcl_str + ',' + ptcl
    else:
        json_pkt_obj['protocol'] = ptcl

#2 layer:     "ssdp":{...}
def add_ptcl_obj(json_pkt_obj, ptcl):
    if ptcl in json_pkt_obj:
        return
    else:
        ptcl_obj = {}
        json_pkt_obj[ptcl] = ptcl_obj


#suit for llmnr/nbns/smb
def add_ptcl_val(json_pkt_obj, ptcl, val):
    if ptcl in json_pkt_obj:
        ptcl_str = json_pkt_obj[ptcl]
        if(-1 == ptcl_str.find(val)):
            json_pkt_obj[ptcl] = ptcl_str + '_nextpacket_' + val
    else:
        json_pkt_obj[ptcl] = val

def add_mdns_rrs(layer_obj, key):
    val = ''
    if type(layer_obj['mdns'][key]) == str:
        if ('' != layer_obj['mdns'][key]):
            val = layer_obj['mdns'][key]
        return val
    keys = layer_obj['mdns'][key].keys()
    model = ''
    for rr_key in keys:
        if not val:
            val = rr_key.replace(':', seperator).replace('.', seperator).replace(',', seperator)
        else:
            val = val + '_nextrr_' + rr_key.replace(':', seperator).replace('.', seperator).replace(',', seperator)
        
        if 'dns.resp.type' in layer_obj['mdns'][key][rr_key]:
            if '16' == layer_obj['mdns'][key][rr_key]['dns.resp.type']:
                txt_list = []
                for rr_val_key in layer_obj['mdns'][key][rr_key].keys():
                    txt_list.append(rr_val_key)
                txt_list.sort()
                for txt_key in txt_list:
                    if ('dns.txt' in txt_key) and ('dns.txt.length' not in txt_key):
                        #print(layer_obj['mdns'][key][rr_key][txt_key])
                        val = val + seperator + layer_obj['mdns'][key][rr_key][txt_key]        
                        if 'model=' in layer_obj['mdns'][key][rr_key][txt_key]:
                            model = layer_obj['mdns'][key][rr_key][txt_key].split('=')[1]
    if model:
        val = val + '&&' + model
    return val

def add_list_val(json_obj, key, val):
    if key in json_obj:
        key_str = json_obj[key]
        ptn1 = "_" + val + "_"
        ptn2 = "_" + val + "$"
        ptn3 = "^" + val + "_"
        ptn4 = "^" + val + "$"
        if (not re.search(ptn1, key_str)) and (not re.search(ptn2, key_str)) and (not re.search(ptn3, key_str)) and (not re.search(ptn4, key_str)):
            json_obj[key] = key_str + '_nextpacket_' + val
    else:
        json_obj[key] = val

#for dhcpv6
def req_list2comma_list(raw_list):
    new_str = ''
    nums = raw_list.split(':')
    for i in range(int(len(nums)/2)):
        temp = nums[i*2] + nums[i*2+1]     
        temp_num = int(temp, 16)
        if not new_str:
            new_str = str(temp_num)
        else:
            new_str = new_str + ',' + str(temp_num)
    return new_str

#for dhcp
def dhcp_req_list2comma_list(raw_list):
    new_str = ''
    nums = raw_list.split(':')
    for i in range(int(len(nums))):
        temp = nums[i] 
        temp_num = int(temp, 16)
        if not new_str:
            new_str = str(temp_num)
        else:
            new_str = new_str + ',' + str(temp_num)
    return new_str

#for udp
def hex_str2char_str(raw_list):
    new_str = ''
    nums = raw_list.split(':')
    for i in range(int(len(nums))):
        temp = nums[i]
        temp_num = int(temp, 16)
        temp_chr = chr(temp_num)
        if not new_str:
            new_str = temp_chr
        else:
            new_str = new_str + temp_chr
    return new_str

def extract_mdns_dot1(raw_str):
    new_str = ''
    packet_list = raw_str.split('_nextpacket_')
    for pkt in packet_list:
        rr_list = pkt.split('_nextrr_')
        for rr in rr_list:
            if not new_str:
                new_str = rr.split(seperator)[0]
            elif (rr.split(seperator)[0] not in new_str):
                new_str = new_str + ',' + rr.split(seperator)[0]
    return new_str

def mac_gene_feature(json_mac_obj, resolved_mac, model):
    if 'feature_label' not in json_mac_obj:
        json_mac_obj['feature_label'] = {}
    json_feature = json_mac_obj['feature_label']
    json_feature['vendor'] = resolved_mac.split('_')[0]
    if 'dhcp' in json_mac_obj:
        if 'request' in json_mac_obj['dhcp']:
            if '12' in json_mac_obj['dhcp']['request']:
                json_feature['dhcp_hostname'] = json_mac_obj['dhcp']['request']['12']
            if '60' in json_mac_obj['dhcp']['request']:
                json_feature['dhcp_vendorclass'] = json_mac_obj['dhcp']['request']['60']
            if '77' in json_mac_obj['dhcp']['request']:
                mod_name = re.findall(r".*Mod=(.+?)\n.*", json_mac_obj['dhcp']['request']['77'])  
                if mod_name:
                    json_feature['dhcp_userclass'] = mod_name[0]
        if 'discover' in json_mac_obj['dhcp']:
            if '12' in json_mac_obj['dhcp']['discover']:
                json_feature['dhcp_hostname'] = json_mac_obj['dhcp']['discover']['12']
            if '60' in json_mac_obj['dhcp']['discover']:
                json_feature['dhcp_vendorclass'] = json_mac_obj['dhcp']['discover']['60']
            if '77' in json_mac_obj['dhcp']['discover']:
                mod_name = re.findall(r".*Mod=(.+?)\n.*", json_mac_obj['dhcp']['discover']['77'])  
                if mod_name:
                    json_feature['dhcp_userclass'] = mod_name[0]
        if ('ack' in json_mac_obj['dhcp']) or ('offer' in json_mac_obj['dhcp']):
            json_feature['dhcp_router'] = 'router'     
    if 'dhcpv6' in json_mac_obj:
        if '39' in json_mac_obj['dhcpv6']:
            json_feature['dhcpv6'] = json_mac_obj['dhcpv6']['39']
    if 'mdns' in json_mac_obj:
        if 'response' in json_mac_obj['mdns']:
            if 'answer' in json_mac_obj['mdns']['response']:
                raw_q_str = json_mac_obj['mdns']['response']['answer'] #query:query, response:answer
                q_name = extract_mdns_dot1(raw_q_str)
                json_feature['mdns_name'] = q_name
        if model:
            json_feature['mdns_model'] = model
    if 'llmnr' in json_mac_obj:
        json_feature['llmnr'] = re.sub(r'_nextpacket_|_nextrr_', ',', json_mac_obj['llmnr'])
    if 'browser' in json_mac_obj:
        json_feature['browser'] = re.sub(r'_nextpacket_|_nextrr_', ',', json_mac_obj['browser'])
    if 'nbns' in json_mac_obj:
        json_feature['nbns'] = re.sub(r'_nextpacket_|_nextrr_', ',', json_mac_obj['nbns'])
    if 'ssdp' in json_mac_obj:
        if 'search' in json_mac_obj['ssdp']:
            if 'user-agent' in json_mac_obj['ssdp']['search']:
                json_feature['ssdp'] = {}
                json_feature['ssdp']['user-agent'] = re.sub(r'_nextpacket_|_nextrr_', ',', json_mac_obj['ssdp']['search']['user-agent'])
            #used for sony tv
            if 'X-AV-Client-Info' in json_mac_obj['ssdp']['search']:
                cn = re.findall(r".*cn=\"(.+?)\";.*", json_mac_obj['ssdp']['search']['X-AV-Client-Info'])[0]
                mn = re.findall(r".*mn=\"(.+?)\";.*", json_mac_obj['ssdp']['search']['X-AV-Client-Info'])[0]
                if cn:
                    if 'ssdp' not in json_feature:
                        json_feature['ssdp'] = {}
                        json_feature['ssdp']['clientcn'] = cn
                    else:
                        json_ssdp_feature = json_feature['ssdp']
                        json_ssdp_feature['clientcn'] = cn
                if mn:
                    if 'ssdp' not in json_feature:
                        json_feature['ssdp'] = {}
                        json_feature['ssdp']['clientmn'] = mn
                    else:
                        json_ssdp_feature = json_feature['ssdp']
                        json_ssdp_feature['clientmn'] = mn
        if 'notify' in json_mac_obj['ssdp']:
            if 'server' in json_mac_obj['ssdp']['notify']:
                if 'ssdp' not in json_feature:
                    json_feature['ssdp'] = {}
                    json_feature['ssdp']['server'] = re.sub(r'_nextpacket_|_nextrr_', ',', json_mac_obj['ssdp']['notify']['server'])
                else:
                    json_ssdp_feature = json_feature['ssdp']
                    json_ssdp_feature['server'] = re.sub(r'_nextpacket_|_nextrr_', ',', json_mac_obj['ssdp']['notify']['server'])
            #used for sony tv
            if 'X-AV-Server-Info' in json_mac_obj['ssdp']['notify']:
                cn = re.findall(r".*cn=\"(.+?)\";.*", json_mac_obj['ssdp']['notify']['X-AV-Server-Info'])[0]  
                mn = re.findall(r".*mn=\"(.+?)\";.*", json_mac_obj['ssdp']['notify']['X-AV-Server-Info'])[0] 
                if cn:
                    if 'ssdp' not in json_feature:
                        json_feature['ssdp'] = {}
                        json_feature['ssdp']['servercn'] = cn
                    else:
                        json_ssdp_feature = json_feature['ssdp']
                        json_ssdp_feature['servercn'] = cn
                if mn:
                    if 'ssdp' not in json_feature:
                        json_feature['ssdp'] = {}
                        json_feature['ssdp']['servermn'] = mn
                    else:
                        json_ssdp_feature = json_feature['ssdp']
                        json_ssdp_feature['servermn'] = mn
    if 'udp' in json_mac_obj:
        json_feature['udp'] = json_mac_obj['udp']     
        
#read csv to dict
def csv2dict(in_file,key,value):
    new_dict = {}
    with open(in_file, 'r') as f:
        reader = csv.reader(f, delimiter=',')
        fieldnames = next(reader)
        reader = csv.DictReader(f, fieldnames=fieldnames, delimiter=',')
        for row in reader:
            new_dict[row[key]] = row[value]
    return new_dict

#only for yuquanlu1
#mac_exist_dict = csv2dict('./csv_result_new/result34.csv', 'mac', 'vendor')


#create json_root_arr
json_root_arr = []
json_feature_arr = []

bootp_option_type_cnt = 0
bootp_option_type_tree_cnt = 0
bootp_option_request_list_item_cnt = 0
http_request_line_cnt = 0
dhcpv6_option_type_cnt = 0
dns_txt_cnt = 0
http_cnt = 0

#remove key duplicate
wf = open(file_name+'.json', 'w+', encoding='utf-8')
with open(file_name,'r') as raw_f:
    for line in raw_f.readlines():
        if 'ip6.arpa' in line:
            line = re.sub(r'(?<=[\"\s])[0-9A-F\.]{64}(?=ip6\.arpa)', 'ipv6,', line)
        line = re.sub(r'((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)', 'ipv4', line)
        if ('dhcp' not in line) and ('bootp' not in line) and ('data.data' not in line):
            line = re.sub(r'(?<![:])([a-f0-9]{1,4}(:[a-f0-9]{1,4}){7}|[a-f0-9]{1,4}(:[a-f0-9]{1,4}){0,7}::[a-f0-9]{0,4}(:[a-f0-9]{1,4}){0,7})(?!:)', 'ipv6', line)
        if 'bootp.option.type\"' in line:
            bootp_option_type_cnt += 1
            new_str = str(bootp_option_type_cnt) + ',bootp.option.type'
            new_line = line.replace('bootp.option.type', new_str)
        elif 'bootp.option.type_tree' in line:
            bootp_option_type_tree_cnt += 1
            new_str = str(bootp_option_type_tree_cnt) + ',bootp.option.type_tree'
            new_line = line.replace('bootp.option.type_tree', new_str)
        elif 'bootp.option.request_list_item' in line:
            bootp_option_request_list_item_cnt += 1
            new_str = 'bootp.option.request_list_item,' + str(bootp_option_request_list_item_cnt)
            new_line = line.replace('bootp.option.request_list_item', new_str)
        #ssdp
        elif 'http.request.line' in line:
            http_request_line_cnt += 1
            new_str = 'http.request.line' + str(http_request_line_cnt)
            new_line = line.replace('http.request.line', new_str)
        elif 'dhcpv6.option.type' in line:
            dhcpv6_option_type_cnt += 1
            new_str = str(dhcpv6_option_type_cnt) + ',dhcpv6.option.type'
            new_line = line.replace('dhcpv6.option.type', new_str)
        elif 'dns.txt' in line:
            dns_txt_cnt += 1
            new_str = str(dns_txt_cnt) + ',dns.txt'
            new_line = line.replace('dns.txt', new_str)
        #mdns
        elif ('http' in line) and ('class' not in line):
            http_cnt += 1
            new_str = str(http_cnt) + ',http'
            new_line = re.sub(r'http(?!:)', new_str, line)
        else:
            new_line = line
        wf.write(new_line)
wf.close()

with open(file_name+'.json', 'r') as load_f:
    pkt_arr = json.load(load_f)

for pkt_obj in pkt_arr:
    model = ''

    src_obj = pkt_obj['_source']
    layer_obj = src_obj['layers']
    
    #src mac:
    eth_obj = layer_obj['eth']
    mac = eth_obj['eth.src']
    #if mac in mac_exist_dict:
    #    continue
    json_mac_obj = find_mac_obj(json_root_arr, mac)
    
    #resolved src mac:
    mac_tree_obj = eth_obj['eth.src_tree']
    resolved_mac = mac_tree_obj['eth.src_resolved']

    #protocol:
    ptcl = extract_ptcl(layer_obj)
    gene_ptcl_obj(json_mac_obj, ptcl)

    if('bootp' == ptcl):
        bootp_keys = layer_obj['bootp'].keys()
        add_ptcl_obj(json_mac_obj, 'dhcp')
        json_dhcp_obj = json_mac_obj['dhcp']
        json_dhcp_type_obj = {}

        flag_cnt = 0
        while(flag_cnt < bootp_option_type_cnt):
            flag_cnt += 1
            option_key = str(flag_cnt) + ',' + 'bootp.option.type'
            val_key = str(flag_cnt) + ',' + 'bootp.option.type_tree'
            add_key = ''
            add_val = ''
            for key in bootp_keys:
                if(option_key == key):
                    add_key = layer_obj['bootp'][key]
            if('53' == add_key):
                for key in bootp_keys:
                    if(val_key == key):
                        add_val = layer_obj['bootp'][key]['bootp.option.dhcp']
            
            #add to json
            if('53' == add_key) and ('1' == add_val):
                dhcp_type = 'discover'
                add_ptcl_obj(json_dhcp_obj, dhcp_type)
                json_dhcp_type_obj = json_dhcp_obj[dhcp_type]
            elif('53' == add_key) and ('3' == add_val):
                dhcp_type = 'request'
                add_ptcl_obj(json_dhcp_obj, dhcp_type)
                json_dhcp_type_obj = json_dhcp_obj[dhcp_type]
            elif('53' == add_key) and ('6' == add_val):
                dhcp_type = 'nak'
                add_ptcl_obj(json_dhcp_obj, dhcp_type)
                json_dhcp_type_obj = json_dhcp_obj[dhcp_type]
            elif('53' == add_key) and ('2' == add_val):
                dhcp_type = 'offer'
                add_ptcl_obj(json_dhcp_obj, dhcp_type)
                json_dhcp_type_obj = json_dhcp_obj[dhcp_type]
            elif('53' == add_key) and ('5' == add_val):
                dhcp_type = 'ack'
                add_ptcl_obj(json_dhcp_obj, dhcp_type)
                json_dhcp_type_obj = json_dhcp_obj[dhcp_type]
            elif('53' == add_key) and ('8' == add_val):
                dhcp_type = 'inform'
                add_ptcl_obj(json_dhcp_obj, dhcp_type)
                json_dhcp_type_obj = json_dhcp_obj[dhcp_type]

        option_cnt = 0
        series_str = ''
        while(option_cnt < bootp_option_type_cnt):
            option_cnt += 1
            option_key = str(option_cnt) + ',' + 'bootp.option.type'
            val_key = str(option_cnt) + ',' + 'bootp.option.type_tree'
            add_key = ''
            add_val = ''
            for key in bootp_keys:
                if (option_key == key):
                    add_key = layer_obj['bootp'][key]
                    if not series_str:
                        series_str = add_key
                    else:
                        series_str = series_str + ',' + add_key
            if('55' == add_key):
                for key in bootp_keys:
                    if(val_key == key):
                        add_val = layer_obj['bootp'][key]['bootp.option.value']
            elif('81' == add_key):
                for key in bootp_keys:
                    if(val_key == key) and ('bootp.fqdn.name' in layer_obj['bootp'][key]):
                        add_val = layer_obj['bootp'][key]['bootp.fqdn.name']
            elif('77' == add_key):
                for key in bootp_keys:
                    if(val_key == key):
                        raw_str = layer_obj['bootp'][key]['bootp.option.user_class_tree']['bootp.option.user_class.data']
                        add_val = hex_str2char_str(raw_str)
            elif('0' != add_key):
                for key in bootp_keys:
                    if (val_key == key) and (len(layer_obj['bootp'][key]) > 1):
                        tree_keys = layer_obj['bootp'][key].keys()
                        for tree_key in tree_keys:
                            if('bootp.option.length' != tree_key) and ('bootp.option.value' != tree_key) and ('bootp.hw.type' != tree_key):
                                add_val = layer_obj['bootp'][key][tree_key]
                                if mac == add_val:
                                    add_val = resolved_mac.split('_')[0]
        
            if('55' == add_key):
                add_val_str = dhcp_req_list2comma_list(add_val)
                add_list_val(json_dhcp_type_obj, add_key, add_val_str)
            elif('0' != add_key) and ('' != add_key):
                add_ptcl_val(json_dhcp_type_obj, add_key, add_val.replace('.', ','))
        add_ptcl_val(json_dhcp_type_obj, 'series', series_str)

    elif('dhcpv6' == ptcl):
        dhcpv6_keys = layer_obj['dhcpv6'].keys()
        add_ptcl_obj(json_mac_obj, ptcl)
        json_dhcpv6_obj = json_mac_obj[ptcl]
        series_str = ''
        opt_cnt = 0
        while(opt_cnt < dhcpv6_option_type_cnt):
            opt_cnt += 1
            add_key = ''
            add_val = ''
            type_key = str(opt_cnt) + ',' + 'dhcpv6.option.type'
            for key in dhcpv6_keys:
                if ('dhcpv6.msgtype' != key and 'dhcpv6.xid' != key):
                    type_trees = layer_obj['dhcpv6'][key].keys()
                    for type_tree in type_trees:
                        if (type_key == type_tree):
                            add_key = layer_obj['dhcpv6'][key][type_tree]
                            if not series_str:
                                series_str = add_key
                            else:
                                series_str = series_str + ',' + add_key
                    
                            if('39' == add_key):
                                add_ptcl_val(json_dhcpv6_obj, add_key, layer_obj['dhcpv6'][key]['dhcpv6.client_fqdn'].replace('.', ','))
                            elif('6' == add_key):
                                req_list = layer_obj['dhcpv6'][key]['dhcpv6.option.value']
                                req_str = req_list2comma_list(req_list)
                                add_list_val(json_dhcpv6_obj, add_key, req_str)
                            else:
                                add_ptcl_val(json_dhcpv6_obj, add_key, 'null')
        add_ptcl_val(json_dhcpv6_obj, 'series', series_str)
                
    if('mdns' == ptcl):
        mdns_keys = layer_obj['mdns'].keys()
        add_ptcl_obj(json_mac_obj, ptcl)
        json_mdns_obj = json_mac_obj[ptcl]
        json_mdns_type_obj = {}
        for key in mdns_keys:
            if('dns.flags' == key):
                if('0x00000000' == layer_obj['mdns'][key]):
                    mdns_type = 'query'
                    add_ptcl_obj(json_mdns_obj, mdns_type)
                    json_mdns_type_obj = json_mdns_obj[mdns_type]
                elif('0x00008400' == layer_obj['mdns'][key]):
                    mdns_type = 'response'
                    add_ptcl_obj(json_mdns_obj, mdns_type)
                    json_mdns_type_obj = json_mdns_obj[mdns_type]
        for key in mdns_keys:
            if('Queries' == key):
                q_val = ''
                query_val = add_mdns_rrs(layer_obj, key)
                if '&&' in query_val:
                    q_val = add_mdns_rrs(layer_obj, key).split('&&')[0]
                    model = add_mdns_rrs(layer_obj, key).split('&&')[1]
                else:
                    q_val = query_val
                add_ptcl_val(json_mdns_type_obj, 'query', q_val)
            elif('Answers' == key):
                a_val = ''
                answer_val = add_mdns_rrs(layer_obj, key)
                if '&&' in answer_val:
                    a_val = add_mdns_rrs(layer_obj, key).split('&&')[0]
                    model = add_mdns_rrs(layer_obj, key).split('&&')[1]
                else:
                    a_val = answer_val
                add_ptcl_val(json_mdns_type_obj, 'answer', a_val)
            elif('Additional records' == key):
                add_val = ''
                addition_val = add_mdns_rrs(layer_obj, key)
                if '&&' in addition_val:
                    add_val = add_mdns_rrs(layer_obj, key).split('&&')[0]
                    model = add_mdns_rrs(layer_obj, key).split('&&')[1]
                else:
                    add_val = addition_val
                add_ptcl_val(json_mdns_type_obj, 'additional', add_val)
            elif('Authoritative nameservers' == key):
                auth_val = ''
                authentity_val = add_mdns_rrs(layer_obj, key)
                if '&&' in authentity_val:
                    auth_val = add_mdns_rrs(layer_obj, key).split('&&')[0]
                    model = add_mdns_rrs(layer_obj, key).split('&&')[1]
                else:
                    auth_val = authentity_val
                add_ptcl_val(json_mdns_type_obj, 'authoritative', auth_val)
    elif('llmnr' == ptcl):
        if isinstance(layer_obj['llmnr']['Queries'], str):
            print(layer_obj['llmnr']['Queries'])
        else:
            llmnr_keys = layer_obj['llmnr']['Queries'].keys()
            for key in llmnr_keys: #only one key
                llmnr_qname = key.split(':')[0]
            add_ptcl_val(json_mac_obj, ptcl, llmnr_qname)
    elif('browser' == ptcl):
        smb_srcname = layer_obj['nbdgm']['nbdgm.source_name']  #only one sourcename
        add_ptcl_val(json_mac_obj, ptcl, smb_srcname)
    elif('nbns' == ptcl):
        if 'Queries' in layer_obj['nbns']:
            if isinstance(layer_obj['nbns']['Queries'], str):
                print(layer_obj['nbns']['Queries'])
            else:
                nbns_keys = layer_obj['nbns']['Queries'].keys()
                for key in nbns_keys:
                    nbns_qname = key.split(':')[0]
                add_ptcl_val(json_mac_obj, ptcl, nbns_qname)
    elif('ssdp' == ptcl):
        ssdp_keys = layer_obj['ssdp'].keys() #key is m-search or notify
        add_ptcl_obj(json_mac_obj, ptcl)
        json_ssdp_obj = json_mac_obj[ptcl]
        json_ssdp_type_obj = {}
        request_line_list = []
        ssdp_type = ''
        for key in ssdp_keys:
            if('M-SEARCH' == key.split(' ')[0]):
                ssdp_type = 'search'
                add_ptcl_obj(json_ssdp_obj, ssdp_type)
                json_ssdp_type_obj = json_ssdp_obj[ssdp_type]
            elif('NOTIFY' == key.split(' ')[0]):
                ssdp_type = 'notify'
                add_ptcl_obj(json_ssdp_obj, ssdp_type)
                json_ssdp_type_obj = json_ssdp_obj[ssdp_type]
        for key in ssdp_keys:
            if ('search' == ssdp_type) and ('http.request.line' in key):
                request_line_list.append(key)
            elif ('notify' == ssdp_type) and ('http' in key):
                request_line_list.append(key)
        request_line_list.sort()
        series_str = ''
        add_key = ''
        add_val = ''
        for item in request_line_list:
            if 'notify' == ssdp_type: 
                if 'http.host' in item:
                    add_key = 'host'
                    add_val = layer_obj['ssdp'][item]
                elif 'http.cache_control' in item:
                    add_key = 'cache_control'
                    add_val = layer_obj['ssdp'][item]
                elif 'http.location' in item:
                    add_key = 'location'
                    add_val = layer_obj['ssdp'][item]
                elif 'http.server' in item:
                    add_key = 'server'
                    add_val = layer_obj['ssdp'][item]
                elif 'http.request.full_uri' in item:
                    add_key = 'full_uri'
                    add_val = layer_obj['ssdp'][item]
                elif 'http.unknown_header' in item:
                    add_key = layer_obj['ssdp'][item].split(':')[0]
                    if len(layer_obj['ssdp'][item].split(':')) > 1:
                        add_val = layer_obj['ssdp'][item].split(':')[1]
                    else:
                        add_val = 'nak'
                else:
                    add_key = ''
            elif 'search' == ssdp_type:
                add_key = layer_obj['ssdp'][item].split(':')[0]
                add_val = layer_obj['ssdp'][item].split(':')[1]

            
            if add_key:
                if (not series_str):
                    series_str = add_key
                else:
                    series_str = series_str + ',' + add_key

            if('user-agent' == add_key):
                add_val = add_val.replace(' ', ',')
            if add_key:
                add_ptcl_val(json_ssdp_type_obj, add_key, add_val.replace(':', ','))
        add_ptcl_val(json_ssdp_type_obj, 'series', series_str)
    elif 'udp' in ptcl:
        if 'data' in layer_obj:
            raw_data_str = layer_obj['data']['data.data']
            data_str = hex_str2char_str(raw_data_str)
            device_name = re.findall(r".*DEVICE_NAME=(.+?)\n.*", data_str)          
            if device_name:
                add_ptcl_val(json_mac_obj, 'udp', device_name[0])
    mac_gene_feature(json_mac_obj, resolved_mac, model) 

with open(output_json_name, 'w') as outfile:
    json.dump(json_root_arr, outfile, indent=4)

#read in knowledge csv
vendor_know_dict = csv2dict(csv_file, 'vendor_key', 'vendor')
type_know_dict = csv2dict(csv_file, 'type_key', 'type')
model_know_dict = csv2dict(csv_file, 'model_key', 'model')


#add prefix
vendor_know_arr = []
type_know_arr = []
model_know_arr = []
for vendor_key in vendor_know_dict.keys():
    vendor_know_arr.append(vendor_key)
    vendor_know_arr.sort(reverse = True)
for type_key in type_know_dict.keys():
    type_know_arr.append(type_key)
    type_know_arr.sort(reverse = True)
for model_key in model_know_dict.keys():
    model_know_arr.append(model_key)
    model_know_arr.sort(reverse = True)

#generate csv file
#mac|feature
mac_list = []
feature_list = []
mac_prefix_list = []
vendor_list = []
type_list = []
model_list = []
for mac_obj in json_root_arr:
    mac_list.append(mac_obj['mac'])

    #mac_prefix
    mac_arr = mac_obj['mac'].split(':')
    mac_prefix = mac_arr[0]
    mac_prefix = mac_prefix + mac_arr[1]
    mac_prefix = mac_prefix + mac_arr[2]

    feature_str = mac_prefix
    for key in mac_obj['feature_label'].keys():
        if 'ssdp' == key:
            for type_key in mac_obj['feature_label']['ssdp'].keys():
                if not feature_str:
                    feature_str = mac_obj['feature_label']['ssdp'][type_key].replace('\r\n', '')
                else:
                    feature_str = feature_str + ',' + mac_obj['feature_label']['ssdp'][type_key].replace('\r\n', '')
        else:
            if not feature_str:
                feature_str = mac_obj['feature_label'][key].replace('\r\n', '')
            else:
                feature_str = feature_str + ',' + mac_obj['feature_label'][key].replace('\r\n', '')
    feature_list.append(feature_str)

    #mac_prefix label:
    mac_prefix_list.append(mac_prefix)

    #vendor label:
    vendor = ''
    for vendor_key in vendor_know_arr:
        if vendor_key.lower() in feature_str.lower():
            vendor = vendor_know_dict[vendor_key]
            break
    vendor_list.append(vendor)
    #type label:
    dev_type = ''
    for type_key in type_know_arr:
        if type_key.lower() in feature_str.lower():
            dev_type = type_know_dict[type_key]
            break
        if 'router' in feature_str.lower():
            dev_type = vendor + '_router'
            break
    type_list.append(dev_type)
    #model label:
    model = ''
    for model_key in model_know_arr:
        if model_key.lower() in feature_str.lower():
            model = model_know_dict[model_key]
            break
    model_list.append(model)

dataframe = pd.DataFrame({'mac':mac_list, 'feature':feature_list, 'mac_prefix':mac_prefix_list, 'vendor':vendor_list, 'type':type_list, 'model':model_list}, columns=["mac", "feature", "mac_prefix", "vendor", "type", "model"])
dataframe.to_csv(output_csv_name, sep=',')
#print(json_root_arr)
   
