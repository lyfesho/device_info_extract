import json
import csv

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

#read json to dict
def json2dict(in_file):
    new_arr = []
    with open(in_file, 'r') as load_f:
        new_arr = json.load(load_f)
    return new_arr

for i in range(658):
    csv_file = './csv_result_new/result' + str(i+1) + '.csv'
    json_file = './train_data_new/train_data' + str(i+1) + '.json'
    output_json_name = './labeled_train_data_new/labeled_train_data' + str(i+1) + '.json'

    mac_prefix_dict = csv2dict(csv_file, 'mac', 'mac_prefix')
    vendor_dict = csv2dict(csv_file, 'mac', 'vendor')
    type_dict = csv2dict(csv_file, 'mac', 'type')
    model_dict = csv2dict(csv_file, 'mac', 'model')

    json_root_arr = json2dict(json_file)
    for mac_obj in json_root_arr:
        mac_prefix = mac_prefix_dict[mac_obj['mac']]
        vendor = vendor_dict[mac_obj['mac']]
        dev_type = type_dict[mac_obj['mac']]
        model = model_dict[mac_obj['mac']]
        mac_obj['label'] = {}
        if mac_prefix:
            mac_obj['label']['mac_prefix'] = mac_prefix
        if vendor:
            mac_obj['label']['vendor'] = vendor
        else:
            mac_obj['label']['vendor'] = 'null'
        if dev_type:
            mac_obj['label']['type'] = dev_type
        else:
            mac_obj['label']['type'] = 'null'
        if model:
            mac_obj['label']['model'] = model
        elif mac_obj['label']['type']:
            mac_obj['label']['model'] = mac_obj['label']['type']
        else:
            mac_obj['label']['model'] = 'null'

    with open(output_json_name, 'w') as outfile:
        json.dump(json_root_arr, outfile, indent=4)
