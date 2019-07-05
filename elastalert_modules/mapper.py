import re
import ast
from collections import OrderedDict
from elastalert.alerts import Alerter, BasicMatchString
from elastalert.util import lookup_es_key

class Mapper(Alerter):

    required_options = set(['output_file_path', 'alert_severity', 'last_var_map'])

    def get_key_pos(self, key):

	key_pos = 0
	match_found = False
	with open(self.rule['rule_file'], 'r') as f:
	    for line in f:
		if re.match("^" + key + ":", line):
		    match_found = True
		    break
		key_pos+=1
	if match_found:
	    return key_pos

    def alert(self, matches):

        for match in matches:
            with open(self.rule['output_file_path'], "a") as output_file:

		try:
                	self.metric_key = self.rule['metric_agg_key']+ '_' + self.rule['metric_agg_type']        
                	if self.metric_key == '_':
                    		curr_value = "NaN"
                	else:
                    		curr_value = match[self.metric_key]

                	self.ci = match[self.rule['query_key']]
		except KeyError:
			curr_value = None
			self.ci = None

		# last_var_map
		last_var_map_output = ''
		last_var_map_value = self.rule['last_var_map']
		last_var_map_dict = ast.literal_eval(last_var_map_value)

		pos_list = OrderedDict()

		for k,v in last_var_map_dict.items():
		    pos = self.get_key_pos(k)
		    if pos != None:
			arr_split = re.split('\+', self.rule[k])
			str_split = ''
			for i in arr_split:
			    if i.strip()[0] == '$':
				str_split += str(lookup_es_key(match, i.strip()[1:]))
			    else:
				str_split += i
			pos_list[pos] = str_split

		#pos = self.get_key_pos('name')
		#if pos != None:
		#    pos_list[pos] = self.rule['name']

		pos = self.get_key_pos('state')
		if pos != None:
		    pos_list[pos] = self.rule['state']

		pos = self.get_key_pos('alert_severity')
		if pos != None:
		    pos_list[pos] = self.rule['alert_severity']

		pos = self.get_key_pos('alert_group')
		if pos != None:
		    pos_list[pos] = self.rule['alert_group']

		pos = self.get_key_pos('alert_subgroup')
		if pos != None:
		    pos_list[pos] = self.rule['alert_subgroup']

		pos = self.get_key_pos('summary')
		if pos != None:
		    pos_list[pos] = self.rule['summary']

		pos = self.get_key_pos('additional_info_1')
		if pos != None:
		    pos_list[pos] = self.rule['additional_info_1']

		pos = self.get_key_pos('max_threshold')
		if pos != None:
		    pos_list[pos] = 'max threshold value: ' + self.rule['max_threshold']

		pos = self.get_key_pos('min_threshold')
		if pos != None:
		    pos_list[pos] = 'min threshold value: ' + self.rule['min_threshold']

		pos = self.get_key_pos('unit')
		if pos != None:
		    pos_list[pos] = self.rule['unit']

		pos = self.get_key_pos('additional_info_2')
		if pos != None:
		    pos_list[pos] = self.rule['additional_info_2']

		pos = self.get_key_pos('additional_info_3')
		if pos != None:
		    pos_list[pos] = self.rule['additional_info_3']

		pos = self.get_key_pos('current_value')
		if pos != None:
		    pos_list[pos] = 'current value: ' + str(curr_value)

		pos_list = OrderedDict(sorted(pos_list.items(), key=lambda x: x[0]))

		match_string = '%s;' % (lookup_es_key(match,self.rule['timestamp_field']))
		for k,v in pos_list.items():
		    match_string += v + ';'
		match_string += '\n'

                #match_string = '%s;;%s_%s;%s;OPEN;%s;%s;%s;%s;%s Current value: %s%s, threshold value: %s%s;%s;%s;%s; \n' % (lookup_es_key(match,self.rule['timestamp_field']), self.rule['name'], self.ci, self.rule['alert_severity'], self.ci, self.rule['alert_group'], self.rule['alert_subgroup'], self.rule['summary'], self.rule['additional_info_1'], curr_value, self.rule.get('unit',""), self.rule.get('max_threshold', self.rule.get('min_threshold')), self.rule.get('unit',""), self.rule['additional_info_2'], self.rule.get('additional_info_3',""), str(pos_list))

                output_file.write(match_string)

    #def get_info(self):
    #    return {'key': "%s_%s" % (self.rule['name'],self.ci),
    #        'alert_severity': self.rule['alert_severity'],
    #        'state': 'OPEN',
    #        'ci': self.ci,
    #        'alert_group': self.rule['alert_group'],
    #        'alert_subgroup': self.rule['alert_subgroup'],
    #        'summary': self.rule['summary'] ,
    #        'additional_info_1': self.rule['additional_info_1'],
    #        'additional_info_2': self.rule['additional_info_2'],
    #        'additional_info_3': self.rule.get('additional_info_3',""),
    #        'threshold': self.rule.get('max_threshold', self.rule.get('min_threshold')),
    #        'output_file': self.rule['output_file_path']}

