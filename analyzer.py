import sys
import re
import networkx as nx

def importFile(filename):
	result_list = []
	try:
		with open(filename) as f: 
			slice_lines = f.readlines()
			for i in range(len(slice_lines)):
				slice_lines[i] = slice_lines[i].replace('\n', '')

			parsed_lines = []
			temp_line = ""

			for line in slice_lines:
				if line[-1] == ';' and temp_line == "":
					parsed_lines.append(line)

				elif line[-1] != ';':
					temp_line += line

				elif line[-1] == ';' and temp_line != "":
					parsed_lines.append(temp_line + " " + line)
					temp_line = ""

			if(temp_line != ""):
				parsed_lines.append(temp_line)

			for line in parsed_lines:
				if line[0] == '$':
					instruction = line.split('=', 1)
					if instruction[1][-1] == ';':
						variable_list = [instruction[0],instruction[1].replace(';', '')]
					else:
						variable_list = [instruction[0],instruction[1]]
					result_list.append(variable_list)
				else:
					result_list.append(["", line])

		f.close()

	except:
		print ("Error opening file")
		sys.exit(1)

	return result_list

def importPatterns(filename):
	try:
		with open(filename) as f:
			patterns = f.readlines()

			result_patterns = []

			for line in patterns:
				if line != '\n':
					line = line.replace('\n', '')
					result_patterns.append(line)

		f.close()
	except:
		print ("Error opening file")
		sys.exit(1)

	structured_patterns = []
	for i in range(0, len(result_patterns), 4):
		temp = []
		temp.append(result_patterns[i])
		temp.append(result_patterns[i+1])
		temp.append(result_patterns[i+2])
		temp.append(result_patterns[i+3])
		structured_patterns.append(temp)

	return structured_patterns

def checkArgs():
	if len(sys.argv) != 2:
		print ("Usage: python analyzer.py <slice>")
		sys.exit(1)

def findPattern(variable_list, patterns):
	found_pattern = []

	i = len(variable_list) - 1
	for pattern in patterns:
		sensitive_sinks = pattern[3].split(',')
		for sensitive_sink in sensitive_sinks:
			if sensitive_sink in variable_list[i][1]:
				found_pattern = pattern
				break
		if(found_pattern != []):
			break

	return found_pattern, sensitive_sink


def createGraph(slice_list):
	graph = nx.DiGraph()
	program_line_number = 0
	for instruction in slice_list:
		graph.add_node(
			program_line_number, tainted = False, variable = instruction[0], body = instruction[1])
		program_line_number+=1

	var_list = []
	if len(graph.nodes()) != 1:
		for node in graph:
			potential_vars = re.findall(r'\$\w+', graph.nodes(data=True)[node][1]['body'])
			for var in potential_vars:
				if var in var_list:
					graph.add_edge(var_list[var_list.index(var)+1],node)
			if graph.nodes(data=True)[node][1]['variable'] != '':
				var_list.append(graph.nodes(data=True)[node][1]['variable'].replace(' ', ''))
				var_list.append(node)

	return graph

def traverseGraph(graph,pattern,sensitive_sink):
	result = []
	sanitization_lines = ["Lines where input is sanitized"]

	for node in sorted(graph):
		successors = graph.successors(node)

		entry_points = pattern[1].split(',')
		sanitization_functions = pattern[2].split(',')

		if successors == []:
			last_node = node
			sink_args = graph.nodes(data=True)[node][1]['body'].split(sensitive_sink)[1:][0].replace(' ', '')
			for entry in entry_points:
				if entry in sink_args:
					graph.node[node]['tainted'] = True
			for function in sanitization_functions:
				if function in sink_args:
					graph.node[node]['tainted'] = False
					sanitization_lines.append(node+1)
		else:
			body = graph.nodes(data=True)[node][1]['body']
			for entry in entry_points:
				if entry in body:
					graph.node[node]['tainted'] = True
			for function in sanitization_functions:
				if function in body:
					all_vars = re.findall(r'\$\w*', body)
					sanitized_vars = re.findall(function + r'\(\$\w*\)', body)
					if len(all_vars) == len(sanitized_vars):
						graph.node[node]['tainted'] = False
						sanitization_lines.append(node+1)

		for successor in successors:
			if graph.nodes(data=True)[node][1]['tainted'] == True:
				graph.node[successor]['tainted'] = True


	result.append(graph.nodes(data=True)[last_node][1]['tainted'])
	if result[0] == True:
		result.append(pattern[0])
	else:
		result.append("Safe")
		result.append(sanitization_lines)
	return result


if __name__ == "__main__":
	checkArgs()

	slice_list = importFile(sys.argv[1])
	patterns = importPatterns("proj-patterns/patterns")

	found_pattern, sensitive_sink = findPattern(slice_list, patterns)

	g = createGraph(slice_list)

	result = traverseGraph(g, found_pattern, sensitive_sink)

	print (result)