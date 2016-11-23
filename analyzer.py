import sys
import re

def importFile(filename):
	dictionary_list = []
	try:
		with open(filename) as f:
			slice_lines = f.read().split(';\n')
			slice_lines.pop()
			
			for line in slice_lines:
				instruction = line.split('=', 1)
				variable_list = [instruction[0],instruction[1].replace(';\n', '') , False]
				dictionary_list.append(variable_list)

		f.close()

	except:
		print ("Error opening file")
		sys.exit(1)

	return dictionary_list

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
		for j in range(4):
			temp.append(result_patterns[j])
		structured_patterns.append(temp)

	return structured_patterns

def substituteVariables(variable_list):
	for i in range(1, len(variable_list)):
		variable_list[i][1] = variable_list[i][1].replace(variable_list[i-1][0], variable_list[i-1][1])

	return variable_list[-1][1]


def checkArgs():
	if len(sys.argv) != 2:
		print ("Usage: python analyzer.py <slice>")
		sys.exit(1)


if __name__ == "__main__":
	checkArgs()
	variable_list = importFile(sys.argv[1])

	patterns = importPatterns("proj-patterns/patterns")

	parsed_instruction = substituteVariables(variable_list)

	content = []
	flag = False

	for pattern in patterns:
		sensitive_sinks = pattern[3].split(',')
		for sink in sensitive_sinks:
			if re.compile(sink + '\((.*?)\)').findall(parsed_instruction) != []:
				content = re.compile(sink + '\((.*?)\)').findall(parsed_instruction)
				content = content[0].split(',')

		inner_inner_content = []
		sanitization_functions = pattern[2].split(',')
		for function in sanitization_functions:
			for inner_content in content:
				if re.compile(function + '\((.*?)\)').findall(inner_content) != []:
					inner_inner_content = re.compile(sink + '\((.*?)\)').findall(inner_content)
					flag = True
					break

		print(content)
		if(flag != True):
			entry_points = pattern[1].split(',')
			for entry_point in entry_points:
				for inner_content in content:
					if re.compile(entry_point.replace('$','\$') + '\[(.*?)\]').findall(inner_content) != []:
						print("Inseguro")
						sys.exit(1)

	print("Seguro")