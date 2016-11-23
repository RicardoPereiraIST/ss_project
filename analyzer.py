import sys
import re

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
				if line[-1] != ';':
					temp_line += line
				elif temp_line != "":
					parsed_lines.append(temp_line)
					temp_line = ""
				else:
					parsed_lines.append(line)

			if temp_line != "":
				parsed_lines.append(temp_line)

			for line in parsed_lines:
				if line[0] == '$':
					instruction = line.split('=', 1)
					if instruction[1][-1] == ';':
						variable_list = [instruction[0],instruction[1].replace(';', '') , False]
					else:
						variable_list = [instruction[0],instruction[1], False]
					result_list.append(variable_list)
				else:
					result_list.append(["", line, ""])

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
	print(parsed_instruction)

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

		if(flag != True):
			entry_points = pattern[1].split(',')
			for entry_point in entry_points:
				for inner_content in content:
					if re.compile(entry_point.replace('$','\$') + '\[(.*?)\]').findall(inner_content) != []:
						print("Inseguro")
						sys.exit(1)

	print("Seguro") 