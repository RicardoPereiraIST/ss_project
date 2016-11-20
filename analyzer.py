import sys

def importFile(filename):
	try:
		slice_lines = [line.rstrip('\n') for line in open(filename)]
	except:
		print "Error opening file"
		sys.exit(1)

	return slice_lines

def checkArgs():
	if len(sys.argv) != 2:
		print "Usage: python analyzer.py <slice>"
		sys.exit(1)

checkArgs()
lines = importFile(sys.argv[1])

