#!/bin/bash

echo "===== Run tests script ====="

for File in $(ls proj-slices/)
do
	file_output=$(python analyzer.py proj-slices/"$File")
	expected_output=$(cat proj-slices-expected/"$File")

	if [ "$file_output" == "$expected_output" ]
	then
		echo "[ $File ] Test passed"
	else
		echo "[ $File ] Test failed"
	fi
done

echo "===== Done ====="
