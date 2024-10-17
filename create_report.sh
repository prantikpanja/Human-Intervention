#!/bin/bash


create_report() {
    
    local file_name_f="$1"
    local event_type="$2"
    shift 2
    local array=("$@")
    total=0
	for keyword in "${array[@]}"
	do
    	# Count the occurrences of each keyword in the input file
    	count=$(grep -o -i "$keyword" "$file_name_f" | wc -l)
    	total=$(($total + $count))
    
    	echo "$keyword: $count" >> "$output_file"
	done
	#for file write
	if ((total==0))
	then
    	echo "Malicious score for $event_type is : 0"
	elif ((total==1))
	then
    	echo "Malicious score for $event_type is : 5"
	elif ((total==2))
	then
    	echo "Malicious score for $event_type is : 6"
	else
    	echo "Malicious score for $event_type is : 7"
	fi >> $output_file
	
	#for return
	if ((total==0))
	then
    	echo "0"
	elif ((total==1))
	then
    	echo "5"
	elif ((total==2))
	then
    	echo "6"
	else
    	echo "7"
	fi
    
}


PARENT_FOLDER="/home/system/Videos/test"

report="report.txt"
final_report="final_report.txt"
output_file2="/home/system/2res.txt"
output_file1="/home/system/final_report.txt"
	

> "$output_file2"
> "$output_file1"
echo "Sample name,Registry access,File access,Process creation/termination,Sensitive privilege use,Network access" >> "$output_file2"

regs=("RegOpenKeyExA" "RegQueryValueExA" "RegCloseKey" "RegSetValueExA" "RegCreateKeyA")
files=("CreateFileA" "OpenProcess" "ReadFile" "WriteFile")
processes=("CreateProcessA" "OpenProcess" "TerminateProcess" "ShellExecuteExA")
Preveledge=("CreateProcessAsUserA" "win_token" "escalate_priv")
networks=("HttpSendRequestA" "HttpOpenRequestA" "HttpAddRequestHeadersA" "InternetOpenA" "WSAStartup" "closesocket")
	
s1="Registry access"
s2="File access"
s3="Process creation/termination"
s4="Sensitive privilege use"
s5="Network access"


find "$PARENT_FOLDER" -type f -name "*report.json" | while read JSON_FILE; do
	STRING=$(jq -r '.target.file.name' "$JSON_FILE")
	directoryBase=${JSON_FILE:0:-11}
	input_file="$directoryBase$STRING.json"
	mv "$JSON_FILE" "$input_file"
	
	output_file=$directoryBase$report
	
	> "$output_file"
	
	echo "Report starting for file: $STRING ------------------------------------"
	echo "Report starting for sample: $STRING ------------------------------------" >> "$output_file"
	echo "--------------------- Score for $s1 ---------------------" >> "$output_file"
	result1=$(create_report "$input_file" "$s1" "${regs[@]}")
	
	echo "--------------------- Score for $s2 ---------------------" >> "$output_file"
	result2=$(create_report "$input_file" "$s2" "${files[@]}")
	
	echo "--------------------- Score for $s3 ---------------------" >> "$output_file"
	result3=$(create_report "$input_file" "$s3" "${processes[@]}")
	
	echo "--------------------- Score for $s4 ---------------------" >> "$output_file"
	result4=$(create_report "$input_file" "$s4" "${Preveledge[@]}")
	
	echo "--------------------- Score for $s5 ---------------------" >> "$output_file"
	result5=$(create_report "$input_file" "$s5" "${networks[@]}")
	
	echo "Report generated and saved to $output_file."
	echo "Final score for sample: $STRING is $(($result1 + $result2 + $result3 + $result4 + $result5))" >> $output_file
	echo "$(($result1 + $result2 + $result3 + $result4 + $result5))" >> $output_file1
	echo "__________________________________________" >> "$output_file"
	echo " " >> "$output_file"
	echo "$STRING,$result1,$result2,$result3,$result4,$result5" >> $output_file2
done
