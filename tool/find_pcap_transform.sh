#!/bin/sh

#!/bin/sh
#ext="pcap"
function ergodic(){
echo "开始扫描目录 $1"
for file in ` ls $1`
do
    if [ -d $1"/"$file ] 
    then
        ergodic $1"/"$file $2"/"$file $3
    else
        local path=$1"/"$file 
                    
        if [ "${file##*.}" = "pcap" ]
        then 
            echo "开始转换 $path  到 $2 payload_type $3"
            ./pcap2wav  "$path"  $2 $3          
        fi
                         
    fi

done
}

ergodic $1 $2 $3



