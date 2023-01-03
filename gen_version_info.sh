#!/bin/sh


SHDIR=$(dirname `readlink -f $0`)

name="ebpc_"
gitversion=$(git rev-parse --short HEAD)
version=$(sed -n "/std::string g_LinuxCompatible = /p" ${SHDIR}/common/version.h | awk -F '[\"]' '{print $2}')

finalname=${name}""${version}

if [ ${#gitversion} -eq 0 ]
then
    echo "there is no git in your shell"
    exit
else
    finalname=${finalname}"_"${gitversion}
fi;

flag=$(sed -n "/g_testflag = /p" ${SHDIR}/common/global.cpp |awk -F '[ ;]' '{print $4}')

if [ $flag -eq 1 ] 
then
    finalversion=${finalname}"_""testnet"
    echo  "${finalversion}"
else  
    finalversion=${finalname}"_""primarynet"
     echo  "${finalversion}"
fi;

if [ -f ${SHDIR}/build/bin/ebpc ]
then
    mv ${SHDIR}/build/bin/ebpc ${SHDIR}/build/bin/${finalversion}
else
    echo "ebpc not exist"
fi;
 

#sed -i "s/build_commit_hash.*;/build_commit_hash = \"${gitversion}\";/g" ./ca/ca_global.cpp