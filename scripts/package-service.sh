#!/bin/bash
echo [!] Packaging User Management Service
cd ../user-management-service/
gradleErr=0
./gradlew clean build -x test || gradleErr=1
if [ $gradleErr == 0 ]
then 
    echo [+] User Management Service successfully packaged 
fi
if [ $gradleErr == 1 ]
then
    echo [-] Error packaging User Management Service. Script cannot continue
    cd ../scripts/
    exit
fi
cd ../scripts/
