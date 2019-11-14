#! /bin/bash

#write authkey to authnode.json
cd ..
cp -r ./docker/authnode/. ./build/bin
cd build/bin
./cfs-authtool authkey
authnodeKey=$(sed -n '3p' keyring.json | sed 's/key/authServiceKey/g')
line=`expr $(cat authnode1.json | wc -l) - 1`
sed -i "${line}i ${authnodeKey}" authnode1.json
sed -i "${line}i ${authnodeKey}" authnode2.json
sed -i "${line}i ${authnodeKey}" authnode3.json

#start authnode
./build.sh      #TODO 需要吗？
docker-compose up -d

#get ticket for auth
./cfs-authtool ticket -host=192.168.0.14:8080 -keyfile=./keyring.json -output=ticket_auth.json getticket AuthService
#create admin
./cfs-authtool api -host=192.168.0.14:8080 -ticketfile=./ticket_auth.json -data=./data_admin.json -output=./key_admin.json AuthService createkey
#get ticket for admin
./cfs-authtool ticket -host=192.168.0.14:8080 -keyfile=./key_admin.json -output=ticket_admin.json getticket AuthService
#create key for master
./cfs-authtool api -host=192.168.0.14:8080 -ticketfile=./ticket_admin.json -data=./data_master.json -output=./key_master.json AuthService createkey
#create key for client
./cfs-authtool api -host=192.168.0.14:8080 -ticketfile=./ticket_admin.json -data=./data_client.json -output=./key_client.json AuthService createkey

#write key to json file
clientKey=$(sed -n '3p' key_client.json | sed 's/key/clientKey/g')
masterKey=$(sed -n '3p' key_master.json | sed 's/key/masterServiceKey/g')
cd ..
cd ..
lineClient=`expr $(cat docker/conf/client.json | wc -l) - 1`
sed -i "${lineClient}i ${clientKey}" docker/conf/client.json
lineMaster=`expr $(cat docker/conf/master1.json | wc -l) - 1`
sed -i "${lineMaster}i ${masterKey}" docker/conf/master1.json
sed -i "${lineMaster}i ${masterKey}" docker/conf/master2.json
sed -i "${lineMaster}i ${masterKey}" docker/conf/master3.json

#start cfs
docker/run_docker_auth.sh -r -d $0

#TODO delete temp files