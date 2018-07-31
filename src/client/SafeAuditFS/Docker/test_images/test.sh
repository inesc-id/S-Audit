#!/bin/sh

cd usr/test_scfs/ 
echo '>writting file ola.txt in client 0'
cd 0/
touch ola.txt
echo 'client 0 files:'
ls
echo 'client 1 files:'
cd ../1/
ls

cd ../0/
echo '>sharing client 0s file ola.txt with client 1'
setfacl -m u:1:rwx ola.txt
echo 'client 0 files:'
ls
echo 'client 1 files:'
cd ../1/
ls