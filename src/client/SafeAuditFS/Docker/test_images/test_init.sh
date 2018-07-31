# Copyright (c) 2007-2013 Ricardo Mendes, Tiago Oliveira , Alysson Bessani, Marcelo Pasin, Nuno Neves, Miguel Correia, and the authors indicated in the @author tags
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

#!/bin/sh

#Start 4 DepSpace servers
echo '>Running 4 DepSpace replicas.'
#cd /usr/scfs/DepSpace
echo 'Running replica 0'
#sh runDepSpace.sh 0 >/usr/test_scfs/logs/DepSpace/0/log.txt &
echo 'Running replica 1'
#sh runDepSpace.sh 1 >/usr/test_scfs/logs/DepSpace/1/log.txt &
echo 'Running replica 2'
#sh runDepSpace.sh 2 >/usr/test_scfs/logs/DepSpace/2/log.txt &
echo 'Running replica 3'
#sh runDepSpace.sh 3 >/usr/test_scfs/logs/DepSpace/3/log.txt &
echo '>Running 2 SCFS clients.'
#launch two clients
cd /usr/scfs
sh configure_x64.sh
echo '>Mounting client 0 in folder /usr/test_scfs/0/.'
sh mountSCFS.sh /usr/test_scfs/0/ 0 --non-sharing -printer >/usr/test_scfs/logs/0/log.txt &
echo '>Mounting client 1 in folder /usr/test_scfs/1/.'
#sh mountSCFS.sh /usr/test_scfs/1/ 1 --non-sharing -printer >/usr/test_scfs/logs/1/log.txt &

echo "Done!"
