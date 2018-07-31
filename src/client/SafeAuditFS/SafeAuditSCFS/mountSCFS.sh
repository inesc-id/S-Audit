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

# ./C2F2_mount.sh 'pasta para mount' 'id'
# args: 1 - mount point
#       2 - user id 

. ./build.conf

LD_LIBRARY_PATH=./jni:$FUSE_HOME/lib $JDK_HOME/java/bin/java -Dfile.encoding=UTF-8 -Xmx1024m -Duid=$(id -u) -Dgid=$(id -g) \
   -classpath bin:./lib/AmazonAccess.jar:./lib/AmazonDriver.jar:./lib/AzureAccess.jar:./lib/DepSkyDependencies.jar:./lib/DepSkyS-backup.jar:./lib/DepSkyS.jar:./lib/DepSpace.jar:./lib/GoogleSAccess.jar:./lib/GoogleStorageDriver.jar:./lib/HomomorphicAuthenticationLibrary.jar:./lib/JReedSolEC.jar:./lib/PVSS.jar:./lib/RackSpaceDriver.jar:./lib/RackspaceAccess.jar:./lib/SMaRt.jar:./lib/StorageTagger.jar:./lib/WindowsAzureDriver.jar:./lib/aws-java-sdk-1.7.2.jar:./lib/azure-common-1.5.4.jar:./lib/azureblob-1.5.4.jar:./lib/commons-codec-1.5.jar:./lib/commons-io-1.4.jar:./lib/commons-lang-2.4.jar:./lib/commons-logging-1.1.1.jar:./lib/fuse-j-javadoc.jar:./lib/fuse-j.jar:./lib/groovy-1.0-JSR-06.jar:./lib/guava-19.0.jar:./lib/httpclient-4.3.3.jar:./lib/httpcore-4.3.2.jar:./lib/jackson-annotations-2.1.1.jar:./lib/jackson-core-2.1.1.jar:./lib/jackson-core-asl-1.8.1.jar:./lib/jackson-databind-2.1.1.jar:./lib/jackson-mapper-asl-1.8.1.jar:./lib/java-xmlbuilder-0.4.jar:./lib/jets3t-0.9.1.jar:./lib/jline-0.9.94.jar:./lib/joda-time-2.2.jar:./lib/log4j-1.2.16.jar:./lib/microsoft-windowsazure-api-0.4.6.jar:./lib/netty-3.1.1.GA.jar:./lib/netty-3.7.0.Final.jar:./lib/servlet-api.jar:./lib/slf4j-api-1.6.1.jar:./lib/slf4j-log4j12-1.6.1.jar:./lib/zookeeper-3.4.8.jar:./lib/jpbc-api-2.0.0.jar:./lib/jpbc-benchmark-2.0.0.jar:./lib/jpbc-crypto-2.0.0.jar:./lib/jpbc-mm-2.0.0.jar:./lib/jpbc-pbc-2.0.0.jar:./lib/jpbc-plaf-2.0.0.jar:./lib/bcprov-jdk16-1.46.jar \
       -Dorg.apache.commons.logging.Log=fuse.logging.FuseLog \
   -Dfuse.logging.level=WARN \
   scfs.general.SCFS -f -s $1 $2 $3 $4 $5 $6 $7 $8;
