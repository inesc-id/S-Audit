mkdir DepSpace;
mkdir DepSpace/lib;
mkdir DepSpace/bin;
mkdir DepSpace/bin/scfs;
mkdir DepSpace/bin/scfs/directoryService;

cp lib/DepSpace.jar lib/PVSS.jar lib/netty-3.1.1.GA.jar lib/SMaRt.jar lib/groovy-1.0-JSR-06.jar lib/commons-codec-1.5.jar DepSpace/lib;

cp -r config DepSpace;

cp bin/scfs/directoryService/FileStats.class DepSpace/bin/scfs/directoryService;

echo -n "#!/bin/sh

java -Dfile.encoding=UTF-8 -cp bin:lib/DepSpace.jar:lib/PVSS.jar:lib/netty-3.1.1.GA.jar:lib/SMaRt.jar:lib/groovy-1.0-JSR-06.jar:lib/commons-codec-1.5.jar server.Main " > DepSpace/runDepSpace.sh;

echo -n "$" >> DepSpace/runDepSpace.sh;
echo -n "1"  >> DepSpace/runDepSpace.sh;

chmod +x DepSpace/runDepSpace.sh

#zip -r DepSpace.zip DepSpace;

#rm -r DepSpace;
