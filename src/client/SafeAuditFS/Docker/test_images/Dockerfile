FROM thesis_img
RUN sudo apt-get -y update
RUN cd /usr/; mkdir test_scfs; cd test_scfs; mkdir 0; mkdir 1; mkdir logs; cd logs; mkdir 0; mkdir 1; mkdir DepSpace; cd DepSpace; mkdir 0; mkdir 1; mkdir 2; mkdir 3
COPY test.sh /
COPY test_init.sh /
COPY list_status.sh /
COPY ServerThread.jar /