FROM pre_thesis_img
ENV LANGUAGE En_US
ENV LC_ALL en_US.UTF-8
ENV LANG en_US.UTF-8
#premiliminaries
RUN sudo apt-get -y update
RUN sudo apt-get -y install fuse
COPY ../SafeAuditSCFS/ /usr/scfs/
COPY ../accountsLOCAL.properties /usr/scfs/config/accounts.properties
RUN cd /usr/scfs/; ./configure_x64.sh ;make; sh getDepSpaceToDeploy.sh