FROM ubuntu
#premiliminaries
ENV LANGUAGE En_US
ENV LC_ALL en_US.UTF-8
ENV LANG en_US.UTF-8
RUN sudo apt-get -y update
RUN sudo apt-get -y install wget vim nano make gcc fuse acl 
#install java and update path
RUN cd /usr/local; wget --no-cookies --no-check-certificate --header "Cookie: oraclelicense=accept-securebackup-cookie" "http://download.oracle.com/otn-pub/java/jdk/7u55-b13/jdk-7u55-linux-x64.tar.gz" -O jdk-7-linux-x64.tar.gz; tar zxvf jdk-7-linux-x64.tar.gz;pwd; rm jdk-7-linux-x64.tar.gz
RUN cd /usr/local;mv jdk1.7.0_55 ../java;  
ENV PATH $PATH:/usr/java/bin
#test instalation
RUN java -version
