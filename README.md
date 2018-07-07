# NetFlowAnalyzer
Written by Cen XIN (辛岑), COI HZAU (华中农业大学信息学院) for 2015级暑期综合实训

A simple NetFlowAnalyzer for monitoring net flows and analysing data packets.

## Environment Requirements
+ Ubuntu 12.04.5 LTS

+ gcc-4.6.3

+ Libpcap-1.8.1

## Install Libpcap
1. Go to TCPDUMP/LIBPCAP website, and then download the latest Libpcap packets.

2. In your Libpcap directory, use './configure'.

3. You may fail to successfully configure. Try to install 'flex' and 'yacc'. \[ Well, if you just succeed, ignore this step : ) \]

4. Then use 'make' and after a few seconds, use 'make install'.

5. That's all. Now enjoy your programming with Libpcap : P

## Usage
1. Clone my directory to local.

2. gcc -o * main.c analysis.c hash.c tcp_info.c -l pcap
### AGAIN: Make sure you have installed Libpcap CORRECTLY!!!

3. Follow the instruction showed in my program, you will make it : )

## Tips
The first time you compile your program with '-l pcap', you may come across the error: while loading shared libraries: libpcap.so.1: cannot open shared object file: No such file or directory

Just open '/etc/ld.so.conf', and put one new line '/usr/local/lib'. Then 'ldconfig'. \[ That may work, I hope so : ) \]

## For any other question, just contact me (directly or through e-mail)
