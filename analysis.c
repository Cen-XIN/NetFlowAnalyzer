/*
 * Version 1.0.2 (2018-07-06)
 * Copyright (c) Cen XIN
 */

#include "analysis.h"

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    static int count = 1;                   /* packet counter */

    const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
    const struct sniff_ip *ip;              /* The IP header */
    const struct sniff_tcp *tcp;            /* The TCP header */
    const char *payload;                    /* Packet payload */

    int size_ip;
    int size_tcp;
    int size_payload;

    struct tcp_info *tmp_info = (struct tcp_info*)malloc(sizeof(struct tcp_info));

    printf("\nPacket number %d:\n", count);
    tmp_info->pkt_num = count;
    count++;

    /* define ethernet header */
    ethernet = (struct sniff_ethernet *) (packet);

    /* define/compute ip header offset */
    ip = (struct sniff_ip *) (packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip) * 4;
    if (size_ip < 20) {
        printf("[!] Invalid IP header length: %u bytes\n", size_ip);
        return;
    }

    /* print source and destination IP addresses */
    printf("    Src IP:   %s\n", inet_ntoa(ip->ip_src));
    printf("    Dst IP:   %s\n", inet_ntoa(ip->ip_dst));
    sprintf(tmp_info->src_ip, "%s", inet_ntoa(ip->ip_src));
    sprintf(tmp_info->dst_ip, "%s", inet_ntoa(ip->ip_dst));

    /* determine protocol */
    switch (ip->ip_p) {
        case IPPROTO_TCP:
            printf("    Protocol: TCP\n");
            tcp_total_num++;
            break;
        case IPPROTO_UDP:
            printf("    Protocol: UDP\n");
            udp_total_num++;
            return;
        case IPPROTO_ICMP:
            printf("    Protocol: ICMP\n");
            icmp_total_num++;
            return;
        case IPPROTO_IP:
            printf("    Protocol: IP\n");
            return;
        default:
            printf("    Protocol: unknown\n");
            unknown_total_num++;
            return;
    }

    /* define/compute tcp header offset */
    tcp = (struct sniff_tcp *) (packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp) * 4;
    if (size_tcp < 20) {
        printf("[!] Invalid TCP header length: %u bytes\n", size_tcp);
        return;
    }

    printf("    Src port: %d\n", ntohs(tcp->th_sport));
    printf("    Dst port: %d\n", ntohs(tcp->th_dport));
    printf("    SEQ:      %d\n", ntohs((uint16_t) tcp->th_seq));
    printf("    ACK:      %d\n", ntohs((uint16_t) tcp->th_ack));
    printf("    OFFSET:   %d\n", ntohs(tcp->th_offx2));
    printf("    FLAGS:    %d\n", ntohs(tcp->th_flags));
    printf("    WIN:      %d\n", ntohs(tcp->th_win));
    printf("    SUM:      %d\n", ntohs(tcp->th_sum));
    printf("    URP:      %d\n", ntohs(tcp->th_urp));
    tmp_info->src_port = ntohs(tcp->th_sport);
    tmp_info->dst_port = ntohs(tcp->th_dport);
    hash_table_put2(tcp_ht, tmp_info->src_ip, tmp_info, free_tcp_info);

    /* define/compute tcp payload (segment) offset */
    payload = (u_char *) (packet + SIZE_ETHERNET + size_ip + size_tcp);

    /* compute tcp payload (segment) size */
    size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

    /* Print payload data as binary */
    if (size_payload > 0) {
        printf("   Payload (%d bytes):\n", size_payload);
        print_payload(payload, size_payload);
    }

    return;
}

void print_payload(const u_char *payload, int len) {
    int len_rem = len;
    int line_width = 16;                /* number of bytes per line */
    int line_len;
    int offset = 0;                     /* zero-based offset counter */
    const u_char *ch = payload;

    if (len <= 0)
        return;

    /* data fits on one line */
    if (len <= line_width) {
        print_hex_ascii_line(ch, len, offset);
        return;
    }

    /* data spans multiple lines */
    for (;;) {
        /* compute current line length */
        line_len = line_width % len_rem;
        /* print line */
        print_hex_ascii_line(ch, line_len, offset);
        /* compute total remaining */
        len_rem = len_rem - line_len;
        /* shift pointer to remaining bytes to print */
        ch = ch + line_len;
        /* add offset */
        offset = offset + line_width;
        /* check if we have line width chars or less */
        if (len_rem <= line_width) {
            /* print last line and get out */
            print_hex_ascii_line(ch, len_rem, offset);
            break;
        }
    }
    return;
}

void print_hex_ascii_line(const u_char *payload, int len, int offset) {
    int i;
    int gap;
    const u_char *ch;

    /* offset */
    printf("%05d   ", offset);

    /* hex */
    ch = payload;
    for (i = 0; i < len; i++) {
        printf("%02x ", *ch);
        ch++;
        /* print extra space after 8th byte for visual aid */
        if (i == 7)
            printf(" ");
    }
    /* print space to handle line less than 8 bytes */
    if (len < 8)
        printf(" ");

    /* fill hex gap with spaces if not full line */
    if (len < 16) {
        gap = 16 - len;
        for (i = 0; i < gap; i++) {
            printf("   ");
        }
    }
    printf("   ");

    /* ascii (if printable) */
    ch = payload;
    for (i = 0; i < len; i++) {
        if (isprint(*ch))
            printf("%c", *ch);
        else
            printf(".");
        ch++;
    }

    printf("\n");

    return;
}

void start_analyse() {
    char *dev = NULL;                       /* capture device name */
    char errbuf[PCAP_ERRBUF_SIZE];          /* error buffer */
    pcap_t *handle;                         /* packet capture handle */

    char filter_exp[16];                    /* filter expression [3] */
    struct bpf_program fp;                  /* compiled filter program (expression) */
    struct in_addr addr;
    struct timeval start, end;
    bpf_u_int32 mask;                       /* subnet mask */
    bpf_u_int32 net;                        /* ip */
    int num_packets = 10;                   /* number of packets to capture */
    int func_num;
    long time_use;

    /* find a capture device if not specified on command-line */
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n",
                errbuf);
        exit(EXIT_FAILURE);
    }

    /* get network number and mask associated with capture device */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
                dev, errbuf);
        net = 0;
        mask = 0;
    }

    /* print capture info */
    printf("Device: %s\n", dev);

    addr.s_addr = net;
    printf("IP address:   %s\n", inet_ntoa(addr));

    addr.s_addr = mask;
    printf("Net mask: %s\n", inet_ntoa(addr));

    printf("How many packets would you like to catch?\n");
    printf("Enter a integer (no more than 100): ");
    scanf("%d", &num_packets);

    printf("\nWhat kind of packet do you want to catch? (input function number): \n");
    printf("1 for TCP\n");
    printf("2 for UDP\n");
    printf("3 for ICMP\n");
    printf("4 for IP\n");
    printf("Enter your choice (function number): ");
    scanf("%d", &func_num);
    switch (func_num) {
        case 1:
            strcpy(filter_exp, "tcp");
            break;
        case 2:
            strcpy(filter_exp, "udp");
            break;
        case 3:
            strcpy(filter_exp, "icmp");
            break;
        case 4:
            strcpy(filter_exp, "ip");
            break;
        default:
            strcpy(filter_exp, "ip");
            break;
    }

    /* open capture device */
    handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        exit(EXIT_FAILURE);
    }

    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "%s is not an Ethernet\n", dev);
        exit(EXIT_FAILURE);
    }

    /* compile the filter expression */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n",
                filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    /* apply the compiled filter */
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n",
                filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    /* initialize TCP Hash Table */
    tcp_ht = hash_table_new();

    /* begin to get packets */

    gettimeofday(&start, NULL);
    pcap_loop(handle, num_packets, got_packet, NULL);
    gettimeofday(&end, NULL);

    /* cleanup */
    pcap_freecode(&fp);
    pcap_close(handle);

    printf("\nCapture complete.\n");
    time_use = 1000000 * (end.tv_sec - start.tv_sec) + end.tv_usec - start.tv_usec;
    printf("This analysis process cost %f s\n", time_use / 1000000.0);
    printf("Packet numbers:\n");
    printf("TCP = %d\n", tcp_total_num);
    printf("UDP = %d\n", udp_total_num);
    printf("ICMP = %d\n", icmp_total_num);
    printf("Unknown = %d\n", unknown_total_num);
}

void got_netflow(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct timeval *old_ts = (struct timeval *) args;
    unsigned long msec_delay = 0;
    unsigned long msec_load = 0;
    struct tm *ltime;
    char timestr[16];
    time_t local_tv_sec;
    double UP_BPS, DOWN_BPS;
    static int count = 1;

    const struct sniff_ethernet *ethernet;
    const struct sniff_ip *ip;
    const struct sniff_tcp *tcp;
    const char *payload;

    int size_ip;
    int size_tcp;
    int size_payload;

    count++;

    local_tv_sec = header->ts.tv_sec;
    ltime = localtime(&local_tv_sec);
    strftime(timestr, sizeof(timestr), "%H:%M:%S", ltime);
    //DEBUG: printf(" %s ", timestr);

    /* define ethernet header */
    ethernet = (struct sniff_ethernet *) (packet);

    /* define/compute ip header offset */
    ip = (struct sniff_ip *) (packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip) * 4;
    if (size_ip < 20) {
        printf("   * Invalid IP header length: %u bytes\n", size_ip);
        return;
    }

    //DEBUG: printf(" scr: %s > dst ", inet_ntoa(ip->ip_src)/*,inet_ntoa(ip->ip_dst)*/);
    //DEBUG: printf("%s", inet_ntoa(ip->ip_dst));

    /* determine protocol */
    switch (ip->ip_p) {
        case IPPROTO_TCP: {
            //DEBUG: printf(" TCP ");
            /* define/compute tcp header offset */
            tcp = (struct sniff_tcp *) (packet + SIZE_ETHERNET + size_ip);
            /*the TCP header length*/
            size_tcp = TH_OFF(tcp) * 4;

            if (size_tcp < 20) {
                printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
                return;
            }

            //DEBUG: printf(" Sp: %d,dp %d\n", ntohs(tcp->th_sport), ntohs(tcp->th_dport));
            /* compute tcp payload (segment) size */
            size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
            /*the download of every packet we get in a seccond*/
            msec_load = ntohs(ip->ip_len) - size_payload;
            break;
        }
        case IPPROTO_UDP: {
            //DEBUG: printf(" UDP ");
            size_payload = size_ip;
            msec_load = ntohs(ip->ip_len) - size_payload;
            break;
        }
        case IPPROTO_ICMP: {
            //DEBUG: printf(" ICMP ");
            size_payload = size_ip;
            msec_load = ntohs(ip->ip_len) - size_payload;
            break;
        }
        case IPPROTO_IP: {
            //DEBUG: printf(" IP ");
            size_payload = size_ip;
            msec_load = ntohs(ip->ip_len) - size_payload;
            break;
        }
        default:
            //DEBUG: printf(" unknown ");
            return;
    }


    msec_delay = (header->ts.tv_sec - old_ts->tv_sec) * 1000000 - old_ts->tv_usec + header->ts.tv_usec;
    /*the position of the last dot in ip*/
    int length = strlen(local_ip) - strlen(strrchr(local_ip, '.'));
    /* decide whether upload or download */
    if (!strncmp(local_ip, inet_ntoa(ip->ip_src), length)) {/* the source ip equal local ip :upload */
        up_sec_load += msec_load;
        sec_delay += msec_delay;
    } else {/* the dest ip equal local ip :download */
        down_sec_load += msec_load;
        sec_delay += msec_delay;
    }

    up_total_load += up_sec_load;
    down_total_load += down_sec_load;

    if (sec_delay >= 100000) { //refresh for 1 sec
        UP_BPS = (up_sec_load * 1000000) / (msec_delay * 2 ^ 10);
        DOWN_BPS = (down_sec_load * 1000000) / (msec_delay * 2 ^ 10);
        sec_delay = 0;
        up_sec_load = 0;
        down_sec_load = 0;

        printf("+--------------------Monitor-----------------------+        \n");
        printf("|  UP_BPS:   %4.2f kb/s, UP_TOTAL:   %lu bytes     |        \n", UP_BPS, up_total_load);
        printf("|  DOWN_BPS: %4.2f kb/s, DOWN_TOTAL: %lu bytes     |        \n", DOWN_BPS, down_total_load);
        printf("+--------------------------------------------------+        \r");
        printf("\033[3A");//move the cursor up 4 column

    }
    /*save the time stamp*/
    old_ts->tv_sec = header->ts.tv_sec;
    old_ts->tv_usec = header->ts.tv_usec;

    return;
}

void start_monitor() {
    char *dev = NULL;                       /* capture device name */
    char errbuf[PCAP_ERRBUF_SIZE];          /* erroebuffer */
    pcap_t *handle;                         /* packet capture handle */

    char filter_exp[] = "ip";               /* filter expression */
    struct bpf_program fp;                  /* compiled filter program (expression) */
    struct in_addr addr;
    bpf_u_int32 mask;                       /* subnet mask */
    bpf_u_int32 net;                        /* ip */
    int num_packets = 0;                    /* number of packets to capture */
    struct timeval original_ts;

    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Failed to find default device: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Failed to get netmask for device %s: %s\n",
                dev, errbuf);
        net = 0;
        mask = 0;
    }

    addr.s_addr = net;
    strcpy(local_ip, inet_ntoa(addr));
    printf("IP address: %s\n", inet_ntoa(addr));

    addr.s_addr = mask;
    printf("Net mask: %s\n", inet_ntoa(addr));

    printf("Device: %s\n", dev);

    handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        exit(EXIT_FAILURE);
    }


    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "%s is not an Ethernet\n", dev);
        exit(EXIT_FAILURE);
    }


    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n",
                filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }


    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n",
                filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    pcap_loop(handle, num_packets, got_netflow, (unsigned char *) &original_ts);

    /* cleanup */
    pcap_freecode(&fp);
    pcap_close(handle);

    return;
}
