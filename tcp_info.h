/*
 * Version 1.0.2 (2018-07-06)
 * Copyright (c) Cen XIN
 */

#ifndef NETFLOWANALYZER_TCP_INFO_H
#define NETFLOWANALYZER_TCP_INFO_H

#include <stdlib.h>
#include <stdio.h>

struct tcp_info {
    int pkt_num;
    char src_ip[32];
    char dst_ip[32];
    int src_port;
    int dst_port;
};

/**
 * free and delete an existing tcp_info struct
 * @param tcp_info_t
 */
void free_tcp_info(void *tcp_info_t);

/**
 * print the content in an existing tcp_info struct
 * @param tmp_info
 */
void show_tcp_info(struct tcp_info *tmp_info);

#endif //NETFLOWANALYZER_TCP_INFO_H
