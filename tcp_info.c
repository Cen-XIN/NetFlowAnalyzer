/*
 * Version 1.0.2 (2018-07-06)
 * Copyright (c) Cen XIN
 */

#include "tcp_info.h"

void free_tcp_info(void *tcp_info_t) {
    free(tcp_info_t);
}

void show_tcp_info(struct tcp_info *tmp_info) {
    printf("No.%d\tSrc_ip: %s\tDst_ip: %s\tSrc_port: %d\tDst_port: %d\n",
           tmp_info->pkt_num,
           tmp_info->src_ip,
           tmp_info->dst_ip,
           tmp_info->src_port,
           tmp_info->dst_port);
}
