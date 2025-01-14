/*
 * common.h - Provide global definitions
 *
 * Copyright (C) 2013 - 2019, Max Lv <max.c.lv@gmail.com>
 *
 * This file is part of the shadowsocks-libev.
 * shadowsocks-libev is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * shadowsocks-libev is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with shadowsocks-libev; see the file COPYING. If not, see
 * <http://www.gnu.org/licenses/>.
 */

#ifndef _COMMON_H
#define _COMMON_H

#ifndef SOL_TCP
#define SOL_TCP IPPROTO_TCP
#endif

#if defined(MODULE_TUNNEL) || defined(MODULE_REDIR)
#define MODULE_LOCAL
#endif

#include "crypto.h"

int init_udprelay(const char *server_host, const char *server_port,
#ifdef MODULE_LOCAL
                  const struct sockaddr *remote_addr, const int remote_addr_len,
#ifdef MODULE_TUNNEL
                  const ss_addr_t tunnel_addr,
#endif
#endif
                  int mtu, crypto_t *crypto, int timeout, const char *iface);

void free_udprelay(void);

#ifdef __ANDROID__
int protect_socket(int fd);
int send_traffic_stat(uint64_t tx, uint64_t rx);
#endif

#define STAGE_ERROR     -1  /* 错误检测 */
#define STAGE_INIT       0  /* 初始阶段 */
#define STAGE_HANDSHAKE  1  /* 与客户端握手 */
#define STAGE_RESOLVE    4  /* 解析主机名 */
#define STAGE_STREAM     5  /* 流阶段，数据在客户端和服务器之间传输 */
#define STAGE_STOP       6  /* 服务器停止响应 */

/* Vals for long options */
enum {
    GETOPT_VAL_HELP = 257, // 帮助
    GETOPT_VAL_REUSE_PORT, // 重用端口
    GETOPT_VAL_FAST_OPEN, // 快速打开
    GETOPT_VAL_NODELAY, // 不延迟
    GETOPT_VAL_ACL, // 访问控制列表
    GETOPT_VAL_MTU, // 最大传输单元
    GETOPT_VAL_MPTCP, // 多路径传输控制协议
    GETOPT_VAL_PLUGIN, // 插件
    GETOPT_VAL_PLUGIN_OPTS, // 插件选项
    GETOPT_VAL_PASSWORD, // 密码
    GETOPT_VAL_KEY, // 密钥
    GETOPT_VAL_MANAGER_ADDRESS, // 管理地址
    GETOPT_VAL_EXECUTABLE, // 可执行文件
    GETOPT_VAL_WORKDIR, // 工作目录
    GETOPT_VAL_TCP_INCOMING_SNDBUF, // 输入缓冲区大小
    GETOPT_VAL_TCP_INCOMING_RCVBUF, // 输入接收缓冲区大小
    GETOPT_VAL_TCP_OUTGOING_SNDBUF, // 输出发送缓冲区大小
    GETOPT_VAL_TCP_OUTGOING_RCVBUF, // 输出接收缓冲区大小
    GETOPT_VAL_NFTABLES_SETS, // nftables sets
};

#endif // _COMMON_H
