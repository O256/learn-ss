/*
 * android.c - Setup IPC for shadowsocks-android
 *
 * Copyright (C) 2013 - 2019, Max Lv <max.c.lv@gmail.com>
 *
 * This file is part of the shadowsocks-libev.
 *
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

#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <locale.h>
#include <signal.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include <errno.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <sys/un.h>
#include <ancillary.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "netutils.h"
#include "utils.h"

// 保护socket
// 参数：文件描述符
// 返回值：成功返回0，失败返回-1
int
protect_socket(int fd)
{
    int sock;
    struct sockaddr_un addr;

    if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        LOGE("[android] socket() failed: %s (socket fd = %d)\n", strerror(errno), sock);
        return -1;
    }

    // Set timeout to 3s
    struct timeval tv;
    tv.tv_sec  = 3;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(struct timeval)); // 设置接收超时
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char *)&tv, sizeof(struct timeval)); // 设置发送超时

    memset(&addr, 0, sizeof(addr)); // 清空地址结构体
    addr.sun_family = AF_UNIX; // 设置地址族
    strncpy(addr.sun_path, "protect_path", sizeof(addr.sun_path) - 1); // 设置路径

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == -1) { // 连接到保护路径
        LOGE("[android] connect() failed for protect_path: %s (socket fd = %d)\n",
             strerror(errno), sock);
        close(sock);
        return -1;
    }

    if (ancil_send_fd(sock, fd)) { // 发送文件描述符
        ERROR("[android] ancil_send_fd"); // 输出错误
        close(sock);
        return -1;
    }

    char ret = 0;

    if (recv(sock, &ret, 1, 0) == -1) { // 接收返回值
        ERROR("[android] recv");
        close(sock);
        return -1;
    }

    close(sock);
    return ret;
}

extern char *stat_path;

// 发送流量统计
// 参数：发送流量，接收流量
// 返回值：成功返回0，失败返回-1
int
send_traffic_stat(uint64_t tx, uint64_t rx)
{
    if (!stat_path) // 如果路径为空 
        return 0;
    int sock; // 套接字
    struct sockaddr_un addr; // 地址结构体

    if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) { // 创建套接字
        LOGE("[android] socket() failed: %s (socket fd = %d)\n", strerror(errno), sock);
        return -1;
    }

    // 设置超时为1s
    struct timeval tv;
    tv.tv_sec  = 1;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(struct timeval)); // 设置接收超时
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char *)&tv, sizeof(struct timeval)); // 设置发送超时 

    memset(&addr, 0, sizeof(addr)); // 清空地址结构体
    addr.sun_family = AF_UNIX; // 设置地址族
    strncpy(addr.sun_path, stat_path, sizeof(addr.sun_path) - 1); // 设置路径

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == -1) { // 连接到流量统计路径
        LOGE("[android] connect() failed for stat_path: %s (socket fd = %d)\n",
             strerror(errno), sock); // 输出错误
        close(sock);
        return -1;
    }

    uint64_t stat[2] = { tx, rx };

    if (send(sock, stat, sizeof(stat), 0) == -1) { // 发送流量统计
        ERROR("[android] send"); // 输出错误
        close(sock);
        return -1;
    }

    close(sock);
    return 0;
}
