/*
 * local.h - Define the client's buffers and callbacks
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

#ifndef _LOCAL_H
#define _LOCAL_H

#include <libcork/ds.h>

#ifdef HAVE_LIBEV_EV_H
#include <libev/ev.h>
#else
#include <ev.h>
#endif

#ifdef __MINGW32__
#include "winsock.h"
#endif

#include "crypto.h"
#include "jconf.h"

#include "common.h"

// 监听上下文
typedef struct listen_ctx {
    ev_io io;
    char *iface;
    int remote_num;
    int timeout;
    int fd;
    int mptcp;
    struct sockaddr **remote_addr;
} listen_ctx_t;

// 服务器上下文
typedef struct server_ctx {
    ev_io io;
    int connected;
    struct server *server;
} server_ctx_t;

// 服务器结构体
typedef struct server {
    int fd; // 文件描述符
    int stage; // 阶段

    cipher_ctx_t *e_ctx;
    cipher_ctx_t *d_ctx;
    struct server_ctx *recv_ctx;
    struct server_ctx *send_ctx;
    struct listen_ctx *listener;
    struct remote *remote;

    buffer_t *buf;
    buffer_t *abuf;

    ev_timer delayed_connect_watcher;

    struct cork_dllist_item entries;
} server_t;

// 远程上下文
typedef struct remote_ctx {
    ev_io io;
    ev_timer watcher;

    int connected;
    struct remote *remote;
} remote_ctx_t;

// 远程结构体
typedef struct remote {
    int fd; // 文件描述符
    int direct; // 直接连接
    int addr_len;
    uint32_t counter;
#ifdef TCP_FASTOPEN_WINSOCK
    OVERLAPPED olap;
    int connect_ex_done;
#endif

    buffer_t *buf;

    struct remote_ctx *recv_ctx;
    struct remote_ctx *send_ctx;
    struct server *server;
    struct sockaddr_storage addr;
} remote_t;

#endif // _LOCAL_H
