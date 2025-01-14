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
    ev_io io; // 事件循环
    char *iface; // 接口
    int remote_num; // 远程连接数
    int timeout; // 超时时间
    int fd; // 文件描述符
    int mptcp; // 多路复用
    struct sockaddr **remote_addr; // 远程地址
} listen_ctx_t;

// 服务器上下文
typedef struct server_ctx {
    ev_io io; // 事件循环   
    int connected; // 连接状态
    struct server *server; // 服务器
} server_ctx_t;

// 服务器结构体，这里的服务器指的是监听服务器，每个连接都会有一个server
typedef struct server {
    int fd; // 文件描述符
    int stage; // 阶段

    cipher_ctx_t *e_ctx; // 加密上下文
    cipher_ctx_t *d_ctx; // 解密上下文
    struct server_ctx *recv_ctx; // 接收上下文
    struct server_ctx *send_ctx; // 发送上下文
    struct listen_ctx *listener; // 监听上下文
    struct remote *remote; // 这里是指来自远程的连接

    buffer_t *buf; // 缓冲区
    buffer_t *abuf; // 缓冲区

    ev_timer delayed_connect_watcher; // 延迟连接计时器

    struct cork_dllist_item entries; // 双向链表，用于存储服务器
} server_t;

// 远程上下文
typedef struct remote_ctx {
    ev_io io; // 事件循环
    ev_timer watcher; // 计时器

    int connected; // 连接状态
    struct remote *remote; // 远程连接
} remote_ctx_t;

// 远程结构体
typedef struct remote {
    int fd; // 文件描述符
    int direct; // 直接连接
    int addr_len; // 地址长度
    uint32_t counter; // 计数器
#ifdef TCP_FASTOPEN_WINSOCK
    OVERLAPPED olap;
    int connect_ex_done;
#endif

    buffer_t *buf; // 缓冲区

    struct remote_ctx *recv_ctx; // 接收上下文
    struct remote_ctx *send_ctx; // 发送上下文
    struct server *server; // 服务器
    struct sockaddr_storage addr; // 地址
} remote_t;

#endif // _LOCAL_H
