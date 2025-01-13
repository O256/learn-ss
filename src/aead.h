/*
 * aead.h - Define the AEAD interface
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

#ifndef _AEAD_H
#define _AEAD_H

#include "crypto.h"

// currently, XCHACHA20POLY1305IETF is not released yet
// XCHACHA20POLY1305 is removed in upstream
#ifdef FS_HAVE_XCHACHA20IETF
#define AEAD_CIPHER_NUM              5
#else
#define AEAD_CIPHER_NUM              4
#endif

int aead_encrypt_all(buffer_t *, cipher_t *, size_t); // 加密所有数据
int aead_decrypt_all(buffer_t *, cipher_t *, size_t); // 解密所有数据

int aead_encrypt(buffer_t *, cipher_ctx_t *, size_t); // 加密
int aead_decrypt(buffer_t *, cipher_ctx_t *, size_t); // 解密

void aead_ctx_init(cipher_t *, cipher_ctx_t *, int); // 初始化上下文
void aead_ctx_release(cipher_ctx_t *); // 释放上下文

cipher_t *aead_init(const char *pass, const char *key, const char *method); // 初始化加密

#endif // _AEAD_H
