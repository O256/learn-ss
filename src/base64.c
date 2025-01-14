/*
 * Copyright (c) 2006 Ryan Martell. (rdm4@martellventures.com)
 *
 * This file is part of FFmpeg.
 *
 * FFmpeg is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * FFmpeg is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with FFmpeg; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

/**
 * @file
 * @brief Base64 encode/decode
 * @author Ryan Martell <rdm4@martellventures.com> (with lots of Michael)
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <limits.h>
#include <stddef.h>

#include "base64.h"

/* ---------------- private code */
static const uint8_t map2[] = // 映射表，这个表是base64编码的映射表，用于解码，解码时，根据这个表，将base64编码转换为原始数据
{
    0xff, 0xff, 0x3e, 0xff, 0xff, 0x34, 0x35, 0x36,
    0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x01,
    0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
    0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11,
    0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
    0xff, 0xff, 0xff, 0xff, 0x3f, 0xff, 0x1a, 0x1b,
    0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23,
    0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b,
    0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33
};

// 解码
// 参数：解码后的数据，原始数据，解码后的数据长度
// 返回值：解码后的数据长度
int base64_decode(uint8_t *out, const char *in, int out_size)
{
    int i, v;
    uint8_t *dst = out; // 解码后的数据

    v = 0;
    for (i = 0; in[i] && in[i] != '='; i++) { // 遍历原始数据，所以base64编码中，=号表示数据结束
        unsigned int index = in[i] - 43; // 计算索引，43是base64编码中，A-Z,a-z,0-9,-,_的ASCII码值
        if (index >= sizeof(map2) || map2[index] == 0xff) // 如果索引超出范围或者索引对应的值为0xff，则返回-1
            return -1;
        v = (v << 6) + map2[index]; // 将索引对应的值转换为6位二进制数，然后加上之前的值，得到新的值
        if (i & 3) { // 如果i是3的倍数，则将6位二进制数转换为8位二进制数，base64编码的字符一定小于8位二进制数
            if (dst - out < out_size) { // 如果解码后的数据长度小于out_size，则将6位二进制数转换为8位二进制数
                *dst++ = v >> (6 - 2 * (i & 3)); // 将6位二进制数转换为8位二进制数
            }
        }
    }

    return dst - out; // 返回解码后的数据长度
}

/*****************************************************************************
* b64_encode: Stolen from VLC's http.c.
* 简化自Michael。
* 由Ryan修复了边缘情况，并使其从数据（vs.字符串）工作。
*****************************************************************************/

// 编码
// 参数：编码后的数据，编码后的数据长度，原始数据，原始数据长度
// 返回值：编码后的数据
char *base64_encode(char *out, int out_size, const uint8_t *in, int in_size)
{
    static const char b64[] = // base64编码的映射表，用于编码，编码时，根据这个表，将原始数据转换为base64编码
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    char *ret, *dst; // 编码后的数据，解码后的数据
    unsigned i_bits = 0; // 8位二进制数
    int i_shift = 0; // 移位
    int bytes_remaining = in_size; // 剩余字节数

    if (in_size >= UINT_MAX / 4 || // 如果原始数据长度大于UINT_MAX / 4，则返回NULL
        out_size < BASE64_SIZE(in_size)) // 如果编码后的数据长度小于BASE64_SIZE(in_size)，则返回NULL
        return NULL;
    ret = dst = out; // 编码后的数据，解码后的数据
    while (bytes_remaining) {
        i_bits = (i_bits << 8) + *in++; // 将原始数据转换为8位二进制数
        bytes_remaining--; // 剩余字节数减1
        i_shift += 8; // 移位加8

        do {
            *dst++ = b64[(i_bits << 6 >> i_shift) & 0x3f]; // 将8位二进制数转换为6位二进制数，然后根据映射表，将6位二进制数转换为base64编码
            i_shift -= 6; // 移位减6
        } while (i_shift > 6 || (bytes_remaining == 0 && i_shift > 0)); // 如果移位大于6或者剩余字节数为0且移位大于0，则将8位二进制数转换为6位二进制数
    }
    while ((dst - ret) & 3) // 如果编码后的数据长度不是4的倍数，则添加=号
        *dst++ = '=';
    *dst = '\0'; // 添加结束符

    return ret;
}
