/*
 * aead.c - Manage AEAD ciphers
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <mbedtls/version.h>
#define CIPHER_UNSUPPORTED "unsupported"
#include <time.h>
#include <stdio.h>
#include <assert.h>

#include <sodium.h>
#ifndef __MINGW32__
#include <arpa/inet.h>
#endif

#include "ppbloom.h"
#include "aead.h"
#include "utils.h"
#include "winsock.h"

#define NONE                    (-1)
#define AES128GCM               0
#define AES192GCM               1
#define AES256GCM               2
/*
 * methods above requires gcm context
 * methods below doesn't require it,
 * then we need to fake one
 */
#define CHACHA20POLY1305IETF    3

#ifdef FS_HAVE_XCHACHA20IETF
#define XCHACHA20POLY1305IETF   4
#endif

#define CHUNK_SIZE_LEN          2 // 长度缓冲区长度
#define CHUNK_SIZE_MASK         0x3FFF // 长度掩码

/*
 * Spec: http://shadowsocks.org/en/spec/AEAD-Ciphers.html
 *
 *  Shadowsocks 使用 AEAD 加密的方式在 SIP004 中定义并在 SIP007 中修订。SIP004 由 @Mygod 提出,
 * 设计灵感来自 @wongsyrone、@Noisyfox 和 @breakwa11。SIP007 由 @riobard 提出,
 * 得到了 @madeye、@Mygod、@wongsyrone 等多位贡献者的建议。
 *
 * 密钥派生
 *
 * HKDF_SHA1 是一个函数，它接受一个密钥、一个非秘密盐、一个信息字符串，并生成一个即使输入密钥较弱也具有强加密性的子密钥。
 *
 *      HKDF_SHA1(key, salt, info) => subkey
 *
 * 信息字符串将生成的子密钥绑定到特定应用程序上下文。在我们的例子中，它必须是 "ss-subkey" 而不能有引号。
 *
 * 我们使用 HKDF_SHA1 从预共享主密钥派生一个会话子密钥。盐必须在整个预共享主密钥的生命周期中保持唯一。
 *
 * TCP
 *
 * 一个 AEAD 加密的 TCP 流以一个随机生成的盐开始，用于派生会话子密钥，后面跟着任意数量的加密数据块。每个数据块的结构如下：
 *
 *      [encrypted payload length][length tag][encrypted payload][payload tag]
 *
 * 数据块长度是一个 2 字节的大端无符号整数，上限为 0x3FFF。更高的两位保留，必须设置为零。因此，数据块被限制为 16*1024 - 1 字节。
 *
 * 第一次 AEAD 加密/解密操作使用从 0 开始的计数非重复。每次加密/解密操作后，非重复数增加 1，就像它是一个无符号的小端整数。
 * 请注意，每个 TCP 数据块涉及两次 AEAD 加密/解密操作：一次用于数据块长度，一次用于数据块。因此，每个数据块
 * 的非重复数增加两次。
 *
 * UDP
 *
 * 一个 AEAD 加密的 UDP 包的结构如下：
 *
 *      [salt][encrypted payload][tag]
 *
 * 盐用于派生会话子密钥，必须随机生成以确保唯一性。每个 UDP 包独立加密/解密，使用派生的子密钥和所有零字节的非重复数。
 *
 */

// 支持的 AEAD 加密方法
const char *supported_aead_ciphers[AEAD_CIPHER_NUM] = {
    "aes-128-gcm",
    "aes-192-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
#ifdef FS_HAVE_XCHACHA20IETF
    "xchacha20-ietf-poly1305"
#endif
};

/*
 * use mbed TLS cipher wrapper to unify handling
 */
static const char *supported_aead_ciphers_mbedtls[AEAD_CIPHER_NUM] = {
    "AES-128-GCM",
    "AES-192-GCM",
    "AES-256-GCM",
    CIPHER_UNSUPPORTED,
#ifdef FS_HAVE_XCHACHA20IETF
    CIPHER_UNSUPPORTED
#endif
};

static const int supported_aead_ciphers_nonce_size[AEAD_CIPHER_NUM] = {
    12, 12, 12, 12,
#ifdef FS_HAVE_XCHACHA20IETF
    24
#endif
};

static const int supported_aead_ciphers_key_size[AEAD_CIPHER_NUM] = {
    16, 24, 32, 32,
#ifdef FS_HAVE_XCHACHA20IETF
    32
#endif
};

static const int supported_aead_ciphers_tag_size[AEAD_CIPHER_NUM] = {
    16, 16, 16, 16,
#ifdef FS_HAVE_XCHACHA20IETF
    16
#endif
};

// 加密函数, 使用 AEAD 加密方法对数据进行加密
static int
aead_cipher_encrypt(cipher_ctx_t *cipher_ctx, // 加密上下文 
                    uint8_t *c, // 加密后的数据
                    size_t *clen, // 加密后的数据长度
                    uint8_t *m, // 明文
                    size_t mlen, // 明文长度
                    uint8_t *ad, // 附加数据
                    size_t adlen, // 附加数据长度
                    uint8_t *n, // 非重复
                    uint8_t *k) // 密钥
{
    int err                      = CRYPTO_OK;
    unsigned long long long_clen = 0;

    size_t nlen = cipher_ctx->cipher->nonce_len;
    size_t tlen = cipher_ctx->cipher->tag_len;

    switch (cipher_ctx->cipher->method) {
    case AES256GCM: // 仅支持 libsodium 的 AES-256-GCM
        if (cipher_ctx->aes256gcm_ctx != NULL) { // 如果 AES-256-GCM 上下文可用，则使用它
            err = crypto_aead_aes256gcm_encrypt_afternm(c, &long_clen, m, mlen,
                                                        ad, adlen, NULL, n,
                                                        (const aes256gcm_ctx *)cipher_ctx->aes256gcm_ctx);
            *clen = (size_t)long_clen; // 安全地将 64 位长度转换为 32 位长度
            break;
        }
    // 否则，使用 mbedTLS 的 AES-NI 加密
    case AES192GCM:
    case AES128GCM:

        err = mbedtls_cipher_auth_encrypt(cipher_ctx->evp, n, nlen, ad, adlen,
                                          m, mlen, c, clen, c + mlen, tlen);
        *clen += tlen;
        break;
    case CHACHA20POLY1305IETF:
        err = crypto_aead_chacha20poly1305_ietf_encrypt(c, &long_clen, m, mlen,
                                                        ad, adlen, NULL, n, k); // 使用 libsodium 的 ChaCha20-Poly1305-IETF 加密
        *clen = (size_t)long_clen;
        break;
#ifdef FS_HAVE_XCHACHA20IETF
    case XCHACHA20POLY1305IETF:
        err = crypto_aead_xchacha20poly1305_ietf_encrypt(c, &long_clen, m, mlen,
                                                         ad, adlen, NULL, n, k);
        *clen = (size_t)long_clen;
        break;
#endif
    default:
        return CRYPTO_ERROR;
    }

    return err;
}

// 解密函数, 使用 AEAD 解密方法对数据进行解密
static int
aead_cipher_decrypt(cipher_ctx_t *cipher_ctx, // 解密上下文 
                    uint8_t *p, size_t *plen, // 解密后的数据
                    uint8_t *m, size_t mlen, // 明文
                    uint8_t *ad, size_t adlen, // 附加数据
                    uint8_t *n, uint8_t *k) // 非重复
{
    int err                      = CRYPTO_ERROR;
    unsigned long long long_plen = 0;

    size_t nlen = cipher_ctx->cipher->nonce_len; // 非重复数长度
    size_t tlen = cipher_ctx->cipher->tag_len; // 标签长度

    switch (cipher_ctx->cipher->method) {
    case AES256GCM: // 仅支持 libsodium 的 AES-256-GCM
        if (cipher_ctx->aes256gcm_ctx != NULL) { // 如果 AES-256-GCM 上下文可用，则使用它
            err = crypto_aead_aes256gcm_decrypt_afternm(p, &long_plen, NULL, m, mlen,
                                                        ad, adlen, n,
                                                        (const aes256gcm_ctx *)cipher_ctx->aes256gcm_ctx);
            *plen = (size_t)long_plen; // it's safe to cast 64bit to 32bit length here
            break;
        }
    // 否则，使用 mbedTLS 的 AES-NI 解密
    case AES192GCM:
    case AES128GCM:
        err = mbedtls_cipher_auth_decrypt(cipher_ctx->evp, n, nlen, ad, adlen,
                                          m, mlen - tlen, p, plen, m + mlen - tlen, tlen);
        break;
    case CHACHA20POLY1305IETF:
        err = crypto_aead_chacha20poly1305_ietf_decrypt(p, &long_plen, NULL, m, mlen,
                                                        ad, adlen, n, k); // 使用 libsodium 的 ChaCha20-Poly1305-IETF 解密
        *plen = (size_t)long_plen; // it's safe to cast 64bit to 32bit length here
        break;
#ifdef FS_HAVE_XCHACHA20IETF
    case XCHACHA20POLY1305IETF:
        err = crypto_aead_xchacha20poly1305_ietf_decrypt(p, &long_plen, NULL, m, mlen,
                                                         ad, adlen, n, k);
        *plen = (size_t)long_plen; // it's safe to cast 64bit to 32bit length here
        break;
#endif
    default:
        return CRYPTO_ERROR;
    }

    // 成功返回值在 libsodium 和 mbedTLS 中都是 0
    if (err != 0)
        // 尽管我们在调用者中从不返回任何库特定的值，
        // 这里我们仍然将错误代码设置为 CRYPTO_ERROR 以避免混淆。
        err = CRYPTO_ERROR;

    return err;
}

/*
 * 获取基本加密算法信息结构
 * 这是由 crypto 库提供的包装器
 */
const cipher_kt_t *
aead_get_cipher_type(int method) // 获取加密算法
{
    if (method < AES128GCM || method >= AEAD_CIPHER_NUM) {
        LOGE("aead_get_cipher_type(): Illegal method");
        return NULL;
    }

    /* 不使用 mbed TLS 的加密算法，直接返回 */
    if (method >= CHACHA20POLY1305IETF) {
        return NULL;
    }

    const char *ciphername  = supported_aead_ciphers[method]; // 加密算法名称
    const char *mbedtlsname = supported_aead_ciphers_mbedtls[method]; // mbedTLS 加密算法名称
    if (strcmp(mbedtlsname, CIPHER_UNSUPPORTED) == 0) { // 如果 mbedTLS 不支持该加密算法
        LOGE("Cipher %s currently is not supported by mbed TLS library",
             ciphername);
        return NULL;
    }
    return mbedtls_cipher_info_from_string(mbedtlsname); // 从 mbedTLS 库中获取加密算法信息
}

static void
aead_cipher_ctx_set_key(cipher_ctx_t *cipher_ctx, int enc) // 设置密钥
{
    const digest_type_t *md = mbedtls_md_info_from_string("SHA1"); // 获取 SHA1 哈希算法
    if (md == NULL) {
        FATAL("SHA1 Digest not found in crypto library");
    }

    int err = crypto_hkdf(md, // 使用 HKDF 生成子密钥
                          cipher_ctx->salt, cipher_ctx->cipher->key_len,
                          cipher_ctx->cipher->key, cipher_ctx->cipher->key_len,
                          (uint8_t *)SUBKEY_INFO, strlen(SUBKEY_INFO),
                          cipher_ctx->skey, cipher_ctx->cipher->key_len); // 使用 HKDF 生成子密钥
    if (err) {
        FATAL("Unable to generate subkey");
    }

    memset(cipher_ctx->nonce, 0, cipher_ctx->cipher->nonce_len);

    /* cipher that don't use mbed TLS, just return */
    if (cipher_ctx->cipher->method >= CHACHA20POLY1305IETF) {
        return;
    }
    if (cipher_ctx->aes256gcm_ctx != NULL) {
        if (crypto_aead_aes256gcm_beforenm(cipher_ctx->aes256gcm_ctx,
                                           cipher_ctx->skey) != 0) {
            FATAL("Cannot set libsodium cipher key");
        }
        return;
    }
    if (mbedtls_cipher_setkey(cipher_ctx->evp, cipher_ctx->skey,
                              cipher_ctx->cipher->key_len * 8, enc) != 0) {
        FATAL("Cannot set mbed TLS cipher key");
    }
    if (mbedtls_cipher_reset(cipher_ctx->evp) != 0) {
        FATAL("Cannot finish preparation of mbed TLS cipher context");
    }
}

// 初始化上下文
static void
aead_cipher_ctx_init(cipher_ctx_t *cipher_ctx, int method, int enc)
{
    if (method < AES128GCM || method >= AEAD_CIPHER_NUM) {
        LOGE("cipher_context_init(): Illegal method");
        return;
    }

    if (method >= CHACHA20POLY1305IETF) {
        return;
    }

    const char *ciphername = supported_aead_ciphers[method];

    const cipher_kt_t *cipher = aead_get_cipher_type(method);

    if (method == AES256GCM && crypto_aead_aes256gcm_is_available()) {
        cipher_ctx->aes256gcm_ctx = ss_aligned_malloc(sizeof(aes256gcm_ctx));
        memset(cipher_ctx->aes256gcm_ctx, 0, sizeof(aes256gcm_ctx));
    } else {
        cipher_ctx->aes256gcm_ctx = NULL;
        cipher_ctx->evp           = ss_malloc(sizeof(cipher_evp_t));
        memset(cipher_ctx->evp, 0, sizeof(cipher_evp_t));
        cipher_evp_t *evp = cipher_ctx->evp;
        mbedtls_cipher_init(evp);
        if (mbedtls_cipher_setup(evp, cipher) != 0) {
            FATAL("Cannot initialize mbed TLS cipher context");
        }
    }

    if (cipher == NULL) {
        LOGE("Cipher %s not found in mbed TLS library", ciphername);
        FATAL("Cannot initialize mbed TLS cipher");
    }

#ifdef SS_DEBUG
    dump("KEY", (char *)cipher_ctx->cipher->key, cipher_ctx->cipher->key_len);
#endif
}

// 初始化上下文
void
aead_ctx_init(cipher_t *cipher, cipher_ctx_t *cipher_ctx, int enc)
{
    sodium_memzero(cipher_ctx, sizeof(cipher_ctx_t));
    cipher_ctx->cipher = cipher;

    aead_cipher_ctx_init(cipher_ctx, cipher->method, enc);

    if (enc) {
        rand_bytes(cipher_ctx->salt, cipher->key_len);
    }
}

// 释放上下文
void
aead_ctx_release(cipher_ctx_t *cipher_ctx)
{
    if (cipher_ctx->chunk != NULL) {
        bfree(cipher_ctx->chunk);
        ss_free(cipher_ctx->chunk);
        cipher_ctx->chunk = NULL;
    }

    if (cipher_ctx->cipher->method >= CHACHA20POLY1305IETF) {
        return;
    }

    if (cipher_ctx->aes256gcm_ctx != NULL) {
        ss_aligned_free(cipher_ctx->aes256gcm_ctx);
        return;
    }

    mbedtls_cipher_free(cipher_ctx->evp);
    ss_free(cipher_ctx->evp);
}

// 加密所有数据，加密的是 plaintext 中的数据，加密后的数据写入到 ciphertext 中， 
// 加密后的数据长度为 salt_len + tag_len + plaintext->len
int
aead_encrypt_all(buffer_t *plaintext, cipher_t *cipher, size_t capacity)
{
    cipher_ctx_t cipher_ctx;
    aead_ctx_init(cipher, &cipher_ctx, 1);

    size_t salt_len = cipher->key_len;
    size_t tag_len  = cipher->tag_len;
    int err         = CRYPTO_OK;

    // 创建临时缓冲区
    static buffer_t tmp = { 0, 0, 0, NULL };
    brealloc(&tmp, salt_len + tag_len + plaintext->len, capacity);
    buffer_t *ciphertext = &tmp;
    ciphertext->len = tag_len + plaintext->len;

    /* 将盐复制到第一个位置 */
    memcpy(ciphertext->data, cipher_ctx.salt, salt_len);

    ppbloom_add((void *)cipher_ctx.salt, salt_len);

    aead_cipher_ctx_set_key(&cipher_ctx, 1);

    size_t clen = ciphertext->len;

    err = aead_cipher_encrypt(&cipher_ctx, // 加密
                              (uint8_t *)ciphertext->data + salt_len, &clen, // 加密后的数据
                              (uint8_t *)plaintext->data, plaintext->len, // 明文
                              NULL, 0, cipher_ctx.nonce, cipher_ctx.skey); // 非重复

    aead_ctx_release(&cipher_ctx);

    if (err)
        return CRYPTO_ERROR;

    assert(ciphertext->len == clen);

    brealloc(plaintext, salt_len + ciphertext->len, capacity); // q: 这样会不会导致传入的指针失效？ a: 不会，因为 brealloc 会重新分配内存，并复制数据
    memcpy(plaintext->data, ciphertext->data, salt_len + ciphertext->len); // 复制加密后的数据
    plaintext->len = salt_len + ciphertext->len; // 加密后的数据长度

    return CRYPTO_OK;
}

// 解密所有数据
int
aead_decrypt_all(buffer_t *ciphertext, cipher_t *cipher, size_t capacity)
{
    size_t salt_len = cipher->key_len; // 盐长度
    size_t tag_len  = cipher->tag_len; // 标签长度
    int err         = CRYPTO_OK; // 错误码

    if (ciphertext->len <= salt_len + tag_len) { // 如果数据长度小于盐长度和标签长度之和，则返回错误
        return CRYPTO_ERROR;
    }

    cipher_ctx_t cipher_ctx;
    aead_ctx_init(cipher, &cipher_ctx, 0); // 初始化上下文

    static buffer_t tmp = { 0, 0, 0, NULL };
    brealloc(&tmp, ciphertext->len, capacity); // 重新分配缓冲区
    buffer_t *plaintext = &tmp;
    plaintext->len = ciphertext->len - salt_len - tag_len;

    /* get salt */
    uint8_t *salt = cipher_ctx.salt;
    memcpy(salt, ciphertext->data, salt_len); // 复制盐

    if (ppbloom_check((void *)salt, salt_len) == 1) { // 检查盐是否重复
        LOGE("crypto: AEAD: repeat salt detected");
        return CRYPTO_ERROR;
    }

    aead_cipher_ctx_set_key(&cipher_ctx, 0); // 设置密钥

    size_t plen = plaintext->len; // 明文长度   
    err = aead_cipher_decrypt(&cipher_ctx, // 解密
                              (uint8_t *)plaintext->data, &plen, // 明文
                              (uint8_t *)ciphertext->data + salt_len, // 加密后的数据
                              ciphertext->len - salt_len, NULL, 0, // 非重复
                              cipher_ctx.nonce, cipher_ctx.skey);

    aead_ctx_release(&cipher_ctx);

    if (err)
        return CRYPTO_ERROR;

    ppbloom_add((void *)salt, salt_len); // 将盐添加到布隆过滤器中

    brealloc(ciphertext, plaintext->len, capacity); // 重新分配缓冲区
    memcpy(ciphertext->data, plaintext->data, plaintext->len); // 复制明文
    ciphertext->len = plaintext->len; // 明文长度

    return CRYPTO_OK;
}

// 加密块，将数据加密之后，写入到c中
static int
aead_chunk_encrypt(cipher_ctx_t *ctx, uint8_t *p, uint8_t *c,
                   uint8_t *n, uint16_t plen)
{
    size_t nlen = ctx->cipher->nonce_len;
    size_t tlen = ctx->cipher->tag_len;

    assert(plen <= CHUNK_SIZE_MASK);

    int err;
    size_t clen;
    uint8_t len_buf[CHUNK_SIZE_LEN]; // 长度缓冲区
    uint16_t t = htons(plen & CHUNK_SIZE_MASK); // 长度
    memcpy(len_buf, &t, CHUNK_SIZE_LEN); // 复制长度

    clen = CHUNK_SIZE_LEN + tlen; // 加密后的长度
    err  = aead_cipher_encrypt(ctx, c, &clen, len_buf, CHUNK_SIZE_LEN,
                               NULL, 0, n, ctx->skey); // 将长度写入到c中
    if (err)
        return CRYPTO_ERROR;

    assert(clen == CHUNK_SIZE_LEN + tlen); // 加密后的长度

    sodium_increment(n, nlen); // 非重复

    clen = plen + tlen; // 加密后的长度
    err  = aead_cipher_encrypt(ctx, c + CHUNK_SIZE_LEN + tlen, &clen, p, plen,
                               NULL, 0, n, ctx->skey); // 将明文写入到c中
    if (err)
        return CRYPTO_ERROR;

    assert(clen == plen + tlen); // 加密后的长度

    sodium_increment(n, nlen); // 如何保证非重复？

    return CRYPTO_OK;
}

/* TCP */
// 编码头部，将数据加密之后，写入到plaintext中
int
aead_encrypt(buffer_t *plaintext, cipher_ctx_t *cipher_ctx, size_t capacity)
{
    if (cipher_ctx == NULL)
        return CRYPTO_ERROR;

    if (plaintext->len == 0) { // 如果数据长度为0，则直接返回
        return CRYPTO_OK;
    }

    static buffer_t tmp = { 0, 0, 0, NULL }; // 临时缓冲区
    buffer_t *ciphertext; // 加密后的数据

    cipher_t *cipher = cipher_ctx->cipher; // 获得加密算法
    int err          = CRYPTO_ERROR; // 错误码
    size_t salt_ofst = 0; // 盐偏移
    size_t salt_len  = cipher->key_len; // 盐长度
    size_t tag_len   = cipher->tag_len; // 标签长度

    if (!cipher_ctx->init) { // 如果未初始化
        salt_ofst = salt_len; // 盐偏移
    }

    size_t out_len = salt_ofst + 2 * tag_len + plaintext->len + CHUNK_SIZE_LEN; // 输出长度
    brealloc(&tmp, out_len, capacity); // 重新分配缓冲区
    ciphertext      = &tmp; // 加密后的数据
    ciphertext->len = out_len; // 加密后的数据长度

    if (!cipher_ctx->init) { // 如果未初始化
        memcpy(ciphertext->data, cipher_ctx->salt, salt_len); // 复制盐
        aead_cipher_ctx_set_key(cipher_ctx, 1); // 设置密钥
        cipher_ctx->init = 1; // 初始化

        ppbloom_add((void *)cipher_ctx->salt, salt_len); // 怎么保证盐不重复？ 
    }

    err = aead_chunk_encrypt(cipher_ctx, // 加密
                             (uint8_t *)plaintext->data, // 明文
                             (uint8_t *)ciphertext->data + salt_ofst, // 加密后的数据
                             cipher_ctx->nonce, plaintext->len); // 非重复
    if (err)
        return err;

    brealloc(plaintext, ciphertext->len, capacity); // 重新分配缓冲区
    memcpy(plaintext->data, ciphertext->data, ciphertext->len); // 复制加密后的数据
    plaintext->len = ciphertext->len; // 加密后的数据长度

    return 0;
}

// 解密块，将数据解密之后，写入到p中
static int
aead_chunk_decrypt(cipher_ctx_t *ctx, uint8_t *p, uint8_t *c, uint8_t *n,
                   size_t *plen, size_t *clen)
{
    int err;
    size_t mlen;
    size_t nlen = ctx->cipher->nonce_len;
    size_t tlen = ctx->cipher->tag_len;

    if (*clen <= 2 * tlen + CHUNK_SIZE_LEN)
        return CRYPTO_NEED_MORE;

    uint8_t len_buf[2];
    err = aead_cipher_decrypt(ctx, len_buf, plen, c, CHUNK_SIZE_LEN + tlen, // 解密
                              NULL, 0, n, ctx->skey); // 非重复
    if (err)
        return CRYPTO_ERROR;
    assert(*plen == CHUNK_SIZE_LEN);

    mlen = load16_be(len_buf); // 从长度缓冲区中加载长度
    mlen = mlen & CHUNK_SIZE_MASK; // 将长度与掩码进行按位与操作

    if (mlen == 0)
        return CRYPTO_ERROR;

    size_t chunk_len = 2 * tlen + CHUNK_SIZE_LEN + mlen; // 块长度

    if (*clen < chunk_len)
        return CRYPTO_NEED_MORE;

    sodium_increment(n, nlen); // 非重复

    err = aead_cipher_decrypt(ctx, p, plen, c + CHUNK_SIZE_LEN + tlen, mlen + tlen, // 解密
                              NULL, 0, n, ctx->skey); // 非重复
    if (err)
        return CRYPTO_ERROR;
    assert(*plen == mlen); // 断言

    sodium_increment(n, nlen); // 非重复

    *clen = *clen - chunk_len; // 更新数据长度

    return CRYPTO_OK;
}

// 解密
int
aead_decrypt(buffer_t *ciphertext, cipher_ctx_t *cipher_ctx, size_t capacity)
{
    int err             = CRYPTO_OK; // 错误码
    static buffer_t tmp = { 0, 0, 0, NULL }; // 临时缓冲区

    cipher_t *cipher = cipher_ctx->cipher; // 获得加密算法

    size_t salt_len = cipher->key_len; // 盐长度

    if (cipher_ctx->chunk == NULL) { // 如果chunk为空
        cipher_ctx->chunk = (buffer_t *)ss_malloc(sizeof(buffer_t)); // 分配内存
        memset(cipher_ctx->chunk, 0, sizeof(buffer_t)); // 初始化
        balloc(cipher_ctx->chunk, capacity); // 分配内存
    }

    brealloc(cipher_ctx->chunk,
             cipher_ctx->chunk->len + ciphertext->len, capacity); // 重新分配缓冲区
    memcpy(cipher_ctx->chunk->data + cipher_ctx->chunk->len, // 复制数据
           ciphertext->data, ciphertext->len); // 复制数据
    cipher_ctx->chunk->len += ciphertext->len; // 更新数据长度

    brealloc(&tmp, cipher_ctx->chunk->len, capacity); // 重新分配缓冲区
    buffer_t *plaintext = &tmp; // 明文

    if (!cipher_ctx->init) { // 如果未初始化
        if (cipher_ctx->chunk->len <= salt_len) // 如果数据长度小于盐长度
            return CRYPTO_NEED_MORE; // 返回需要更多的数据

        memcpy(cipher_ctx->salt, cipher_ctx->chunk->data, salt_len); // 复制盐

        if (ppbloom_check((void *)cipher_ctx->salt, salt_len) == 1) { // 检查盐是否重复
            LOGE("crypto: AEAD: repeat salt detected");
            return CRYPTO_ERROR;
        }

        aead_cipher_ctx_set_key(cipher_ctx, 0); // 设置密钥

        memmove(cipher_ctx->chunk->data, cipher_ctx->chunk->data + salt_len, // 移动数据
                cipher_ctx->chunk->len - salt_len); // 更新数据长度 
        cipher_ctx->chunk->len -= salt_len;

        cipher_ctx->init = 1;
    }

    size_t plen = 0; // 明文长度
    size_t cidx = 0; // 数据索引
    while (cipher_ctx->chunk->len > 0) {
        size_t chunk_clen = cipher_ctx->chunk->len; // 块长度
        size_t chunk_plen = 0; // 明文长度
        err = aead_chunk_decrypt(cipher_ctx, // 解密
                                 (uint8_t *)plaintext->data + plen, // 明文
                                 (uint8_t *)cipher_ctx->chunk->data + cidx, // 加密后的数据
                                 cipher_ctx->nonce, &chunk_plen, &chunk_clen); // 非重复
        if (err == CRYPTO_ERROR) {
            return err;
        } else if (err == CRYPTO_NEED_MORE) { // 如果需要更多的数据 
            if (plen == 0) // 如果明文长度为0
                return err; // 返回错误
            else{
                memmove((uint8_t *)cipher_ctx->chunk->data, // 移动数据
			(uint8_t *)cipher_ctx->chunk->data + cidx, chunk_clen); // 更新数据长度
                break; // 退出循环
            }
        }
        cipher_ctx->chunk->len = chunk_clen; // 更新数据长度
        cidx += cipher_ctx->cipher->tag_len * 2 + CHUNK_SIZE_LEN + chunk_plen; // 更新数据索引
        plen                  += chunk_plen; // 更新明文长度
    }
    plaintext->len = plen; // 更新明文长度

    // 将盐添加到布隆过滤器中
    if (cipher_ctx->init == 1) {
        if (ppbloom_check((void *)cipher_ctx->salt, salt_len) == 1) {
            LOGE("crypto: AEAD: repeat salt detected");
            return CRYPTO_ERROR;
        }
        ppbloom_add((void *)cipher_ctx->salt, salt_len);
        cipher_ctx->init = 2;
    }

    brealloc(ciphertext, plaintext->len, capacity); // 重新分配缓冲区
    memcpy(ciphertext->data, plaintext->data, plaintext->len); // 复制明文
    ciphertext->len = plaintext->len; // 更新明文长度

    return CRYPTO_OK; // 返回成功
}

// 初始化密钥
// 方法：加密算法
// 密码：密码
// 密钥：密钥
cipher_t *
aead_key_init(int method, const char *pass, const char *key)
{
    if (method < AES128GCM || method >= AEAD_CIPHER_NUM) { // 如果方法不合法
        LOGE("aead_key_init(): Illegal method");
        return NULL;
    }

    cipher_t *cipher = (cipher_t *)ss_malloc(sizeof(cipher_t));
    memset(cipher, 0, sizeof(cipher_t));

    if (method >= CHACHA20POLY1305IETF) {
        cipher_kt_t *cipher_info = (cipher_kt_t *)ss_malloc(sizeof(cipher_kt_t));
        cipher->info             = cipher_info; // 设置密钥信息
        cipher->info->base       = NULL; // 设置密钥信息
        cipher->info->key_bitlen = supported_aead_ciphers_key_size[method] * 8; // 设置密钥长度
        cipher->info->iv_size    = supported_aead_ciphers_nonce_size[method]; // 设置iv长度
    } else {
        cipher->info = (cipher_kt_t *)aead_get_cipher_type(method); // 设置密钥信息
    }

    if (cipher->info == NULL && cipher->key_len == 0) { // 如果密钥信息为空且密钥长度为0
        LOGE("Cipher %s not found in crypto library", supported_aead_ciphers[method]); // 输出错误
        FATAL("Cannot initialize cipher"); // 输出错误
    }

    if (key != NULL)
        cipher->key_len = crypto_parse_key(key, cipher->key, // 解析密钥
                                           supported_aead_ciphers_key_size[method]); // 设置密钥长度
    else
        cipher->key_len = crypto_derive_key(pass, cipher->key, // 导出密钥
                                            supported_aead_ciphers_key_size[method]); // 设置密钥长度

    if (cipher->key_len == 0) { // 如果密钥长度为0
        FATAL("Cannot generate key and nonce"); // 输出错误
    }

    cipher->nonce_len = supported_aead_ciphers_nonce_size[method]; // 设置iv长度
    cipher->tag_len   = supported_aead_ciphers_tag_size[method]; // 设置标签长度
    cipher->method    = method; // 设置方法

    return cipher;
}

// 初始化
// 密码：密码
// 密钥：密钥
// 方法：加密算法
cipher_t *
aead_init(const char *pass, const char *key, const char *method)
{
    int m = AES128GCM;
    if (method != NULL) {
        /* check method validity */
        for (m = AES128GCM; m < AEAD_CIPHER_NUM; m++)
            if (strcmp(method, supported_aead_ciphers[m]) == 0) {
                break;
            }
        if (m >= AEAD_CIPHER_NUM) { // 如果方法不合法
            LOGE("Invalid cipher name: %s, use chacha20-ietf-poly1305 instead", method); // 输出错误
            m = CHACHA20POLY1305IETF; // 设置方法
        }
    }
    return aead_key_init(m, pass, key); // 初始化密钥
}
