//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2017-2018 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
// Unfortunately, even in our brave BoringSSL world, we have "functions" that are
// macros too complex for the clang importer. This file handles them.
#include "CNIOBoringSSLShims.h"

X509_EXTENSION *CNIOBoringSSLShims_sk_X509_EXTENSION_value(const STACK_OF(X509_EXTENSION) *sk, size_t i) {
    return sk_X509_EXTENSION_value(sk, i);
}

size_t CNIOBoringSSLShims_sk_X509_EXTENSION_num(const STACK_OF(X509_EXTENSION) *sk) {
    return sk_X509_EXTENSION_num(sk);
}

GENERAL_NAME *CNIOBoringSSLShims_sk_GENERAL_NAME_value(const STACK_OF(GENERAL_NAME) *sk, size_t i) {
    return sk_GENERAL_NAME_value(sk, i);
}

size_t CNIOBoringSSLShims_sk_GENERAL_NAME_num(const STACK_OF(GENERAL_NAME) *sk) {
    return sk_GENERAL_NAME_num(sk);
}

void *CNIOBoringSSLShims_SSL_CTX_get_app_data(const SSL_CTX *ctx) {
    return SSL_CTX_get_app_data(ctx);
}

int CNIOBoringSSLShims_SSL_CTX_set_app_data(SSL_CTX *ctx, void *data) {
    return SSL_CTX_set_app_data(ctx, data);
}

int CNIOBoringSSLShims_ERR_GET_LIB(uint32_t err) {
  return ERR_GET_LIB(err);
}

int CNIOBoringSSLShims_ERR_GET_REASON(uint32_t err) {
  return ERR_GET_REASON(err);
}

#if defined(__APPLE__)
#include <Availability.h>
#include <compression.h>
#endif

// Brotli ALG_ID per RFC 8879.
#define CNIOBORINGSSL_CERT_COMPRESSION_ALG_BROTLI 2

// Client-side: never compress. Servers register a real compressor;
// clients only need the decompressor for incoming server certs.
static int CNIOBoringSSLShims_brotli_compress(
    SSL *ssl, CBB *out, const uint8_t *in, size_t in_len
) {
  (void)ssl; (void)out; (void)in; (void)in_len;
  return 0;
}

// Decompress server cert with Apple libcompression on Darwin. The
// BoringSSL contract: write exactly |uncompressed_len| bytes into a
// fresh CRYPTO_BUFFER and return 1 on success, 0 on failure.
static int CNIOBoringSSLShims_brotli_decompress(
    SSL *ssl, CRYPTO_BUFFER **out,
    size_t uncompressed_len,
    const uint8_t *in, size_t in_len
) {
  (void)ssl;
#if defined(__APPLE__)
  uint8_t *buf = NULL;
  CRYPTO_BUFFER *cb = CRYPTO_BUFFER_alloc(&buf, uncompressed_len);
  if (cb == NULL) {
    return 0;
  }
  size_t produced = compression_decode_buffer(
      buf, uncompressed_len,
      in, in_len,
      NULL,
      COMPRESSION_BROTLI
  );
  if (produced != uncompressed_len) {
    CRYPTO_BUFFER_free(cb);
    return 0;
  }
  *out = cb;
  return 1;
#else
  (void)out; (void)uncompressed_len; (void)in; (void)in_len;
  // Without a brotli decompressor we cannot complete a handshake
  // where the server actually compresses its certificate. Returning
  // 0 here causes BoringSSL to abort the handshake with
  // SSL_R_CERT_DECOMPRESSION_FAILED, which is the correct behaviour.
  // The extension itself is still emitted in our ClientHello (BoringSSL
  // only requires the algorithm be registered with both pointers).
  return 0;
#endif
}

int CNIOBoringSSLShims_register_brotli_cert_compression(SSL_CTX *ctx) {
  return SSL_CTX_add_cert_compression_alg(
      ctx,
      CNIOBORINGSSL_CERT_COMPRESSION_ALG_BROTLI,
      CNIOBoringSSLShims_brotli_compress,
      CNIOBoringSSLShims_brotli_decompress
  );
}
