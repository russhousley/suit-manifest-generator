// ----------------------------------------------------------------------------
// Copyright 2020 Vigil Security, LLC
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// ----------------------------------------------------------------------------

/*
 * This is the file that implements the hashing API that is used in
 * https://github.com/cisco/hash-sigs, except it uses exclusively
 * the MbedTLS implementation of SHA-256.
 */

#include "hss_hash.h"
#include "../mbedtls/sha256.h"

/*
 * Hash the message; assume that the result buffer is 32 bytes.
 */
void hss_hash_ctx(void *result, int hash_type, union hash_context *ctx,
          const void *message, size_t message_len) {

    if (hash_type != 1)
        return;

    mbedtls_sha256_init(&ctx->sha256);
    mbedtls_sha256_starts_ret(&ctx->sha256, 0);
    mbedtls_sha256_update_ret(&ctx->sha256,
                              (const unsigned char *)message,
                              message_len);
    mbedtls_sha256_finish_ret(&ctx->sha256,
                              (unsigned char *) result);
}

/*
* Allocate the context, hash the message, and then wipe the context.
*/
void hss_hash(void *result, int hash_type,
          const void *message, size_t message_len) {

    if (hash_type != 1)
        return;

    union hash_context ctx;
    hss_hash_ctx(result, hash_type, &ctx, message, message_len);
    mbedtls_sha256_free(&ctx.sha256);
}

/*
 * Create the context for incremental hashing.
 */
void hss_init_hash_context(int h, union hash_context *ctx) {

    if (h != 1)
        return;
    
    mbedtls_sha256_init(&ctx->sha256);
    mbedtls_sha256_starts_ret(&ctx->sha256, 0);
}

/*
 * Process the message as part of incremental hashing.
 */
void hss_update_hash_context(int h, union hash_context *ctx,
                         const void *msg, size_t len_msg) {
    
    if (h != 1)
        return;

    mbedtls_sha256_update_ret(&ctx->sha256,
                              (const unsigned char *)msg,
                              len_msg);
}

/*
 * Finish incremental hashing and return the hash value.
 */
void hss_finalize_hash_context(int h, union hash_context *ctx, void *buffer) {

    if (h != 1)
        return;

    mbedtls_sha256_finish_ret(&ctx->sha256, (unsigned char *) buffer);
}

/*
 * Get the output hash length.
 */
unsigned hss_hash_length(int hash_type) {
    switch (hash_type) {
    case HASH_SHA256: return 32;
    }
    return 0;
}

/*
* Get the internal block size for the hash algorithm.
*/
unsigned hss_hash_blocksize(int hash_type) {
    switch (hash_type) {
    case HASH_SHA256: return 64;
    }
    return 0;
}
