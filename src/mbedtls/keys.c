// Copyright (c) NetFoundry Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <mbedtls/pk.h>
#include <string.h>
#include <tlsuv/tlsuv.h>

#include "../um_debug.h"
#include "../alloc.h"
#include "keys.h"
#include "psa/crypto.h"
#include "p11.h"
#include "mbed_p11.h"

static void pubkey_free(tlsuv_public_key_t k);
static int pubkey_verify(tlsuv_public_key_t pk, enum hash_algo md, const char *data, size_t datalen, const char *sig, size_t siglen);
static int pubkey_pem(tlsuv_public_key_t pk, char **pem, size_t *pemlen);

static struct pub_key_s PUB_KEY_API = {
        .free = pubkey_free,
        .to_pem = pubkey_pem,
        .verify = pubkey_verify,
};


static void privkey_free(tlsuv_private_key_t k);
static tlsuv_public_key_t privkey_pubkey(tlsuv_private_key_t pk);
static int privkey_to_pem(tlsuv_private_key_t pk, char **pem, size_t *pemlen);
static int privkey_sign(tlsuv_private_key_t pk, enum hash_algo md,
                        const char *data, size_t datalen, char *sig, size_t *siglen);

static struct priv_key_s PRIV_KEY_API = {
        .free = privkey_free,
        .to_pem = privkey_to_pem,
        .pubkey = privkey_pubkey,
        .sign = privkey_sign,
};

void pub_key_init(struct pub_key_s *pubkey) {
    *pubkey = PUB_KEY_API;
}

void priv_key_init(struct priv_key_s *privkey) {
    *privkey = PRIV_KEY_API;
}

static void pubkey_free(tlsuv_public_key_t k) {
    struct pub_key_s *pub = (struct pub_key_s *) k;
    mbedtls_pk_free(&pub->pkey);
    tlsuv__free(pub);
}

static int pubkey_pem(tlsuv_public_key_t pk, char **pem, size_t *pemlen) {
    struct pub_key_s *pub = (struct pub_key_s *) pk;
    size_t len = 1024;
    char *buf = tlsuv__malloc(len);
    int rc;
    rc = mbedtls_pk_write_pubkey_pem(&pub->pkey, (unsigned char*)buf, len);
    if (rc != 0) {
        tlsuv__free(buf);
        UM_LOG(WARN, "pubkey to_pem error: %d/%s", rc, mbedtls_error(rc));
        return -1;
    }
    *pem = buf;
    *pemlen = strlen(buf);
    return 0;
}


int verify_signature (mbedtls_pk_context *pk, enum hash_algo md, const char* data, size_t datalen, const char* sig, size_t siglen) {

    int type;
    const mbedtls_md_info_t *md_info = NULL;
    switch (md) {
        case hash_SHA256:
            type = MBEDTLS_MD_SHA256;
            md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
            break;
        case hash_SHA384:
            type = MBEDTLS_MD_SHA384;
            md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA384);
            break;
        case hash_SHA512:
            type = MBEDTLS_MD_SHA512;
            md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
            break;
        default:
            return -1;
    }

    unsigned char hash[MBEDTLS_MD_MAX_SIZE];
    if (mbedtls_md(md_info, (uint8_t *)data, datalen, hash) != 0) {
        return -1;
    }

    if (mbedtls_pk_verify(pk, type, hash, mbedtls_md_get_size(md_info), (uint8_t *)sig, siglen) != 0) {
        return -1;
    }

    return 0;
}

static int pubkey_verify(tlsuv_public_key_t pk, enum hash_algo md, const char *data, size_t datalen, const char *sig, size_t siglen) {
    struct pub_key_s *pub = (struct pub_key_s *) pk;
    return verify_signature(&pub->pkey, md, data, datalen, sig, siglen);
}

static void privkey_free(tlsuv_private_key_t k) {
    struct priv_key_s *priv = (struct priv_key_s *) k;
    mbedtls_pk_free(&priv->pkey);
    tlsuv__free(priv);
}

static int privkey_sign(tlsuv_private_key_t pk, enum hash_algo md, const char *data, size_t datalen, char *sig, size_t *siglen) {
    struct priv_key_s *priv = (struct priv_key_s *) pk;

    int type;
    const mbedtls_md_info_t *md_info = NULL;
    switch (md) {
        case hash_SHA256:
            type = MBEDTLS_MD_SHA256;
            md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
            break;
        case hash_SHA384:
            type = MBEDTLS_MD_SHA384;
            md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA384);
            break;
        case hash_SHA512:
            type = MBEDTLS_MD_SHA512;
            md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
            break;
        default:
            return -1;
    }

    unsigned char hash[MBEDTLS_MD_MAX_SIZE];
    memset(hash, 0, sizeof(hash));
    if (mbedtls_md(md_info, (uint8_t *)data, datalen, hash) != 0) {
        return -1;
    }
    int size = mbedtls_md_get_size(md_info);

    psa_crypto_init();
    if (mbedtls_pk_sign(&priv->pkey, type, hash, size, (uint8_t *)sig, *siglen, siglen) != 0) {
        return -1;
    }
    return 0;
}


static tlsuv_public_key_t privkey_pubkey(tlsuv_private_key_t pk) {
    struct priv_key_s *priv = (struct priv_key_s *) pk;
    struct pub_key_s *pub = tlsuv__calloc(1, sizeof(*pub));
    pub_key_init(pub);

    // there is probably a more straight-forward way,
    // but I did not find it
    uint8_t buf[4096];
    mbedtls_pk_write_pubkey_pem(&priv->pkey, buf, sizeof(buf));
    mbedtls_pk_parse_public_key(&pub->pkey, buf, strlen((char*)buf) + 1);

    return (tlsuv_public_key_t) pub;
}

static int privkey_to_pem(tlsuv_private_key_t pk, char **pem, size_t *pemlen) {
    struct priv_key_s *privkey = (struct priv_key_s *) pk;
    uint8_t keybuf[4096];
    int ret;
    if ((ret = mbedtls_pk_write_key_pem(&privkey->pkey, keybuf, sizeof(keybuf))) != 0) {
        UM_LOG(ERR, "mbedtls_pk_write_key_pem returned -0x%04x: %s", -ret, mbedtls_error(ret));
        return ret;
    }

    *pemlen = strlen((char*)keybuf) + 1;
    *pem = tlsuv__strdup((char*)keybuf);
    return 0;
}

int load_key(tlsuv_private_key_t *key, const char* keydata, size_t keydatalen) {
    struct priv_key_s *privkey = tlsuv__calloc(1, sizeof(struct priv_key_s));
    priv_key_init(privkey);
    mbedtls_pk_init(&privkey->pkey);

    int rc = (int) psa_crypto_init();
    if (rc != 0) {
        UM_LOG(ERR, "psa_crypto_init failed: %d", rc);
        mbedtls_pk_free(&privkey->pkey);
        tlsuv__free(privkey);
        *key = NULL;
        return rc;
    }
    size_t keylen = keydata[keydatalen - 1] == 0 ? keydatalen : keydatalen + 1;
    rc = mbedtls_pk_parse_key(&privkey->pkey, (const unsigned char *) keydata, keylen, NULL, 0);
    if (rc < 0) {
        rc = mbedtls_pk_parse_keyfile(&privkey->pkey, keydata, NULL);
        if (rc < 0) {
            mbedtls_pk_free(&privkey->pkey);
            tlsuv__free(privkey);
            *key = NULL;
            return rc;
        }
    }
    *key = (tlsuv_private_key_t) privkey;
    return rc;
}


int gen_key(tlsuv_private_key_t *key) {
    int ret;

    struct priv_key_s *private_key = tlsuv__calloc(1, sizeof(struct priv_key_s));
    *private_key = PRIV_KEY_API;
    mbedtls_pk_context *pk = &private_key->pkey;
    mbedtls_pk_init(pk);

    // raw ECP key generation (mbedtls_ecp_gen_key et al.) is private/internal
    // as of mbedtls 4.x -- keys are generated via PSA and copied into a
    // standalone (non-opaque) legacy pk context so the rest of this file
    // (sign/pubkey/to_pem) keeps working unmodified.
    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        UM_LOG(ERR, "psa_crypto_init failed: %d", (int)status);
        ret = (int)status;
        goto on_error;
    }

    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_EXPORT);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attributes, 256);

    mbedtls_svc_key_id_t psa_key_id;
    status = psa_generate_key(&attributes, &psa_key_id);
    if (status != PSA_SUCCESS) {
        UM_LOG(ERR, "psa_generate_key failed: %d", (int)status);
        ret = (int)status;
        goto on_error;
    }

    ret = mbedtls_pk_copy_from_psa(psa_key_id, pk);
    psa_destroy_key(psa_key_id);
    if (ret != 0) {
        UM_LOG(ERR, "mbedtls_pk_copy_from_psa returned -0x%04x: %s", -ret, mbedtls_error(ret));
        goto on_error;
    }

    on_error:
    if (ret != 0) {
        mbedtls_pk_free(pk);
        tlsuv__free(private_key);
    } else {
        *key = (tlsuv_private_key_t)private_key;
    }

    return ret;
}

int load_key_p11(tlsuv_private_key_t *key, const char *lib, const char *slot, const char *pin, const char *id, const char *label) {
    UM_LOG(WARN, "not implemented");
    return -1;
}
