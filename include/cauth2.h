#define CAUTH_LITTLE_ENDIAN
#ifndef CAUTH2_H
 #define CAUTH2_H

#include <time.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define TRUE (int)(1==1)
#define FALSE (int)(1!=1)

#define ALG_SHA1_DEFAULT (int)2
#define ALG_SHA256 (int)4
#define ALG_SHA512 (int)6

typedef int CAUTH_BOOL;

typedef enum cauth_2fa_auth_code_err_t {
   CAUTH_2FA_ERR_EMPTY_KEY_SIZE=10800,
   CAUTH_2FA_ERR_INVALID_ALG_TYPE,
   CAUTH_2FA_ERR_HMAC_MALLOC_ERROR,
   CAUTH_2FA_ERR_DIGIT_SIZE,
   CAUTH_2FA_ERR_TOTP_NULL_STR,
   CAUTH_2FA_ERR_DIV_ZERO,
   CAUTH2_2FA_BASE32_ALLOC,
   CAUTH2_2FA_BASE32_DECODE,
   CAUTH2_2FA_BASE32_ZERO_SZ,
   CAUTH_2FA_ERR_WRONG_KEY_SIZE
} CAUTH_2FA_AUTH_CODE_ERR;

typedef enum cauth_sign_err_t {
   CAUTH_EMPTY_KEY_ERR=10700,
   CAUTH_EMPTY_MESSAGE,
   CAUTH_ERR_INVALID_ALG_TYPE,
   CAUTH_SIGN_ALLOC
} CAUTH_SIGN_CODE_ERR;

typedef enum cauth_verify_err_t {
   CAUTH_VERIFY_SIGNATURE_ERR=-40,
   CAUTH_VERIFY_WRONG_SIZE_ERR,
   CAUTH_VERIFY_INVALID=3033,
   CAUTH_VERIFY_OK=1981
} CAUTH_VERIFY_CODE_ERR;

#define ERROR_SUCCESS (int)0

CAUTH_2FA_AUTH_CODE_ERR
cauth_2fa_auth_code(
   uint32_t *,
   int,
   uint8_t *,
   size_t,
   int,
   uint64_t,
   uint64_t,
   time_t *,
   uint8_t
);

CAUTH_SIGN_CODE_ERR
sign_message_dynamic(
   void **, size_t *,
   int,
   uint8_t *, size_t,
   uint8_t *, size_t
);

int
cauth_str_to_hex(
   uint8_t *,
   char *,
   size_t
);

CAUTH_VERIFY_CODE_ERR
cauth_verify_message_with_err(
   uint8_t *, size_t,
   int,
   uint8_t *, size_t,
   uint8_t *, size_t
);

CAUTH_BOOL
cauth_verify_message(
   uint8_t *, size_t,
   int,
   uint8_t *, size_t,
   uint8_t *, size_t
);

typedef enum hex2str_type_t {
   IS_LOWER_CASE=0,
   IS_UPPER_CASE=1
} HEX2STR_TYPE;

char *
cauth_hex2str_dynamic(
   const uint8_t *,
   size_t,
   HEX2STR_TYPE
);

CAUTH_2FA_AUTH_CODE_ERR
check_base32_oauth_key_valid(
   size_t *,
   const char *, size_t,
   int
);

const char *
cauth_getVersion();

const char *
cauth_buildDate();

const char *
cauth_endianess();
#endif