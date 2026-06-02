# ESP32 AES-256-CBC Encryption with mbedTLS

## Overview

This project demonstrates **AES-256-CBC encryption** on an ESP32 microcontroller using the built-in `mbedTLS` library. It encrypts variable-length strings (e.g., JSON payloads) and outputs the result as an uppercase hex string via the ESP logging system.

The implementation handles:
- Arbitrary-length input strings via **PKCS#5/PKCS#7 padding**
- **AES-256** encryption (256-bit key)
- **CBC mode** (Cipher Block Chaining) with an initialization vector (IV)
- Conversion of raw encrypted bytes to a **hex string**

---

## Encryption Method: AES-256-CBC

### What is AES-CBC?

**AES (Advanced Encryption Standard)** is a symmetric block cipher that operates on 16-byte (128-bit) blocks. **CBC (Cipher Block Chaining)** is a mode of operation where each plaintext block is XORed with the previous ciphertext block before encryption — making each encrypted block dependent on all previous blocks.

```
Plaintext[0]  XOR  IV        → AES Encrypt → Ciphertext[0]
Plaintext[1]  XOR  Cipher[0] → AES Encrypt → Ciphertext[1]
Plaintext[2]  XOR  Cipher[1] → AES Encrypt → Ciphertext[2]
...
```

| Parameter     | Value           |
|---------------|-----------------|
| Algorithm     | AES             |
| Mode          | CBC             |
| Key Size      | 256 bits (32 bytes) |
| Block Size    | 128 bits (16 bytes) |
| IV Size       | 16 bytes        |
| Padding       | PKCS#5 (PKCS#7) |

---

## Step-by-Step: How the Code Works

### Step 1 — Calculate Padded Length

AES operates on 16-byte blocks. If the input is not a multiple of 16, it must be padded.

```c
int input_len = strlen(input) + 1;       // include null terminator
int modulo16  = input_len % 16;

if (input_len < 16)
    padded_input_len = 16;
else
    padded_input_len = (strlen(input) / 16 + 1) * 16;
```

**Example:**
- Input: `{"device":"d8:3a:dd:d9:bc:60","msg":"test_msg"}}` → 47 characters
- With null: 48 bytes → `48 % 16 = 0`, but code always rounds up → padded to **64 bytes**

### Step 2 — Apply PKCS#5 Padding

PKCS#5/PKCS#7 padding fills remaining bytes with a value equal to the number of padding bytes needed.

```c
uint8_t pkc5_value = (17 - modulo16);

for (int i = strlen(input); i < padded_input_len; i++) {
    padded_input[i] = pkc5_value;
}
```

**Example:**
- If 1 padding byte is needed → fill with `0x01`
- If 5 padding bytes are needed → fill with `0x05 0x05 0x05 0x05 0x05`

> ⚠️ **Note:** The standard PKCS#7 value is `16 - (len % 16)`. This implementation uses `17 - modulo16`, which is a slight variant — ensure your decryption side uses the same formula.

### Step 3 — Initialize mbedTLS AES Context

```c
mbedtls_aes_context aes;
mbedtls_aes_init(&aes);
mbedtls_aes_setkey_enc(&aes, key, 256);  // 256-bit key
```

- `mbedtls_aes_init` — zeroes out the context struct
- `mbedtls_aes_setkey_enc` — expands the key into AES round keys for encryption

### Step 4 — Encrypt with AES-256-CBC

```c
mbedtls_aes_crypt_cbc(
    &aes,
    MBEDTLS_AES_ENCRYPT,
    padded_input_len,         // must be multiple of 16
    iv,                       // 16-byte IV (modified in-place)
    (unsigned char *)padded_input,
    encrypt_output
);
```

> ⚠️ **Important:** `mbedtls_aes_crypt_cbc` modifies the IV buffer in-place. If you need to reuse the IV, make a copy before calling this function.

### Step 5 — Convert to Hex String

```c
for (int i = 0; i < padded_input_len; i++) {
    sprintf(&hex_output[i * 2], "%02X", encrypt_output[i]);
}
hex_output[padded_input_len * 2] = '\0';
```

Each encrypted byte is converted to 2 uppercase hex characters. The output buffer size is `padded_input_len * 2 + 1`.

### Step 6 — Free Resources

```c
mbedtls_aes_free(&aes);
free(padded_input);
free(encrypt_output);
```

Always free mbedTLS contexts and heap allocations to prevent memory leaks on the ESP32.

---

## Full Example

### Input

```c
char enc_key[32] = "12345678901234567890123456789012"; // 32 bytes = 256-bit key
char enc_iv[16]  = "1234567890123456";                 // 16 bytes IV
char *enc_input  = "{\"device\":\"d8:3a:dd:d9:bc:60\",\"msg\":\"test_msg\"}}";
```

### Processing

| Stage              | Value                                                         |
|--------------------|---------------------------------------------------------------|
| Input string       | `{"device":"d8:3a:dd:d9:bc:60","msg":"test_msg"}}`           |
| Input length       | 47 bytes                                                      |
| With null terminator | 48 bytes                                                   |
| Padded length      | 64 bytes (next multiple of 16)                               |
| Padding value      | `17 - (48 % 16)` = `17 - 0` = `17` → `0x11`                |
| Padding bytes      | 16 bytes of `0x11` appended                                  |

### Expected Log Output

```
I (xxx) HEX: <64-byte uppercase hex string>
```

Example (illustrative — actual output depends on AES computation):
```
I (312) HEX: 3A9F2C1B8E047D6F5C2A1B9E4F803D1A7E2C4B8A1F3D5E9C0B2A4F6E8D1C3A5B...
```

---

## Complete Source Code

```c
#include "esp_log.h"
#include "mbedtls/aes.h"
#include <stdio.h>
#include <string.h>

void encrypt_any_length_string(const char *input, uint8_t *key, uint8_t *iv)
{
    int padded_input_len = 0;
    int input_len = strlen(input) + 1;
    int modulo16 = input_len % 16;

    if (input_len < 16)
        padded_input_len = 16;
    else
        padded_input_len = (strlen(input) / 16 + 1) * 16;

    char *padded_input = (char *)malloc(padded_input_len);
    if (!padded_input) {
        printf("Failed to allocate memory\n");
        return;
    }

    memcpy(padded_input, input, strlen(input));
    uint8_t pkc5_value = (17 - modulo16);
    for (int i = strlen(input); i < padded_input_len; i++) {
        padded_input[i] = pkc5_value;
    }

    unsigned char *encrypt_output = (unsigned char *)malloc(padded_input_len);
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_enc(&aes, key, 256);
    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, padded_input_len, iv,
                          (unsigned char *)padded_input, encrypt_output);
    mbedtls_aes_free(&aes);

    char *hex_output = (char *)malloc(padded_input_len * 2 + 1);
    if (!hex_output) {
        printf("Failed to allocate memory for hex output\n");
        free(padded_input);
        free(encrypt_output);
        return;
    }

    for (int i = 0; i < padded_input_len; i++) {
        sprintf(&hex_output[i * 2], "%02X", encrypt_output[i]);
    }
    hex_output[padded_input_len * 2] = '\0';

    free(padded_input);
    free(encrypt_output);

    ESP_LOGI("HEX", "%s", hex_output);
    free(hex_output);
}

void app_main(void)
{
    char enc_key[32] = "12345678901234567890123456789012";
    char enc_iv[16]  = "1234567890123456";
    char *enc_input  = "{\"device\":\"d8:3a:dd:d9:bc:60\",\"msg\":\"test_msg\"}}";

    encrypt_any_length_string(enc_input, (uint8_t *)enc_key, (uint8_t *)enc_iv);
}
```

---

## Dependencies & Configuration

### `idf_component.yml` / `CMakeLists.txt`

mbedTLS is bundled with ESP-IDF. Ensure it is enabled in `sdkconfig`:

```
CONFIG_MBEDTLS_AES_C=y
CONFIG_MBEDTLS_CIPHER_MODE_CBC=y
```

### Required Headers

```c
#include "mbedtls/aes.h"   // AES context, init, setkey, crypt
#include "esp_log.h"        // ESP_LOGI
#include <string.h>         // strlen, memcpy
#include <stdlib.h>         // malloc, free
```

---

## Notes & Caveats

| Item | Detail |
|------|--------|
| IV reuse | `mbedtls_aes_crypt_cbc` updates the IV in place — save a copy if needed |
| Padding formula | Uses `17 - modulo16` (non-standard) — decryptor must match |
| `hex_output` leak | Original code does not `free(hex_output)` — the corrected code above adds this |
| Thread safety | mbedTLS AES context is not thread-safe; use separate contexts per task |
| Key storage | Hardcoded keys are for demonstration only — use `nvs_flash` or secure storage in production |
