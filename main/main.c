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
    if (!padded_input)
    {
        printf("Failed to allocate memory\n");
        return;
    }
    memcpy(padded_input, input, strlen(input));
    uint8_t pkc5_value = (17 - modulo16);
    for (int i = strlen(input); i < padded_input_len; i++)
    {
        padded_input[i] = pkc5_value;
    }
    unsigned char *encrypt_output = (unsigned char *)malloc(padded_input_len);
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_enc(&aes, key, 256);
    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, padded_input_len, iv,
                          (unsigned char *)padded_input, encrypt_output);
    // ESP_LOG_BUFFER_HEX("cbc_encrypt", encrypt_output, padded_input_len);

    mbedtls_aes_free(&aes);

    // Allocate memory for the hex string (2 chars per byte + null terminator)
    char *hex_output = (char *)malloc(padded_input_len * 2 + 1);
    if (!hex_output)
    {
        printf("Failed to allocate memory for hex output\n");
        free(padded_input);
        free(encrypt_output);
    }

    // Convert encrypted bytes to uppercase hex string
    for (int i = 0; i < padded_input_len; i++)
    {
        sprintf(&hex_output[i * 2], "%02X", encrypt_output[i]);
    }
    hex_output[padded_input_len * 2] = '\0'; // Null-terminate

    // Clean up
    free(padded_input);
    free(encrypt_output);

    ESP_LOGI("HEX", "%s", hex_output);
}

void app_main(void)
{
    char enc_key[32] = "12345678901234567890123456789012";
    char enc_iv[16] = "1234567890123456";

    char *enc_input = "{\"device\":\"d8:3a:dd:d9:bc:60\",\"msg\":\"test_msg\"}}";

    encrypt_any_length_string(enc_input, (uint8_t *)enc_key, (uint8_t *)enc_iv);
}
