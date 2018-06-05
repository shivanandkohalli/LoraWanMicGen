#include<stdio.h>
#include "mbedtls/aes.h"

#define SIZE_NWK_KEY 16
#define SIZE_JOIN_NONCE 3
#define SIZE_JOIN_EUI 8
#define SIZE_DEV_NONCE 2


/**
 * \brief              Calculates the length of string
 * \param str          Input string.
 * \return             length of the string
 */
unsigned int calc_strlen(const unsigned char *str)
{
    unsigned int i = 0;
    for(i=0;str[i]!= '\0';i++);
    return i;
}


/**
 * \brief              This is a helper function to convert characters into hexadecimal
 * \param length       length of input in bytes
 * \param input        input string data
 * \param result       To store the hex value
 * \return             0 on success.
 * \return             1 on failure.
 */
int helper_str_hex(unsigned char length, const unsigned char *input, unsigned char *result)
{
    for(unsigned char j=0;j<length;j++)
    {
        unsigned char a = input[j*2];
        unsigned char b = input[j*2 + 1];

        // Checking if the string is hex
        if(a >= '0' && a <= '9')
            a = a - '0';
        else if(a >= 'A' && a <= 'F')
            a = a - 'A' + 0xA;
        else if(a >= 'a' && a <= 'f')
            a = a - 'a' + 0xA;
        else
            return 1;

        if(b >= '0' && b <= '9')
            b = b - '0';
        else if(b >= 'A' && b <= 'F')
            b = b - 'A' + 0xA;
        else if(b >= 'a' && b <= 'f')
            b = b - 'a' + 0xA;
        else
            return 1;
        // Storing the MSB first
        result[length -(j+1)] = a << 4 | b;
    }

    return 0;
}


/**
 * \brief              This function parses the array of input string and converts into hexadecimal bytes and stores in respective data fields
 * \param argv         array of input strings
 * \param nwk_key      To store the device network key
 * \param join_nonce   To store the Join Nonce
 * \param join_eui     To store the Join EUI
 * \param dev_nonce    To store the Device nonce
 *
 * \return             0 on success.
 * \return             1 on failure.
 */
int convert_str_hex(const unsigned char **argv, unsigned char * nwk_key,unsigned char * join_nonce,unsigned char * join_eui,unsigned char * dev_nonce)
{

    // int i=0;
    // for(i=0;*temp != '\0'; i++,temp++);

    unsigned char param_length[4];
    param_length[0] = SIZE_NWK_KEY;
    param_length[1] = SIZE_JOIN_NONCE;
    param_length[2] = SIZE_JOIN_EUI;
    param_length[3] = SIZE_DEV_NONCE;

    unsigned char *data[4];
    data[0] = nwk_key;
    data[1] = join_nonce;
    data[2] = join_eui;
    data[3] = dev_nonce;

    for(unsigned char i=1;i<5;i++)
    {
        if(calc_strlen(argv[i]) != param_length[i-1]*2)
        {
            printf("Error in arguement %d length \n",i-1);
            return 1;
        }

        if(helper_str_hex(param_length[i-1], argv[i], data[i-1]))
        {
            printf("Error not a valid hex arguement %d\n", i-1);
            return 1;
        }
    }
    return 0;
}

/**
 * \brief           Copies the fixed size bytes from the source to the destination.
 * \param src       input source address
 * \param dest      output destination address
 * \param length      length to be copied
 * \return
 */
void byte_copy(const unsigned char * src, unsigned char * dest,unsigned int length)
{
    for (int i=0;i<length;i++)
    {
        dest[i] = src[i];
    }
}


/**
 * \brief              This function calculates the FNwkSIntKey (Forwarding Network Session Integrity Key) and SNwkSIntKey(Serving Network Session Integrity Key)
 *
 * \param nwk_key      The device network key
 * \param join_nonce   Join Nonce
 * \param join_eui     Join EUI
 * \param dev_nonce    Device nonce
 * \param FNwkSIntKey  To store the FNwkSIntKey
 * \param SNwkSIntKey  To store the SNwkSIntKey
 *
 * \return             0 on success.
 * \return             1 on failure.
 */
int gen_mic_keys(const unsigned char * nwk_key,const unsigned char * join_nonce,const unsigned char * join_eui,const unsigned char * dev_nonce, unsigned char *FNwkSIntKey, unsigned char *SNwkSIntKey)
{
    int retval = 0;
    unsigned char input[16];
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    mbedtls_aes_setkey_enc(&ctx, nwk_key, 128);

    input[15] = 0x01;
    byte_copy(join_nonce, &input[12], SIZE_JOIN_NONCE);
    byte_copy(join_eui, &input[12-SIZE_JOIN_EUI], SIZE_JOIN_EUI);
    byte_copy(dev_nonce, &input[12-SIZE_DEV_NONCE-SIZE_JOIN_EUI], SIZE_DEV_NONCE);
    // Padding
    input[1] = 0x00;
    input[0] = 0x00;

    if(mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, (const unsigned char *)input,FNwkSIntKey))
        retval = 1;

    input[15] = 0x03;
    if(mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, (const unsigned char *)input,SNwkSIntKey))
        retval = 1;

    mbedtls_aes_free(&ctx);
    return retval;

}

int main(int argc, char **argv)
{
    unsigned char nwk_key[16];
    unsigned char join_nonce[3];
    unsigned char join_eui[8];
    unsigned char dev_nonce[2];

    unsigned char FNwkSIntKey[16];  //TODO: follow the same style of naming variables
    unsigned char SNwkSIntKey[16];

    if(argc != 5)
    {
        printf("Usage: ./nwksintkeys <NwkKey> <JoinNonce> <JoinEUI> <DevNonce>\n");
        return 0;
    }

    if(convert_str_hex((const unsigned char **)argv, nwk_key, join_nonce, join_eui, dev_nonce))
    {
        printf("Usage: ./nwksintkeys <NwkKey> <JoinNonce> <JoinEUI> <DevNonce>\n");
        printf("All the parameters must be a valid hexadecimal number\n");
        return 0;
    }


#ifdef DEBUGGING
    printf("nwk_key\n");
    for(int i=0;i<16;i++)
    {
        printf("%x", nwk_key[i]);
    }
    printf("join_nonce\n");
    for(int i=0;i<3;i++)
    {
        printf("%x", join_nonce[i]);
    }

    printf("join_eui\n");
        for(int i=0;i<8;i++)
    {
        printf("%x", join_eui[i]);
    }

    printf("dev_nonce\n");
        for(int i=0;i<2;i++)
    {
        printf("%x", dev_nonce[i]);
    }
#endif

    if(gen_mic_keys((const unsigned char *) nwk_key, (const unsigned char *) join_nonce,(const unsigned char *) join_eui,(const unsigned char *)dev_nonce,FNwkSIntKey,SNwkSIntKey))
    {
        printf("Error in gen_mic_keys\n");
    }
    else
    {
        printf("FNwkSIntKey: ");
        for(int i=15; i>=0;i--)
            printf("%02X", FNwkSIntKey[i]);

        printf("\nSNwkSIntKey: ");
        for(int i=15; i>=0;i--)
            printf("%02X", SNwkSIntKey[i]);
        printf("\n");
    }

    return 0;
}


// TODO: Structures could be used to wrap the arguements
// TODO: Use better naming for functions
// TODO: Error handling needs to be improved, create an enum and return the actual error type
