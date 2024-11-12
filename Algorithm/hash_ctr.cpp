#include "hash_ctr.h"
#define HASH_DATA_LEN 3072

HASH_CTR::HASH_CTR(PFC *p)
{
    pfc = p;
    Data = (uint8_t *)malloc(HASH_DATA_LEN);
}
HASH_CTR::~HASH_CTR()
{
    free(Data);
}
int HASH_CTR::init(GT &key, Big &ctr)
{
    memset(Data, 0, HASH_DATA_LEN);
    DataLen = 0;
    KEY = key;
    CTR = ctr;
    return 0;
}

int HASH_CTR::encrypt_add(unsigned char *data, int add_len)
{
    if (DataLen + add_len > HASH_DATA_LEN)
        return -1;
    memcpy(Data + DataLen, data, add_len);
    DataLen = DataLen + add_len;
    return 0;
}

int HASH_CTR::encrypt_add(Big &data)
{
    Big_C data_c;
    BN_T.Trf_Big_to_Char(data, data_c);

    int add_len = sizeof(Big_C);
    if (DataLen + add_len > HASH_DATA_LEN)
        return -1;
    memcpy(Data + DataLen, &data_c, add_len);
    DataLen = DataLen + add_len;
    //BN_T.bn_printfBig("encrypt_add Big", data_c);
    // printf("encrypt_add DataLen=%d\n",DataLen);
    return 0;
}
int HASH_CTR::encrypt_add(G1 &data)
{
    G1_C data_c;
    BN_T.Trf_G1_to_Char(data, data_c);

    int add_len = sizeof(G1_C);
    if (DataLen + add_len > HASH_DATA_LEN)
        return -1;
    memcpy(Data + DataLen, &data_c, add_len);
    DataLen = DataLen + add_len;
    //  printf("encrypt_add DataLen=%d\n",DataLen);
    return 0;
}
int HASH_CTR::encrypt_add(G2 &data)
{
    G2_C data_c;
    BN_T.Trf_G2_to_Char(data, data_c);

    int add_len = sizeof(G2_C);
    if (DataLen + add_len > HASH_DATA_LEN)
        return -1;
    memcpy(Data + DataLen, &data_c, add_len);
    DataLen = DataLen + add_len;
    //  printf("encrypt_add DataLen=%d\n",DataLen);
    return 0;
}
int HASH_CTR::encrypt_add(GT &data)
{
    GT_C data_c;
    BN_T.Trf_GT_to_Char(data, data_c);

    int add_len = sizeof(GT_C);
    if (DataLen + add_len > HASH_DATA_LEN)
        return -1;
    memcpy(Data + DataLen, &data_c, add_len);
    DataLen = DataLen + add_len;
    //  printf("encrypt_add DataLen=%d\n",DataLen);
    return 0;
}
int HASH_CTR::encrypt_data(unsigned char *cipher, unsigned int *cipher_len)
{
    *cipher_len = DataLen;
    int i, j, b = *cipher_len / 32;
    int r = *cipher_len % 32;
    unsigned char hash[32]={0};
    Big h;
    Big_C hc;
    for (i = 0; i < b; i++)
    {
        pfc->start_hash();
        pfc->add_to_hash(KEY);
        pfc->add_to_hash(CTR);
        h = pfc->finish_hash_to_group();
        memcpy(hash, (char*)(h.fn->w), 32);
        for (j = 0; j < 32; j++)
        {
            cipher[i * 32 + j] = Data[i * 32 + j] ^ hash[j];
        }
        CTR = CTR + 1;
    }
    if (r != 0)
    {
        pfc->start_hash();
        pfc->add_to_hash(KEY);
        pfc->add_to_hash(CTR);
        h = pfc->finish_hash_to_group();
        memcpy(hash, (char*)(h.fn->w), 32);
        CTR = 0;
        for (j = 0; j < r; j++)
        {
            cipher[i * 32 + j] = Data[i * 32 + j] ^ hash[j];
        }
    }
    return 0;
}
int HASH_CTR::decrypt_data(unsigned char *cipher, unsigned int cipher_len)
{
    DataLen = cipher_len;
    if (DataLen > HASH_DATA_LEN)
        return -1;
    int i, j, b = cipher_len / 32;
    int r = cipher_len % 32;
    unsigned char hash[32];
    Big h;


    for (i = 0; i < b; i++)
    {
        pfc->start_hash();
        pfc->add_to_hash(KEY);
        pfc->add_to_hash(CTR);
        h = pfc->finish_hash_to_group();
        memcpy(hash, (char*)(h.fn->w), 32);
        for (j = 0; j < 32; j++)
        {
            Data[i * 32 + j] = cipher[i * 32 + j] ^ hash[j];
        }
        CTR = CTR + 1;
    }
    if (r != 0)
    {
        pfc->start_hash();
        pfc->add_to_hash(KEY);
        pfc->add_to_hash(CTR);
        h = pfc->finish_hash_to_group();
        memcpy(hash, (char*)(h.fn->w), 32);
        CTR = 0;
        for (j = 0; j < r; j++)
        {
            Data[i * 32 + j] = cipher[i * 32 + j] ^ hash[j];
        }
    }
    return 0;
}
int HASH_CTR::decrypt_red(unsigned char *data, int *add_len)
{
    memcpy(data, Data, DataLen);
    *add_len = DataLen;
    DataLen = 0;
    return 0;
}
int HASH_CTR::decrypt_red(Big &data)
{
    int add_len = sizeof(Big_C);
    if (DataLen - add_len < 0)
        return -1;

    Big_C data_c;
    memcpy(&data_c, Data + DataLen - add_len, add_len);
    BN_T.Trf_Char_to_Big(data_c, data);
    DataLen = DataLen - add_len;
    //BN_T.bn_printfBig("decrypt_red Big", data_c);
    //   printf("decrypt_red DataLen=%d\n",DataLen);
    return 0;
}
int HASH_CTR::decrypt_red(G1 &data)
{
    int add_len = sizeof(G1_C);
    if (DataLen - add_len < 0)
        return -1;

    G1_C data_c;
    memcpy(&data_c, Data + DataLen - add_len, add_len);
    BN_T.Trf_Char_to_G1(data_c, data);
    DataLen = DataLen - add_len;
    //   printf("decrypt_red DataLen=%d\n",DataLen);
    return 0;
}
int HASH_CTR::decrypt_red(G2 &data)
{
    int add_len = sizeof(G2_C);
    if (DataLen - add_len < 0)
        return -1;

    G2_C data_c;
    memcpy(&data_c, Data + DataLen - add_len, add_len);
    BN_T.Trf_Char_to_G2(data_c, data);
    DataLen = DataLen - add_len;
    //   printf("decrypt_red DataLen=%d\n",DataLen);
    return 0;
}
int HASH_CTR::decrypt_red(GT &data)
{
    int add_len = sizeof(GT_C);
    if (DataLen - add_len < 0)
        return -1;

    GT_C data_c;
    memcpy(&data_c, Data + DataLen - add_len, add_len);
    BN_T.Trf_Char_to_GT(data_c, data);
    DataLen = DataLen - add_len;
    //   printf("decrypt_red DataLen=%d\n",DataLen);
    return 0;
}
