#ifndef HASH_CTR_H
#define HASH_CTR_H
#include "miracl.h"
#include "pairing_3.h"
#include "bn_transfer.h"

class HASH_CTR
{
    PFC *pfc;
    unsigned char *Data;
    unsigned int DataLen;
    BN_transfer BN_T;
    GT KEY;
    Big CTR;
public:
    HASH_CTR(PFC *p);
    ~HASH_CTR();
    int init(GT &key, Big &ctr);
    int encrypt_add(unsigned char *data,int add_len);
    int encrypt_add(Big &data);
    int encrypt_add(G1 &data);
    int encrypt_add(G2 &data);
    int encrypt_add(GT &data);
    int encrypt_data(unsigned char *cipher, unsigned int *cipher_len);
    int decrypt_data(unsigned char *cipher, unsigned int cipher_len);
    int decrypt_red(unsigned char *data,int *add_len);
    int decrypt_red(Big &data);
    int decrypt_red(G1 &data);
    int decrypt_red(G2 &data);
    int decrypt_red(GT &data);
    
};

#endif // HASH_CTR_H
