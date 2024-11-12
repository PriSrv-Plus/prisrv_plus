#ifndef COMMON_H
#define COMMON_H
#include"pairing_3.h"
#include "macddh.h"
#include "bn_transfer.h"
#include <iostream>
#include <time.h>

using namespace std;

#define AES_SECURITY 128


#define PRISRV_PLUS_AK_ATTR_NUM 6 // l1 l2
#define PRISRV_PLUS_MATRIX_M 5 //14*8
#define PRISRV_PLUS_MATRIX_N 3 //14*8
#define PRISRV_PLUS_SET_I 3
#define PRISRV_PLUS_CIPHER_B_LEN 920
#define PRISRV_PLUS_CIPHER_C_LEN 1160
//#define PRISRV_PLUS_REDUCE_M 7 //7*7
//#define PRISRV_PLUS_REDUCE_N 7 //7*7



typedef struct
{
    G1 h;
    GT Z,Y;
    G2 sgm0, sgm1, sgm2;

} prisrv_plus_feme_mpk_st;

typedef struct
{
    Big alfa, x, niu, b1, b2;

} prisrv_plus_feme_msk_st;

typedef struct
{
    int attr_name[PRISRV_PLUS_AK_ATTR_NUM];
    Big value[PRISRV_PLUS_AK_ATTR_NUM];

} prisrv_plus_feme_attr_list_st;

typedef struct
{
    int attr_name[PRISRV_PLUS_AK_ATTR_NUM];
    G1 ek1[PRISRV_PLUS_AK_ATTR_NUM];
    G2 ek2,ek3;
    G1 ek4;

} prisrv_plus_feme_ekey_st;

typedef struct
{
    int attr_name[PRISRV_PLUS_AK_ATTR_NUM];
    G1 dk2[PRISRV_PLUS_AK_ATTR_NUM];
    G2 dk3;
    G1 dk1;
} prisrv_plus_feme_dkey_st;

typedef struct
{
    int MSP[PRISRV_PLUS_MATRIX_M][PRISRV_PLUS_MATRIX_N];
    int attr_name[PRISRV_PLUS_MATRIX_M];

} prisrv_plus_feme_attr_policy_st;
//MSP

typedef struct
{
    prisrv_plus_feme_attr_policy_st pol;
    G1 sk2[PRISRV_PLUS_MATRIX_M], sk3[PRISRV_PLUS_MATRIX_M], sk4[PRISRV_PLUS_MATRIX_M], sk5[PRISRV_PLUS_MATRIX_M];
    G2 sk1;

} prisrv_plus_feme_poly_key_st;

typedef struct
{
    prisrv_plus_feme_attr_policy_st pol;
    int attr_name[PRISRV_PLUS_AK_ATTR_NUM];
    G1 ct3[PRISRV_PLUS_MATRIX_M], ct5[PRISRV_PLUS_AK_ATTR_NUM], ct6[PRISRV_PLUS_AK_ATTR_NUM], ct9;
    G2 ct1, ct2, ct41, ct42, ct7, ct8;

} prisrv_plus_feme_cipher_text_st;

typedef struct 
{
    Big bid;
    G1 Z;
    Big Service_type;
    Big Service_par; 
    MACddh_SK Kc;
} prisrv_plus_msg_b_st;


typedef struct 
{
    prisrv_plus_feme_cipher_text_st ct;
    prisrv_plus_msg_b_st msg_b;
    unsigned char cipher[PRISRV_PLUS_CIPHER_B_LEN];
    unsigned int cipher_len;
} prisrv_plus_brdcst_ct_st;

typedef struct 
{
    Big z;
    Big y;
    MACddh_SK Kc;
} prisrv_plus_server_sk_st;

typedef struct 
{
    MACddh_SK Ks;
    Big flag;
    Big bid;
    Big sid;
    G1 X1,X2,Z; 
} prisrv_plus_msg_c_st;

typedef struct 
{
    MACddh_MAC sgmc;
    prisrv_plus_feme_cipher_text_st CT;
    prisrv_plus_msg_c_st msg_c;
    unsigned char cipher[PRISRV_PLUS_CIPHER_C_LEN];
    unsigned int cipher_len;
} prisrv_plus_client_ct_st;

typedef struct 
{
    Big x1,x2;
    MACddh_SK Ks;
} prisrv_plus_client_sk_st;

typedef struct 
{
    Big flag;
    Big bid;
    Big sid;
    G1 X1,X2,Y,Z; 
} prisrv_plus_msg_s_st;


typedef struct 
{
    prisrv_plus_msg_s_st msg_s;
    MACddh_MAC sgms;
//    char cipher[PRISRV_PLUS_CIPHER_MAX_LEN];
//    unsigned int cipher_len;
} prisrv_plus_server_ct_st;

typedef struct
{
    Big ssk;
} prisrv_plus_server_ssk_st;

///////////////////////////////////

#endif // COMMON_H
