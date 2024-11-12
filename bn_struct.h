#ifndef BN_STRUCT_H
#define BN_STRUCT_H

#define WLEN 4


typedef struct 
{
    unsigned int len;
    unsigned long w[WLEN];
} Big_C;
typedef struct 
{
    Big_C X;
    Big_C Y;
    Big_C Z;
} G1_C;
typedef struct 
{
    Big_C Xa,Xb;
    Big_C Ya,Yb;
    Big_C Za,Zb;
}G2_C ;
typedef struct 
{
    Big_C Aaa,Aab,Aba,Abb;
   // bool Aunitary;
    Big_C Baa,Bab,Bba,Bbb;
   // bool Bunitary;
    Big_C Caa,Cab,Cba,Cbb;
   // bool Cunitary;
} GT_C;

#define ST_MACddh_PARA_N 7 
#define ST_PRISRV_PLUS_AK_ATTR_NUM 6 // l1 l2
#define ST_PRISRV_PLUS_MATRIX_M 5 //5*3
#define ST_PRISRV_PLUS_MATRIX_N 3 //
#define ST_PRISRV_PLUS_CIPHER_B_LEN 920
#define ST_PRISRV_PLUS_CIPHER_C_LEN 1160


typedef struct
{
    G1_C h;
    GT_C Z,Y;
    G2_C sgm0, sgm1, sgm2;
 
} prisrv_plus_feme_mpk_st_c;

typedef struct
{
    Big_C alfa, x, niu, b1, b2;

} prisrv_plus_feme_msk_st_c;

typedef struct
{
    int attr_name[ST_PRISRV_PLUS_AK_ATTR_NUM];
    Big_C value[ST_PRISRV_PLUS_AK_ATTR_NUM];
} prisrv_plus_feme_attr_list_st_c;

typedef struct
{
    int attr_name[ST_PRISRV_PLUS_AK_ATTR_NUM];
    G1_C ek1[ST_PRISRV_PLUS_AK_ATTR_NUM];
    G2_C ek2,ek3;
    G1_C ek4;

} prisrv_plus_feme_ekey_st_c;

typedef struct
{
    int attr_name[ST_PRISRV_PLUS_AK_ATTR_NUM];
    G1_C dk2[ST_PRISRV_PLUS_AK_ATTR_NUM];
    G2_C dk3;
    G1_C dk1;

} prisrv_plus_feme_dkey_st_c;

typedef struct
{
    int MSP[ST_PRISRV_PLUS_MATRIX_M][ST_PRISRV_PLUS_MATRIX_N];
    int attr_name[ST_PRISRV_PLUS_MATRIX_M];

} prisrv_plus_feme_attr_policy_st_c;
//MSP

typedef struct
{
    prisrv_plus_feme_attr_policy_st_c pol;
    G1_C sk2[ST_PRISRV_PLUS_MATRIX_M], sk3[ST_PRISRV_PLUS_MATRIX_M], sk4[ST_PRISRV_PLUS_MATRIX_M], sk5[ST_PRISRV_PLUS_MATRIX_M];
    G2_C sk1;

} prisrv_plus_feme_poly_key_st_c;

typedef struct
{
    prisrv_plus_feme_attr_policy_st_c pol;
    int attr_name[ST_PRISRV_PLUS_AK_ATTR_NUM];
//    GT_C ct0;
    G1_C ct3[ST_PRISRV_PLUS_MATRIX_M], ct5[ST_PRISRV_PLUS_AK_ATTR_NUM], ct6[ST_PRISRV_PLUS_AK_ATTR_NUM], ct9;
    G2_C ct1, ct2, ct41, ct42, ct7, ct8;

} prisrv_plus_feme_cipher_text_st_c;

typedef struct
{
    Big_C x[ST_MACddh_PARA_N+1];
    Big_C y[ST_MACddh_PARA_N+1];
    Big_C z;
} MACddh_SK_C;

typedef struct 
{
    G1_C sig_x,sig_y,sig_z,sig_w;
} MACddh_MAC_C;
typedef struct 
{
    Big_C bid;
    G1_C Z;
    Big_C Service_type;
    Big_C Service_par; 
    MACddh_SK_C K_c;
} prisrv_plus_msg_b_st_c;


typedef struct 
{
    prisrv_plus_feme_cipher_text_st_c ct;
    unsigned char cipher[ST_PRISRV_PLUS_CIPHER_B_LEN];
    unsigned int cipher_len;
//    prisrv_plus_msg_b_st_c msg_b;
} prisrv_plus_brdcst_ct_st_c;

typedef struct 
{
    Big_C z;
    Big_C y;
    MACddh_SK_C Kc;
} prisrv_plus_server_sk_st_c;

typedef struct 
{
    MACddh_SK_C Ks;
    Big_C flag;
    Big_C bid;
    Big_C sid;
    G1_C X1,X2,Z; 
} prisrv_plus_msg_c_st_c;

typedef struct 
{
    MACddh_MAC_C sgmc;
    prisrv_plus_feme_cipher_text_st_c CT;
//    prisrv_plus_msg_c_st_c msg_c;
    unsigned char cipher[ST_PRISRV_PLUS_CIPHER_C_LEN];
    unsigned int cipher_len;
 
} prisrv_plus_client_ct_st_c;

typedef struct 
{
    Big_C x1,x2;
    MACddh_SK_C Ks;
  
} prisrv_plus_client_sk_st_c;

typedef struct 
{
    Big_C flag;
    Big_C bid;
    Big_C sid;
    G1_C X1,X2,Y,Z; 
} prisrv_plus_msg_s_st_c;

typedef struct 
{
    prisrv_plus_msg_s_st_c msg_s;
    MACddh_MAC_C sgms;
} prisrv_plus_server_ct_st_c;

typedef struct
{
    Big_C ssk;
} prisrv_plus_server_ssk_st_c;

#endif // BN_STRUCT_H
