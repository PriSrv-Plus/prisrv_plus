#include "prisrv_plus_export.h"
#include "prisrv_plus.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "bn_transfer.h"

static PFC pfc(AES_SECURITY);
static PriSrv_Plus prisrv_plus(&pfc);
static BN_transfer BNT;
static prisrv_plus_feme_mpk_st mpk;
static prisrv_plus_feme_msk_st msk;
static void Trf_Ekey_st_to_Ekey(prisrv_plus_feme_ekey_st &ekey_st, prisrv_plus_feme_ekey_st_c *ekey)
{
    memcpy(ekey->attr_name, ekey_st.attr_name, sizeof(int) * ST_PRISRV_PLUS_AK_ATTR_NUM);
    for (int i = 0; i < PRISRV_PLUS_AK_ATTR_NUM; i++)
    {
        BNT.Trf_G1_to_Char(ekey_st.ek1[i], ekey->ek1[i]);
    }
    BNT.Trf_G2_to_Char(ekey_st.ek2, ekey->ek2);
    BNT.Trf_G2_to_Char(ekey_st.ek3, ekey->ek3);
    BNT.Trf_G1_to_Char(ekey_st.ek4, ekey->ek4);
}

static void Trf_Ekey_to_Ekey_st(prisrv_plus_feme_ekey_st_c *ekey, prisrv_plus_feme_ekey_st &ekey_st)
{
    memcpy(ekey_st.attr_name, ekey->attr_name, sizeof(int) * ST_PRISRV_PLUS_AK_ATTR_NUM);
    for (int i = 0; i < PRISRV_PLUS_AK_ATTR_NUM; i++)
    {
        BNT.Trf_Char_to_G1(ekey->ek1[i], ekey_st.ek1[i]);
    }
    BNT.Trf_Char_to_G2(ekey->ek2, ekey_st.ek2);
    BNT.Trf_Char_to_G2(ekey->ek3, ekey_st.ek3);
    BNT.Trf_Char_to_G1(ekey->ek4, ekey_st.ek4);
}
static void Trf_Dkey_st_to_Dkey(prisrv_plus_feme_dkey_st &dkey_st, prisrv_plus_feme_dkey_st_c *dkey)
{
    memcpy(dkey->attr_name, dkey_st.attr_name, sizeof(int) * ST_PRISRV_PLUS_AK_ATTR_NUM);
    for (int i = 0; i < PRISRV_PLUS_AK_ATTR_NUM; i++)
    {
        BNT.Trf_G1_to_Char(dkey_st.dk2[i], dkey->dk2[i]);
    }
    BNT.Trf_G2_to_Char(dkey_st.dk3, dkey->dk3);
    BNT.Trf_G1_to_Char(dkey_st.dk1, dkey->dk1);
}

static void Trf_Dkey_to_Dkey_st(prisrv_plus_feme_dkey_st_c *dkey, prisrv_plus_feme_dkey_st &dkey_st)
{
    memcpy(dkey_st.attr_name, dkey->attr_name, sizeof(int) * ST_PRISRV_PLUS_AK_ATTR_NUM);
    for (int i = 0; i < PRISRV_PLUS_AK_ATTR_NUM; i++)
    {
        BNT.Trf_Char_to_G1(dkey->dk2[i], dkey_st.dk2[i]);
    }
    BNT.Trf_Char_to_G2(dkey->dk3, dkey_st.dk3);
    BNT.Trf_Char_to_G1(dkey->dk1, dkey_st.dk1);
}
static void Trf_Pkey_st_to_Pkey(prisrv_plus_feme_poly_key_st &pkey_st, prisrv_plus_feme_poly_key_st_c *pkey)
{
    memcpy(pkey->pol.attr_name, pkey_st.pol.attr_name, sizeof(int) * PRISRV_PLUS_MATRIX_M);

    for (int i = 0; i < PRISRV_PLUS_MATRIX_M; i++)
    {
        BNT.Trf_G1_to_Char(pkey_st.sk2[i], pkey->sk2[i]);
        BNT.Trf_G1_to_Char(pkey_st.sk3[i], pkey->sk3[i]);
        BNT.Trf_G1_to_Char(pkey_st.sk4[i], pkey->sk4[i]);
        BNT.Trf_G1_to_Char(pkey_st.sk5[i], pkey->sk5[i]);
    }
    BNT.Trf_G2_to_Char(pkey_st.sk1, pkey->sk1);
}
static void Trf_Pkey_to_Pkey_st(prisrv_plus_feme_poly_key_st_c *pkey, prisrv_plus_feme_poly_key_st &pkey_st)
{
    memcpy(pkey_st.pol.attr_name, pkey->pol.attr_name, sizeof(int) * PRISRV_PLUS_MATRIX_M);

    for (int i = 0; i < PRISRV_PLUS_MATRIX_M; i++)
    {
        BNT.Trf_Char_to_G1(pkey->sk2[i], pkey_st.sk2[i]);
        BNT.Trf_Char_to_G1(pkey->sk3[i], pkey_st.sk3[i]);
        BNT.Trf_Char_to_G1(pkey->sk4[i], pkey_st.sk4[i]);
        BNT.Trf_Char_to_G1(pkey->sk5[i], pkey_st.sk5[i]);
    }
    BNT.Trf_Char_to_G2(pkey->sk1, pkey_st.sk1);
}
static void Trf_Ddhkey_st_to_Ddhkey(MACddh_SK &ddk_key, MACddh_SK_C *ddk_key_c)
{
    for (int i = 0; i < MACddh_PARA_N + 1; i++)
    {
        BNT.Trf_Big_to_Char(ddk_key.x[i], ddk_key_c->x[i]);
        BNT.Trf_Big_to_Char(ddk_key.y[i], ddk_key_c->y[i]);
    }
    BNT.Trf_Big_to_Char(ddk_key.z, ddk_key_c->z);
}

static void Trf_Ddhkey_to_Ddhkey_st(MACddh_SK_C *ddk_key_c, MACddh_SK &ddk_key)
{
    for (int i = 0; i < MACddh_PARA_N + 1; i++)
    {
        BNT.Trf_Char_to_Big(ddk_key_c->x[i], ddk_key.x[i]);
        BNT.Trf_Char_to_Big(ddk_key_c->y[i], ddk_key.y[i]);
    }
    BNT.Trf_Char_to_Big(ddk_key_c->z, ddk_key.z);
}
static void Trf_Server_sk_st_to_Server_sk(prisrv_plus_server_sk_st &server_sk_st, prisrv_plus_server_sk_st_c *server_sk)
{
    BNT.Trf_Big_to_Char(server_sk_st.z, server_sk->z);
    BNT.Trf_Big_to_Char(server_sk_st.y, server_sk->y);
    Trf_Ddhkey_st_to_Ddhkey(server_sk_st.Kc, &(server_sk->Kc));
}

static void Trf_Server_sk_to_Server_sk_st(prisrv_plus_server_sk_st_c *server_sk, prisrv_plus_server_sk_st &server_sk_st)
{
    BNT.Trf_Char_to_Big(server_sk->z, server_sk_st.z);
    BNT.Trf_Char_to_Big(server_sk->y, server_sk_st.y);
    Trf_Ddhkey_to_Ddhkey_st(&(server_sk->Kc), server_sk_st.Kc);
}
static void Trf_feme_ct_st_to_feme_ct(prisrv_plus_feme_cipher_text_st &ct_st, prisrv_plus_feme_cipher_text_st_c *ct)
{
    memcpy(&(ct->pol), &(ct_st.pol), sizeof(prisrv_plus_feme_attr_policy_st));
    memcpy(ct->attr_name, ct_st.attr_name, sizeof(int) * PRISRV_PLUS_AK_ATTR_NUM);
    for (int i = 0; i < ST_PRISRV_PLUS_MATRIX_M; i++)
    {
        BNT.Trf_G1_to_Char(ct_st.ct3[i], ct->ct3[i]);
    }
    for (int i = 0; i < PRISRV_PLUS_AK_ATTR_NUM; i++)
    {
        BNT.Trf_G1_to_Char(ct_st.ct5[i], ct->ct5[i]);
        BNT.Trf_G1_to_Char(ct_st.ct6[i], ct->ct6[i]);
    }
    BNT.Trf_G1_to_Char(ct_st.ct9, ct->ct9);
    BNT.Trf_G2_to_Char(ct_st.ct1, ct->ct1);
    BNT.Trf_G2_to_Char(ct_st.ct2, ct->ct2);
    BNT.Trf_G2_to_Char(ct_st.ct41, ct->ct41);
    BNT.Trf_G2_to_Char(ct_st.ct42, ct->ct42);
    BNT.Trf_G2_to_Char(ct_st.ct7, ct->ct7);
    BNT.Trf_G2_to_Char(ct_st.ct8, ct->ct8);

}
static void Trf_feme_ct_to_feme_ct_st(prisrv_plus_feme_cipher_text_st_c *ct, prisrv_plus_feme_cipher_text_st &ct_st)
{
    memcpy(&(ct_st.pol), &(ct->pol), sizeof(prisrv_plus_feme_attr_policy_st));
    memcpy(ct_st.attr_name, ct->attr_name, sizeof(int) * PRISRV_PLUS_AK_ATTR_NUM);

    for (int i = 0; i < ST_PRISRV_PLUS_MATRIX_M; i++)
    {
        BNT.Trf_Char_to_G1(ct->ct3[i], ct_st.ct3[i]);
    }
    for (int i = 0; i < PRISRV_PLUS_AK_ATTR_NUM; i++)
    {
        BNT.Trf_Char_to_G1(ct->ct5[i], ct_st.ct5[i]);
        BNT.Trf_Char_to_G1(ct->ct6[i], ct_st.ct6[i]);
    }
    BNT.Trf_Char_to_G1(ct->ct9, ct_st.ct9);
    BNT.Trf_Char_to_G2(ct->ct1, ct_st.ct1);
    BNT.Trf_Char_to_G2(ct->ct2, ct_st.ct2);
    BNT.Trf_Char_to_G2(ct->ct41, ct_st.ct41);
    BNT.Trf_Char_to_G2(ct->ct42, ct_st.ct42);
    BNT.Trf_Char_to_G2(ct->ct7, ct_st.ct7);
    BNT.Trf_Char_to_G2(ct->ct8, ct_st.ct8);
}
static void Trf_CT_b_st_to_CT_b(prisrv_plus_brdcst_ct_st &ct_b_st, prisrv_plus_brdcst_ct_st_c *ct_b)
{
    Trf_feme_ct_st_to_feme_ct(ct_b_st.ct, &(ct_b->ct));
    /* Trf_Ddhkey_st_to_Ddhkey(ct_b_st.msg_b.Kc, &(ct_b->msg_b.K_c));
    BNT.Trf_Big_to_Char(ct_b_st.msg_b.bid, ct_b->msg_b.bid);
    BNT.Trf_Big_to_Char(ct_b_st.msg_b.Service_type, ct_b->msg_b.Service_type);
    BNT.Trf_Big_to_Char(ct_b_st.msg_b.Service_par, ct_b->msg_b.Service_par);
    BNT.Trf_G1_to_Char(ct_b_st.msg_b.Z, ct_b->msg_b.Z); */
    memcpy(ct_b->cipher, ct_b_st.cipher, ct_b_st.cipher_len);
    ct_b->cipher_len = ct_b_st.cipher_len;
 
}
static void Trf_CT_b_to_CT_b_st(prisrv_plus_brdcst_ct_st_c *ct_b, prisrv_plus_brdcst_ct_st &ct_b_st)
{
    Trf_feme_ct_to_feme_ct_st(&(ct_b->ct), ct_b_st.ct);
    /* Trf_Ddhkey_to_Ddhkey_st(&(ct_b->msg_b.K_c), ct_b_st.msg_b.Kc);
    BNT.Trf_Char_to_Big(ct_b->msg_b.bid, ct_b_st.msg_b.bid);
    BNT.Trf_Char_to_Big(ct_b->msg_b.Service_type, ct_b_st.msg_b.Service_type);
    BNT.Trf_Char_to_Big(ct_b->msg_b.Service_par, ct_b_st.msg_b.Service_par);
    BNT.Trf_Char_to_G1(ct_b->msg_b.Z, ct_b_st.msg_b.Z); */
    memcpy(ct_b_st.cipher, ct_b->cipher, ct_b->cipher_len);
    ct_b_st.cipher_len = ct_b->cipher_len;
    
}
static void Trf_Client_sk_st_to_Client_sk(prisrv_plus_client_sk_st &client_sk_st, prisrv_plus_client_sk_st_c *client_sk)
{
    BNT.Trf_Big_to_Char(client_sk_st.x1, client_sk->x1);
    BNT.Trf_Big_to_Char(client_sk_st.x2, client_sk->x2);
    Trf_Ddhkey_st_to_Ddhkey(client_sk_st.Ks, &(client_sk->Ks));
}
static void Trf_Client_sk_to_Client_sk_st(prisrv_plus_client_sk_st_c *client_sk, prisrv_plus_client_sk_st &client_sk_st)
{
    BNT.Trf_Char_to_Big(client_sk->x1, client_sk_st.x1);
    BNT.Trf_Char_to_Big(client_sk->x2, client_sk_st.x2);
    Trf_Ddhkey_to_Ddhkey_st(&(client_sk->Ks), client_sk_st.Ks);
}
static void Trf_Ddhmac_st_to_Ddhmac(MACddh_MAC &ddk_mac, MACddh_MAC_C *ddk_mac_c)
{
    
    BNT.Trf_G1_to_Char(ddk_mac.sig_w, ddk_mac_c->sig_w);
    BNT.Trf_G1_to_Char(ddk_mac.sig_y, ddk_mac_c->sig_y);
    BNT.Trf_G1_to_Char(ddk_mac.sig_z, ddk_mac_c->sig_z);
    BNT.Trf_G1_to_Char(ddk_mac.sig_x, ddk_mac_c->sig_x);
}
static void Trf_Ddhmac_to_Ddhmac_st(MACddh_MAC_C *ddk_mac_c, MACddh_MAC &ddk_mac)
{
    
    BNT.Trf_Char_to_G1(ddk_mac_c->sig_w, ddk_mac.sig_w);
    BNT.Trf_Char_to_G1(ddk_mac_c->sig_y, ddk_mac.sig_y);
    BNT.Trf_Char_to_G1(ddk_mac_c->sig_z, ddk_mac.sig_z);
    BNT.Trf_Char_to_G1(ddk_mac_c->sig_x, ddk_mac.sig_x);
}
static void Trf_CT_c_st_to_CT_c(prisrv_plus_client_ct_st &ct_c_st, prisrv_plus_client_ct_st_c *ct_c)
{
    Trf_feme_ct_st_to_feme_ct(ct_c_st.CT, &(ct_c->CT));
    Trf_Ddhmac_st_to_Ddhmac(ct_c_st.sgmc, &(ct_c->sgmc));
    /* Trf_Ddhkey_st_to_Ddhkey(ct_c_st.msg_c.Ks,  &(ct_c->msg_c.Ks));
    BNT.Trf_Big_to_Char(ct_c_st.msg_c.bid, ct_c->msg_c.bid);
    BNT.Trf_Big_to_Char(ct_c_st.msg_c.flag, ct_c->msg_c.flag);
    BNT.Trf_Big_to_Char(ct_c_st.msg_c.sid, ct_c->msg_c.sid);
    BNT.Trf_G1_to_Char(ct_c_st.msg_c.X1, ct_c->msg_c.X1);
    BNT.Trf_G1_to_Char(ct_c_st.msg_c.X2, ct_c->msg_c.X2);
    BNT.Trf_G1_to_Char(ct_c_st.msg_c.Z, ct_c->msg_c.Z); */
    memcpy(ct_c->cipher, ct_c_st.cipher, ct_c_st.cipher_len);
    ct_c->cipher_len = ct_c_st.cipher_len;
}
static void Trf_CT_c_to_CT_c_st(prisrv_plus_client_ct_st_c *ct_c, prisrv_plus_client_ct_st &ct_c_st)
{
    Trf_feme_ct_to_feme_ct_st( &(ct_c->CT), ct_c_st.CT);
    Trf_Ddhmac_to_Ddhmac_st( &(ct_c->sgmc), ct_c_st.sgmc);
   /*  Trf_Ddhkey_to_Ddhkey_st( &(ct_c->msg_c.Ks), ct_c_st.msg_c.Ks);
    BNT.Trf_Char_to_Big(ct_c->msg_c.bid, ct_c_st.msg_c.bid);
    BNT.Trf_Char_to_Big(ct_c->msg_c.flag, ct_c_st.msg_c.flag);
    BNT.Trf_Char_to_Big(ct_c->msg_c.sid, ct_c_st.msg_c.sid);
    BNT.Trf_Char_to_G1(ct_c->msg_c.X1, ct_c_st.msg_c.X1);
    BNT.Trf_Char_to_G1(ct_c->msg_c.X2, ct_c_st.msg_c.X2);
    BNT.Trf_Char_to_G1(ct_c->msg_c.Z, ct_c_st.msg_c.Z); */
    memcpy(ct_c_st.cipher, ct_c->cipher, ct_c->cipher_len);
    ct_c_st.cipher_len = ct_c->cipher_len;
}
static void Trf_CT_s_st_to_CT_s(prisrv_plus_server_ct_st &ct_s_st, prisrv_plus_server_ct_st_c *ct_s)
{
    BNT.Trf_Big_to_Char(ct_s_st.msg_s.bid, ct_s->msg_s.bid);
    BNT.Trf_Big_to_Char(ct_s_st.msg_s.sid, ct_s->msg_s.sid);
    BNT.Trf_Big_to_Char(ct_s_st.msg_s.flag, ct_s->msg_s.flag);
    BNT.Trf_G1_to_Char(ct_s_st.msg_s.Z, ct_s->msg_s.Z);
    BNT.Trf_G1_to_Char(ct_s_st.msg_s.X1, ct_s->msg_s.X1);
    BNT.Trf_G1_to_Char(ct_s_st.msg_s.X2, ct_s->msg_s.X2);
    BNT.Trf_G1_to_Char(ct_s_st.msg_s.Y, ct_s->msg_s.Y);
    Trf_Ddhmac_st_to_Ddhmac(ct_s_st.sgms,  &(ct_s->sgms));
    
    

}
static void Trf_CT_s_to_CT_s_st(prisrv_plus_server_ct_st_c *ct_s, prisrv_plus_server_ct_st &ct_s_st)
{
    BNT.Trf_Char_to_Big(ct_s->msg_s.bid, ct_s_st.msg_s.bid);
    BNT.Trf_Char_to_Big(ct_s->msg_s.sid, ct_s_st.msg_s.sid);
    BNT.Trf_Char_to_Big(ct_s->msg_s.flag, ct_s_st.msg_s.flag);
    BNT.Trf_Char_to_G1(ct_s->msg_s.Z, ct_s_st.msg_s.Z);
    BNT.Trf_Char_to_G1(ct_s->msg_s.X1, ct_s_st.msg_s.X1);
    BNT.Trf_Char_to_G1(ct_s->msg_s.X2, ct_s_st.msg_s.X2);
    BNT.Trf_Char_to_G1(ct_s->msg_s.Y, ct_s_st.msg_s.Y);
    Trf_Ddhmac_to_Ddhmac_st( &(ct_s->sgms), ct_s_st.sgms);
}
int Setup()
{

    return prisrv_plus.setup(mpk, msk);
}
int EKeyGen(prisrv_plus_feme_attr_list_st_c *ek_attr_list, prisrv_plus_feme_ekey_st_c *ekey)
{
    prisrv_plus_feme_attr_list_st ek_attr_list_st;
    prisrv_plus_feme_ekey_st ekey_st;
    int ret = prisrv_plus.EKeyGen(mpk, msk, ek_attr_list_st, ekey_st);
    if (ret != 0)
        return ret;

    // trans
    memcpy(ek_attr_list->attr_name, ek_attr_list_st.attr_name, sizeof(int)*PRISRV_PLUS_AK_ATTR_NUM);
    Trf_Ekey_st_to_Ekey(ekey_st, ekey);

    return 0;
}
int DKeyGen(prisrv_plus_feme_attr_list_st_c *dk_attr_list, prisrv_plus_feme_dkey_st_c *dkey)
{
    prisrv_plus_feme_attr_list_st dk_attr_list_st;
    prisrv_plus_feme_dkey_st dkey_st;
    int ret = prisrv_plus.DKeyGen(mpk, msk, dk_attr_list_st, dkey_st);
    if (ret != 0)
        return ret;

    // trans
    memcpy(dk_attr_list->attr_name, dk_attr_list_st.attr_name, sizeof(int)*PRISRV_PLUS_AK_ATTR_NUM);
    Trf_Dkey_st_to_Dkey(dkey_st, dkey);

    return 0;
}
int PolKeyGen(prisrv_plus_feme_attr_policy_st_c *attr_policy, prisrv_plus_feme_poly_key_st_c *pkey)
{
    prisrv_plus_feme_attr_policy_st attr_policy_st;
    prisrv_plus_feme_poly_key_st pkey_st;
    int ret = prisrv_plus.PolKeyGen(mpk, msk, attr_policy_st, pkey_st);
    if (ret != 0)
        return ret;
    // trans
    memcpy(attr_policy->attr_name, attr_policy_st.attr_name, sizeof(int) * PRISRV_PLUS_MATRIX_M);
    Trf_Pkey_st_to_Pkey(pkey_st, pkey);

    return 0;
}

// service
int Broadcast(prisrv_plus_feme_ekey_st_c *server_ekey, prisrv_plus_feme_attr_policy_st_c *server_attr_policy, prisrv_plus_server_sk_st_c *server_sk, prisrv_plus_brdcst_ct_st_c *ct_b)
{
    int ret = 0;
    prisrv_plus_feme_ekey_st server_ekey_st;
    prisrv_plus_feme_attr_policy_st server_attr_policy_st;
    prisrv_plus_server_sk_st server_sk_st;
    prisrv_plus_brdcst_ct_st ct_b_st;

    // Trans
    // server_ekey
    Trf_Ekey_to_Ekey_st(server_ekey, server_ekey_st);
    // server_attr_policy
    memcpy(server_attr_policy_st.attr_name, server_attr_policy->attr_name, sizeof(int) * PRISRV_PLUS_MATRIX_M);

    ret = prisrv_plus.Broadcast(mpk, server_ekey_st, server_attr_policy_st, server_sk_st, ct_b_st);

    if (ret != 0)
        return -1;
    // Trans
    //  server_sk
    Trf_Server_sk_st_to_Server_sk(server_sk_st, server_sk);
    // ct_b
    Trf_CT_b_st_to_CT_b(ct_b_st, ct_b);
    return ret;
}

int AMA_Cinit(prisrv_plus_feme_ekey_st_c *client_ekey, prisrv_plus_feme_dkey_st_c *client_dkey, prisrv_plus_feme_poly_key_st_c *client_pkey, prisrv_plus_brdcst_ct_st_c *ct_b, prisrv_plus_client_sk_st_c *client_sk, prisrv_plus_client_ct_st_c *ct_c)
{
    int ret = 0;

    prisrv_plus_feme_ekey_st client_ekey_st;
    prisrv_plus_feme_dkey_st client_dkey_st;
    prisrv_plus_feme_poly_key_st client_pkey_st;
    prisrv_plus_brdcst_ct_st ct_b_st;
    prisrv_plus_client_sk_st client_sk_st;
    prisrv_plus_client_ct_st ct_c_st;

    // Trans
    // client_ekey
    Trf_Ekey_to_Ekey_st(client_ekey, client_ekey_st);
    // client_dkey
    Trf_Dkey_to_Dkey_st(client_dkey, client_dkey_st);
    // client_pkey
    Trf_Pkey_to_Pkey_st(client_pkey, client_pkey_st);
    // ct_b
    Trf_CT_b_to_CT_b_st(ct_b, ct_b_st);

    ret = prisrv_plus.AMA_Cinit(mpk, client_ekey_st, client_dkey_st, client_pkey_st, ct_b_st, client_sk_st, ct_c_st);

    if (ret != 0)
        return -1;
    // Trans
    // client_sk
    Trf_Client_sk_st_to_Client_sk(client_sk_st, client_sk);
    // ct_c
    Trf_CT_c_st_to_CT_c(ct_c_st, ct_c);
    return ret;
}

int AMA_S(prisrv_plus_feme_ekey_st_c *server_ekey, prisrv_plus_feme_dkey_st_c *server_dkey, prisrv_plus_feme_poly_key_st_c *server_pkey, prisrv_plus_client_ct_st_c *ct_c, prisrv_plus_server_sk_st_c *server_sk, prisrv_plus_server_ct_st_c *ct_s, prisrv_plus_server_ssk_st_c *ssk)
{
    int ret = 0;

    prisrv_plus_feme_ekey_st server_ekey_st;
    prisrv_plus_feme_dkey_st server_dkey_st;
    prisrv_plus_feme_poly_key_st server_pkey_st;
    prisrv_plus_client_ct_st ct_c_st;
    prisrv_plus_server_sk_st server_sk_st;
    prisrv_plus_server_ct_st ct_s_st;
    prisrv_plus_server_ssk_st ssk_st;

    // Trans
    //server_ekey
    Trf_Ekey_to_Ekey_st(server_ekey, server_ekey_st);

    //server_dkey
    Trf_Dkey_to_Dkey_st(server_dkey, server_dkey_st);
    //server_pkey
    Trf_Pkey_to_Pkey_st(server_pkey, server_pkey_st);

    //ct_c
    Trf_CT_c_to_CT_c_st(ct_c, ct_c_st);

    //server_sk
    Trf_Server_sk_to_Server_sk_st(server_sk, server_sk_st);

    ret = prisrv_plus.AMA_S(mpk, server_ekey_st, server_dkey_st, server_pkey_st, ct_c_st, server_sk_st, ct_s_st, ssk_st);
    if (ret != 0)
        return ret;
    // Trans
    //ct_s
     Trf_CT_s_st_to_CT_s(ct_s_st,  ct_s);
    //ssk
    BNT.Trf_Big_to_Char(ssk_st.ssk, ssk->ssk);

    return ret;
}

int AMA_Cverify(prisrv_plus_client_sk_st_c *client_sk, prisrv_plus_server_ct_st_c *ct_s, prisrv_plus_server_ssk_st_c *ssk)
{
    int ret = 0;
    prisrv_plus_client_sk_st client_sk_st;
    prisrv_plus_server_ct_st ct_s_st;
    prisrv_plus_server_ssk_st ssk_st;
    // Trans
    //client_sk
    Trf_Client_sk_to_Client_sk_st(client_sk, client_sk_st);
    //ct_s
    Trf_CT_s_to_CT_s_st(ct_s, ct_s_st);

    ret = prisrv_plus.AMA_Cverify(client_sk_st, ct_s_st, ssk_st);
    if (ret != 0)
        return -1;
    // Trans
    //ssk
    BNT.Trf_Big_to_Char(ssk_st.ssk, ssk->ssk);

    return ret;
}