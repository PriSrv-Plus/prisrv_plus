#ifndef PRISRV_PLUS_H
#define PRISRV_PLUS_H
#include "common.h"
#include "feme.h"
#include "macddh.h"
#include <fstream>
#include <iostream>
#include "hash_ctr.h"
using namespace std;


class PriSrv_Plus
{
private:
    PFC *pfc;
    MACddh mac_ddh;
    FEME feme;
    HASH_CTR hash_ctr;

public:

    PriSrv_Plus(PFC *p);
    ~PriSrv_Plus();
    int setup(prisrv_plus_feme_mpk_st &mpk, prisrv_plus_feme_msk_st &msk);
    int EKeyGen(prisrv_plus_feme_mpk_st &mpk,prisrv_plus_feme_msk_st &msk, prisrv_plus_feme_attr_list_st &ek_attr_list, prisrv_plus_feme_ekey_st &ekey);
    int DKeyGen(prisrv_plus_feme_mpk_st &mpk,prisrv_plus_feme_msk_st &msk, prisrv_plus_feme_attr_list_st &dk_attr_list, prisrv_plus_feme_dkey_st &dkey);
    int PolKeyGen(prisrv_plus_feme_mpk_st &mpk,prisrv_plus_feme_msk_st &msk, prisrv_plus_feme_attr_policy_st &attr_policy, prisrv_plus_feme_poly_key_st &pkey);
    
    //service
    int Broadcast(prisrv_plus_feme_mpk_st &mpk, prisrv_plus_feme_ekey_st &server_ekey, prisrv_plus_feme_attr_policy_st &server_attr_policy, prisrv_plus_server_sk_st &server_sk, prisrv_plus_brdcst_ct_st &ct_b);

    int AMA_Cinit(prisrv_plus_feme_mpk_st &mpk, prisrv_plus_feme_ekey_st &client_ekey, prisrv_plus_feme_dkey_st &client_dkey,  prisrv_plus_feme_poly_key_st &client_pkey, prisrv_plus_brdcst_ct_st &ct_b, prisrv_plus_client_sk_st &client_sk, prisrv_plus_client_ct_st &ct_c);

    int AMA_S(prisrv_plus_feme_mpk_st &mpk, prisrv_plus_feme_ekey_st &server_ekey, prisrv_plus_feme_dkey_st &server_dkey,  prisrv_plus_feme_poly_key_st &server_pkey, prisrv_plus_client_ct_st &ct_c, prisrv_plus_server_sk_st &server_sk, prisrv_plus_server_ct_st &ct_s, prisrv_plus_server_ssk_st &ssk);

    int AMA_Cverify(prisrv_plus_client_sk_st &client_sk, prisrv_plus_server_ct_st &ct_s, prisrv_plus_server_ssk_st &ssk);
    
};

#endif // PRISRV_PLUS_H
