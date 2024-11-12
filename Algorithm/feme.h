#ifndef FEME_H
#define FEME_H

#include"common.h"



class FEME
{
private:
    PFC *pfc;
    Big inner_multi_mod(int *x, Big *y, int dim);
public:

    FEME(PFC *p);
    ~FEME();
    int setup(prisrv_plus_feme_mpk_st &mpk, prisrv_plus_feme_msk_st &msk);
    int EKeyGen(prisrv_plus_feme_mpk_st &mpk,prisrv_plus_feme_msk_st &msk, prisrv_plus_feme_attr_list_st &ek_attr_list, prisrv_plus_feme_ekey_st &ekey);
    int DKeyGen(prisrv_plus_feme_mpk_st &mpk,prisrv_plus_feme_msk_st &msk, prisrv_plus_feme_attr_list_st &dk_attr_list, prisrv_plus_feme_dkey_st &dkey);
    int PolKeyGen(prisrv_plus_feme_mpk_st &mpk,prisrv_plus_feme_msk_st &msk, prisrv_plus_feme_attr_policy_st &attr_policy, prisrv_plus_feme_poly_key_st &pkey);
    int Enc(prisrv_plus_feme_mpk_st &mpk,prisrv_plus_feme_ekey_st &snd_ekey, prisrv_plus_feme_attr_policy_st &snd_attr_policy, prisrv_plus_feme_cipher_text_st &snd_CT, GT &V);
    int Dec(prisrv_plus_feme_mpk_st &mpk,prisrv_plus_feme_dkey_st &rcv_dkey, prisrv_plus_feme_poly_key_st &rcv_pkey, prisrv_plus_feme_cipher_text_st &snd_CT, GT &V);
};

#endif // FEME_H
