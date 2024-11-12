#include "feme.h"

int main()
{
    PFC pfc(AES_SECURITY);
    FEME feme(&pfc);
    int ret = 0;

    prisrv_plus_feme_mpk_st mpk;
    prisrv_plus_feme_msk_st msk;

    ret = feme.setup(mpk, msk);
    if (ret != 0)
    {
        printf("feme.setup erro ret =%d\n", ret);
        return -1;
    }
    // snd keygen
    prisrv_plus_feme_attr_list_st snd_attr_list;
    prisrv_plus_feme_ekey_st snd_ekey;

    ret = feme.EKeyGen(mpk, msk, snd_attr_list, snd_ekey);
    if (ret != 0)
    {
        printf("feme.snd_EKeyGen erro ret =%d\n", ret);
        return -1;
    }

    prisrv_plus_feme_dkey_st snd_dkey;
    ret = feme.DKeyGen(mpk, msk, snd_attr_list, snd_dkey);
    if (ret != 0)
    {
        printf("feme.snd_DKeyGen erro ret =%d\n", ret);
        return -1;
    }

    prisrv_plus_feme_attr_policy_st snd_attr_policy;
    prisrv_plus_feme_poly_key_st snd_pkey;

    ret = feme.PolKeyGen(mpk, msk, snd_attr_policy, snd_pkey);
    if (ret != 0)
    {
        printf("feme.snd_PolKeyGen erro ret =%d\n", ret);
        return -1;
    }
    // rcv keygen
    prisrv_plus_feme_attr_list_st rcv_attr_list;
    prisrv_plus_feme_ekey_st rcv_ekey;

    ret = feme.EKeyGen(mpk, msk, rcv_attr_list, rcv_ekey);
    if (ret != 0)
    {
        printf("feme.rcv_EKeyGen erro ret =%d\n", ret);
        return -1;
    }

    prisrv_plus_feme_dkey_st rcv_dkey;
    ret = feme.DKeyGen(mpk, msk, rcv_attr_list, rcv_dkey);
    if (ret != 0)
    {
        printf("feme.rcv_DKeyGen erro ret =%d\n", ret);
        return -1;
    }

    prisrv_plus_feme_attr_policy_st rcv_attr_policy;
    prisrv_plus_feme_poly_key_st rcv_pkey;

    ret = feme.PolKeyGen(mpk, msk, rcv_attr_policy, rcv_pkey);
    if (ret != 0)
    {
        printf("feme.rcv_PolKeyGen erro ret =%d\n", ret);
        return -1;
    }

    // snd enc
    GT snd_V = *pfc.gt;
    prisrv_plus_feme_cipher_text_st snd_CT;
    for (int i = 0; i < 10; i++)
    {
        ret = feme.Enc(mpk, snd_ekey, snd_attr_policy, snd_CT, snd_V);
        if (ret != 0)
        {
            printf("feme.Enc erro ret =%d\n", ret);
            return -1;
        }

        // rcv dec
        GT rcv_V;
        ret = feme.Dec(mpk, rcv_dkey, rcv_pkey, snd_CT, rcv_V);
        if (ret != 0)
        {
            printf("feme.Dec erro ret =%d\n", ret);
            return -1;
        }

        if (snd_V != rcv_V)
        {
            printf("feme erro ret =%d\n", ret);
            return -2;
        }
        printf("feme correct !!\n");
    }
    

    return 0;
}