#include "prisrv_plus.h"
int correct()
{
    PFC pfc(AES_SECURITY);
    PriSrv_Plus prisrv_plus(&pfc);
    int ret = 0;

    prisrv_plus_feme_mpk_st mpk;
    prisrv_plus_feme_msk_st msk;

    ret = prisrv_plus.setup(mpk, msk);
    if (ret != 0)
    {
        printf("prisrv_plus.setup erro ret =%d\n", ret);
        return -1;
    }
    // snd keygen
    prisrv_plus_feme_attr_list_st server_attr_list;
    prisrv_plus_feme_ekey_st server_ekey;
    ret = prisrv_plus.EKeyGen(mpk, msk, server_attr_list, server_ekey);
    if (ret != 0)
    {
        printf("prisrv_plus.server_EKeyGen erro ret =%d\n", ret);
        return -1;
    }

    prisrv_plus_feme_dkey_st server_dkey;
    ret = prisrv_plus.DKeyGen(mpk, msk, server_attr_list, server_dkey);
    if (ret != 0)
    {
        printf("prisrv_plus.server_DKeyGen erro ret =%d\n", ret);
        return -1;
    }

    prisrv_plus_feme_attr_policy_st server_attr_policy;
    prisrv_plus_feme_poly_key_st server_pkey;

    ret = prisrv_plus.PolKeyGen(mpk, msk, server_attr_policy, server_pkey);
    if (ret != 0)
    {
        printf("prisrv_plus.server_PolKeyGen erro ret =%d\n", ret);
        return -1;
    }
    // rcv keygen
    prisrv_plus_feme_attr_list_st client_attr_list;
    prisrv_plus_feme_ekey_st client_ekey;

    ret = prisrv_plus.EKeyGen(mpk, msk, client_attr_list, client_ekey);
    if (ret != 0)
    {
        printf("prisrv_plus.client_EKeyGen erro ret =%d\n", ret);
        return -1;
    }

    prisrv_plus_feme_dkey_st client_dkey;
    ret = prisrv_plus.DKeyGen(mpk, msk, client_attr_list, client_dkey);
    if (ret != 0)
    {
        printf("prisrv_plus.client_DKeyGen erro ret =%d\n", ret);
        return -1;
    }

    prisrv_plus_feme_attr_policy_st client_attr_policy;
    prisrv_plus_feme_poly_key_st client_pkey;

    ret = prisrv_plus.PolKeyGen(mpk, msk, client_attr_policy, client_pkey);
    if (ret != 0)
    {
        printf("prisrv_plus.client_PolKeyGen erro ret =%d\n", ret);
        return -1;
    }

    // broadcast
    prisrv_plus_server_sk_st server_sk;
    prisrv_plus_brdcst_ct_st ct_b;
    ret = prisrv_plus.Broadcast(mpk, server_ekey, server_attr_policy, server_sk, ct_b);
    if (ret != 0)
    {
        printf("prisrv_plus.Broadcast erro ret =%d\n", ret);
        return -1;
    }

    // AMA_Cinit
    prisrv_plus_client_sk_st client_sk;
    prisrv_plus_client_ct_st ct_c;
    ret = prisrv_plus.AMA_Cinit(mpk, client_ekey, client_dkey, client_pkey, ct_b, client_sk, ct_c);
    if (ret != 0)
    {
        printf("prisrv_plus.AMA_Cinit erro ret =%d\n", ret);
        return -1;
    }
    prisrv_plus_server_ct_st ct_s;
    prisrv_plus_server_ssk_st server_ssk, client_ssk;
    ret = prisrv_plus.AMA_S(mpk, server_ekey, server_dkey, server_pkey, ct_c, server_sk, ct_s, server_ssk);
    if (ret != 0)
    {
        printf("prisrv_plus.AMA_S erro ret =%d\n", ret);
        return -1;
    }

    ret = prisrv_plus.AMA_Cverify(client_sk, ct_s, client_ssk);
    if (ret != 0)
    {
        printf("prisrv_plus.AMA_Cverify erro ret =%d\n", ret);
        return -1;
    }

    if (client_ssk.ssk != server_ssk.ssk)
    {
        printf("PriSrv ssk erro !!\n");
        return -1;
    }

    printf("PriSrv_plus correct !!\n");
}
#include <ctime>
#include <time.h>
#define TEST_TIME 1
int speed()
{
    PFC pfc(AES_SECURITY);
    PriSrv_Plus prisrv_plus(&pfc);
    int ret = 0;
    int i;
    clock_t start, finish;
    double sum;

    prisrv_plus_feme_mpk_st mpk;
    prisrv_plus_feme_msk_st msk;
    start = clock();
    for (i = 0; i < TEST_TIME; i++)
    {
        ret = prisrv_plus.setup(mpk, msk);
        if (ret != 0)
        {
            printf("prisrv_plus.setup erro ret =%d\n", ret);
            return -1;
        }
    }
    finish = clock();
    sum = (double)(finish - start) / (CLOCKS_PER_SEC * TEST_TIME);
    printf("prisrv_plus.setup ret : %d time =%f sec\n", ret, sum);
    // snd keygen
    prisrv_plus_feme_attr_list_st server_attr_list;
    prisrv_plus_feme_ekey_st server_ekey;
    start = clock();
    for (i = 0; i < TEST_TIME; i++)
    {
        ret = prisrv_plus.EKeyGen(mpk, msk, server_attr_list, server_ekey);
        if (ret != 0)
        {
            printf("prisrv_plus.server_EKeyGen erro ret =%d\n", ret);
            return -1;
        }
    }
    finish = clock();
    sum = (double)(finish - start) / (CLOCKS_PER_SEC * TEST_TIME);
    printf("prisrv_plus.server_EKeyGen ret : %d time =%f sec\n", ret, sum);

    prisrv_plus_feme_dkey_st server_dkey;
    start = clock();
    for (i = 0; i < TEST_TIME; i++)
    {
        ret = prisrv_plus.DKeyGen(mpk, msk, server_attr_list, server_dkey);
        if (ret != 0)
        {
            printf("prisrv_plus.server_DKeyGen erro ret =%d\n", ret);
            return -1;
        }
    }
    finish = clock();
    sum = (double)(finish - start) / (CLOCKS_PER_SEC * TEST_TIME);
    printf("prisrv_plus.server_DKeyGen ret : %d time =%f sec\n", ret, sum);

    prisrv_plus_feme_attr_policy_st server_attr_policy;
    prisrv_plus_feme_poly_key_st server_pkey;
    start = clock();
    for (i = 0; i < TEST_TIME; i++)
    {
        ret = prisrv_plus.PolKeyGen(mpk, msk, server_attr_policy, server_pkey);
        if (ret != 0)
        {
            printf("prisrv_plus.server_PolKeyGen erro ret =%d\n", ret);
            return -1;
        }
    }
    finish = clock();
    sum = (double)(finish - start) / (CLOCKS_PER_SEC * TEST_TIME);
    printf("prisrv_plus.server_PolKeyGen ret : %d time =%f sec\n", ret, sum);
    // rcv keygen
    prisrv_plus_feme_attr_list_st client_attr_list;
    prisrv_plus_feme_ekey_st client_ekey;
    start = clock();
    for (i = 0; i < TEST_TIME; i++)
    {
        ret = prisrv_plus.EKeyGen(mpk, msk, client_attr_list, client_ekey);
        if (ret != 0)
        {
            printf("prisrv_plus.client_EKeyGen erro ret =%d\n", ret);
            return -1;
        }
    }
    finish = clock();
    sum = (double)(finish - start) / (CLOCKS_PER_SEC * TEST_TIME);
    printf("prisrv_plus.client_EKeyGen ret : %d time =%f sec\n", ret, sum);

    prisrv_plus_feme_dkey_st client_dkey;
    start = clock();
    for (i = 0; i < TEST_TIME; i++)
    {
        ret = prisrv_plus.DKeyGen(mpk, msk, client_attr_list, client_dkey);
        if (ret != 0)
        {
            printf("prisrv_plus.client_DKeyGen erro ret =%d\n", ret);
            return -1;
        }
    }
    finish = clock();
    sum = (double)(finish - start) / (CLOCKS_PER_SEC * TEST_TIME);
    printf("prisrv_plus.client_DKeyGen ret : %d time =%f sec\n", ret, sum);

    prisrv_plus_feme_attr_policy_st client_attr_policy;
    prisrv_plus_feme_poly_key_st client_pkey;
    start = clock();
    for (i = 0; i < TEST_TIME; i++)
    {
        ret = prisrv_plus.PolKeyGen(mpk, msk, client_attr_policy, client_pkey);
        if (ret != 0)
        {
            printf("prisrv_plus.client_PolKeyGen erro ret =%d\n", ret);
            return -1;
        }
    }
    finish = clock();
    sum = (double)(finish - start) / (CLOCKS_PER_SEC * TEST_TIME);
    printf("prisrv_plus.client_PolKeyGen ret : %d time =%f sec\n", ret, sum);

    // broadcast
    prisrv_plus_server_sk_st server_sk;
    prisrv_plus_brdcst_ct_st ct_b;
    start = clock();
    for (i = 0; i < TEST_TIME; i++)
    {
        ret = prisrv_plus.Broadcast(mpk, server_ekey, server_attr_policy, server_sk, ct_b);
        if (ret != 0)
        {
            printf("prisrv_plus.Broadcast erro ret =%d\n", ret);
            return -1;
        }
    }
    finish = clock();
    sum = (double)(finish - start) / (CLOCKS_PER_SEC * TEST_TIME);
    printf("prisrv_plus.Broadcast ret : %d time =%f sec\n", ret, sum);

    // AMA_Cinit
    prisrv_plus_client_sk_st client_sk;
    prisrv_plus_client_ct_st ct_c;
    start = clock();
    for (i = 0; i < TEST_TIME; i++)
    {
        ret = prisrv_plus.AMA_Cinit(mpk, client_ekey, client_dkey, client_pkey, ct_b, client_sk, ct_c);
        if (ret != 0)
        {
            printf("prisrv_plus.AMA_Cinit erro ret =%d\n", ret);
            return -1;
        }
    }
    finish = clock();
    sum = (double)(finish - start) / (CLOCKS_PER_SEC * TEST_TIME);
    printf("prisrv_plus.AMA_Cinit ret : %d time =%f sec\n", ret, sum);
    prisrv_plus_server_ct_st ct_s;
    prisrv_plus_server_ssk_st server_ssk, client_ssk;
    start = clock();
    for (i = 0; i < TEST_TIME; i++)
    {
        ret = prisrv_plus.AMA_S(mpk, server_ekey, server_dkey, server_pkey, ct_c, server_sk, ct_s, server_ssk);
        if (ret != 0)
        {
            printf("prisrv_plus.AMA_S erro ret =%d\n", ret);
            return -1;
        }
    }
    finish = clock();
    sum = (double)(finish - start) / (CLOCKS_PER_SEC * TEST_TIME);
    printf("prisrv_plus.AMA_S ret : %d time =%f sec\n", ret, sum);
    start = clock();
    for (i = 0; i < TEST_TIME; i++)
    {
        ret = prisrv_plus.AMA_Cverify(client_sk, ct_s, client_ssk);
        if (ret != 0)
        {
            printf("prisrv_plus.AMA_Cverify erro ret =%d\n", ret);
            return -1;
        }
    }
    finish = clock();
    sum = (double)(finish - start) / (CLOCKS_PER_SEC * TEST_TIME);
    printf("prisrv_plus.AMA_Cverify ret : %d time =%f sec\n", ret, sum);

    if (client_ssk.ssk != server_ssk.ssk)
    {
        printf("PriSrv ssk erro !!\n");
        return -1;
    }

}
int main()
{
    PFC pfc(AES_SECURITY);
    PriSrv_Plus prisrv_plus(&pfc);
    int ret = 0;

    prisrv_plus_feme_mpk_st mpk;
    prisrv_plus_feme_msk_st msk;

    ret = prisrv_plus.setup(mpk, msk);
    if (ret != 0)
    {
        printf("prisrv_plus.setup erro ret =%d\n", ret);
        return -1;
    }
    // snd keygen
    prisrv_plus_feme_attr_list_st server_attr_list;
    prisrv_plus_feme_ekey_st server_ekey;
    ret = prisrv_plus.EKeyGen(mpk, msk, server_attr_list, server_ekey);
    if (ret != 0)
    {
        printf("prisrv_plus.server_EKeyGen erro ret =%d\n", ret);
        return -1;
    }

    prisrv_plus_feme_dkey_st server_dkey;
    ret = prisrv_plus.DKeyGen(mpk, msk, server_attr_list, server_dkey);
    if (ret != 0)
    {
        printf("prisrv_plus.server_DKeyGen erro ret =%d\n", ret);
        return -1;
    }

    prisrv_plus_feme_attr_policy_st server_attr_policy;
    prisrv_plus_feme_poly_key_st server_pkey;

    ret = prisrv_plus.PolKeyGen(mpk, msk, server_attr_policy, server_pkey);
    if (ret != 0)
    {
        printf("prisrv_plus.server_PolKeyGen erro ret =%d\n", ret);
        return -1;
    }
    // rcv keygen
    prisrv_plus_feme_attr_list_st client_attr_list;
    prisrv_plus_feme_ekey_st client_ekey;

    ret = prisrv_plus.EKeyGen(mpk, msk, client_attr_list, client_ekey);
    if (ret != 0)
    {
        printf("prisrv_plus.client_EKeyGen erro ret =%d\n", ret);
        return -1;
    }

    prisrv_plus_feme_dkey_st client_dkey;
    ret = prisrv_plus.DKeyGen(mpk, msk, client_attr_list, client_dkey);
    if (ret != 0)
    {
        printf("prisrv_plus.client_DKeyGen erro ret =%d\n", ret);
        return -1;
    }

    prisrv_plus_feme_attr_policy_st client_attr_policy;
    prisrv_plus_feme_poly_key_st client_pkey;

    ret = prisrv_plus.PolKeyGen(mpk, msk, client_attr_policy, client_pkey);
    if (ret != 0)
    {
        printf("prisrv_plus.client_PolKeyGen erro ret =%d\n", ret);
        return -1;
    }

    // broadcast
    prisrv_plus_server_sk_st server_sk;
    prisrv_plus_brdcst_ct_st ct_b;
    ret = prisrv_plus.Broadcast(mpk, server_ekey, server_attr_policy, server_sk, ct_b);
    if (ret != 0)
    {
        printf("prisrv_plus.Broadcast erro ret =%d\n", ret);
        return -1;
    }

    // AMA_Cinit
    prisrv_plus_client_sk_st client_sk;
    prisrv_plus_client_ct_st ct_c;
    ret = prisrv_plus.AMA_Cinit(mpk, client_ekey, client_dkey, client_pkey, ct_b, client_sk, ct_c);
    if (ret != 0)
    {
        printf("prisrv_plus.AMA_Cinit erro ret =%d\n", ret);
        return -1;
    }
    prisrv_plus_server_ct_st ct_s;
    prisrv_plus_server_ssk_st server_ssk, client_ssk;
    ret = prisrv_plus.AMA_S(mpk, server_ekey, server_dkey, server_pkey, ct_c, server_sk, ct_s, server_ssk);
    if (ret != 0)
    {
        printf("prisrv_plus.AMA_S erro ret =%d\n", ret);
        return -1;
    }

    ret = prisrv_plus.AMA_Cverify(client_sk, ct_s, client_ssk);
    if (ret != 0)
    {
        printf("prisrv_plus.AMA_Cverify erro ret =%d\n", ret);
        return -1;
    }

    if (client_ssk.ssk != server_ssk.ssk)
    {
        printf("PriSrv ssk erro !!\n");
        return -1;
    }

    printf("PriSrv_plus correct !!\n");

    return 0;
}