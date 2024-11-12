
#include "feme.h"
#include "iostream"
// policy ((((F and M) or J) or W) and Q)  instantiation
static int MSP[PRISRV_PLUS_MATRIX_M][PRISRV_PLUS_MATRIX_N] = {0};
static int ROU[PRISRV_PLUS_MATRIX_M] = {'F', 'M', 'J', 'W', 'Q'};
static int ATTR_NAME[PRISRV_PLUS_AK_ATTR_NUM] = {'Q', 'J', 'W', 'R', 'M', 'F'};
static int SET_PI[PRISRV_PLUS_SET_I] = {0, 1, 4};
static int SET_AI[PRISRV_PLUS_SET_I] = {5, 4, 0};
static int OMG_I[PRISRV_PLUS_SET_I] = {1, 1, 1};

FEME::FEME(PFC *p)
{
    pfc = p;
    time_t seed;
    //    time(&seed); // initialise (insecure!) random numbers
    irand(0x12345678); // const seed

    pfc->precomp_for_mult(*pfc->gg);  // g1 is fixed, so precompute on it
    pfc->precomp_for_mult(*pfc->gg1); // h is fixed, so precompute on it
    pfc->precomp_for_mult(*pfc->hh);
    pfc->precomp_for_power(*pfc->gt);
    MSP[0][0] = 1;
    MSP[0][1] = 1;
    MSP[0][2] = 1;
    MSP[1][0] = 0;
    MSP[1][1] = 0;
    MSP[1][2] = -1;
    MSP[2][0] = 1;
    MSP[2][1] = 1;
    MSP[2][2] = 0;
    MSP[3][0] = 1;
    MSP[3][1] = 1;
    MSP[3][2] = 0;
    MSP[4][0] = 0;
    MSP[4][1] = -1;
    MSP[4][2] = 0;
}
FEME::~FEME()
{
}
int FEME::setup(prisrv_plus_feme_mpk_st &mpk, prisrv_plus_feme_msk_st &msk)
{
    int ret = 0;
    pfc->random(msk.alfa);
    pfc->random(msk.b1);
    pfc->random(msk.b2);
    pfc->random(msk.x);
    pfc->random(msk.niu);
    mpk.Z = pfc->power(*pfc->gt, msk.alfa);

    Big t = pfc->Zpmulti(msk.x, msk.niu);
    mpk.Y = pfc->power(*pfc->gt, t);
    mpk.sgm0 = pfc->mult(*pfc->hh, msk.niu);
    mpk.sgm1 = pfc->mult(*pfc->hh, msk.b1);
    mpk.sgm2 = pfc->mult(*pfc->hh, msk.b2);

    pfc->precomp_for_power(mpk.Z);
    pfc->precomp_for_power(mpk.Y);
    pfc->precomp_for_mult(mpk.sgm0);
    pfc->precomp_for_mult(mpk.sgm1);
    pfc->precomp_for_mult(mpk.sgm2);
    //    cout << "msk.alfa:" << msk.alfa << endl; //test
    return ret;
}
int FEME::EKeyGen(prisrv_plus_feme_mpk_st &mpk, prisrv_plus_feme_msk_st &msk, prisrv_plus_feme_attr_list_st &ek_attr_list, prisrv_plus_feme_ekey_st &ekey)
{
    int ret = 0;
    int i;
    Big tau;
    pfc->random(tau);
    for (i = 0; i < PRISRV_PLUS_AK_ATTR_NUM; i++)
    {
        pfc->start_hash();
        Big name = ek_attr_list.attr_name[i] = ATTR_NAME[i];
        pfc->add_to_hash(name);
        //        pfc->add_to_hash(ek_attr_list.value[i]); //test
        Big t = pfc->finish_hash_to_group();
        G1 H = pfc->mult(*pfc->gg, t);
        ekey.ek1[i] = pfc->mult(H, tau);
        ekey.attr_name[i] = ek_attr_list.attr_name[i];
    }
    ekey.ek2 = pfc->mult(mpk.sgm1, tau);
    ekey.ek3 = pfc->mult(mpk.sgm2, tau);
    ekey.ek4 = pfc->mult(*pfc->gg, msk.x) + pfc->mult(*pfc->gg1, tau);
    return ret;
}
Big FEME::inner_multi_mod(int *x, Big *y, int dim)
{
    int i;
    Big sum = 0;
    for (i = 0; i < dim; i++)
    {
        if (x[i] == -1)
        {
            sum = pfc->Zpsub(sum, y[i]);
        }
        else if (x[i] == 1)
        {
            sum = pfc->Zpadd(sum, y[i]);
        }
        else
            sum = sum;
    }
    return sum;
}
int FEME::DKeyGen(prisrv_plus_feme_mpk_st &mpk, prisrv_plus_feme_msk_st &msk, prisrv_plus_feme_attr_list_st &dk_attr_list, prisrv_plus_feme_dkey_st &dkey)
{
    int ret = 0;
    int i;
    Big r;
    pfc->random(r);
// #if 0 // test
//     r = 1;
// #endif
    for (i = 0; i < PRISRV_PLUS_AK_ATTR_NUM; i++)
    {
        pfc->start_hash();
        Big name = dk_attr_list.attr_name[i] = ATTR_NAME[i];
        pfc->add_to_hash(name);
        //        pfc->add_to_hash(dk_attr_list.value[i]);//test
        Big t = pfc->finish_hash_to_group();
        G1 H = pfc->mult(*pfc->gg, t);
        dkey.dk2[i] = pfc->mult(H, r);
        // printf("\n ATTR_NAME %x \n", ATTR_NAME[i]);
        // cout<<"dkey.dk2 H:"<<H.g<<endl;
        // cout<<"dkey.dk2:"<<dkey.dk2[i].g<<endl;
        dkey.attr_name[i] = dk_attr_list.attr_name[i];
    }
    dkey.dk3 = pfc->mult(*pfc->hh, r);
    dkey.dk1 = pfc->mult(*pfc->gg, msk.alfa) + pfc->mult(*pfc->gg1, r);
    return ret;
}
int FEME::PolKeyGen(prisrv_plus_feme_mpk_st &mpk, prisrv_plus_feme_msk_st &msk, prisrv_plus_feme_attr_policy_st &attr_policy, prisrv_plus_feme_poly_key_st &pkey)
{
    int ret = 0, i;
    Big y[PRISRV_PLUS_MATRIX_N], t, sum;
    Big r;
    Big b1_inv, b2_inv;
    G1 H, T, E;

    memcpy(attr_policy.MSP, MSP, sizeof(int) * PRISRV_PLUS_MATRIX_M * PRISRV_PLUS_MATRIX_N);
    memcpy(attr_policy.attr_name, ROU, sizeof(int) * PRISRV_PLUS_MATRIX_M);

    for (i = 0; i < PRISRV_PLUS_MATRIX_N - 1; i++)
    {
        pfc->random(y[i + 1]);
    }
    pfc->random(r);

    b1_inv = pfc->Zpinverse(msk.b1);
    b2_inv = pfc->Zpinverse(msk.b2);

    memcpy(pkey.pol.MSP, MSP, sizeof(int) * PRISRV_PLUS_MATRIX_M * PRISRV_PLUS_MATRIX_N);
    memcpy(pkey.pol.attr_name, ROU, sizeof(int) * PRISRV_PLUS_MATRIX_M);

    pkey.sk1 = pfc->mult(*pfc->hh, r);

    for (i = 0; i < PRISRV_PLUS_MATRIX_M; i++)
    {
        pfc->start_hash();
        Big name = pkey.pol.attr_name[i] = ROU[i]; // rou[i]
        pfc->add_to_hash(name);
        //        pfc->add_to_hash( pkey.pol.value[i]);//test
        t = pfc->finish_hash_to_group();
        H = pfc->mult(*pfc->gg, t);
        E = pfc->mult(H, r);

        y[0] = msk.alfa;
        sum = inner_multi_mod(MSP[i], y, PRISRV_PLUS_MATRIX_N);
        T = pfc->mult(*pfc->gg, sum) + E;
        pkey.sk2[i] = pfc->mult(T, b1_inv);
        pkey.sk3[i] = pfc->mult(T, b2_inv);

        y[0] = msk.niu;
        sum = inner_multi_mod(MSP[i], y, PRISRV_PLUS_MATRIX_N);
        T = pfc->mult(*pfc->gg1, sum) + E;
        pkey.sk4[i] = pfc->mult(T, b1_inv);
        pkey.sk5[i] = pfc->mult(T, b2_inv);
    }

    return ret;
}
int FEME::Enc(prisrv_plus_feme_mpk_st &mpk, prisrv_plus_feme_ekey_st &snd_ekey, prisrv_plus_feme_attr_policy_st &snd_attr_policy, prisrv_plus_feme_cipher_text_st &snd_CT, GT &V)
{
    int ret = 0, i;
    Big s1, s21, s22, s31, s32, tau, v[PRISRV_PLUS_MATRIX_N];
    Big s2, s3, sums1s2, t, sum;
    G1 H;

    pfc->random(s1);
    pfc->random(s21);
    pfc->random(s22);
    s2 = pfc->Zpadd(s21, s22);
    sums1s2 = pfc->Zpadd(s1, s2);
    pfc->random(s31);
    pfc->random(s32);
    s3 = pfc->Zpadd(s31, s32);
    for (i = 0; i < PRISRV_PLUS_MATRIX_N - 1; i++)
    {
        pfc->random(v[i + 1]);
    }

    V = pfc->power(mpk.Z, sums1s2) * pfc->power(mpk.Y, s3);

    snd_CT.ct1 = pfc->mult(*pfc->hh, s1);
    snd_CT.ct2 = pfc->mult(*pfc->hh, s3);

    snd_CT.ct41 = pfc->mult(mpk.sgm1, s21);
    snd_CT.ct42 = pfc->mult(mpk.sgm2, s22);

    snd_CT.ct7 = pfc->mult(mpk.sgm1, tau) + snd_ekey.ek2;
    snd_CT.ct7 = pfc->mult(snd_CT.ct7, s31);

    snd_CT.ct8 = pfc->mult(mpk.sgm2, tau) + snd_ekey.ek3;
    snd_CT.ct8 = pfc->mult(snd_CT.ct8, s32);

    snd_CT.ct9 = pfc->mult(*pfc->gg1, tau) + snd_ekey.ek4;
    snd_CT.ct9 = pfc->mult(snd_CT.ct9, s3);

    for (i = 0; i < PRISRV_PLUS_MATRIX_M; i++)
    {
        pfc->start_hash();
        Big name = snd_attr_policy.attr_name[i] = ROU[i]; // pi[i]
        pfc->add_to_hash(name);
        t = pfc->finish_hash_to_group();
        H = pfc->mult(*pfc->gg, t);

        v[0] = s1;
        sum = inner_multi_mod(MSP[i], v, PRISRV_PLUS_MATRIX_N);
        snd_CT.ct3[i] = pfc->mult(*pfc->gg1, sum) + pfc->mult(H, s3);
    }

    memcpy(snd_CT.pol.MSP, MSP, sizeof(int) * PRISRV_PLUS_MATRIX_M * PRISRV_PLUS_MATRIX_N);
    memcpy(snd_CT.pol.attr_name, ROU, sizeof(int) * PRISRV_PLUS_MATRIX_M);

    for (i = 0; i < PRISRV_PLUS_AK_ATTR_NUM; i++)
    {
        pfc->start_hash();
        Big name = snd_ekey.attr_name[i] = ATTR_NAME[i];
        pfc->add_to_hash(name);
        t = pfc->finish_hash_to_group();
        H = pfc->mult(*pfc->gg, t);
        snd_CT.ct5[i] = pfc->mult(H, s2);
        G1 T = pfc->mult(H, tau);
        T = T + snd_ekey.ek1[i];
        snd_CT.ct6[i] = pfc->mult(T, s3);
        snd_CT.attr_name[i] = snd_ekey.attr_name[i];
    }
#if 0
    V = *pfc->gt;
#endif
    return ret;
}

int FEME::Dec(prisrv_plus_feme_mpk_st &mpk, prisrv_plus_feme_dkey_st &rcv_dkey, prisrv_plus_feme_poly_key_st &rcv_pkey, prisrv_plus_feme_cipher_text_st &snd_CT, GT &V)
{
    int ret = 0, i, j;
    G1 ZERO = pfc->mult(*pfc->gg, 0);
    G1 SCT3 = ZERO, SDK2 = ZERO;
    for (i = 0; i < PRISRV_PLUS_SET_I; i++)
    {
        SCT3 = SCT3 + pfc->mult(snd_CT.ct3[SET_PI[i]], OMG_I[i]);
        SDK2 = SDK2 + pfc->mult(rcv_dkey.dk2[SET_AI[i]], OMG_I[i]);
    }

    G1 SCT5 = ZERO, SSK2 = ZERO, SSK3 = ZERO, SSK4 = ZERO, SSK5 = ZERO, SCT6 = ZERO;
    for (i = 0; i < PRISRV_PLUS_SET_I; i++)
    {
        SCT5 = SCT5 + pfc->mult(snd_CT.ct5[SET_AI[i]], OMG_I[i]);
        SCT6 = SCT6 + pfc->mult(snd_CT.ct6[SET_AI[i]], OMG_I[i]);
        SSK2 = SSK2 + pfc->mult(rcv_pkey.sk2[SET_PI[i]], OMG_I[i]);
        SSK3 = SSK3 + pfc->mult(rcv_pkey.sk3[SET_PI[i]], OMG_I[i]);
        SSK4 = SSK4 + pfc->mult(rcv_pkey.sk4[SET_PI[i]], OMG_I[i]);
        SSK5 = SSK5 + pfc->mult(rcv_pkey.sk5[SET_PI[i]], OMG_I[i]);
    }
    GT E1 = (pfc->pairing(snd_CT.ct1, rcv_dkey.dk1) * pfc->pairing(snd_CT.ct2, SDK2))/pfc->pairing(rcv_dkey.dk3, SCT3);

    GT E2 = (pfc->pairing(snd_CT.ct41, SSK2) * pfc->pairing(snd_CT.ct42, SSK3))/pfc->pairing(rcv_pkey.sk1, SCT5);

    GT E3 = (pfc->pairing(mpk.sgm0, snd_CT.ct9) * pfc->pairing(rcv_pkey.sk1, SCT6))/(pfc->pairing(snd_CT.ct7, SSK4) * pfc->pairing(snd_CT.ct8, SSK5)) ;

    V = E1 * E2 * E3;
#if 0
    V = *pfc->gt;
#endif
    return ret;
}