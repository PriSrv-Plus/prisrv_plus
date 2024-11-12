#include "prisrv_plus.h"

PriSrv_Plus::PriSrv_Plus(PFC *p) : mac_ddh(p), feme(p), hash_ctr(p)
{
    pfc = p;
}
PriSrv_Plus::~PriSrv_Plus()
{
}
int PriSrv_Plus::setup(prisrv_plus_feme_mpk_st &mpk, prisrv_plus_feme_msk_st &msk)
{
    return feme.setup(mpk, msk);
}

int PriSrv_Plus::EKeyGen(prisrv_plus_feme_mpk_st &mpk, prisrv_plus_feme_msk_st &msk, prisrv_plus_feme_attr_list_st &ek_attr_list, prisrv_plus_feme_ekey_st &ekey)
{
    return feme.EKeyGen(mpk, msk, ek_attr_list, ekey);
}
int PriSrv_Plus::DKeyGen(prisrv_plus_feme_mpk_st &mpk, prisrv_plus_feme_msk_st &msk, prisrv_plus_feme_attr_list_st &dk_attr_list, prisrv_plus_feme_dkey_st &dkey)
{
    return feme.DKeyGen(mpk, msk, dk_attr_list, dkey);
}
int PriSrv_Plus::PolKeyGen(prisrv_plus_feme_mpk_st &mpk, prisrv_plus_feme_msk_st &msk, prisrv_plus_feme_attr_policy_st &attr_policy, prisrv_plus_feme_poly_key_st &pkey)
{
    return feme.PolKeyGen(mpk, msk, attr_policy, pkey);
}

// service
int PriSrv_Plus::Broadcast(prisrv_plus_feme_mpk_st &mpk, prisrv_plus_feme_ekey_st &server_ekey, prisrv_plus_feme_attr_policy_st &server_attr_policy, prisrv_plus_server_sk_st &server_sk, prisrv_plus_brdcst_ct_st &ct_b)
{
    int ret = 0;
    pfc->random(ct_b.msg_b.bid);
    pfc->random(ct_b.msg_b.Service_par);
    pfc->random(ct_b.msg_b.Service_type);
    pfc->random(server_sk.z);

    ct_b.msg_b.Z = pfc->mult(*pfc->gg1, server_sk.z);

    MACddh_PK pk;
    mac_ddh.KeyGen(server_sk.Kc, pk);
    for (int i = 0; i < MACddh_PARA_N + 1; i++)
    {
        ct_b.msg_b.Kc.x[i] = server_sk.Kc.x[i];
        ct_b.msg_b.Kc.y[i] = server_sk.Kc.y[i];
    }
    ct_b.msg_b.Kc.z = server_sk.Kc.z;

    GT V;

    ret = feme.Enc(mpk, server_ekey, server_attr_policy, ct_b.ct, V);
    if (ret != 0)
        return -1;
//    cout<<"Broadcast V:"<<V.g<<endl;
    Big CTR = 1;
    hash_ctr.init(V, CTR);
    hash_ctr.encrypt_add(ct_b.msg_b.bid);
    hash_ctr.encrypt_add(ct_b.msg_b.Z);
    hash_ctr.encrypt_add(ct_b.msg_b.Service_par);
    hash_ctr.encrypt_add(ct_b.msg_b.Service_type);
    for (int i = 0; i < MACddh_PARA_N + 1; i++)
    {
        hash_ctr.encrypt_add(ct_b.msg_b.Kc.x[i]);
    }
    for (int i = 0; i < MACddh_PARA_N + 1; i++)
    {
        hash_ctr.encrypt_add(ct_b.msg_b.Kc.y[i]);
    }
    hash_ctr.encrypt_add(ct_b.msg_b.Kc.z);
    ret = hash_ctr.encrypt_data(ct_b.cipher, &(ct_b.cipher_len));
    if (ret != 0)
        return -2;
//    printf("\nBroadcast cipher_len = %d\n", ct_b.cipher_len);
    return ret;
}

int PriSrv_Plus::AMA_Cinit(prisrv_plus_feme_mpk_st &mpk, prisrv_plus_feme_ekey_st &client_ekey, prisrv_plus_feme_dkey_st &client_dkey, prisrv_plus_feme_poly_key_st &client_pkey, prisrv_plus_brdcst_ct_st &ct_b, prisrv_plus_client_sk_st &client_sk, prisrv_plus_client_ct_st &ct_c)
{
    int ret = 0;
    GT V;
    Big CTR = 1;
    ret = feme.Dec(mpk, client_dkey, client_pkey, ct_b.ct, V);
    if (ret != 0)
        return -1;
//    cout<<"AMA_Cinit V:"<<V.g<<endl;
    hash_ctr.init(V, CTR);
    ret = hash_ctr.decrypt_data(ct_b.cipher, ct_b.cipher_len);
    if (ret != 0)
        return -2;

    hash_ctr.decrypt_red(ct_b.msg_b.Kc.z);
    for (int i = 0; i < MACddh_PARA_N + 1; i++)
    {
        hash_ctr.decrypt_red(ct_b.msg_b.Kc.y[MACddh_PARA_N - i]);
    }
    for (int i = 0; i < MACddh_PARA_N + 1; i++)
    {
        hash_ctr.decrypt_red(ct_b.msg_b.Kc.x[MACddh_PARA_N - i]);
    }
    hash_ctr.decrypt_red(ct_b.msg_b.Service_type);
    hash_ctr.decrypt_red(ct_b.msg_b.Service_par);
    hash_ctr.decrypt_red(ct_b.msg_b.Z);
    hash_ctr.decrypt_red(ct_b.msg_b.bid);


    pfc->random(client_sk.x1);
    pfc->random(client_sk.x2);

    pfc->random(ct_c.msg_c.sid);
    ct_c.msg_c.flag = 1;
    ct_c.msg_c.bid = ct_b.msg_b.bid;
    ct_c.msg_c.Z = ct_b.msg_b.Z;
    ct_c.msg_c.X1 = pfc->mult(*pfc->gg, client_sk.x1);
    ct_c.msg_c.X2 = pfc->mult(*pfc->gg1, client_sk.x2);

    MACddh_M M;
    Big CS, X1, X2, Z;
    pfc->start_hash();
    pfc->add_to_hash(ct_c.msg_c.X1);
    X1 = pfc->finish_hash_to_group();
    pfc->start_hash();
    pfc->add_to_hash(ct_c.msg_c.X2);
    X2 = pfc->finish_hash_to_group();
    pfc->start_hash();
    pfc->add_to_hash(ct_c.msg_c.Z);
    Z = pfc->finish_hash_to_group();

    M.N = 6;
    M.m[0] = ct_c.msg_c.flag;
    M.m[1] = ct_c.msg_c.bid;
    M.m[2] = ct_c.msg_c.sid;
    M.m[3] = X1;
    M.m[4] = X2;
    M.m[5] = Z;

    ret = mac_ddh.MAC(ct_b.msg_b.Kc, M, ct_c.sgmc);
    if (ret != 0)
        return -2;
    MACddh_PK pk;
    ret = mac_ddh.KeyGen(client_sk.Ks, pk);
    if (ret != 0)
        return -3;
    for (int i = 0; i < MACddh_PARA_N + 1; i++)
    {
        ct_c.msg_c.Ks.x[i] = client_sk.Ks.x[i];
        ct_c.msg_c.Ks.y[i] = client_sk.Ks.y[i];
    }
    ct_c.msg_c.Ks.z = client_sk.Ks.z;


    ret = feme.Enc(mpk, client_ekey, client_pkey.pol, ct_c.CT, V);
    if (ret != 0)
        return -4;
    CTR = 1;
    hash_ctr.init(V, CTR);
    hash_ctr.encrypt_add(ct_c.msg_c.bid);
    hash_ctr.encrypt_add(ct_c.msg_c.flag);
    for (int i = 0; i < MACddh_PARA_N + 1; i++)
    {
        hash_ctr.encrypt_add(ct_c.msg_c.Ks.x[i]);
    }
    for (int i = 0; i < MACddh_PARA_N + 1; i++)
    {
        hash_ctr.encrypt_add(ct_c.msg_c.Ks.y[i]);
    }
    hash_ctr.encrypt_add(ct_c.msg_c.Ks.z);
    hash_ctr.encrypt_add(ct_c.msg_c.sid);
    hash_ctr.encrypt_add(ct_c.msg_c.X1);
    hash_ctr.encrypt_add(ct_c.msg_c.X2);
    hash_ctr.encrypt_add(ct_c.msg_c.Z);

    ret = hash_ctr.encrypt_data(ct_c.cipher, &(ct_c.cipher_len));
    if (ret != 0)
        return -5;
//    printf("\nAMA_Cinit cipher_len = %d\n", ct_c.cipher_len);

    return ret;
}

int PriSrv_Plus::AMA_S(prisrv_plus_feme_mpk_st &mpk, prisrv_plus_feme_ekey_st &server_ekey, prisrv_plus_feme_dkey_st &server_dkey, prisrv_plus_feme_poly_key_st &server_pkey, prisrv_plus_client_ct_st &ct_c, prisrv_plus_server_sk_st &server_sk, prisrv_plus_server_ct_st &ct_s, prisrv_plus_server_ssk_st &ssk)
{
    int ret = 0;
    GT V;
    ret = feme.Dec(mpk, server_dkey, server_pkey, ct_c.CT, V);
    if (ret != 0)
        return -1;
    Big CTR = 1;
    hash_ctr.init(V, CTR);
    ret = hash_ctr.decrypt_data(ct_c.cipher, ct_c.cipher_len);
    if (ret != 0)
        return -5;
   
    hash_ctr.decrypt_red(ct_c.msg_c.Z);
    hash_ctr.decrypt_red(ct_c.msg_c.X2);
    hash_ctr.decrypt_red(ct_c.msg_c.X1);
    hash_ctr.decrypt_red(ct_c.msg_c.sid);
    hash_ctr.decrypt_red(ct_c.msg_c.Ks.z);
    for (int i = 0; i < MACddh_PARA_N + 1; i++)
    {
        hash_ctr.decrypt_red(ct_c.msg_c.Ks.y[MACddh_PARA_N - i]);
    }
    for (int i = 0; i < MACddh_PARA_N + 1; i++)
    {
        hash_ctr.decrypt_red(ct_c.msg_c.Ks.x[MACddh_PARA_N - i]);
    }

    hash_ctr.decrypt_red(ct_c.msg_c.flag);
    hash_ctr.decrypt_red(ct_c.msg_c.bid);

    pfc->random(server_sk.y);
    ct_s.msg_s.Y = pfc->mult(*pfc->gg, server_sk.y);
    ct_s.msg_s.Z = ct_c.msg_c.Z;
    ct_s.msg_s.X1 = ct_c.msg_c.X1;
    ct_s.msg_s.X2 = ct_c.msg_c.X2;
    ct_s.msg_s.flag = ct_c.msg_c.flag;
    ct_s.msg_s.bid = ct_c.msg_c.bid;
    ct_s.msg_s.sid = ct_c.msg_c.sid;

    MACddh_M M;
    Big CS, X1, X2, Z, Y;
    pfc->start_hash();
    pfc->add_to_hash(ct_c.msg_c.X1);
    X1 = pfc->finish_hash_to_group();
    pfc->start_hash();
    pfc->add_to_hash(ct_c.msg_c.X2);
    X2 = pfc->finish_hash_to_group();
    pfc->start_hash();
    pfc->add_to_hash(ct_c.msg_c.Z);
    Z = pfc->finish_hash_to_group();

    M.N = 6;
    M.m[0] = ct_c.msg_c.flag;
    M.m[1] = ct_c.msg_c.bid;
    M.m[2] = ct_c.msg_c.sid;
    M.m[3] = X1;
    M.m[4] = X2;
    M.m[5] = Z;

    ret = mac_ddh.Verify(server_sk.Kc, M, ct_c.sgmc);
    if (ret != 0)
        return -2;

    pfc->start_hash();
    pfc->add_to_hash(ct_s.msg_s.Y);
    Y = pfc->finish_hash_to_group();

    M.N = 7;
    M.m[0] = ct_c.msg_c.flag;
    M.m[1] = ct_c.msg_c.bid;
    M.m[2] = ct_c.msg_c.sid;
    M.m[3] = X1;
    M.m[4] = X2;
    M.m[5] = Y;
    M.m[5] = Z;

    ret = mac_ddh.MAC(ct_c.msg_c.Ks, M, ct_s.sgms);
    if (ret != 0)
        return -2;

    G1 X1Y = pfc->mult(ct_c.msg_c.X1, server_sk.y);
    G1 X2Z = pfc->mult(ct_c.msg_c.X2, server_sk.z);

    pfc->start_hash();
    pfc->add_to_hash(X1Y);
    pfc->add_to_hash(X2Z);
    ssk.ssk = pfc->finish_hash_to_group();

    return ret;
}

int PriSrv_Plus::AMA_Cverify(prisrv_plus_client_sk_st &client_sk, prisrv_plus_server_ct_st &ct_s, prisrv_plus_server_ssk_st &ssk)
{
    int ret = 0;
    MACddh_M M;
    Big CS, X1, X2, Z, Y;
    pfc->start_hash();
    pfc->add_to_hash(ct_s.msg_s.X1);
    X1 = pfc->finish_hash_to_group();
    pfc->start_hash();
    pfc->add_to_hash(ct_s.msg_s.X2);
    X2 = pfc->finish_hash_to_group();
    pfc->start_hash();
    pfc->add_to_hash(ct_s.msg_s.Z);
    Z = pfc->finish_hash_to_group();
    M.N = 7;
    M.m[0] = ct_s.msg_s.flag;
    M.m[1] = ct_s.msg_s.bid;
    M.m[2] = ct_s.msg_s.sid;
    M.m[3] = X1;
    M.m[4] = X2;
    M.m[5] = Y;
    M.m[5] = Z;
    ret = mac_ddh.Verify(client_sk.Ks, M, ct_s.sgms);
    if (ret != 0)
        return -2;

    G1 X1Y = pfc->mult(ct_s.msg_s.Y, client_sk.x1);
    G1 X2Z = pfc->mult(ct_s.msg_s.Z, client_sk.x2);

    pfc->start_hash();
    pfc->add_to_hash(X1Y);
    pfc->add_to_hash(X2Z);
    ssk.ssk = pfc->finish_hash_to_group();

    return ret;
}