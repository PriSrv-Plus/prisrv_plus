#include"prisrv_plus_export.h"


int correct()
{
    
    int ret =0;
    //初始化操作-客户端和服务端都执行
    ret = Setup();
    if(ret != 0)
    {
        printf("SetUp Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("prisrv.SetUp pass\n");
    
    //客户端密钥生成
    prisrv_plus_feme_attr_list_st_c client_attr_list;
    prisrv_plus_feme_ekey_st_c client_ekey;
    ret = EKeyGen(&client_attr_list, &client_ekey);
    if(ret != 0)
    {
        printf("client_EKeyGen Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("client_EKeyGen pass\n");

    prisrv_plus_feme_dkey_st_c client_dkey;
    ret = DKeyGen(&client_attr_list, &client_dkey);
    if(ret != 0)
    {
        printf("client_DKeyGen Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("client_DKeyGen pass\n");

    prisrv_plus_feme_attr_policy_st_c client_attr_policy; prisrv_plus_feme_poly_key_st_c client_pkey;
    ret = PolKeyGen(&client_attr_policy, &client_pkey);
    if(ret != 0)
    {
        printf("client_PolKeyGen Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("client_PolKeyGen pass\n");

    //服务端密钥生成
    prisrv_plus_feme_attr_list_st_c server_attr_list;
    prisrv_plus_feme_ekey_st_c server_ekey;
    ret = EKeyGen(&server_attr_list, &server_ekey);
    if(ret != 0)
    {
        printf("server_EKeyGen Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("server_EKeyGen pass\n");

    prisrv_plus_feme_dkey_st_c server_dkey;
    ret = DKeyGen(&server_attr_list, &server_dkey);
    if(ret != 0)
    {
        printf("server_DKeyGen Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("server_DKeyGen pass\n");

    prisrv_plus_feme_attr_policy_st_c server_attr_policy; prisrv_plus_feme_poly_key_st_c server_pkey;
    ret = PolKeyGen(&server_attr_policy, &server_pkey);
    if(ret != 0)
    {
        printf("server_PolKeyGen Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("server_PolKeyGen pass\n");


    /*************协议流程******************/

    //1 服务端广播
    prisrv_plus_server_sk_st_c server_sk;
    prisrv_plus_brdcst_ct_st_c ct_b;

    ret = Broadcast(&server_ekey, &server_attr_policy, &server_sk, &ct_b);
    if(ret != 0)
    {
        printf("Broadcast Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("Broadcast pass\n");

    //2 客户端接收
    prisrv_plus_client_sk_st_c client_sk;
    prisrv_plus_client_ct_st_c ct_c;
    ret = AMA_Cinit(&client_ekey, &client_dkey,  &client_pkey, &ct_b, &client_sk, &ct_c);
    if(ret != 0)
    {
        printf("AMA_Cinit Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("AMA_Cinit pass\n");


    //3 服务端接收和回复
    prisrv_plus_server_ssk_st_c server_ssk;
    prisrv_plus_server_ct_st_c ct_s;
    ret = AMA_S(&server_ekey, &server_dkey,  &server_pkey, &ct_c, &server_sk, &ct_s, &server_ssk);
    if(ret != 0)
    {
        printf("AMA_S Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("AMA_S pass\n");


    //4 客户端接收和验证
    prisrv_plus_server_ssk_st_c client_ssk;
    ret = AMA_Cverify(&client_sk, &ct_s, &client_ssk);
    if(ret != 0)
    {
        printf("AMA_Cverify Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("AMA_Cverify pass\n");

    if(memcmp(&(server_ssk.ssk.len),&(client_ssk.ssk.len),sizeof(unsigned long)*server_ssk.ssk.len) == 0)
    {
        printf("PriSrc_Plus AMA  success!\n");
    }
    else
    {
        printf("PriSrc_Plus AMA  fail!\n");

    }

    return 0;
}


int main()
{
    return correct();

}
