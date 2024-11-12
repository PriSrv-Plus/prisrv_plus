#ifndef PRISRV_EXPORT_PLUS_H
#define PRISRV_EXPORT_PLUS_H
#include"stdio.h"
#include"string.h"
#include"stdlib.h"
#include "bn_struct.h"

#ifdef __cplusplus
extern "C" {
//////////////////////////////////////////////////
/// \brief SetUp
/// \param intput: 
/// \param output: 
/// \param transmit: 
/// \return correct 0/ erro !0
int Setup();

//////////////////////////////////////////////////
/// \brief EKeyGen
/// \param intput: 
/// \param output: ek_attr_list, ekey
/// \param transmit: 
/// \return correct 0/ erro !0
int EKeyGen(prisrv_plus_feme_attr_list_st_c *ek_attr_list, prisrv_plus_feme_ekey_st_c *ekey);

//////////////////////////////////////////////////
/// \brief DKeyGen
/// \param intput: 
/// \param output: dk_attr_list, dkey
/// \param transmit: 
/// \return correct 0/ erro !0
int DKeyGen(prisrv_plus_feme_attr_list_st_c *dk_attr_list, prisrv_plus_feme_dkey_st_c *dkey);


//////////////////////////////////////////////////
/// \brief PolKeyGen
/// \param intput: 
/// \param output: attr_policy, pkey
/// \param transmit: 
/// \return correct 0/ erro !0
int PolKeyGen(prisrv_plus_feme_attr_policy_st_c *attr_policy, prisrv_plus_feme_poly_key_st_c *pkey);
    
//////////////////////////////////////////////////
/// \brief Broadcast
/// \param intput: server_ekey, server_attr_policy
/// \param output: server_sk, ct_b
/// \param transmit: ct_b
/// \return correct 0/ erro !0
int Broadcast(prisrv_plus_feme_ekey_st_c *server_ekey, prisrv_plus_feme_attr_policy_st_c 
*server_attr_policy, prisrv_plus_server_sk_st_c *server_sk, prisrv_plus_brdcst_ct_st_c *ct_b);

//////////////////////////////////////////////////
/// \brief AMA_Cinit
/// \param intput: client_ekey, client_dkey, client_pkey, ct_b
/// \param output: client_sk, ct_c
/// \param transmit: ct_c
/// \return correct 0/ erro !0
int AMA_Cinit(prisrv_plus_feme_ekey_st_c *client_ekey, prisrv_plus_feme_dkey_st_c *client_dkey,  prisrv_plus_feme_poly_key_st_c *client_pkey, prisrv_plus_brdcst_ct_st_c *ct_b, prisrv_plus_client_sk_st_c *client_sk, prisrv_plus_client_ct_st_c *ct_c);

//////////////////////////////////////////////////
/// \brief AMA_S
/// \param intput: server_ekey, server_dkey, server_pkey, server_sk,ct_c
/// \param output: ct_s, ssk
/// \param transmit: ct_s
/// \return correct 0/ erro !0
int AMA_S(prisrv_plus_feme_ekey_st_c *server_ekey, prisrv_plus_feme_dkey_st_c *server_dkey,  prisrv_plus_feme_poly_key_st_c *server_pkey, prisrv_plus_client_ct_st_c *ct_c, prisrv_plus_server_sk_st_c *server_sk, prisrv_plus_server_ct_st_c *ct_s, prisrv_plus_server_ssk_st_c *ssk);

//////////////////////////////////////////////////
/// \brief AMA_Cverify
/// \param intput: client_ekey, client_dkey, client_pkey, client_sk, ct_s
/// \param output: ssk
/// \param transmit: 
/// \return correct 0/ erro !0
int AMA_Cverify(prisrv_plus_client_sk_st_c *client_sk, prisrv_plus_server_ct_st_c *ct_s, prisrv_plus_server_ssk_st_c *ssk);



    }
#endif //__cplusplus
#endif // PRISRV_EXPORT_PLUS_H