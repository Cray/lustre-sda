/*! \file TCGValues.h
    \brief Basic definition for common TCG values.

    This file defines TCG spec values.
    
    \legal 
    All software, source code, and any additional materials contained
    herein (the "Software") are owned by Seagate Technology LLC and are 
    protected by law and international treaties.  No rights to the 
    Software, including any rights to distribute, reproduce, sell, or 
    use the Software, are granted unless a license agreement has been 
    mutually agreed to and executed between Seagate Technology LLC and 
    an authorized licensee. 

    The Software contains SEAGATE CONFIDENTIAL INFORMATION AND SEAGATE 
    TRADE SECRET INFORMATION that must be protected as such.

    Copyright © 2008.  Seagate Technology LLC  All Rights Reserved.

    The Software is provided under the Agreement No. 134849 between Seagate
    Technology and Calsoft. All Intellectual Property rights to the Software,
    as between Calsoft and Seagate, will be governed under the terms of the 
    Agreement No. 134849; no other rights to the Software are granted.

*/

#ifndef TCGVALUES_DOT_H
#define TCGVALUES_DOT_H

//=================================
// defines
//=================================

// Security Protocol Field Definitions
#define SECURITY_PROTOCOLID_INFORMATION_DISCOVERY        0x00
#define SECURITY_PROTOCOLID_COMPACKET_IO                 0x01
#define SECURITY_PROTOCOLID_COMID_MANAGEMENT             0x02
#define SECURITY_PROTOCOLID_MAXTCGID                     0x06

// Security Procotol Specific Field Definitions
#define SPSPECIFIC_P00_SUPPORTED_SECURITY_PROTOCOL_LIST  0x0000
#define SPSPECIFIC_P00_CERTIFICATE_DATA                  0x0001
#define SPSPECIFIC_P00_SECURITY_COMPLIANCE_INFO          0x0002   // For Yara eDrives 2012-1-3 jls
#define SPSPECIFIC_P01_LEVEL0_DISCOVERY                  0x0001
#define SPSPECIFIC_P02_GET_COM_ID                        0x0000
#define SPSPECIFIC_P02_TPER_RESET                        0x0004

// SP00: SPS_CERTIFICATE_DATA Definitions                         // 2012-7-16 jls
// to be completed later with cert info

// SP00: SPS_SECURITY_COMPLIANCE_INFO Data Definitions            // 2012-7-16 jls
#define SPS_SEC_REQ_FOR_CRYPTOGRAPHIC_MODULES_TYPE       0x0001   // 2012-7-16 jls
#define SPS_SEC_REQ_FOR_CRYPTOGRAPHIC_MODULES_LENGTH     520      // 2012-7-16 jls

// SP01: Level 0 Discovery Returned Data Definitions              // 2012-7-16 jls
#define L0_DISCOVERY_HEADER_SIZE                         48
#define L0_DISCOVERY_TPERDESCRIPTOR_SIZE                 16
#define L0_DISCOVERY_LOCKINGDESCRIPTOR_SIZE              16
#define L0_DISCOVERY_SSCDESCRIPTOR_SIZE                  20
#define L0_DISCOVERY_VERSION_MASK                        0xF0
#define L0_DISCOVERY_TPER_SYNC_MASK                      0x01
#define L0_DISCOVERY_TPER_ASYNC_MASK                     0x02
#define L0_DISCOVERY_TPER_ACKNAK_MASK                    0x04
#define L0_DISCOVERY_TPER_BUFFERMGMT_MASK                0x08
#define L0_DISCOVERY_TPER_STREAMING_MASK                 0x10
#define L0_DISCOVERY_TPER_COMIDMGMT_MASK                 0x40
#define L0_DISCOVERY_LOCK_LOCKINGSUPPORTED_MASK          0x01
#define L0_DISCOVERY_LOCK_LOCKINGENABLED_MASK            0x02
#define L0_DISCOVERY_LOCK_LOCKED_MASK                    0x04
#define L0_DISCOVERY_LOCK_MEDIAENCRYPTION_MASK           0x08
#define L0_DISCOVERY_LOCK_MBRENABLED_MASK                0x10
#define L0_DISCOVERY_LOCK_MBRDONE_MASK                   0x20
#define L0_DISCOVERY_OPAL_SINGLEUSERMODE_ANY_MASK        0x01
#define L0_DISCOVERY_OPAL_SINGLEUSERMODE_ALL_MASK        0x02
#define L0_DISCOVERY_OPAL_SINGLEUSERMODE_POLICY_MASK     0x04
#define L0_DISCOVERY_FEATURECODE_TPER                    0x0001
#define L0_DISCOVERY_FEATURECODE_LOCKING                 0x0002
#define L0_DISCOVERY_FEATURECODE_SSC_OPAL_GEOMETRY       0x0003 // jls 20120103
#define L0_DISCOVERY_FEATURECODE_SSC_ENTERPRISE          0x0100
#define L0_DISCOVERY_FEATURECODE_SSC_OPAL                0x0200
#define L0_DISCOVERY_FEATURECODE_SSC_OPAL_SINGLEUSERMODE 0x0201
#define L0_DISCOVERY_FEATURECODE_SSC_OPAL_DATASTORETABLE 0x0202
#define L0_DISCOVERY_FEATURECODE_SSC_OPAL_V2             0x0203 // nvn20110520
#define L0_DISCOVERY_FEATURECODE_SSC_MARBLE              0x0300
#define L0_DISCOVERY_FEATURECODE_VU_STX_LOGICALPORT      0xC001
#define L0_DISCOVERY_FEATURECODE_UNSET                   0x0000

// Minimum Com Packet length should be 512 bytes
#define MIN_SEND_RECV_LEN                       0x200
#define COM_PKT_HDR_LEN                         0x14           // number of bytes in COM Packet header
#define PKT_HDR_LEN                             0x18           // number of bytes in Packet header
#define SUB_PKT_HDR_LEN                         0x0C           // number of bytes in Sub Packet header
#define DATA_SUB_PKT                            0x0000         // data subpacket
#define CREDIT_SUB_PKT                          0x8001         // credit subpacket


// Com Packet Definitions
#define NUMBER_PRESET_COMIDS                    2
#define ACKTYPE                                 0x0000
#define COMID1                                  0x0FFF
#define COMID2                                  0x0FEE
#define COM_ID1                                 0x07FE
#define COM_ID2                                 0x07FF
#define EXTENDEDCOMID1                          0x0FFF0000     // HurricaneFDE v1.0 - v1.02
#define EXTENDEDCOMID2                          0x0FFE0000     // HurricaneFDE v1.0 - v1.02
#define EXT_COM_ID1                             0x07FE0000     // HurricaneFDE v1.1 (v1.03+)
#define EXT_COM_ID2                             0x07FF0000     // HurricaneFDE v1.1 (v1.03+)
#define NAME                                    0xA3666F6F
#define VALUE                                   0x03
#define SHORT_ATOM_SID_TOKEN                    0x83
#define WRITE_DIRECTION                         1
#define READ_DIRECTION                          2
#define STATUS_SUCCESS                          0x00
#define TPERSID_POS                             0x50
#define SYNCSS_POS                              0x45
#define UID_SIZE                                0x08
#define WRITE_SESSION                           0x01
#define MSID_LENGTH                             0x20
#define VERIFY_COMID_REQ_CODE                   0x00000001
#define PROTOCOL_STACK_RESET_REQ_CODE           0x00000002

#define	MAX_NUMBER_OF_BANDS                     0x03FF
#define	MAX_NUMBER_OF_DATASTORETABLES           0x00FF

//
//UIDs
//

// - SP UIDS
#define	UID_SP_ADMIN                            0x0000020500000001
#define	UID_SP_LOCKING_E                        0x0000020500010001   // defined in Enterprise-SSC
#define	UID_SP_LOCKING_OM                       0x0000020500000002   // defined in Opal-SSC & Marble-SSC

// - Special purpose UIDs (as defined in Core2.0 Table-237)
#define UID_NULL                                0x0000000000000000
#define UID_THIS_SP                             0x0000000000000001
#define	UID_SESSION_MANAGER                     0x00000000000000FF
#define	UID_C_PIN_CHARSET                       0x0000000B00000001

// - Table UIDs (as defined in Core2.0 Table-238)
#define UID_TABLE_TABLE                         0x0000000100000000
#define UID_TABLE_SPINFO                        0x0000000200000000
#define UID_TABLE_SPTEMPLATES                   0x0000000300000000
#define UID_TABLE_COLUMN                        0x0000000400000000
#define UID_TABLE_TYPE                          0x0000000500000000
#define UID_TABLE_METHODID                      0x0000000600000000
#define UID_TABLE_METHOD                        0x0000000700000000   // Called "Method" table in Core1.0
#define UID_TABLE_ACCESSCONTROL                 0x0000000700000000   // Core2.0
#define UID_TABLE_ACE                           0x0000000800000000
#define UID_TABLE_AUTHORITY                     0x0000000900000000
#define UID_TABLE_CERTIFICATES                  0x0000000A00000000
#define UID_TABLE_C_PIN                         0x0000000B00000000
#define UID_TABLE_C_RSA_1024                    0x0000000C00000000
#define UID_TABLE_C_RSA_2048                    0x0000000D00000000
#define UID_TABLE_C_AES_128                     0x0000000E00000000
#define UID_TABLE_C_AES_256                     0x0000000F00000000
#define UID_TABLE_C_EC_160                      0x0000001000000000
#define UID_TABLE_C_EC_192                      0x0000001100000000
#define UID_TABLE_C_EC_224                      0x0000001200000000
#define UID_TABLE_C_EC_256                      0x0000001300000000
#define UID_TABLE_C_EC_384                      0x0000001400000000
#define UID_TABLE_C_EC_521                      0x0000001500000000
#define UID_TABLE_C_EC_163                      0x0000001600000000
#define UID_TABLE_C_EC_233                      0x0000001700000000
#define UID_TABLE_C_EC_283                      0x0000001800000000
#define UID_TABLE_C_HMAC_160                    0x0000001900000000
#define UID_TABLE_C_HMAC_256                    0x0000001A00000000
#define UID_TABLE_C_HMAC_384                    0x0000001B00000000
#define UID_TABLE_C_HMAC_512                    0x0000001C00000000
#define UID_TABLE_SECRET_PROTECT                0x0000001D00000000
#define UID_TABLE_TPERINFO                      0x0000020100000000
#define UID_TABLE_PROPERTIES                    0x0000020200000000   // defined in Core1.0, obsolete in Core2.0
#define UID_TABLE_CRYPTO_SUITE                  0x0000020300000000
#define UID_TABLE_TEMPLATE                      0x0000020400000000
#define UID_TABLE_SP                            0x0000020500000000
#define UID_TABLE_CLOCKTIME                     0x0000040100000000
#define UID_TABLE_H_SHA_1                       0x0000060100000000
#define UID_TABLE_H_SHA_256                     0x0000060200000000
#define UID_TABLE_H_SHA_384                     0x0000060300000000
#define UID_TABLE_H_SHA_512                     0x0000060400000000
#define UID_TABLE_LOG                           0x00000A0100000000
#define UID_TABLE_LOGLIST                       0x00000A0200000000
#define UID_TABLE_LOCKINGINFO                   0x0000080100000000
#define UID_TABLE_LOCKING                       0x0000080200000000
#define UID_TABLE_MBRCONTROL                    0x0000080300000000
#define UID_TABLE_MBR                           0x0000080400000000
#define UID_TABLE_K_AES_128                     0x0000080500000000
#define UID_TABLE_K_AES_256                     0x0000080600000000
#define UID_TABLE_DATASTORE1_EM                 0x0000800100000000   // defined in Ent-SSC & Marble-SSC (DataStoreB-MB)
#define UID_TABLE_DATASTORE1_OM                 0x0000100100000000   // defined in Opal-SSC & Marble-SSC (DataStoreA)
/* Seagate's extra Opal SSC 1.0 DS Tables
_DataStore1 00000001 00010008
_DataStore2 00000001 00010009
_DataStore3 00000001 0001000A
_DataStore4 00000001 0001000B
*/
#define UID_TABLE_RESTRICTEDCMDS                0x00000C0100000000   // defined in Opal-SSC & Marble-SSC (O)
#define UID_TABLE_SECURITY_OPERATING_MODE       0x0001000700000000   // Seagate proprietary, defined in "TcgFdeProductRequirements"

// - TableTable Row UIDs (as defined in Core2.0 Table-238)
#define UID_TABLETABLE_TABLE                    0x0000000100000001
#define UID_TABLETABLE_SPINFO                   0x0000000100000002
#define UID_TABLETABLE_SPTEMPLATES              0x0000000100000003
#define UID_TABLETABLE_COLUMN                   0x0000000100000004
#define UID_TABLETABLE_TYPE                     0x0000000100000005
#define UID_TABLETABLE_METHODID                 0x0000000100000006
#define UID_TABLETABLE_ACCESSCONTROL            0x0000000100000007
#define UID_TABLETABLE_ACE                      0x0000000100000008
#define UID_TABLETABLE_AUTHORITY                0x0000000100000009
#define UID_TABLETABLE_CERTIFICATES             0x000000010000000A
#define UID_TABLETABLE_C_PIN                    0x000000010000000B
#define UID_TABLETABLE_C_RSA_1024               0x000000010000000C
#define UID_TABLETABLE_C_RSA_2048               0x000000010000000D
#define UID_TABLETABLE_C_AES_128                0x000000010000000E
#define UID_TABLETABLE_C_AES_256                0x000000010000000F
#define UID_TABLETABLE_C_EC_160                 0x0000000100000010
#define UID_TABLETABLE_C_EC_192                 0x0000000100000011
#define UID_TABLETABLE_C_EC_224                 0x0000000100000012
#define UID_TABLETABLE_C_EC_256                 0x0000000100000013
#define UID_TABLETABLE_C_EC_384                 0x0000000100000014
#define UID_TABLETABLE_C_EC_521                 0x0000000100000015
#define UID_TABLETABLE_C_EC_163                 0x0000000100000016
#define UID_TABLETABLE_C_EC_233                 0x0000000100000017
#define UID_TABLETABLE_C_EC_283                 0x0000000100000018
#define UID_TABLETABLE_C_HMAC_160               0x0000000100000019
#define UID_TABLETABLE_C_HMAC_256               0x000000010000001A
#define UID_TABLETABLE_C_HMAC_384               0x000000010000001B
#define UID_TABLETABLE_C_HMAC_512               0x000000010000001C
#define UID_TABLETABLE_SECRET_PROTECT           0x000000010000001D
#define UID_TABLETABLE_TPERINFO                 0x0000000100000201
#define UID_TABLETABLE_PROPERTIES               0x0000000100000202   // defined in Core1.0, obsolete in Core2.0
#define UID_TABLETABLE_CRYPTO_SUITE             0x0000000100000203
#define UID_TABLETABLE_TEMPLATE                 0x0000000100000204
#define UID_TABLETABLE_SP                       0x0000000100000205
#define UID_TABLETABLE_CLOCKTIME                0x0000000100000401
#define UID_TABLETABLE_H_SHA_1                  0x0000000100000601
#define UID_TABLETABLE_H_SHA_256                0x0000000100000602
#define UID_TABLETABLE_H_SHA_384                0x0000000100000603
#define UID_TABLETABLE_H_SHA_512                0x0000000100000604
#define UID_TABLETABLE_LOG                      0x0000000100000A01
#define UID_TABLETABLE_LOGLIST                  0x0000000100000A02
#define UID_TABLETABLE_LOCKINGINFO              0x0000000100000801
#define UID_TABLETABLE_LOCKING                  0x0000000100000802
#define UID_TABLETABLE_MBRCONTROL               0x0000000100000803
#define UID_TABLETABLE_MBR                      0x0000000100000804
#define UID_TABLETABLE_K_AES_128                0x0000000100000805
#define UID_TABLETABLE_K_AES_256                0x0000000100000806
#define UID_TABLETABLE_DATASTORE1_EM            0x0000000100008001   // defined in Ent-SSC & Marble-SSC (DataStoreB)
#define UID_TABLETABLE_DATASTORE1_OM            0x0000000100001001   // defined in Opal-SSC & Marble-SSC (DataStoreA)
#define UID_TABLETABLE_DATASTORE2_O2            0x0000000100001002   // jls20120316 Additional DataStore (SSC 2)
/* Seagate's extra Opal SSC 1.0 DS Tables                            // jls20120316 Hopefully not used by ISVs
_DataStore1 00000001 00010008
_DataStore2 00000001 00010009
_DataStore3 00000001 0001000A
_DataStore4 00000001 0001000B
*/
#define UID_TABLETABLE_RESTRICTEDCMDS           0x0000000100000C01   // defined in Opal-SSC & Marble-SSC (TT2)
#define UID_TABLETABLE_SECURITY_OPERATING_MODE  0x0000000100010007   // Seagate proprietary, defined in "TcgFdeProductRequirements"

// - Session Mgr Method UIDs (as defined in Core2.0 Table-239)
#define	UID_M_PROPERTIES                        0x000000000000FF01
#define	UID_M_START_SESSION                     0x000000000000FF02
#define	UID_M_SYNC_SESSION                      0x000000000000FF03
#define	UID_M_START_TRUSTED_SESSION             0x000000000000FF04
#define	UID_M_SYNC_TRUSTED_SESSION              0x000000000000FF05
#define	UID_M_CLOSE_SESSION                     0x000000000000FF06

// - Method UIDs (as defined in Core2.0 Table-240)
#define UID_M_DELETE_SP                         0x0000000600000001
#define UID_M_CREATE_TABLE                      0x0000000600000002
#define UID_M_DELETE                            0x0000000600000003
#define UID_M_CREATE_ROW                        0x0000000600000004
#define UID_M_DELETE_ROW                        0x0000000600000005
#define UID_M_GET1                              0x0000000600000006   // defined in Core1.0, obsolete in Core2.0
#define UID_M_SET1                              0x0000000600000007   // defined in Core1.0, obsolete in Core2.0
#define UID_M_NEXT                              0x0000000600000008
#define UID_M_GET_FREESPACE                     0x0000000600000009
#define UID_M_GET_FREEROWS                      0x000000060000000A
#define UID_M_DELETE_METHOD                     0x000000060000000B
#define UID_M_AUTHENTICATE1                     0x000000060000000C   // defined in Core1.0, obsolete in Core2.0
#define UID_M_GET_ACL                           0x000000060000000D
#define UID_M_ADD_ACE                           0x000000060000000E
#define UID_M_REMOVE_ACE                        0x000000060000000F
#define UID_M_GEN_KEY                           0x0000000600000010
#define UID_M_REVERTSP                          0x0000000600000011   // defined in Opal-SSC, marked as "reserved for SSC" in Core2.0
#define UID_M_GET_PACKAGE2                      0x0000000600000012   // defined in Core2.0, to replace Core1.0
#define UID_M_SET_PACKAGE2                      0x0000000600000013   // defined in Core2.0, to replace Core1.0
#define UID_M_GET2                              0x0000000600000016   // defined in Core2.0, to replace Core1.0
#define UID_M_SET2                              0x0000000600000017   // defined in Core2.0, to replace Core1.0
#define UID_M_AUTHENTICATE2                     0x000000060000001C   // defined in Core2.0, to replace Core1.0
#define UID_M_ISSUE_SP                          0x0000000600000201
#define UID_M_REVERT                            0x0000000600000202   // defined in Opal-SSC, marked as "reserved for SSC" in Core2.0
#define UID_M_ACTIVATE                          0x0000000600000203   // defined in Opal-SSC, marked as "reserved for SSC" in Core2.0
#define UID_M_GET_CLOCK                         0x0000000600000401
#define UID_M_RESET_CLOCK                       0x0000000600000402
#define UID_M_SET_CLOCKHIGH                     0x0000000600000403
#define UID_M_SET_LAGHIGH                       0x0000000600000404
#define UID_M_SET_CLOCKLOW                      0x0000000600000405
#define UID_M_SET_LAGLOW                        0x0000000600000406
#define UID_M_INCREMENT_COUNTER                 0x0000000600000407
#define UID_M_RANDOM                            0x0000000600000601
#define UID_M_SALT                              0x0000000600000602
#define UID_M_DECRYPT_INIT                      0x0000000600000603
#define UID_M_DECRYPT                           0x0000000600000604
#define UID_M_DECRYPT_FINALIZE                  0x0000000600000605
#define UID_M_ENCRYPT_INIT                      0x0000000600000606
#define UID_M_ENCRYPT                           0x0000000600000607
#define UID_M_ENCRYPT_FINALIZE                  0x0000000600000608
#define UID_M_HMAC_INIT                         0x0000000600000409
#define UID_M_HAMC                              0x000000060000040A
#define UID_M_HAMC_FINALIZE                     0x000000060000040B
#define UID_M_HASH_INIT                         0x000000060000040C
#define UID_M_HASH                              0x000000060000040D
#define UID_M_HASH_FINALIZE                     0x000000060000040E
#define UID_M_SIGN                              0x000000060000060F
#define UID_M_VERIFY                            0x0000000600000610
#define UID_M_XOR                               0x0000000600000611
#define UID_M_ADD_LOG                           0x0000000600000A01
#define UID_M_CREATE_LOG                        0x0000000600000A02
#define UID_M_CLEAR_LOG                         0x0000000600000A03
#define UID_M_FLUSH_LOG                         0x0000000600000A04
#define UID_M_REACTIVATE                        0x0000000600000801   // defined in Opal-SSC Fixed ACL (Core2.0)
#define UID_M_GET_PACKAGE1                      0x0000000600000801   // defined in Core1.0, obsolete in Core2.0
#define UID_M_SET_PACKAGE1                      0x0000000600000802   // defined in Core1.0, obsolete in Core2.0
#define UID_M_ERASE                             0x0000000600000803   // defined in Ent-SSC, Marble-SSC(MB), and Opal Single-User-Mode spec, marked as "reserved for SSC" in Core2.0
 
// - Authority UIDs (as defined in Core2.0 Table-241)
#define UID_AUT_ANYBODY                         0x0000000900000001
#define UID_AUT_ADMINS                          0x0000000900000002
#define UID_AUT_ADMIN1                          0x0000000900010001   // defined in Opal-SSC & Marble-SSC
#define UID_AUT_LOCKINGSP_ADMIN1                0x0000000900010001   // jls20120316 Opal-SSC1.0
#define UID_AUT_ADMINSP_ADMIN1                  0x0000000900000201   // jls20120316 Opal-SSC2.0
#define UID_AUT_ADMIN2                          0x0000000900010002   // defined in Opal-SSC & Marble-SSC
#define UID_AUT_ADMINSP_ADMIN2                  0x0000000900000202   // jls20120316 Opal-SSC2.0
#define UID_AUT_USERS                           0x0000000900030000   // defined in Opal-SSC & Marble-SSC
#define UID_AUT_USER1                           0x0000000900030001   // defined in Opal-SSC & Marble-SSC
#define UID_AUT_USER2                           0x0000000900030002   // defined in Opal-SSC & Marble-SSC
#define UID_AUT_MAKERS                          0x0000000900000003
#define UID_AUT_MAKERSYMK                       0x0000000900000004
#define UID_AUT_MAKERPUK                        0x0000000900000005
#define UID_AUT_SID                             0x0000000900000006
#define UID_AUT_TPER_SIGN                       0x0000000900000007
#define UID_AUT_TPER_EXCH                       0x0000000900000008
#define UID_AUT_ADMIN_EXCH                      0x0000000900000009
#define UID_AUT_ISSUERS                         0x0000000900000201
#define UID_AUT_EDITORS                         0x0000000900000202
#define UID_AUT_DELETERS                        0x0000000900000203
#define UID_AUT_SERVERS                         0x0000000900000204
#define UID_AUT_RESERVE0                        0x0000000900000205
#define UID_AUT_RESERVE1                        0x0000000900000206
#define UID_AUT_RESERVE2                        0x0000000900000207
#define UID_AUT_RESERVE3                        0x0000000900000208
#define UID_AUT_BANDMASTER0                     0x0000000900008001   // defined in Ent-SSC & Marble-SSC (MB)
#define UID_AUT_BANDMASTER1                     0x0000000900008002   // defined in Ent-SSC & Marble-SSC (MB)
#define UID_AUT_ERASEMASTER                     0x0000000900008401   // defined in Ent-SSC & Marble-SSC (MB)
#define UID_AUT_MSID                            0x0000000900008402
#define UID_AUT_PSID                            0x000000090001FF01   // (Seagate properprietory)
#define UID_AUT_BANDMASTERS                     0x0000000900008403   // defined in Marble-SSC (MB)

// - Single Row Table Row UIDs (as defined in Core2.0 Table-242)
#define UID_SPINFO                              0x0000000200000001
#define UID_TPERINFO_E                          0x0000020100000001
#define UID_TPERINFO_OM                         0x0000020100030001   // defined in Opal/Marble-SSC
#define UID_LOCKINGINFO                         0x0000080100000001
#define UID_MBRCONTROL                          0x0000080300000001

// - Multiple Row Table Row UIDs
#define UID_LOCKING_RANGE0                      0x0000080200000001   // Common to all
#define UID_LOCKING_RANGE1_E                    0x0000080200000002   // Ent-SSC
#define UID_LOCKING_RANGE1_OM                   0x0000080200030001   // Opal-SSC & Marble-SSC
#define UID_K_AES_128_RANGE0                    0x0000080500000001   // Common to all
#define UID_K_AES_128_RANGE1_E                  0x0000080500000002   // Ent-SSC
#define UID_K_AES_128_RANGE1_OM                 0x0000080500030001   // Opal-SSC & Marble-SSC
#define UID_K_AES_256_RANGE0                    0x0000080600000001   // Common to all
#define UID_K_AES_256_RANGE1_E                  0x0000080600000002   // Ent-SSC
#define UID_K_AES_256_RANGE1_OM                 0x0000080600030001   // Opal-SSC & Marble-SSC

// - PIN UIDs
#define UID_C_PIN_SID                           0x0000000B00000001   // common to all
#define UID_C_PIN_MSID                          0x0000000B00008402   // common to all
#define UID_C_PIN_PSID                          0x0000000B0001FF01   // common to all (Seagate proprietary)
#define UID_C_PIN_BANDMASTER0                   0x0000000B00008001   // defined in Ent-SSC & Marble-SSC (MB)
#define UID_C_PIN_BANDMASTER1                   0x0000000B00008002   // defined in Ent-SSC & Marble-SSC (MB)
#define UID_C_PIN_ERASEMASTER                   0x0000000B00008401   // defined in Ent-SSC & Marble-SSC (MB)
#define UID_C_PIN_ADMIN1                        0x0000000B00010001   // defined in Opal-SSC & Marble-SSC (MA)
#define UID_C_PIN_ADMIN2                        0x0000000B00010002   // defined in Opal-SSC & Marble-SSC (MA)
#define UID_C_PIN_USER1                         0x0000000B00030001   // defined in Opal-SSC & Marble-SSC (MA)
#define UID_C_PIN_USER2                         0x0000000B00030002   // defined in Opal-SSC & Marble-SSC (MA)

// - ACE UIDs
#define UID_ACE_LOCKING_RANGE0_GET_RANGESTARTTOACTIVEKEY  0x000000080003D000
#define UID_ACE_LOCKING_RANGE1_GET_RANGESTARTTOACTIVEKEY  0x000000080003D001
#define UID_ACE_LOCKING_RANGE0_SET_RDLOCKED               0x000000080003E000
#define UID_ACE_LOCKING_RANGE1_SET_RDLOCKED               0x000000080003E001
#define UID_ACE_LOCKING_RANGE0_SET_WRLOCKED               0x000000080003E800
#define UID_ACE_LOCKING_RANGE1_SET_WRLOCKED               0x000000080003E801
#define UID_ACE_MBRCONTROL_ADMINS_SET                     0x000000080003F800
#define UID_ACE_MBRCONTROL_SET_DONE                       0x000000080003F801
#define UID_ACE_DATASTORE1_GET_ALL                        0x000000080003FC00
#define UID_ACE_DATASTORE1_SET_ALL                        0x000000080003FC01

// - Half-UIDs
#define HALFUID_AUTHORITY_REF                   0x00000C05
#define HALFUID_BOOLEAN_ACE                     0x0000040E

// - Seagate proprietary, defined in IV specs
#define UID__PORTLOCKING_DIAGNOSTIC             0x0001000200010001   //jls20120229 (Seagate Diagnostic Port)
#define UID__PORTLOCKING_FWDOWNLOAD             0x0001000200010002
#define UID__PORTLOCKING_SECURE_UDS             0x0001000200010003   //jls20120229
#define UID__PORTLOCKING_CHANGEDEF              0x0001000200010005   //jls20120229
#define UID__PORTLOCKING_DCO                    0x000100020001000D   //jls20120229
#define UID__PORTLOCKING_CSFWDOWNLOAD           0x000100020001000E   //jls20121002 (Seagate internal configuration port)

//
// TCG Tokens
//

// Atom Tokens - TINY
#define TOKEN_TYPE_TINY              0x00        // Bit 7 : 0xxxxxxx
#define TOKEN_MASK_TINY_TYPE         0x80        // Bit 7
#define TOKEN_MASK_TINY_SIGN         0x40        // Bit 6
#define TOKEN_MASK_TINY_DATA         0x3F        // Bit 5-0 (range: 0-63 for unsigned, and -32 to 31 for signed)
#define TOKEN_MASK_TINY_DATA_MSB     0x20        // Bit 5 (sign bit for signed value)
#define TOKEN_MASK_TINY_DATA_NEG     0xC0        // Bit 7-6

// Atom Tokens - SHORT
#define TOKEN_TYPE_SHORT             0x80        // Bit 7-6 : 10xxxxxx
#define TOKEN_MASK_SHORT_TYPE        0xC0        // Bit 7-6
#define TOKEN_MASK_SHORT_BYTE        0x20        // Bit 5
#define TOKEN_MASK_SHORT_SIGN        0x10        // Bit 4
#define TOKEN_MASK_SHORT_SIZE        0x0F        // Bit 3-0 (0-15 bytes of data to follow, where, 0-sized means zero of value, header only)

// Atom Tokens - MEDIUM
#define TOKEN_TYPE_MEDIUM            0xC0        // Bit 7-5 : 110xxxxx
#define TOKEN_MASK_MEDIUM_TYPE       0xE0        // Bit 7-5
#define TOKEN_MASK_MEDIUM_BYTE       0x10        // Bit 4
#define TOKEN_MASK_MEDIUM_SIGN       0x08        // Bit 3
#define TOKEN_MASK_MEDIUM_SIZE       0x07FF      // Bit 2-0 + Byte1 (11-bit representing 1-2047 bytes of data to follow)

// Atom Tokens - LONG
#define TOKEN_TYPE_LONG              0xE0        // Bit 7-4 : 1110xxxx
#define TOKEN_MASK_LONG_TYPE         0xF0        // Bit 7-4
#define TOKEN_MASK_LONG_BYTE         0x02        // Bit 1
#define TOKEN_MASK_LONG_SIGN         0x01        // Bit 0
#define TOKEN_MASK_LONG_SIZE         0x00FFFFFF  // Byte 1-3 (2-0,range: 1-16,777,215 bytes of data to follow)

// Compound Tokens
#define TOKEN_TYPE_START_LIST        0xF0
#define TOKEN_TYPE_END_LIST          0xF1
#define TOKEN_TYPE_START_NAME        0xF2
#define TOKEN_TYPE_END_NAME          0xF3

// Control Tokens
#define TOKEN_TYPE_CALL              0xF8
#define TOKEN_TYPE_END_OF_DATA       0xF9
#define TOKEN_TYPE_END_OF_SESSION    0xFA
#define TOKEN_TYPE_START_TRANSACTION 0xFB
#define TOKEN_TYPE_END_TRANSACTION   0xFC
#define TOKEN_TYPE_EMPTY             0xFF

// FDE Drive Security Life Cycle State
#define FDE_SETUP                    0x00
#define FDE_FAILED                   0xFF
#define FDE_DIAGNOSTICS              0x01
#define FDE_USE                      0x80
#define FDE_MANUFACTURING            0x81

//securtiy state control
#define SECURITY_STATE_CONTROL      0x0001000300000000

//=================================
// typedefs
//=================================
typedef tUINT8*  PUINT8;
typedef tUINT64* PUINT64;
typedef tUINT8   TCG_STATUS;
typedef tUINT64  TCG_UID;
typedef std::vector< TCG_UID > TCG_UIDs;
typedef std::vector< int > TCG_BANDNOs;
typedef std::vector< tUINT64 > UINT64VALs;

//=================================
// enums
//=================================
enum TCGStatus              // TCG Status values
{
   TS_SUCCESS                       = 0x00,
   TS_NOT_AUTHORIZED                = 0x01,
   TS_SP_READ_ONLY                  = 0x02,  // Marked as 'Obsolete' in CS2.0
   TS_SP_BUSY                       = 0x03,
   TS_SP_FAILED                     = 0x04,
   TS_SP_DISABLED                   = 0x05,
   TS_SP_FROZEN                     = 0x06,
   TS_NO_SESSION_AVAILABLE          = 0x07,
   TS_INDEX_CONFLICT                = 0x08,
   TS_INSUFFICIENT_SPACE            = 0x09,
   TS_INSUFFICIENT_ROWS             = 0x0A,
   TS_INVALID_COMMAND               = 0x0B,
   TS_INVALID_PARAMETER             = 0x0C,
   TS_INVALID_REFERENCE             = 0x0D,  // Marked as 'Obsolete' in CS2.0
   TS_INVALID_SECMSG_PROPERTIES     = 0x0E,  // Marked as 'Obsolete' in CS2.0
   TS_TPER_MALFUNCTION              = 0x0F,
   TS_TRANSACTION_FAILURE           = 0x10,
   TS_RESPONSE_OVERFLOW             = 0x11,
   TS_AUTHORITY_LOCKED_OUT          = 0x12,
   TS_FAIL                          = 0x3F,

   TS_DTL_ERROR                     = 0xFF  // This gives an error code for failure within the DTL layer.
};

enum etSPLifeCycleState
{
   evIssued                         = 0x00,
   evIssued_Disabled                = 0x01,
   evIssued_Frozen                  = 0x02,
   evIssued_Disabled_Frozen         = 0x03,
   evIssued_Failed                  = 0x04,
   // 5-7 unsigned
   evManufactured_Inactive          = 0x08,
   evManufactured                   = 0x09,
   evManufactured_Disabled          = 0x0A,
   evManufactured_Frozen            = 0x0B,
   evManufactured_Disabled_Frozen   = 0x0C,
   evManufactured_Failed            = 0x0D
   // 14-15 unsigned
};

enum etComIDState
{
   evINVALID                        = 0x00,
   evINACTIVE                       = 0x01,
   evISSUED                         = 0x02,
   evASSOCIATED                     = 0x03
};

enum etSetParameter
{
   evWhere                          = 0x00,
   evValues                         = 0x01
};

enum etCellBlock
{
   evTable                          = 0x00,
   evStartRow                       = 0x01,
   evEndRow                         = 0x02,
   evStartColumn                    = 0x03,
   evEndColumn                      = 0x04
};

enum etBooleanACE
{
   evAnd                            = 0x00,
   evOr                             = 0x01,
   evNot                            = 0x02,
};

enum CryptoAlgorithms
{
   CALGO_3DES_ECB                   = 0x00,
   CALGO_3DES_CBC                   = 0x01,
   CALGO_DES_ECB                    = 0x02,
   CALGO_DES_CBC                    = 0x03,
   CALGO_RSA_512                    = 0x04,
   CALGO_RSA_768                    = 0x05,
   CALGO_RSA_1024                   = 0x06,
   CALGO_RSA_2048                   = 0x07,
   CALGO_AES_ECB_128                = 0x08,
   CALGO_AES_CBC_128                = 0x09,
   CALGO_AES_ECB_192                = 0x0A,
   CALGO_AES_CBC_192                = 0x0B,
   CALGO_AES_ECB_256                = 0x0C,
   CALGO_AES_CBC_256                = 0x0D
};

#endif // TCGVALUES_DOT_H
