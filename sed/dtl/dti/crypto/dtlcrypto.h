/*! \file dtlcrypto.h
    \brief Function definitions for cryptography used in TDT.

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

#ifndef _DTL_CRYPTO_DOT_H_
#define _DTL_CRYPTO_DOT_H_
/*=================================
// Include files
//===============================*/
#include <rcarray.h>

// Include the platform-specific files
#if defined (_WIN32)
#include <../platform/win32/mscapi/buffer.h>
#include <../platform/win32/mscapi/win32helper.h>
#elif defined (__DJGPP)
#include "./platform/dos/buffer.h" // nvn20110616
#elif defined (__linux__)
//#include "./platform/linux32/buffer.h" // nvn20110616
#else
#error "Operating system not defined!"
#endif

#include <dta/common.h>

/*=================================
// Constant definitions             
//===============================*/
#define TRIPLEDES_TWO_KEY_LENGTH 16
#define AES_128_KEY_LENGTH       16
#define AES_192_KEY_LENGTH       24
#define AES_256_KEY_LENGTH       32

#define SHA1_HASH_SIZE           20    /// SHA1 Hash size
#define SHA256_HASH_SIZE         32    /// SHA256 Hash size
#define SHA384_HASH_SIZE         48    /// SHA384 Hash size
#define SHA512_HASH_SIZE         64    /// SHA512 Hash size

#define SHA1_BLOCK_SIZE          64    /// SHA1 Block size
#define SHA256_BLOCK_SIZE        64    /// SHA256 Block size
#define SHA384_BLOCK_SIZE        128   /// SHA384 Block size
#define SHA512_BLOCK_SIZE        128   /// SHA384 Block size

#define DES_BLOCK_SIZE           8
#define TRIPLE_DES_BLOCK_SIZE    8
#define AES_BLOCK_SIZE           16

/*=================================
// Static and external variables                
//===============================*/

enum ePadOptions
{
   PADDING_PKCS7,
   PADDING_PAD_TO_NEXT_BLOCK
};

/*=================================
// Structures and type definitions     
//===============================*/
typedef rcarray<tUINT8> Byte_Array;

/*=================================
// Class & function definitions
//===============================*/

/*=================================
// Code
//===============================*/
namespace DTLCRYPTO
{

   typedef tUINT32   DATA_LENGTH;

   enum eAlgorithm
   {
      ALGO_3DES,
      ALGO_AES,
      ALGO_RSA,
      ALGO_SHA1,
      ALGO_SHA256,
      ALGO_SHA384,
      ALGO_SHA512,
      ALGO_HMACSHA1,
      ALGO_HMACSHA256,
      ALGO_HMACSHA384,
      ALGO_HMACSHA512,
   };


///////////////////////////////////////////////////////////
// CreateHash : abstract the details of creating a hash
// value from a provided hashing key and data buffer.
//
Byte_Array CreateHash( const Byte_Array& data, const tUINT8 algo=DTLCRYPTO::ALGO_SHA1);
Byte_Array CreateHash( const Byte_Array& data, const Byte_Array& key, const tUINT8 algo=DTLCRYPTO::ALGO_HMACSHA256);

class CDTLCrypto
{
public:
    static CDTLCrypto* Create( const tUINT8 *pbKey, bool modeECB=false, eAlgorithm algo=DTLCRYPTO::ALGO_3DES );
    static CDTLCrypto* Create( const tUINT8 *pbKey, eAlgorithm algo=DTLCRYPTO::ALGO_RSA );

   virtual tINT32 Decrypt(
      tUINT8        *unencrypted,
      const tINT32  unencryptedMaxLen,
      const tUINT8  *encrypted,
      const tINT32  encryptedLen,
      ePadOptions padding
      ) = 0;

   virtual tINT32 Encrypt(
      tUINT8        *encrypted,
      const tINT32  encryptedMaxLen,
      const tUINT8  *unencrypted,
      const tINT32  unencryptedLen,
      ePadOptions padding
      ) = 0;

   virtual DATA_LENGTH KeyLength() const = 0;
   virtual DATA_LENGTH BlockSize() const = 0;
   #if defined(_WIN32) // nvn20110616
   virtual void SetCryptoIV( MSCAPI::CBuffer buffer) = 0;
   #else
   //TODO: linux crypto
   #endif

   virtual ~CDTLCrypto() {}
};

//=================================================================================
/// \brief Function for encryption and decrytion 3DES.
///
/// \param key [in]                  Pointer to key array.
/// \param encryptedData [in,out]    Pointer to buffer of encrypted bytes.
/// \param encryptedDataSize [in]    Length of encrypted buffer.
/// \param unencryptedData [in,out]  Pointer to buffer of encrypted bytes.
/// \param unencryptedDataSize [in]  Length of encrypted buffer.
/// \param encrypt [in]              Determines whether to encrypt or decrypt.
/// \param modeECB [in]              Set whether to use ECB or CBC.
///
//=================================================================================
tINT32 crypt3Des(tUINT8*      key,
                 tUINT8*      encryptedData,
                 tINT32       encryptedDataSize,
                 tUINT8*      unencryptedData,
                 tINT32       unencryptedDataSize,
                 const bool   encrypt,
                 const bool   modeECB=true,
                 tUINT8*      iv=NULL,
                 tINT32       ivSize=0);

//=================================================================================
/// \brief Function for encryption and decrytion AES.
///
/// \param key[in]                  Pointer to key array.
/// \param encryptedData[in,out]    Pointer to buffer of encrypted bytes.
/// \param encryptedDataSize[in]    Length of encrypted buffer.
/// \param unencryptedData[in,out]  Pointer to buffer of encrypted bytes.
/// \param unencryptedDataSize[in]  Length of encrypted buffer.
/// \param encrypt[in]              Determines whether to encrypt or decrypt.
/// \param modeECB[in]              Set whether to use ECB or CBC.
/// \param bitSize[in]              AES algorithm selection for bit size (i.e. 128, 192, etc)
/// \param iv[in]                   Initialization vector.
/// \param ivSize[in]               Initialization vector length.
///
//=================================================================================
tINT32 cryptAes( tUINT8*      key,
                 tUINT8*      encryptedData,
                 tINT32       encryptedDataSize,
                 tUINT8*      unencryptedData,
                 tINT32       unencryptedDataSize,
                 const bool   encrypt,
                 const bool   modeECB=true,
                 tUINT16      bitSize=128,
                 tUINT8*      iv=NULL,
                 tINT32       ivSize=0);

//=================================================================================
/// \brief Function for encryption and decrytion RSA.
///
/// \param key[in]                  Pointer to key array.
/// \param encryptedData[in,out]    Pointer to buffer of encrypted bytes.
/// \param encryptedDataSize[in]    Length of encrypted buffer.
/// \param unencryptedData[in,out]  Pointer to buffer of encrypted bytes.
/// \param unencryptedDataSize[in]  Length of encrypted buffer.
/// \param encrypt[in]              Determines whether to encrypt or decrypt.
/// \param bitSize[in]              AES algorithm selection for bit size (i.e. 128, 192, etc)
/// \param iv[in]                   Initialization vector.
/// \param ivSize[in]               Initialization vector length.
///
//=================================================================================
tINT32 cryptRsa( tUINT8*      key,
                 tUINT8*      encryptedData,
                 tINT32       encryptedDataSize,
                 tUINT8*      unencryptedData,
                 tINT32       unencryptedDataSize,
                 const bool   encrypt,
                 tUINT16      bitSize=1024,
                 tUINT8*      iv=NULL,
                 tINT32       ivSize=0);

} // end namespace DTLCRYPTO
#endif // #ifndef _DTL_CRYPTO_DOT_H_
