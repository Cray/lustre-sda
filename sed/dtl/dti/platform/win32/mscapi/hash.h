/*! \file hash.h
    \brief Simple class embedding some of the HCRYPTHASH functionality.

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

#ifndef __MSCAPI_HASH_DOT_H__
#define __MSCAPI_HASH_DOT_H__
//=================================
// Include files
//=================================
#include "key.h"

//=================================
// Constant definitions
//=================================

//=================================
// Static and external variables
//=================================

//=================================
// Structures and type definitions
//=================================

//=================================
// Class definitions
//=================================
namespace MSCAPI {

/// Simple class embedding some of the HCRYPTKEY functionality.
class CHash
{
public:
   //------------------------------------------------------
   // Methods in alphabetical order.
   //------------------------------------------------------

   /// Adds data to be hashes.  Usually, an application
   /// will call AddHashData() one or more times and then
   /// call GetHashResult() to retrieve the hashed buffer.
   /// This method mostly wraps the CryptoAPI method
   /// CryptHashData() appropriately.
   ///
   /// Error Handling : Throws a CException on error.
   void AddHashData( const Data& data );

   /// Returns the hash result.  Usually, an application
   /// will call AddHashData() one or more times and then
   /// call GetHashResult() to retrieve the hashed buffer.
   ///
   /// Error Handling : Throws a CException on error.
   Data GetHashResult();

   /// Releases the current hash resources.
   ///
   /// Error Handling : Throws a CException on error.
   void Release();

   //------------------------------------------------------
   // Constructor / destructor / operators
   //------------------------------------------------------

   /// Constructor for non-keyed hashes.  This is mostly 
   /// a wrapper around CryptoAPI's CryptCreateHash() 
   /// function.
   ///
   /// Error Handling : Throws a CException on error.
   CHash( const CContext context, 
            ALG_ID Algid   = CALG_SHA1,
            DWORD  dwFlags = 0
            ); 

   /// Constructor for keyed hashes.  This is mostly 
   /// a wrapper around CryptoAPI's CryptCreateHash() 
   /// function.
   ///
   /// Error Handling : Throws a CException on error.
   CHash( const CKey &key, 
            ALG_ID Algid   = CALG_SHA1,
            DWORD  dwFlags = 0
            ); 

   /// Default destructor.  This will ensure that the context
   /// resources are released back to Windows when this object
   /// goes out of scope.
   ///
   /// Error Handling : Errors, if any, are ignored.
   ~CHash();

   operator HCRYPTHASH() const { return m_hash; }
private:
   HCRYPTHASH m_hash;
   CContext   m_context;
};

}      // namespace MSCAPI
#endif // __MSCAPI_HASH_DOT_H__