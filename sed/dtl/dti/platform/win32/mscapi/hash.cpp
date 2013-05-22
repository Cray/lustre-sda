/*! \file hash.cpp
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

//=================================
// Include files
//=================================
#include "hash.h"

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
// Code
//=================================

/// Adds data to be hashes.  Usually, an application
/// will call AddHashData() one or more times and then
/// call GetHashResult() to retrieve the hashed buffer.
/// This method mostly wraps the CryptoAPI method
/// CryptHashData() appropriately.
///
/// Error Handling : Throws a CException on error.
void MSCAPI::CHash::AddHashData( const MSCAPI::Data& data )
{
   WIN32EX_CHECK_TRUE(
      CryptHashData(m_hash,data.Ptr(),data.Count(), 0)
   );
}

/// Returns the hash result.  Usually, an application
/// will call AddHashData() one or more times and then
/// call GetHashResult() to retrieve the hashed buffer.
///
/// Error Handling : Throws a CException on error.
MSCAPI::Data MSCAPI::CHash::GetHashResult()
{
   DWORD len = sizeof(DWORD);
   WIN32EX_CHECK_TRUE(
      CryptGetHashParam(m_hash,HP_HASHSIZE,NULL,&len,0)
      );

   // Determine the actual necessary data size.  Why
   // (and if) HP_HASHSIZE above is necessary is unclear
   // based on the MS documentation.
   WIN32EX_CHECK_TRUE(
      CryptGetHashParam(m_hash,HP_HASHVAL,NULL,&len,0)
      );

   // Allocate the buffer for the hashed data.
   MSCAPI::Data data( len );

   // And go get the actual result!
   WIN32EX_CHECK_TRUE(
      CryptGetHashParam(m_hash,HP_HASHVAL,data,&len,0)
      );

   return data;
}

/// Releases the current key resources.
///
/// Error Handling : Throws a CException on error.
void MSCAPI::CHash::Release()
{
   const HCRYPTHASH hash( m_hash );
   m_hash = NULL;

   BOOL success = TRUE;
   DWORD error  = ERROR_SUCCESS;

   if ( hash )
   {
      // We can't throw on error right here because we
      // want to release the context after attempting
      // to destroy the key, regardless of success or
      // failure.  It means we can't use our handy-
      // dandy macros, but such is the price of accuracy.
      success = CryptDestroyHash( hash );
      if (!success)
      {
         error = GetLastError();
      }
   }

   m_context.Release();

   if ( !success )
   {
      WIN32EX_CHECK_DWORD( error,
         _T("CryptDestroyHash()")
         );
   }
}

//------------------------------------------------------
// Constructor / destructor / operators
//------------------------------------------------------

/// Constructor for non-keyed hashes.  This is mostly 
/// a wrapper around CryptoAPI's CryptCreateHash() 
/// function.
///
/// Error Handling : Throws a CException on error.
MSCAPI::CHash::CHash( const MSCAPI::CContext prov, 
            ALG_ID Algid,  // default: CALG_SHA1
            DWORD  dwFlags // default: 0
            )
: m_hash( 0 ), m_context( prov )
{
   WIN32EX_CHECK_TRUE(
      CryptCreateHash(prov,Algid,0,dwFlags,&m_hash)
      );
}

/// Constructor for keyed hashes.  This is mostly 
/// a wrapper around CryptoAPI's CryptCreateHash() 
/// function.
///
/// Error Handling : Throws a CException on error.
MSCAPI::CHash::CHash( const MSCAPI::CKey &key, 
            ALG_ID Algid,  // default: CALG_SHA1
            DWORD  dwFlags // default: 0
            )
: m_hash( 0 ), m_context( key.GetContext() )
{
   HCRYPTPROV prov( m_context );
   WIN32EX_CHECK_TRUE(
      CryptCreateHash(prov,Algid,key,dwFlags,&m_hash)
      );
}

/// Default destructor.  This will ensure that the context
/// resources are released back to Windows when this object
/// goes out of scope.
///
/// Error Handling : Errors, if any, are ignored.
MSCAPI::CHash::~CHash()
{
   try
   {
      Release();
   }
   catch( MSCAPI::CException& e )
   {
      // A failure to release a key is *bad*, but there
      // is really very little we can do.  As a result,
      // ignore any error.
      DWORD   err    = e.Error();
      LPCTSTR call   = e.Call();
      LPCTSTR method = e.Method();
   }
}
