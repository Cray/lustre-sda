/*! \file context.cpp
    \brief Simple wrapper class around the HCRYPTPROV handle.

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
// Code
//=================================
MSCAPI::CContext::CContext( )
: m_ctx( NULL )
{
}

MSCAPI::CContext::CContext( 
      LPCTSTR pszContainer,
      LPCTSTR pszProvider, 
      DWORD   dwProvType,
      DWORD   dwFlags
      )
: m_ctx( NULL )
{
   HCRYPTPROV prov = NULL;

   BOOL success = CryptAcquireContext( &prov, pszContainer, 
      pszProvider, dwProvType, dwFlags);

   // If the following are all true:
   // 1) We couldn't acquire a context.
   // 2) The flags were not set to allow creation of a context.
   // 3) The error code is consistent with a keyset-not-found.
   // Then we try again, allowing the keyset to be created.
   if (  !success 
      && !(dwFlags & CRYPT_NEWKEYSET)
      && ( NTE_BAD_KEYSET ==GetLastError() )
      )
   {
      dwFlags |= CRYPT_NEWKEYSET;
      success = CryptAcquireContext( &prov, pszContainer, 
         pszProvider, dwProvType, dwFlags);
   }

   if ( !success )
   {
      WIN32EX_CHECK_ERROR( _T("CryptAcquireContext()") );
   }

   // We're creating a context : allocate the structure.
   m_ctx = new CONTEXTINFO;
   ZeroMemory( m_ctx, sizeof(CONTEXTINFO) );
   m_ctx->refCount = 1;
   m_ctx->prov = prov;

}

MSCAPI::CContext::CContext( const MSCAPI::CContext& two )
: m_ctx( NULL )
{
   *this = two;
}

MSCAPI::CContext::~CContext()
{
   try
   {
      Release();
   }
   catch( MSCAPI::CException& e)
   {
      // A failure to release a context is *bad*, but there
      // is really very little we can do.  As a result,
      // ignore any error.
      DWORD   err    = e.Error();
      LPCTSTR call   = e.Call();
      LPCTSTR method = e.Method();
   }
}

MSCAPI::CContext& MSCAPI::CContext::operator=( const MSCAPI::CContext& two )
{
   Release();
   if ( two.m_ctx )
   {
      two.m_ctx->refCount++;
      m_ctx = two.m_ctx;
   }
   return *this;
}

/// Wrapper around CryptoAPI's CryptGetUserKey().  It
/// also may create the key pair if requested to do so.
///
/// Error Handling : Throws a CException on error.
void MSCAPI::CContext::GetUserKey( 
                                  MSCAPI::CKey& key, 
                                  DWORD keySpec,
                                  bool createIfNotFound, 
                                  DWORD createFlags
                                 ) const
{
   HCRYPTKEY hKey = NULL;
   LPCTSTR win32call = _T("CryptGetUserKey()");
   BOOL success = CryptGetUserKey( *this, keySpec, &hKey );
   if ( ( !success )                      // We failed
      && ( NTE_NO_KEY == GetLastError() ) // and it's because there was no key
      && createIfNotFound                 // and we're allowed to create
      && ( AT_SIGNATURE == keySpec  ||    // and the keySpec is known to
         AT_KEYEXCHANGE == keySpec )      // be valid to CryptGenKey()
      )
   {
      win32call = _T("CryptGenKey()");
      success = CryptGenKey( *this, keySpec, createFlags, &hKey );
   }

   if ( !success )
   {
      WIN32EX_CHECK_ERROR( win32call );
   }

   key.Assign( hKey, *this );
}

/// Wrapper around CryptoAPI's CryptImportKey().
///
/// Error Handling : Throws a CException on error.
void MSCAPI::CContext::ImportKey( MSCAPI::CKey& newKey, BYTE* pbData,
   DWORD dwDataLen, const CKey& pubKey, DWORD dwFlags ) const
{
   HCRYPTKEY key;
   WIN32EX_CHECK_TRUE(
      CryptImportKey(*this,pbData,dwDataLen,pubKey,dwFlags,&key)
      );
   newKey.Assign( key, *this );
}

/// Releases the current context resources.
///
/// Error Handling : Throws a CException on error.
void MSCAPI::CContext::Release()
{
   if ( m_ctx )
   {
      MSCAPI::CONTEXTINFO *ctx( m_ctx );
      m_ctx = NULL;

      if ( 0 == --ctx->refCount )
      {
         const HCRYPTPROV prov( ctx->prov );
         delete ctx;

         if ( prov )
         {
            WIN32EX_CHECK_TRUE(
               CryptReleaseContext( prov, 0 )
               );
         }
      }
   }
}
