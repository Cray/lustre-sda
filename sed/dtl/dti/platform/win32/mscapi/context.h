/*! \file context.h
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

#ifndef __MSCAPI_CONTEXT_DOT_H__
#define __MSCAPI_CONTEXT_DOT_H__
//=================================
// Include files
//=================================
#include <windows.h>
#include "win32ex.h"

//=================================
// Constant definitions
//=================================

//=================================
// Static and external variables
//=================================

//=================================
// Structures and type definitions
//=================================
namespace MSCAPI {

// The CContext class needs its data reference counted.
// This is because all key objects created from the 
// context *MUST* be destroyed before the context
// itself can be destroyed.
typedef struct _CONTEXTINFO
{
   size_t     refCount;
   HCRYPTPROV prov;
} CONTEXTINFO;

//=================================
// Class definitions
//=================================

// Forward reference to the MSCAPI::CKey object.  This
// object is properly defined in mscapi/key.h
class CKey;

/// A simple wrapper class around a default HCRYPTPROV.
/// This class will take care of necessary steps to acquire
/// and release contexts for the user, so that the user
/// does not have to think about the details.
class CContext
{
public:
   //------------------------------------------------------
   // Methods in alphabetical order.
   //------------------------------------------------------

   /// Wrapper around CryptoAPI's CryptGetUserKey().  It
   /// also may create the key pair if requested to do so.
   ///
   /// Error Handling : Throws a CException on error.
   void GetUserKey( CKey& key, DWORD keySpec,
      bool createIfNotFound = true, DWORD createFlags=0 ) const;

   /// Wrapper around CryptoAPI's CryptImportKey().
   ///
   /// Error Handling : Throws a CException on error.
   void ImportKey( CKey& newKey, BYTE* pbData,
      DWORD dwDataLen, const CKey& pubKey, DWORD dwFlags=0 ) const;

   /// Releases the current context resources.
   ///
   /// Error Handling : Throws a CException on error.
   void Release();

   //------------------------------------------------------
   // Constructor / destructor / operators
   //------------------------------------------------------

   /// Default constructor.  Does not allocate a crypto context.
   CContext();

   /// Constructor.  Attempt to acquire or create the 
   /// default context with the provided flags.
   ///
   /// Constructor parameters directly correspond to the
   /// same parameters in Microsoft's CryptAcquireContext()
   /// API call.  Consult MSDN for details.
   ///
   /// Error Handling : Throws a CException on error.
   CContext( 
      LPCTSTR pszContainer,
      LPCTSTR pszProvider  = NULL/*MS_ENHANCED_PROV*/,
      DWORD   dwProvType   = PROV_RSA_AES,
      DWORD   dwFlags      = CRYPT_VERIFYCONTEXT
      );

   /// Copy constructor.
   ///
   /// Error Handling : Throws a CException on error.
   CContext( const CContext& two );

   /// Default destructor.  This will ensure that the context
   /// resources are released back to Windows when this object
   /// goes out of scope.
   ///
   /// Error Handling : Errors, if any, are ignored.
   ~CContext();

   /// Assignment operator.  Used by the copy constructor.
   ///
   /// Error Handling : Throws a CException on error.
   CContext& operator= ( const CContext& two );

   operator HCRYPTPROV() const
   { return m_ctx ? m_ctx->prov : NULL; }
private:
   CONTEXTINFO *m_ctx;
};

} // namespace MSCAPI
#endif