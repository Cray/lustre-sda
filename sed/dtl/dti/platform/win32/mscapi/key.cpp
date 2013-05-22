/*! \file key.cpp
    \brief Simple class embedding some of the HCRYPTKEY functionality.

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

/// Assigns the associated HCRYPTKEY to this object.
/// Primarily this means that the CKey object will use
/// this handle and destroy the handle when the object
/// goes out of scope ( using Release() ).
///
/// Note that Assign() is allowed when a valid key has
/// already been Assign()ed, but the previous key will
/// be closed before the new assignment is made.
///
/// Error Handling : Throws a CException on error.
void MSCAPI::CKey::Assign( HCRYPTKEY key, const MSCAPI::CContext& context )
{
   Release();
   m_context = context;
   m_key = key;
}

/// Decrypts a buffer.  Makes any lenth adjustments
/// necessary to the buffers, to make things easy on
/// the user.
///
/// Return Value: A decrypted copy of the input.
///
/// Error Handling : Throws a CException on error.
MSCAPI::Data MSCAPI::CKey::Decrypt( 
                                   const MSCAPI::Data& encrypted, 
                                   bool final )
{
   MSCAPI::Data result( encrypted.Count() );

   CopyMemory( result.Ptr(), encrypted.Ptr(), 
      encrypted.Count() );

   DWORD len = Decrypt( result, result.Count(), 
                  encrypted.Count(), final );

   return result.Mid( 0, len );
}

/// Decrypts a buffer.  This is a wrapper around the
/// CryptoAPI CryptDecrypt() method.
///
/// Return Value: returns the number of bytes encrypted
/// or necessary to encrypt the buffer.
///
/// Error Handling : Throws a CException on error.
DWORD MSCAPI::CKey::Decrypt( 
                            BYTE* data, 
                            DWORD dataTotalSize,
                            DWORD dataBytesToDecrypt,
                            bool final,     // defaults to true
                            DWORD flags,  // defaults to 0
                            HCRYPTHASH hash // defaults to 0
                           )
{
   DWORD len  = dataBytesToDecrypt;
   BOOL  pad  = final ? TRUE : FALSE;

   WIN32EX_CHECK_TRUE(
      CryptDecrypt(m_key,hash,pad,flags,data,&len)
      );

   return len;
}

/// Encrypts a buffer.  Makes any lenth adjustments
/// necessary to the buffers, to make things easy on
/// the user.
///
/// Return Value: An encrypted copy of the input.
///
/// Error Handling : Throws a CException on error.
MSCAPI::Data MSCAPI::CKey::Encrypt( 
                                   const MSCAPI::Data& unencrypted, 
                                   bool final )
{
   MSCAPI::Data result( unencrypted.Count() + GetBlockSize() );

   CopyMemory( result.Ptr(), unencrypted.Ptr(), 
      unencrypted.Count() );

   DWORD len = Encrypt( result, result.Count(), 
                  unencrypted.Count(), final );

   return result.Mid( 0, len );
}

/// Encrypts a buffer.  This is a wrapper around the
/// CryptoAPI CryptEncrypt() method.
///
/// Return Value: returns the number of bytes encrypted
/// or necessary to encrypt the buffer.
///
/// Error Handling : Throws a CException on error.
DWORD MSCAPI::CKey::Encrypt( 
                            BYTE* data, 
                            DWORD dataTotalSize,
                            DWORD dataBytesToEncrypt,
                            bool final,     // defaults to true
                            DWORD flags,  // defaults to 0
                            HCRYPTHASH hash // defaults to 0
                           )
{
   DWORD len  = dataBytesToEncrypt;
   BOOL  pad  = final ? TRUE : FALSE;

   WIN32EX_CHECK_TRUE(
      CryptEncrypt(m_key,hash,pad,flags,data,&len,dataTotalSize)
      );

   return len;
}

/// Gets the block size of the cipher.  Internally,
/// this uses GetParam() to complete the request.
///
/// Return Value: returns the block size for the cipher,
/// but the value is returned in BYTES, not bits as
/// preferred by CryptoAPI.
///
/// Error Handling : Throws a CException on error.
DWORD MSCAPI::CKey::GetBlockSize() const
{
   DWORD blockSize = 0;
   GetParam( KP_BLOCKLEN, (BYTE*)&blockSize, sizeof(blockSize), 0 );
   return blockSize / 8;
}

DWORD MSCAPI::CKey::GetKeyLength() const
{
   DWORD keyLength = 0;
   GetParam( KP_KEYLEN, (BYTE*)&keyLength, sizeof(keyLength), 0 );
   return keyLength;
}

/// Gets a key parameter.  This is a wrapper around the
/// CryptoAPI CryptGetKeyParam() method.
///
/// Return Value: returns the number of bytes copied
/// to the output buffer.  See pdwDataLen in the 
/// MSDN documentation for more details.
///
/// Error Handling : Throws a CException on error.
DWORD MSCAPI::CKey::GetParam( DWORD dwParam, 
                              BYTE* pbData,
                              DWORD dwDataLen, 
                              DWORD dwFlags
                            ) const
{
   DWORD len = dwDataLen;
   WIN32EX_CHECK_TRUE(
      CryptGetKeyParam(m_key,dwParam,pbData,&len,dwFlags)
      );
   return len;
}


/// Releases the current key resources.
///
/// Error Handling : Throws a CException on error.
void MSCAPI::CKey::Release()
{
   const HCRYPTKEY key( m_key );
   m_key = NULL;

   BOOL success = TRUE;
   DWORD error  = ERROR_SUCCESS;

   if ( key )
   {
      // We can't throw on error right here because we
      // want to release the context after attempting
      // to destroy the key, regardless of success or
      // failure.  It means we can't use our handy-
      // dandy macros, but such is the price of accuracy.
      success = CryptDestroyKey( key );
      if (!success)
      {
         error = GetLastError();
      }
   }

   m_context.Release();

   if ( !success )
   {
      WIN32EX_CHECK_DWORD( error,
         _T("CryptDestroyKey()")
         );
   }
}

/// Sets the cipher mode.  Internally, this uses
/// SetParam() to complete the request.
///
/// Error Handling : Throws a CException on error.
void MSCAPI::CKey::SetMode( DWORD dwMode ) const
{
   SetParam( KP_MODE, (PBYTE)&dwMode );
}

/// Sets a key parameter.  This is a wrapper around the
/// CryptoAPI CryptSetKeyParam() method.
///
/// Error Handling : Throws a CException on error.
void MSCAPI::CKey::SetParam( DWORD dwParam, 
   BYTE* pbData, DWORD dwFlags ) const
{
   WIN32EX_CHECK_TRUE(
      CryptSetKeyParam(m_key,dwParam,pbData,dwFlags)
      );
}

//------------------------------------------------------
// Constructor / destructor / operators
//------------------------------------------------------

/// Default constructor.  If no context is provided, it will
/// attempt to acquire or create the default context with
/// the provided flags.
///
/// Error Handling : Throws a CException on error.
MSCAPI::CKey::CKey( )
: m_key( 0 )
{
}

/// Default destructor.  This will ensure that the context
/// resources are released back to Windows when this object
/// goes out of scope.
///
/// Error Handling : Errors, if any, are ignored.
MSCAPI::CKey::~CKey()
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