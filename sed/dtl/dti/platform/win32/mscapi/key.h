/*! \file key.h
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

#ifndef __MSCAPI_KEY_DOT_H__
#define __MSCAPI_KEY_DOT_H__
//=================================
// Include files
//=================================
#include "context.h"
#include <rcarray.h> // reference counted arrays, useful for buffers.

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

typedef rcarray<BYTE,DWORD> Data;

//=================================
// Class definitions
//=================================

/// Simple class embedding some of the HCRYPTKEY functionality.
class CKey
{
public:
   //------------------------------------------------------
   // Methods in alphabetical order.
   //------------------------------------------------------

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
   void Assign( HCRYPTKEY key, const CContext& context );

   /// Decrypts a buffer.  Makes any lenth adjustments
   /// necessary to the buffers, to make things easy on
   /// the user.
   ///
   /// Return Value: A decrypted copy of the input.
   ///
   /// Error Handling : Throws a CException on error.
   Data Decrypt( const Data& encrypted, bool final=true );

   /// Decrypts a buffer.  This is a wrapper around the
   /// CryptoAPI CryptDecrypt() method.
   ///
   /// Return Value: returns the number of bytes encrypted
   /// or necessary to encrypt the buffer.
   ///
   /// Error Handling : Throws a CException on error.
   DWORD Decrypt( BYTE* data, DWORD dataTotalSize,
      DWORD dataBytesToDecrypt, bool final=true,
      DWORD flags=0, HCRYPTHASH hash=0 );

   /// Encrypts a buffer.  Makes any lenth adjustments
   /// necessary to the buffers, to make things easy on
   /// the user.
   ///
   /// Return Value: An encrypted copy of the input.
   ///
   /// Error Handling : Throws a CException on error.
   Data Encrypt( const Data& unencrypted, bool final=true );

   /// Encrypts a buffer.  This is a wrapper around the
   /// CryptoAPI CryptEncrypt() method.
   ///
   /// Return Value: returns the number of bytes encrypted
   /// or necessary to encrypt the buffer.
   ///
   /// Error Handling : Throws a CException on error.
   DWORD Encrypt( BYTE* pbData, DWORD dataTotalSize,
      DWORD dataBytesToEncrypt, bool final=true,
      DWORD dwFlags=0, HCRYPTHASH hash=0 );

   /// Gets the block size of the cipher.  Internally,
   /// this uses GetParam() to complete the request.
   ///
   /// Return Value: returns the block size for the cipher,
   /// but the value is returned in BYTES, not bits as
   /// preferred by CryptoAPI.
   ///
   /// Error Handling : Throws a CException on error.
   DWORD GetBlockSize() const;

   /// Gets the length of key in bits.  Internally,
   /// this uses GetParam() to complete the request.
   ///
   /// Return Value: returns the length of the key in bits.
   ///
   /// Error Handling : Throws a CException on error.
   DWORD GetKeyLength() const;

   /// Returns the context associated with the key.
   ///
   /// Error Handling : Throws a CException on error.
   const CContext& GetContext() const { return m_context; }

   /// Gets a key parameter.  This is a wrapper around the
   /// CryptoAPI CryptGetKeyParam() method.
   ///
   /// Return Value: returns the number of bytes copied
   /// to the output buffer.  See pdwDataLen in the 
   /// MSDN documentation for more details.
   ///
   /// Error Handling : Throws a CException on error.
   DWORD GetParam( DWORD dwParam, BYTE* pbData,
      DWORD dwDataLen, DWORD dwFlags=0 ) const;

   /// Sets the cipher mode.  Internally, this uses
   /// SetParam() to complete the request.
   ///
   /// Error Handling : Throws a CException on error.
   void SetMode( DWORD dwMode ) const;

   /// Sets a key parameter.  This is a wrapper around the
   /// CryptoAPI CryptSetKeyParam() method.
   ///
   /// Error Handling : Throws a CException on error.
   void SetParam( DWORD dwParam, 
      BYTE* pbData, DWORD dwFlags=0 ) const;

   /// Releases the current key resources.
   ///
   /// Error Handling : Throws a CException on error.
   void Release();

   //------------------------------------------------------
   // Constructor / destructor / operators
   //------------------------------------------------------

   /// Default constructor.  If no context is provided, it will
   /// attempt to acquire or create the default context with
   /// the provided flags.
   ///
   /// Error Handling : Throws a CException on error.
   CKey(); 

   /// Default destructor.  This will ensure that the context
   /// resources are released back to Windows when this object
   /// goes out of scope.
   ///
   /// Error Handling : Errors, if any, are ignored.
   ~CKey();

   operator HCRYPTKEY() const { return m_key; }
private:
   HCRYPTKEY m_key;
   CContext  m_context;
};

}      // namespace MSCAPI
#endif // __MSCAPI_KEY_DOT_H__