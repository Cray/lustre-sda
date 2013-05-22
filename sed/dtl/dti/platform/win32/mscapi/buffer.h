/*! \file buffer.h
    \brief Simple class that deals with safely allocating and clearing
           byte buffers used by crypto functions.

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

#ifndef __MSCAPI_BUFFER_DOT_H__
#define __MSCAPI_BUFFER_DOT_H__
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

//=================================
// Class definitions
//=================================
namespace MSCAPI {

/// A simple class that deals with buffers used in crypto
/// functions.  CryptoAPI does not require this, per se, but
/// it is important to reduce the chance of an attacker being
/// able to scan free memory and discover key material or 
/// other sensitive information easily.
class CBuffer
{
public:
   //------------------------------------------------------
   // Methods in alphabetical order.
   //------------------------------------------------------

   /// Allocates a buffer of requested size.  It will safely 
   /// free any previous buffer allocation prior to 
   /// allocating the requested memory.
   ///
   /// Error Handling : Throws a CException on error.
   void Allocate( size_t bytes );

   /// Erases the contents of the current memory buffer.
   ///
   /// Error Handling : Throws a CException on error.
   void Erase();

   /// Returns a boolean indicating if the buffer is currently
   /// valid.  'Valid' is defined as a buffer that is both
   /// allocated and has length.
   ///
   /// Error Handling : None needed.
   bool IsValid() const;

   /// A simple function just to inline casting of the buffer
   /// as necessary.
   template < class T > T* Ptr() const { return (T*)m_buf; }

   /// Releases the current memory buffer, after first ensuring
   /// any contents are cleared.
   ///
   /// Error Handling : Throws a CException on error.
   void Release();

   /// Returns current buffer size.  Zero is returned if
   /// no buffer is currently allocated.
   ///
   /// Error Handling : None needed.
   size_t Size() const;

   //------------------------------------------------------
   // Constructor / destructor / operators
   //------------------------------------------------------

   /// Default constructor.  It creates an object without
   /// any buffer memory being allocated.
   ///
   /// Error Handling : Throws a CException on error.
   CBuffer();

   /// Constructor with initial allocation size in bytes.
   ///
   /// Error Handling : Throws a CException on error.
   CBuffer( size_t bytes );

   /// Default destructor.  This will ensure that any
   /// memory allocated is both first cleared and then
   /// released back to the OS.
   ///
   /// Error Handling : Errors ignored.
   ~CBuffer();

   operator UINT8*() { return Ptr<UINT8>(); }
   //------------------------------------------------------
   // Member variables.
   //------------------------------------------------------
private:
   HLOCAL m_buf;
   size_t m_size;
};

}      // namespace MSCAPI
#endif // __MSCAPI_BUFFER_DOT_H__
