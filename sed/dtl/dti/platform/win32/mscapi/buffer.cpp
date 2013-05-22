/*! \file buffer.cpp 
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

//=================================
// Include files
//=================================
#include "buffer.h"

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

//------------------------------------------------------
// Methods in alphabetical order.
//------------------------------------------------------

/// Allocates a buffer of requested size.  It will safely 
/// free any previous buffer allocation prior to 
/// allocating the requested memory.
///
/// Error Handling : Throws a CException on error.
void MSCAPI::CBuffer::Allocate( size_t bytes )
{
   Release();
   HLOCAL buf = LocalAlloc( LPTR, bytes );
   if ( !buf )
   {
      WIN32EX_CHECK_ERROR( _T("LocalAlloc") );
   }
   m_buf  = buf;
   m_size = bytes;
}

/// Erases the contents of the current memory buffer.
///
/// Error Handling : Throws a CException on error.
void MSCAPI::CBuffer::Erase()
{
   if ( IsValid() )
   {
      SecureZeroMemory( m_buf, m_size );
   }
}

/// Returns a boolean indicating if the buffer is currently
/// valid.  'Valid' is defined as a buffer that is both
/// allocated and has length.
///
/// Error Handling : None needed.
bool MSCAPI::CBuffer::IsValid() const
{
   return (m_buf && m_size);
}

/// Releases the current memory buffer, after first ensuring
/// any contents are cleared.
///
/// Error Handling : Throws a CException on error.
void MSCAPI::CBuffer::Release()
{
   // Clear things out first.  If an exception happens,
   // then we've already lost the buffer to callers.
   Erase();
   const HLOCAL buf ( m_buf  );
   m_buf = NULL;
   m_size = 0;

   if ( buf )
   {
      WIN32EX_CHECK_FALSE( LocalFree( buf ) );
   }
}

/// Returns current buffer size.  Zero is returned if
/// no buffer is currently allocated.
///
/// Error Handling : None needed.
size_t MSCAPI::CBuffer::Size() const
{
   return IsValid() ? m_size : 0;
}

//------------------------------------------------------
// Constructor / destructor / operators
//------------------------------------------------------

/// Default constructor.  It creates an object without
/// any buffer memory being allocated.
///
/// Error Handling : Throws a CException on error.
MSCAPI::CBuffer::CBuffer( )
: m_buf( NULL )
, m_size( 0 )
{
}


/// Constructor with initial allocation size in bytes.
///
/// Error Handling : Throws a CException on error.
MSCAPI::CBuffer::CBuffer( size_t bytes )
: m_buf( NULL )
, m_size( 0 )
{
   Allocate( bytes );
}

/// Default destructor.  This will ensure that any
/// memory allocated is both first cleared and then
/// released back to the OS.
///
/// Error Handling : Errors ignored.
MSCAPI::CBuffer::~CBuffer()
{
   // A failure to release a context is *bad*, but there
   // is really very little we can do.  As a result,
   // ignore any error.
   try
   {
      Release();
   }
   catch ( DWORD /*error*/ )
   {
   }
}