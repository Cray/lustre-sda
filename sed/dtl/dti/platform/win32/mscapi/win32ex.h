/*! \file win32ex.h
    \brief Simple exception class used by the MSCAPI classes.

    It wraps the DWORD errors returned from CryptoAPI and the
    function / operation name that triggered the problem.

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

#ifndef __MSCAPI_WIN32EX_DOT_H__
#define __MSCAPI_WIN32EX_DOT_H__
//=================================
// Include files
//=================================
#include <windows.h>
#include <tchar.h>

//=================================
// macro definitions
//=================================
#define WIN32EX_CHECK_TRUE( value )                       \
   if ( ! value )                                         \
   {                                                      \
      throw CException( GetLastError(),                   \
         (LPCTSTR)__FUNCTION__, (LPCTSTR)#value );        \
   }

#define WIN32EX_CHECK_DWORD( value, name )                \
   if ( ERROR_SUCCESS != value )                          \
   {                                                      \
      throw CException( value,                            \
         (LPCTSTR)__FUNCTION__, name );                   \
   }

#define WIN32EX_CHECK_ERROR( name )                       \
   if ( ERROR_SUCCESS != GetLastError() )                 \
   {                                                      \
      throw CException( GetLastError(),                   \
         (LPCTSTR)__FUNCTION__, name );                   \
   }

#define WIN32EX_CHECK_FALSE( value )                      \
   if ( value )                                           \
   {                                                      \
      throw CException( GetLastError(),                   \
         (LPCTSTR)__FUNCTION__, (LPCTSTR)#value );        \
   }

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

/// Simple exception class used by the MSCAPI classes.
/// It wraps the DWORD errors returned from CryptoAPI and the
/// function / operation name that triggered the problem.
class CException
{
public:
   //------------------------------------------------------
   // Methods in alphabetical order.
   //------------------------------------------------------

   /// Returns the Windows error code for the thrown error.
   DWORD Error() const { return m_error; }

   /// Returns the name of the method name that threw the
   /// error.  This may be an empty string if not available.
   LPCTSTR Method() const { return m_method ? m_method : _T(""); }

   /// Returns the name of the related call that caused the
   /// error.  This may be an empty string if not available.
   LPCTSTR Call() const { return m_method ? m_method : _T(""); }

   //------------------------------------------------------
   // Constructor / destructor / operators
   //------------------------------------------------------

   /// Default constructor.  It creates and initializes the
   /// object.  It is usually helpful to use one of the
   /// WIN32EX_*() macros to create the object.
   CException( DWORD error, LPCTSTR method, LPCTSTR call )
      : m_error(error), m_method(method), m_call(call)
   {
   }

   /// Copy constructor.
   CException( const CException& two )
      : m_error( two.m_error ) 
      , m_method( two.m_method )
      , m_call ( two.m_call )
   {
   }
   //------------------------------------------------------
   // Member variables.
   //------------------------------------------------------
private:
   DWORD   m_error;
   LPCTSTR m_method;
   LPCTSTR m_call;
};

}      // namespace MSCAPI
#endif // __MSCAPI_WIN32EX_DOT_H__