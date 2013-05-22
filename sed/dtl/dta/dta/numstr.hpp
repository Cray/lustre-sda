/*! \file numstr.hpp
    \brief Simple template classes for numeric / string conversions.
    
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

#ifndef NUMSTR_DOT_HPP
#define NUMSTR_DOT_HPP
//=================================
// Include files
//=================================
#ifndef __cplusplus
#error "C++ support required for numstr.hpp"
#endif // ifndef __cplusplus

#include "errors.h"
#include <sstream>

//=================================
// Macro definitions
//=================================

//=================================
// typedefs and structures
//=================================
//================================================================
//
/// Convert a string to a numeric type.
///
/// This method will convert the data from a string into a
/// numeric type.  It will throw a DTA_ERROR if any unexpected
/// data is encountered.
///
/// \param dest (OUT) The numeric value extracted
///      from the string source.
///
/// \param source (IN) The string containing the numeric value.
///
/// \return None
///
/// @pre None
///
/// @post None
//
//================================================================
template < class T >
void numstr( T& dest, const _tstring& source )
{
   T temp = 0;
   _tstring::const_iterator iter;
   for ( iter = source.begin(); iter != source.end(); iter++ )
   {
      if ( *iter > '9' || *iter < '0' )
      {
#if defined(_WIN32) // nvn20110624
    	  dta::Throw ( dta::eGenericInvalidParameter );
#else
    	  throw ( dta::eGenericInvalidParameter);
#endif
      }
      temp = ( 10 * temp ) + ( *iter - '0' );
   }
   dest = temp;
}

//================================================================
//
/// Convert a numeric type to a string.
///
/// This method will convert the data from a numeric type
/// into string format.  It will throw a DTA_ERROR if any 
/// unexpected error is encountered.
///
/// \param dest (OUT) The string destination for the numeric value.
///
/// \param source (IN) The source numeric value.
///
/// \return None
///
/// @pre None
///
/// @post None
//
//================================================================
template < class T >
void numstr( _tstring& dest, const T& source )
{
   _tostringstream sstr;
   sstr << source;
   dest = sstr.str();
}

#endif // NUMSTR_DOT_HPP
