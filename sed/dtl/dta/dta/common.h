/*! \file common.h
    \brief OpenDisc common include file.
    
    This file provides a basic include point for OpenDisc macros,
    typedefs, and classes.

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

#if !defined(DTA_COMMON_DOT_H)
/// Header file include guard.
#define DTA_COMMON_DOT_H
//=================================
// Include files
//=================================

// Include the platform-specific file
#if defined (_WIN32)
#include "./platform/win32/Pcommon.h"
#elif defined (__DJGPP)
#include "./platform/dos/Pcommon.h"
#elif defined (__linux__)
#include "./platform/linux32/Pcommon.h"
#else
#error "Operating system not defined!"
#endif

// Now include the compiler-specific file
#if defined (_MSC_VER)
#include "./compilers/msvc/Xcommon.h"
#elif defined (__GNUC__)
#include "./compilers/gcc/Xcommon.h"
#else
#error "Unknown compiler being used!"
#endif

//=================================
// Macro definitions
//=================================

/*!
  \def TXT(str)
  Properly prefixes a constant text string for ASCII or
  UNICODE, as appropriate.
*/
#if defined(_UNICODE)
   #define TXT(str) L##str
#else  // !defined(_UNICODE)
   #define TXT(str) str
#endif

#define M_AlignPtr(p, size) \
               (void*)(((size_t)p + ((size_t)size - 1)) & ~((size_t)size - 1))

//=================================
// typedefs and structures
//=================================

#endif // DTA_COMMON_DOT_H
