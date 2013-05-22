/*! \file Xcommon.h
    \brief Custom compiler definitions.
    
    This file defines common typedefs and macros based on 
    the target compiler (e.g. msvc, gcc).

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

#if !defined(XCOMMON_DOT_H)
/// Header file include guard.
#define XCOMMON_DOT_H
//=================================
// Include files
//=================================

//=================================
// Constant definitions
//=================================

//=================================
// Structures and type definitions
//=================================

/// The following macro is to declare an int64 constant.
#define LLCONST(x)            x##i64
/// This one is the format string for an int64 in a printf/scanf.
#define LLPRINTF              "I64"
/// The base type for a 64-bit integer.
#define LLTYPE                __int64

#if 0 // nvn20110614

/// Microsoft-specific mapping for snprintf
#define snprintf _snprintf       // Microsoft likes an _

// On Win32 these macros do nothing.  In theory,
// this macro tests the condition you pass it, and hints to the compiler
// that you expect that the test will fail, and so the optimizations should
// be biased against the body of the test.  Probably only useful for usage
// in "inner loops" where performance is super-critical.
// Example: if (unlikely(ptr == NULL))...
/// Optimization hint for compiler.
#define unlikely(cond)  cond
// This macro is the same, but biases towards the body of the test.
/// Optimization hint for compiler.
#define likely(cond)  cond

#include <tchar.h>
/// Typedef for a string, either Unicode or ASCII, based
/// on the compiler definitions.
typedef TCHAR tCHAR;

#if defined(_UNICODE)

   /// Map _tsscanf to compiler-specific function.
   #define _tsscanf        swscanf
   /// Map _tfopen to compiler-specific function.
   #define _tfopen         _wfopen
   /// Map _tostringstream to compiler-specific class.
   #define _tostringstream std::wostringstream
   /// Map _tistringstream to compiler-specific class.
   #define _tistringstream std::wistringstream
   /// Map _tstring to compiler-specific class.
   #define _tstring std::wstring
   /// Map _tofstream to compiler-specific class.
   #define _tofstream std::wofstream
   /// Map _tatoi to compiler-specific class.
   #define _tatoi _wtoi
   /// Map _tcin to compiler-specific class.
   #define _tcin std::wcin
   /// Map _tcout to compiler-specific class.
   #define _tcout std::wcout
   /// Map _tcerr to compiler-specific class.
   #define _tcerr std::wcerr

#else // !defined(_UNICODE)

   /// Map _tsscanf to compiler-specific function.
   #define _tsscanf        scanf
   /// Map _tfopen to compiler-specific function.
   #define _tfopen         fopen
   /// Map _tostringstream to compiler-specific class.
   #define _tostringstream std::ostringstream
   /// Map _tistringstream to compiler-specific class.
   #define _tistringstream std::istringstream
   /// Map _tstring to compiler-specific class.
   #define _tstring std::string
   /// Map _tofstream to compiler-specific class.
   #define _tofstream std::ofstream
   /// Map _tatoi to compiler-specific class.
   #define _tatoi atoi
   /// Map _tcin to compiler-specific class.
   #define _tcin std::cin
   /// Map _tcout to compiler-specific class.
   #define _tcout std::cout
   /// Map _tcerr to compiler-specific class.
   #define _tcerr std::cerr

#endif // !defined(_UNICODE)

//=================================
// Static and external variables
//=================================

//=================================
// Code
//=================================

#endif // nvn

// nvn20110614

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/timeb.h> // TODO: becareful with env. linux sys 

typedef char TCHAR;
typedef char tCHAR;

#if defined(_UNICODE)
   #define _tsscanf           swscanf
   #define _tostringstream    std::wostringstream
   #define _tistringstream    std::wistringstream
   #define _tstring           std::wstring
   #define _tofstring         std::wofstring
   #define _tofstream         std::wofstream
   #define _tatoi             atoi
   #define _tcin              std::wcin
   #define _tcout             std::wcout
   #define _tcerr             std::wcerr
   #define _tfopen            fopen
   #define _timeb             timeb
#else
   #define _tsscanf           scanf
   #define _tostringstream    std::ostringstream
   #define _tistringstream    std::istringstream
   #define _tstring           std::string
   #define _tofstring         std::ofstring
   #define _tofstream         std::ofstream
   #define _tatoi             atoi
   #define _tcin              std::cin
   #define _tcout             std::cout
   #define _tcerr             std::cerr
   #define _tfopen            fopen
   #define _timeb             timeb
   #define _tstoi64           atoll
#endif

#define __T(x) L##x

#ifndef max
#define max(a, b)   ( ( (a) > (b) ) ? (a) : (b) )
#endif

#ifndef min
#define min(a, b)   ( ( (a) < (b) ) ? (a) : (b) )
#endif

#ifndef _stricmp
#define _stricmp(s1, s2) strcasecmp(s1, s2)
#endif

#ifndef _strnicmp
#define _strnicmp(s1, s2, n) strncasecmp(s1, s2, (n))
#endif

#endif // XCOMMON_DOT_H
