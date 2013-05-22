/*! \file Pcommon.h
    \brief Custom platform definitions.
    
    This file defines common typedefs and macros based on 
    the target platform (e.g. win32, DOS, or linux).

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

#if !defined(PCOMMON_DOT_H)
/// Header file include guard.
#define PCOMMON_DOT_H
//=================================
// Include files
//=================================

//=================================
// Constant definitions
//=================================
/// Determines whether or not the target platform has
/// case-sensitive file names.  It is advantageous on
/// platforms with case-insensitive filenames (e.g.
/// Windows) to convert filename text to a single
/// case setting (e.g. lower) so string comparisons
/// and other such functions are done easily.
#define PLATFORM_IS_CASE_SENSITIVE (0)

//=================================
// Structures and type definitions
//=================================

/// unsigned, 8 bit integer.  This definition is cross-platform.
typedef unsigned __int8       tUINT8;
/// unsigned, 16 bit integer.  This definition is cross-platform.
typedef unsigned __int16      tUINT16;
/// unsigned, 32 bit integer.  This definition is cross-platform.
typedef unsigned __int32      tUINT32;
/// unsigned, 64 bit integer.  This definition is cross-platform.
typedef unsigned __int64      tUINT64;

/// signed, 8 bit integer.  This definition is cross-platform.
typedef __int8                tINT8;
/// signed, 16 bit integer.  This definition is cross-platform.
typedef __int16               tINT16;
/// signed, 32 bit integer.  This definition is cross-platform.
typedef __int32               tINT32;
/// signed, 64 bit integer.  This definition is cross-platform.
typedef __int64               tINT64;

#if defined(__cplusplus)

   /// boolean type (true/false).  This definition is cross-platform.
   typedef bool               tBOOL;

#else // !defined(__cplusplus)

   /// boolean type (true/false).  This definition is cross-platform.
   typedef int                tBOOL;

#endif // !defined(__cplusplus)

/// \brief Specifies the basic type of an OS error code.
///
/// For Windows, DWORD is the typical OS error return value.
/// We map tOSError to point to the same base type as the one
/// mappd to by DWORD.  (We could typedef aganist DWORD, but
/// that would mean including windows.h, and giving programmers
/// easy automatic access to things that might not be cross-
/// platform).
typedef unsigned long tOSError;

/// Platform-specific define that demonstrates the 'proper'
/// character(s) to use for file-system pathing.  This value
/// is typically '\' on Windows/Dos and '/' on Linux/Unix.
#define PATH_SLASH "\\"

//=================================
// Static and external variables
//=================================

//=================================
// Code
//=================================

#endif // PCOMMON_DOT_H
