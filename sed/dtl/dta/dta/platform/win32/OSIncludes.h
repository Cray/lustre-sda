/*! \file OSIncludes.h
    \brief Workarounds for ntddscsi.h, ntddstor.h and Windows.h conflicts.

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

#if !defined(_OSINCLUDES_H_INCLUDED_)
#define _OSINCLUDES_H_INCLUDED_

//=================================
// Include files
//=================================

// Explanation: Microsoft finally 'fixed' the whole DDK/SDK versioning
// problem with the Vista SDK, where you no longer need to do some
// jury-rigging to get ntddstor's includes appropriately defined.
//
// Unfortunately, that also means for backwards compatibility, at 
// compile time you need to know if you're using the Vista Platform SDK
// (or newer, presumably), or if you need the old 'hackerage' to include
// the appropriate file.
//
// Even more unfortunately, Microsoft doesn't have an easy way to check
// for that.  This hack-upon-a-hack includes an extra header that is
// in both, just so it can check to see if a define exists 
// that's no longer present in the Vista SDK.
//
#include <XmlDsodid.h>
#if defined DISPID_XOBJ_MAX
	#define FIXED_PLATFORM_SDK_IN_USE 0
#else
	#define FIXED_PLATFORM_SDK_IN_USE 1
#endif

#if FIXED_PLATFORM_SDK_IN_USE
	#include <Windows.h>
#else
	// Here's some idiocy to work around the defective 
	// Windows SDK/DDK header separation.  Isn't is special?
   #if defined _NTDDSTOR_H_
      #define _NTDDSTOR_H_PREVIOUSLY_DEFINED_
   #else
   	#define _NTDDSTOR_H_
   #endif
   #include <Windows.h>
   #if defined _NTDDSTOR_H_PREVIOUSLY_DEFINED_
   	#undef _NTDDSTOR_H_PREVIOUSLY_DEFINED_
   #else
   	#undef _NTDDSTOR_H_
   #endif
	#include <devioctl.h>	
	#include <ntddstor.h>
#endif

// Here's another "nasty include" that causes problems when
// the ntddscsi.h file lives sometimes in the Windows SDK
// and sometimes in the Windows DDK.
//
// Note that if DEFINE_GUID is already defined, it will 
// cause the ntddscsi.h file to generate duplicate defs.
// We work the same magic here as for the ntddstor.h file
// with regard to hacking ifdefs before and after.

#ifdef DEFINE_GUID
   #undef DEFINE_GUID
   #define SEAGATE_DEFINE_GUID_PREVIOUSLY_DEFINED_
#endif

// If you get a compile error about not finding this file,
// then your VisualStudio is not linked to the Windows SDK.
// To fix this, go to your Windows SDK program files and
// locate the program that provides Visual Studio Registration
// or that "Integrates Visual Studio" with the Windows SDK.
// Restart VisualStudio and this file should be found OK.
#include <ntddscsi.h>   // ATA_PASS_THROUGH_DIRECT lives here

#ifdef SEAGATE_DEFINE_GUID_PREVIOUSLY_DEFINED_
   #undef SEAGATE_DEFINE_GUID_PREVIOUSLY_DEFINED_
   #define DEFINE_GUID
#endif


//=================================
// Structures and type definitions
//=================================

//=================================
// Static and external variables
//=================================

#endif // _OSINCLUDES_H_INCLUDED_

