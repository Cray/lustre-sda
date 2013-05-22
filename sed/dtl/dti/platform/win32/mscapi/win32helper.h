/*! \file win32helper.h 
    \brief Classes to help do device discovery via the CM_* 
           and SetupDI* API calls from Microsoft.

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

#if !defined(_Win32Helper_DOT_H)
#define      _Win32Helper_DOT_H

//=========================================================
// Include files
//=========================================================
#include <iostream>
#include <tchar.h>

//#define _WIN32_WINNT 0x0502

#include <windows.h>
#include <windef.h>
//#include <devioctl.h>
//#include <ntdddisk.h>
#include <ntddscsi.h>
#define _NTSCSI_USER_MODE_
//#include <Winsock2.h>
#include <Setupapi.h>
#include <devguid.h>
#include <cfgmgr32.h>

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <assert.h>
#include <vector>
#include <list>
#include <queue>
#include <map>

#include "dtlexceptions.h"
//=========================================================
// Macros
//=========================================================

//=========================================================
// Constant definitions
//=========================================================
#define CHECK_FAIL( os_call, fail_result )                \
   if ( fail_result == (os_call) )                        \
   {                                                      \
      M_ThrowTaggedEO( CWin32Exception,                   \
         ::GetLastError(),                                \
         #os_call );                                      \
   };

#define CHECK_SUCCESS( os_call, success_result )          \
   if ( success_result != (os_call) )                     \
   {                                                      \
      M_ThrowTaggedEO( CWin32Exception,                   \
         ::GetLastError(),                                \
         #os_call );                                      \
   };

//=========================================================
// enums (Typed constants)
//=========================================================

//=========================================================
// Typedefs and Structures
//=========================================================
typedef std::vector< DEVINST > DevInstCollection;
typedef std::list< std::string > tListStrings;

//=========================================================
// Static and external variables
//=========================================================

//=========================================================
// Code : Unclassed Function Declarations
//=========================================================

_tstring GetDevInstID(DEVINST devInst);

void GatherChildren( const DEVINST devInst, DevInstCollection& coll );

_tstring GetInterfaceDevicePath( HDEVINFO DeviceInfoSet, 
   PSP_DEVICE_INTERFACE_DATA DeviceInterfaceData );

//=========================================================
// Code : Class Definitions
//=========================================================

//
// AutoHDevInfo is a simple class used to open and close
// HDEVINFO structures with a minimum of fuss or things to
// remember.
class AutoHDevInfo
{
public:
   AutoHDevInfo( const HDEVINFO& hdi ) : m_hdi(hdi) 
   {
      assert( INVALID_HANDLE_VALUE != hdi );
   }
   AutoHDevInfo(
    CONST GUID *ClassGuid = NULL,
    HWND        hwndParent= NULL
    ) : m_hdi(INVALID_HANDLE_VALUE)
   {
      CHECK_FAIL(
         m_hdi = ::SetupDiCreateDeviceInfoList( ClassGuid, hwndParent ),
         INVALID_HANDLE_VALUE );
   }
   ~AutoHDevInfo()
   {
      if (INVALID_HANDLE_VALUE != m_hdi)
      {
         CHECK_FAIL( ::SetupDiDestroyDeviceInfoList( m_hdi ), FALSE );
      }
   }
   operator HDEVINFO&() { return m_hdi; }
private:
   HDEVINFO m_hdi;
};


// 
// DevInfoDataCollection is a simple class used to build
// a list of attached SP_DEVINFO_DATA from a provided
// HDEVINFO.
class DevInfoDataCollection : public std::list<SP_DEVINFO_DATA>
{
public:
   DevInfoDataCollection( const HDEVINFO& hdi
      = INVALID_HANDLE_VALUE );
   void Build( const HDEVINFO& hdi );
};

//=========================================================
// Code : Inline Class and Template Functions
//=========================================================


#endif    // _Win32Helper_DOT_H
