#pragma once
/*! \file GetClassDevs.hpp
    \brief Header file for CDeviceInfoList and CGetClassDevs.
    
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

#include <windows.h>
#include <setupapi.h>   // for SetupDiXxx functions.
//include <cfgmgr32.h>   // for SetupDiXxx functions.

namespace SetupDi
{
//
/// \brief CDeviceInfoList is a wrapper class for the
///   windows setup32 API
//
class CDeviceInfoList
{
public:
   CDeviceInfoList() 
      : m_hDevInfo( INVALID_HANDLE_VALUE )
      , m_lastError( NO_ERROR )
   {}
   virtual ~CDeviceInfoList();
   DWORD DestroyDeviceInfoList();

   operator HDEVINFO() const { return m_hDevInfo; }
   /*! Returns NO_ERROR if the last method succeeded or a Windows
    *  error code if the last method failed.
    */
   DWORD LastError() const { return m_lastError; }
protected:
   HDEVINFO m_hDevInfo;
   DWORD    m_lastError;
};


//
/// \brief CClassDevs is a wrapper class for the windows setup32 API
//
class CClassDevs : public CDeviceInfoList
{
public:
   // Methods.
   DWORD Get(
      const GUID* ClassGuid,
      PCTSTR Enumerator,
      HWND hwndParent,
      DWORD Flags
      );
   DWORD GetSetupClass(
      const GUID* ClassGuid,
      PCTSTR Enumerator = NULL,
      HWND hwndParent = NULL,
      DWORD Flags = DIGCF_PRESENT
      );
   DWORD GetInterfaceClass(
      const GUID* ClassGuid,
      PCTSTR Enumerator = NULL,
      HWND hwndParent = NULL,
      DWORD Flags = DIGCF_PRESENT
      );

   DWORD EnumDeviceInterfaces(
      OUT SP_DEVICE_INTERFACE_DATA& DeviceInterfaceData,
      IN  DWORD  MemberIndex,
      IN  LPGUID InterfaceClassGuid,
      IN  PSP_DEVINFO_DATA DeviceInfoData = NULL
    );

};

} // namespace SetupDi
