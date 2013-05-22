/*! \file GetClassDevs.cpp
    \brief Implementation file for CDeviceInfoList and CClassDevs.
    
    \legal 
    All software, source code, and any additional materials contained
    herein (the "Software") are owned by Seagate Technology LLC and are 
    protected by law and international treaties.� No rights to the 
    Software, including any rights to distribute, reproduce, sell, or 
    use the Software, are granted unless a license agreement has been 
    mutually agreed to and executed between Seagate Technology LLC and 
    an authorized licensee.�

    The Software contains SEAGATE CONFIDENTIAL INFORMATION AND SEAGATE 
    TRADE SECRET INFORMATION that must be protected as such.

    Copyright � 2008.� Seagate Technology LLC �All Rights Reserved.

    The Software is provided under the Agreement No. 134849 between Seagate
    Technology and Calsoft. All Intellectual Property rights to the Software,
    as between Calsoft and Seagate, will be governed under the terms of the 
    Agreement No. 134849; no other rights to the Software are granted.
*/

#include "GetClassDevs.hpp" // nvn20110629

using namespace SetupDi;

CDeviceInfoList::~CDeviceInfoList()
/*!
\brief Calls DestroyDeviceInfoList() to release any current resources.
 *
 * This method loses any error information generated while attempting
 * to release resources.  If error tracking is important, you must
 * manually call DestroyDeviceInfoList() prior to destroying the class
 * object.
 */
{
   DestroyDeviceInfoList();
}

DWORD CDeviceInfoList::DestroyDeviceInfoList()
/*! 
\brief Releases resources via SetupDiDestroyDeviceInfoList
 * as necessary.  
 *
 * This method is called automatically by the destructor.
 *
\return Returns NO_ERROR on success or a Windows error code if
 * the call to SetupDiDestroyDeviceInfoList failed.
 */
{
   m_lastError = NO_ERROR;
   if (  INVALID_HANDLE_VALUE != m_hDevInfo 
      //&& !SetupDiDestroyDeviceInfoList( m_hDevInfo ) // TODO: // nvn20110629 - temp
      )
   {
      m_lastError = errno; // nvn20110629
   }
   return m_lastError;
}

DWORD CClassDevs::Get(
   int* ClassGuid, //const GUID* ClassGuid, // TODO: // nvn20110629 - temp
   PCTSTR Enumerator,
   HWND hwndParent,
   DWORD Flags
   )
/*!
\brief Method that maps directly to SetupDiGetClassDevs call.
 *
 * See the MSDN documentation for SetupDiGetClassDevs() for more complete
 * information on parameters and valid uses.
 *
\param ClassGuid [optional in] NULL, a class GUID, or an interface GUID.
\param Enumerator [optional in] NULL, or a pointer to a NULL-terminated string.
\param hwndParent [in] NULL, or handle to the top-level window as needed for UI.
\param Flags [in] Control options for building the set.
 *
\return If no error occurred, NO_ERROR will be returned.  Otherwise, a Windows
 * error code will be generated and returned.
 */
{
   if ( NULL == ClassGuid )
   {
      Flags |= 0x01; // DIGCF_ALLCLASSES; // TODO: // nvn20110629 - temp
   }
   if ( NO_ERROR == DestroyDeviceInfoList() )
   {
      //m_hDevInfo = SetupDiGetClassDevs( ClassGuid, Enumerator,
      //   hwndParent, Flags ); // TODO: // nvn20110629 - temp
      if ( INVALID_HANDLE_VALUE == m_hDevInfo )
      {
         m_lastError = errno; // nvn20110629
      }
   }
   return m_lastError;
}

DWORD CClassDevs::GetSetupClass(
   int* ClassGuid, //const GUID* ClassGuid, // TODO: // nvn20110629 - temp
   PCTSTR Enumerator,
   HWND hwndParent,
   DWORD Flags
   )
/*!
\brief Method that maps directly to SetupDiGetClassDevs call with a setup GUID.
 *
 * See the MSDN documentation for SetupDiGetClassDevs() for more complete
 * information on parameters and valid uses.
 *
\param ClassGuid [in] a class GUID
\param Enumerator [optional in] NULL, or a pointer to a NULL-terminated string.
\param hwndParent [in] NULL, or handle to the top-level window as needed for UI.
\param Flags [in] Control options for building the set.  DIGCF_DEVICEINTERFACE
 *     will specifically be excluded from the flags list, if preset.
 *
\return If no error occurred, NO_ERROR will be returned.  Otherwise, a Windows
 * error code will be generated and returned.
 */
{
   Flags &= 0x01; //~DIGCF_DEVICEINTERFACE; // TODO: // nvn20110629 - temp
   return Get( ClassGuid, Enumerator, hwndParent, Flags );
}

DWORD CClassDevs::GetInterfaceClass(
   int* ClassGuid, //const GUID* ClassGuid, // TODO: // nvn20110629 - temp
   PCTSTR Enumerator,
   HWND hwndParent,
   DWORD Flags
   )
/*!
\brief Method that maps directly to SetupDiGetClassDevs call 
* with an interface GUID.
 *
 * See the MSDN documentation for SetupDiGetClassDevs() for more complete
 * information on parameters and valid uses.
 *
\param ClassGuid [in] a class GUID
\param Enumerator [optional in] NULL, or a pointer to a NULL-terminated string.
\param hwndParent [in] NULL, or handle to the top-level window as needed for UI.
\param Flags [in] Control options for building the set.  DIGCF_DEVICEINTERFACE
 *     will specifically be included from the flags list.
 *
\return If no error occurred, NO_ERROR will be returned.  Otherwise, a Windows
 * error code will be generated and returned.
 */
{
   Flags |= 0x01; //DIGCF_DEVICEINTERFACE; // TODO: // nvn20110629 - temp
   return Get( ClassGuid, Enumerator, hwndParent, Flags );
}

DWORD CClassDevs::EnumDeviceInterfaces(
   /*OUT SP_DEVICE_INTERFACE_DATA& DeviceInterfaceData,
   IN DWORD  MemberIndex,
   IN LPGUID InterfaceClassGuid,
   IN PSP_DEVINFO_DATA DeviceInfoData*/ // TODO: // nvn20110629 - temp
   int& DeviceInterfaceData,
   DWORD  MemberIndex,
   int* InterfaceClassGuid,
   int* DeviceInfoData
   )
/*!
\brief Method that maps directly to SetupDiEnumDeviceInterfaces.
 *
 * See the MSDN documentation for SetupDiEnumDeviceInterfaces() for more complete
 * information on parameters and valid uses.
 *
\param DeviceInterfaceData [out] the resulting information, if successful.
\param MemberIndex [in] The zero-based index of the interface.
\param InterfaceClassGuid [in] The device interface class for the requested interface.
\param DeviceInfoData [optional in] Allows restriction to a single device in the set.
 *
\return If no error occurred, NO_ERROR will be returned.  Otherwise, a Windows
 * error code will be generated and returned.
 */
{
   m_lastError = NO_ERROR;
   /*DeviceInterfaceData.cbSize = sizeof(DeviceInterfaceData);
   if (!SetupDiEnumDeviceInterfaces(
      m_hDevInfo, DeviceInfoData, InterfaceClassGuid,
      MemberIndex, &DeviceInterfaceData
      ))*/ // TODO: // nvn20110629 - temp
   {
      m_lastError = errno;
   }
   return m_lastError;
}
