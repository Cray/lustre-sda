/*! \file win32helper.cpp
    \brief Platform dependent API helper function implementations.

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

#include "win32helper.h"

//=================================
// Structures and type definitions
//=================================

//=================================
// Macro definitions
//=================================

//=================================
// Static and external variables
//=================================

//=================================
// Code : class DevInfoDataCollection
//=================================

DevInfoDataCollection::DevInfoDataCollection( const HDEVINFO& hdi )
{
   if ( INVALID_HANDLE_VALUE != hdi )
   {
      Build(hdi);
   }
}

void DevInfoDataCollection::Build( const HDEVINFO& hdi )
{
   erase( begin(), end() );
   SP_DEVINFO_DATA temp = { sizeof(SP_DEVINFO_DATA) };
   bool bContinue = true;
   for ( DWORD index = 0; bContinue; index++ )
   {
      if ( ::SetupDiEnumDeviceInfo( hdi, index, &temp ) )
      {
         push_back(temp);
      }
      else
      {
         bContinue = ( ERROR_NO_MORE_ITEMS != ::GetLastError() );
      }
   }
}

//=================================
// Code : un-classed functions.
//=================================

_tstring GetDevInstID(DEVINST devInst)
{
   _tstring result;

   CONFIGRET cmRes;
   ULONG size = 0;

   cmRes = CM_Get_Device_ID_Size( &size, devInst, 0 );
   if ( CR_SUCCESS == cmRes && 0 != size )
   {
      result.resize( ++size );

      cmRes = CM_Get_Device_ID(devInst, &result[0], 
                  size, 0);

      if ( CR_SUCCESS != cmRes )
      {
         result.resize(0);
      }
   }
   return result;
} // GetDevInstID


void GatherChildren( const DEVINST devInst, DevInstCollection& coll )
{
   CONFIGRET crVal;
   DEVINST   temp;
   for( crVal = CM_Get_Child(&temp,devInst,0);
      CR_SUCCESS == crVal;
      crVal = CM_Get_Sibling(&temp, temp, 0) )
   {
      coll.push_back( temp );
   }
}

_tstring GetInterfaceDevicePath( HDEVINFO DeviceInfoSet, 
   PSP_DEVICE_INTERFACE_DATA DeviceInterfaceData )
{
   _tstring result = _T("");
   DWORD dwError, dwRequiredSize;
   BOOL  bSuccess;

   // First, make a call to SetupDIGDED() to determine how big of
   // a buffer will be needed for the data.
   bSuccess = ::SetupDiGetDeviceInterfaceDetail( DeviceInfoSet, 
      DeviceInterfaceData, NULL, 0, &dwRequiredSize, NULL );
   dwError  = ::GetLastError();

   if ( !( (0==bSuccess) && (ERROR_INSUFFICIENT_BUFFER==dwError) ) )
   {
      // Something didn't work right.
      assert(false);
      return result;
   }

   std::auto_ptr<BYTE> buffer( new BYTE[dwRequiredSize] );
   PSP_DEVICE_INTERFACE_DETAIL_DATA ptr = 
      PSP_DEVICE_INTERFACE_DETAIL_DATA(buffer.get());
   ptr->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA);

   // Buffer's now allocated, go do the get "for real".
   bSuccess = ::SetupDiGetDeviceInterfaceDetail( DeviceInfoSet, 
      DeviceInterfaceData, ptr, dwRequiredSize, &dwRequiredSize,
      NULL );
   dwError = ::GetLastError();

   if ( !bSuccess )
   {
      assert(false);
      return result;
   }

   result = ptr->DevicePath;
   return result;
}