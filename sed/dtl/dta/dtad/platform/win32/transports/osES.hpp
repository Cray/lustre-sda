/*! \file osES.hpp
    \brief Implementation of CDriveTrustSession via the EnhancedStorage transport.

    TODO : Detailed description
    
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

#ifndef XPORT_ES_HPP
#define XPORT_ES_HPP

// !defined __cplusplus

// Disabled Microsoft warnings on C-style functions
#if defined (_WIN32)
#pragma warning(disable : 4995)
#pragma warning(disable : 4996)
#endif

//=================================
// COM Include files
//=================================
#define _ATL_CSTRING_EXPLICIT_CONSTRUCTORS  // some CString constructors will be explicit
#include <atlbase.h>
#include <atlstr.h>
#include <atlcom.h>
#include <specstrings.h>
#include <strsafe.h>
#include <commdlg.h>

//=================================
// Include files
//=================================
#include "../osDTSession.hpp"
#include <dtad/platform/win32/enhancedstorage/ehstorapi.h>

namespace dtad {
//=================================
// macro definitions
//=================================

//=================================
// constants
//=================================

//=================================
// typedefs and structures
//=================================

//=================================
// class definitions
//=================================

/// \brief Class representing a communication session between
///        an application and an Enhanced Storage device.
///
/// TODO : Detailed description
///
//
class COSDTSessionES : public COSDTSession
{
public:
   /// Constructor.
   COSDTSessionES();

   //================================================================
   // Implementations of methods defined in COSDTSessionES
   //================================================================
   virtual dta::DTA_ERROR Open(
      const dta::DTIdentifier  &identifier,
      const tUINT8             protocol,
      const std::wstring       &optionString
      );

   virtual dta::DTA_ERROR Destroy();

   virtual dta::DTA_ERROR SecurityDataExchange( 
      tUINT8 protocolID,
      tUINT16 spSpecific,
      const dta::tBytes &dataToSend,
      dta::tBytes &dataToRecv 
      );

   //================================================================
   /// Not supported by the Windows Enhanced Storage API.
   ///
   /// \return DTA error, Not Impelemented.
   //================================================================
   inline virtual dta::DTA_ERROR SecurityDataToDevice(const dta::tBytes &dataToSend)
   {
      if (GetThrowOnError())
         throw dta::Error(dta::eGenericNotImplemented);
      return dta::Error(dta::eGenericNotImplemented);
   };

   //================================================================
   /// Not supported by the Windows Enhanced Storage API.
   ///
   /// \return DTA error, Not Impelemented.
   //================================================================
   inline virtual dta::DTA_ERROR SecurityDataFromDevice(dta::tBytes &dataToRecv)
   {
      if (GetThrowOnError())
         throw dta::Error(dta::eGenericNotImplemented);
      return dta::Error(dta::eGenericNotImplemented);
   };

   //================================================================
   /// Not supported by the Windows Enhanced Storage API.
   ///
   /// \return DTA error, Not Impelemented.
   //================================================================
   inline virtual dta::DTA_ERROR SecurityDataToDevice(tUINT8 protocolID,
                                                      tUINT16 spSpecific,
                                                      const dta::tBytes &dataToSend)
   {
      if (GetThrowOnError())
         throw dta::Error(dta::eGenericNotImplemented);
      return dta::Error(dta::eGenericNotImplemented);
   };

   //================================================================
   /// Not supported by the Windows Enhanced Storage API.
   ///
   /// \return DTA error, Not Impelemented.
   //================================================================
   inline virtual dta::DTA_ERROR SecurityDataFromDevice(tUINT8 protocolID,
                                                        tUINT16 spSpecific,
                                                        dta::tBytes &dataToRecv)
   {
      if (GetThrowOnError())
         throw dta::Error(dta::eGenericNotImplemented);
      return dta::Error(dta::eGenericNotImplemented);
   };

   virtual dta::DTA_ERROR GetAttribute(
      const _tstring& attribute,
      _tstring& value
      );

   virtual dta::DTA_ERROR SetAttribute(
      const _tstring& attribute,
      const _tstring& value
      );
protected:
   //================================================================
   /// Not supported by the Windows Enhanced Storage API.
   ///
   /// \return DTA error, Not Impelemented.
   //================================================================
   inline virtual size_t GetBlockSize()
   {
      // Enhanced storage works in 512 byte blocks
      return 512;
   };

private:
    IEnhancedStorageACT* m_ACT;
    IEnhancedStorageSilo** m_silos;
    ULONG m_siloCount;

};

}  // end namespace dtad
#endif // XPORT_ES_HPP
