/*! \file osES.cpp
    \brief Windows-specific implementation of COSDTSessionES.

    This implementation is specific to the Windows O/S.  It may include
    Windows-specific headers and definitions as necessary.
    
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
#include "osES.hpp"
#include <sstream>
#include <assert.h>
#include <dta/numstr.hpp>
#include <dta/parseoptions.hpp>
using namespace dtad;

//=================================
// macro/constant definitions
//=================================
//=================================
// typedefs and structures
//=================================

/// Alignment type.  This type is used only to force the 
/// compiler to align things on a particular boundary.
typedef tUINT64 tAlignment;

//=================================
// function implementations
//=================================

//=================================
// class implementations
//=================================

COSDTSessionES::COSDTSessionES()
: COSDTSession()
{
   m_supportedAttributes.push_back( txtTransport );
}

//=======================================================================================
// Open
//=======================================================================================
dta::DTA_ERROR COSDTSessionES::Open(const dta::DTIdentifier &identifier, const tUINT8 protocol,
                                    const std::wstring &optionString)
{
   M_DriveTrustBaseTry()
   {
      FreeResources();

      dta::tstringMap options;
      dta::tstringMap::iterator option;
      _tstring wildcard = dta::ParseOptions( options, optionString );
      option = options.find( TXT("-log") );
      if ( options.end() != option )
      {
         // Log file specified!
         m_log.Open(option->second, TXT("Open Session " + identifier));
      }

      // Get a pointer to the ACT
      CComPtr<IEnumEnhancedStorageACT> pEnum;
      IEnhancedStorageACT** rgACTs = NULL;
      HRESULT hr = CoCreateInstance(CLSID_EnumEnhancedStorageACT,
                                    NULL,
                                    CLSCTX_INPROC_SERVER,
                                    IID_IEnumEnhancedStorageACT,
                                    (VOID**) &pEnum);
      hr = pEnum->GetMatchingACT(LPWSTR(&identifier[0]), &m_ACT);
      CoTaskMemFree(rgACTs);
      if (FAILED(hr))
      {
         dta::DTA_ERROR dtaError(dta::Error(::GetLastError()));
         throw dtaError;
      }

      // Populate a list of silos
      hr = m_ACT->GetSilos(&m_silos, &m_siloCount);
      if (FAILED(hr))
      {
         dta::DTA_ERROR dtaError(dta::Error(::GetLastError()));
         throw dtaError;
      }

      // Create the session's mutex
      CreateSessionMutex(identifier);

      //
      // TODO : Parse the options string for additional
      //        settings as necessary.
      m_protocolID = dta::eSPIEEE1667;
      m_timeout    = 15;         // [jls: changed to accomodate FDE terminate 8 second time]
      m_spSpecific = 0;
      m_deviceName = identifier;
   }
   M_DriveTrustBaseSimpleEndTry()
} // Open

//=======================================================================================
// Destroy
//=======================================================================================
dta::DTA_ERROR COSDTSessionES::Destroy()
{
   for (unsigned int i = 0; i < m_siloCount; i++)
   {
      m_silos[i]->Release();
   }
   CoTaskMemFree(m_silos);
   return dta::Success;
   //M_DriveTrustBaseTry()
   //{
   //   // Enhanced Storage COM cleanup
   //   for (unsigned int i = 0; i < m_siloCount; i++)
   //   {
   //      m_silos[i]->Release();
   //   }
   //   CoTaskMemFree(m_silos);
   //   dta::COSDTSession::Destroy();
   //}
   //M_DriveTrustBaseSimpleEndTry()
} // Destroy

//=======================================================================================
// SecurityDataExchange
//=======================================================================================
dta::DTA_ERROR COSDTSessionES::SecurityDataExchange(tUINT8 protocolID, tUINT16 spSpecific,
                                                    const dta::tBytes &dataToSend,
                                                    dta::tBytes &dataToRecv )
{
   M_DriveTrustBaseTry()
   {
      dta::CSessionAutoLock<dta::eLockTypeTxRx> lock( this );
      
      // Silo index is lower byte of SP Specific, and FunctionID the upper byte
      tUINT8 siloIndex  = tUINT8(spSpecific);
      tUINT8 functionID = tUINT8(spSpecific >> 8);

      // Make sure the silo index is valid
      if (siloIndex >= m_siloCount)
      {
         throw dta::Error(dta::eGenericInvalidParameter);
      }

      // Pad out the send buffer, if nessary, and copy it in.
      dta::tBytes sendBuffer(dataToSend);
      tUINT16 blocks = static_cast<tUINT16>((dataToSend.size() + 512 - 1) / 512);
      sendBuffer.resize(blocks * 512);

      // Pad out the receive buffer, if necessary
      dataToRecv.resize(((dataToRecv.size() + 512 - 1)/ 512) * 512);

      // Now exchange the data
      ULONG dataReceived = (ULONG)dataToRecv.size();
      HRESULT hr = m_silos[siloIndex]->SendCommand(functionID,
                                                   (BYTE*)&sendBuffer[0],
                                                   (ULONG)sendBuffer.size(),
                                                   (BYTE*)&dataToRecv[0],
                                                   &dataReceived);
      // Return the error, if the exchange failed
      if (FAILED(hr))
      {
         throw dta::Error(GetLastError());
      }

      // Make sure we didn't get back more bytes than expected
      if (dataReceived > dataToRecv.size())
      {
         throw dta::Error(dta::eGenericMemoryError);
      }
   }
   M_DriveTrustBaseSimpleEndTry()
} // SecurityDataExchange

//=======================================================================================
// GetAttribute
//=======================================================================================
dta::DTA_ERROR COSDTSessionES::GetAttribute(const _tstring& attribute, _tstring& value)
{
   M_DriveTrustBaseTry()
   {
      if ( txtBlockSize == attribute )
      {
         numstr( value, GetBlockSize() );
      }
      else if ( txtTransport == attribute )
      {
         value = txtEnhancedStorage;
      }
      else
      {
         COSDTSession::GetAttribute(attribute, value );
      }
   }
   M_DriveTrustBaseSimpleEndTry()
} // GetAttribute

//=======================================================================================
// SetAttribute
//=======================================================================================
dta::DTA_ERROR COSDTSessionES::SetAttribute(const _tstring& attribute, const _tstring& value)
{
   M_DriveTrustBaseTry()
   {
      if ( txtBlockSize == attribute )
      {
         // Can't change the block size.
         throw AddLogEntry(
            dta::Error( dta::eGenericAttributeReadOnly ),
            TXT("Error: Block Size attribute may not be changed")
            );
      }
      else
      {
         COSDTSession::SetAttribute(attribute, value);
      }
   }
   M_DriveTrustBaseSimpleEndTry()
} // SetAttribute