/*! \file ieee1667i.cpp
    \brief Basic implementations of base class members from <dta/ieee1667.hpp>.

    These implementation shall be cross-platform and relatively generic.
    Some or all of them may be overloaded by derived classes.
    
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

// Disabled Microsoft warnings on C-style functions
#if defined (_WIN32)
#pragma warning(disable : 4996)
#include <windows.h>
#endif

//=================================
// Include files
//=================================
#include "ieee1667i.hpp"
using namespace dti;

//=======================================================================================
// CIEEE1667Interface
//=======================================================================================
CIEEE1667Interface::CIEEE1667Interface(dta::CDriveTrustSession* newSession)
                                       : CDriveTrustInterface(newSession)
{
} // CIEEE1667Interface

//=======================================================================================
// CIEEE1667Interface
//=======================================================================================
CIEEE1667Interface::CIEEE1667Interface(dta::CDriveTrustSession* newSession,
                                       const _tstring logFileName)
                                       : CDriveTrustInterface(newSession, logFileName)
{
} // CIEEE1667Interface

//=======================================================================================
// sendCommand
//=======================================================================================
IEEE1667_STATUS CIEEE1667Interface::sendCommand(const tUINT8 siloIndex,
                                                const tUINT8 functionID,
                                                dta::tBytes &dataToSend,
                                                dta::tBytes &dataToRecv)
{
   // The Silo Index becomes the upper byte of SP Specific, and Function ID the lower.
   tUINT16 spSpecific = functionID;
   spSpecific |= tUINT16(siloIndex << 8);

   // Now send the command and handle any errors
   IEEE1667_STATUS __result = SC_SUCCESS;
   bool __throwOnError = m_session->SetThrowOnError(true);
   try
   {
      m_session->SecurityDataExchange(dta::eSPIEEE1667, spSpecific, dataToSend, dataToRecv);
      __result = parseResponse(dataToRecv);
      if ((__result != SC_SUCCESS) && (__result != SC_DEFAULT_BEHAVIOR))
      {
         throw (__result);
      }
   }
   catch( const dta::DTA_ERROR& err )
   {
      setLastError(err);
      __result = SC_DTL_ERROR;
   }
   catch( const IEEE1667_STATUS & status )
   {
      setLastError( dta::Error( static_cast<dta::eDtaProtocolError>( status ) ) );
      __result = status;
   }
   m_session->SetThrowOnError(__throwOnError);
   if ((__result != SC_SUCCESS) && (__result != SC_DEFAULT_BEHAVIOR) && __throwOnError)
   {
      throw getLastError();
   }
   return __result;
} // sendCommand

//=======================================================================================
// protocolOut
//=======================================================================================
IEEE1667_STATUS CIEEE1667Interface::protocolOut(const tUINT8 siloIndex,
                                                const tUINT8 functionID,
                                                dta::tBytes &dataToSend)
{
   // The Silo Index becomes the upper byte of SP Specific, and Function ID the lower.
   tUINT16 spSpecific = functionID;
   spSpecific |= tUINT16(siloIndex << 8);

   // Now send the command and handle any errors
   IEEE1667_STATUS __result = SC_SUCCESS;
   bool __throwOnError = m_session->SetThrowOnError(true);
   try
   {
      m_session->SecurityDataToDevice(dta::eSPIEEE1667, spSpecific, dataToSend);
   }
   catch( const dta::DTA_ERROR& err )
   {
      setLastError(err);
      __result = SC_DTL_ERROR;
   }
   m_session->SetThrowOnError(__throwOnError);
   if ((__result != SC_SUCCESS) && (__result != SC_DEFAULT_BEHAVIOR) && __throwOnError)
   {
      throw getLastError();
   }
   return __result;
} // protocolOut

//=======================================================================================
// protocolIn
//=======================================================================================
IEEE1667_STATUS CIEEE1667Interface::protocolIn(const tUINT8 siloIndex,
                                               const tUINT8 functionID,
                                               dta::tBytes &dataToRecv)
{
   // The Silo Index becomes the upper byte of SP Specific, and Function ID the lower.
   tUINT16 spSpecific = functionID;
   spSpecific |= tUINT16(siloIndex << 8);

   // Now send the command and handle any errors
   IEEE1667_STATUS __result = SC_SUCCESS;
   bool __throwOnError = m_session->SetThrowOnError(true);
   try
   {
      m_session->SecurityDataFromDevice(dta::eSPIEEE1667, spSpecific, dataToRecv);
      __result = parseResponse(dataToRecv);
      if ((__result != SC_SUCCESS) && (__result != SC_DEFAULT_BEHAVIOR))
      {
         throw (__result);
      }
   }
   catch( const dta::DTA_ERROR& err )
   {
      setLastError(err);
      __result = SC_DTL_ERROR;
   }
   catch( const IEEE1667_STATUS & status )
   {
      setLastError( dta::Error( static_cast<dta::eDtaProtocolError>( status ) ) );
      __result = status;
   }
   m_session->SetThrowOnError(__throwOnError);
   if ((__result != SC_SUCCESS) && (__result != SC_DEFAULT_BEHAVIOR) && __throwOnError)
   {
      throw getLastError();
   }
   return __result;
} // protocolIn

//=======================================================================================
// parseResponse
//=======================================================================================
IEEE1667_STATUS CIEEE1667Interface::parseResponse(dta::tBytes &payload) const
{
   // Make sure the response payload is atleast has the header
   if (payload.size() < sizeof(ResponsePayloadHeader))
   {
      throw (dta::Error(dta::eProtocolFatalError));
   }

   // Read the payload out to match the response header
   ResponsePayloadHeader* responsePayloadHeader = (ResponsePayloadHeader*)&payload[0];

   // Find the response code
   IEEE1667_STATUS result = responsePayloadHeader->statusCode;

   // Now resize to match the payload length
   tUINT32 contentLength = m_swapper.NetToHost((tUINT32)responsePayloadHeader->payloadContentLength);
   payload.resize(contentLength);

   return result;
} // parseResponse

//=======================================================================================
// probeCommand
//=======================================================================================
IEEE1667_STATUS CIEEE1667Interface::probeCommand()
{
   M_IEEE1667Try()
   {
      // Fill in the probe command payload
      dta::tBytes payload(sizeof(ProbeCommandPayload));
      ProbeCommandPayload* probeCommandPayload = (ProbeCommandPayload*) &payload[0];
      probeCommandPayload->hostIEEE1667MajorVersion       = IEEE1667_MAJOR_VERSION;
      probeCommandPayload->hostIEEE1667MinorVersion       = IEEE1667_MINOR_VERSION;
      probeCommandPayload->hostImplementationMajorVersion = IEEE1667_PROBE_SILO_MAJOR;
      probeCommandPayload->hostImplementationMinorVersion = IEEE1667_PROBE_SILO_MINOR;

      // Host Specific Code
#ifdef _WIN32
      //
      // Microsoft Windows Implementation
      //

      // Fill in the general fields
      probeCommandPayload->hostOS = eOSWindows;
      probeCommandPayload->hostOSSpecificationLength = sizeof(WindowsOSSpecification);

      // Now make room for Window specific block, and fill in
      payload.resize(payload.size() + sizeof(WindowsOSSpecification));
      WindowsOSSpecification* osSpec = (WindowsOSSpecification*)&payload[sizeof(ProbeCommandPayload)];
      OSVERSIONINFO versionInfo;
      versionInfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
      GetVersionEx(&versionInfo);
      osSpec->windowsMajorVersion = m_swapper.HostToNet((tUINT32)versionInfo.dwMajorVersion);
      osSpec->windowsMinorVersion = m_swapper.HostToNet((tUINT32)versionInfo.dwMinorVersion);
      osSpec->windowsBuildNumber  = m_swapper.HostToNet((tUINT32)versionInfo.dwBuildNumber);
      osSpec->windowsPlatformID   = m_swapper.HostToNet((tUINT32)versionInfo.dwPlatformId);
#endif

      // Now execute the command
      dta::tBytes recvPayload(512);
      add1667CommandHeader(payload);
      sendCommand(IEEE1667_PROBE_SILO_INDEX, eProbeFunction, payload, recvPayload);

      // Parse the received payload and populate the silo list
      ProbeResponse* probeResponse = (ProbeResponse*)&recvPayload[0];

      // TODO: Check Available payload length

      // Read through the silo list length
      const tUINT16 siloListLength = m_swapper.NetToHost(probeResponse->siloListLength);
      
      // Now read through the response buffer and re-populate the list of silos
      m_silos.clear();
      const unsigned int numSilos = (siloListLength / sizeof(SiloListElement));
      SiloListElement* siloListElementPtr = (SiloListElement*)&probeResponse->siloList;
      for (unsigned int i = 0; i < numSilos; i++)
      {
         // Add the silo element to the list.
         m_silos.push_back(siloListElementPtr->siloElement);

         // Copy the Silo Type ID from big-endian to what ever the host is.
         m_silos.back().siloTypeID = m_swapper.HostToNet(m_silos.back().siloTypeID);
         siloListElementPtr++;
      } // for
   }
   M_IEEE1667Catch()
} // probeCommand

//=======================================================================================
// getSiloIndex
//=======================================================================================
tUINT8 CIEEE1667Interface::getSiloIndex(tUINT32 stid)
{
   tUINT8 siloIndex = 0xFF;

   // If the silo list is empty, then we haven't done a probe command yet.
   if (m_silos.size() == 0)
   {
      try
      {
         probeCommand();
      }
      catch(...)
      {
         return siloIndex;
      }
   } // if

   // Okay, the silo list should now be populated, now let's find the Silo Type ID
   for (unsigned int i = 0; i < m_silos.size(); i++)
   {
      if (m_silos[i].siloTypeID == stid)
      {
         return i;
      }
   } // for

   return siloIndex;
} // getSiloIndex

//=======================================================================================
// add1667CommandHeader
//=======================================================================================
void CIEEE1667Interface::add1667CommandHeader(dta::tBytes& payload)
{
   static CByteOrder swapper;

   // Copy in the command payload header and fill in the size
   if (payload.size() < sizeof(CommonPayloadHeader))
   {
      // Make sure we have enough room
      payload.resize(sizeof(CommonPayloadHeader));
   }
   CommonPayloadHeader* commandPayloadHeader  = (CommonPayloadHeader*)&payload[0];
   commandPayloadHeader->payloadContentLength = swapper.HostToNet((tUINT32)payload.size());
} // add1667CommandHeader

//=======================================================================================
// statusToString
//=======================================================================================
_tstring CIEEE1667Interface::statusToString(const IEEE1667_STATUS status)
{
   switch ( status )
   {
      case SC_SUCCESS: 
         return TXT("The command completed without failure"); 
      case SC_FAILURE: 
         return TXT("General failure condition"); 
      case SC_INCOMPLETE_COMMAND: 
         return TXT("A truncated or incomplete IEEE 1667 command was received");
      case SC_INVALID_SILO: 
         return TXT("A command addressed to an unimplemented silo was received."); 
      case SC_INVALID_PARAMETER: 
         return TXT("A parameter sent to the silo is invalid"); 
      case SC_SEQUENCE_REJECTION: 
         return TXT("Command rejected for being out of SPOUT/SPIN Sequence"); 
      case SC_NO_PROBE:
         return TXT("Non-Probe Command received before Probe Command"); 
      case SC_RESERVED_FUNCITON: 
         return TXT("The FUNCTION_ID field in the CDB contains a reserved value"); 
      default:
         return TXT("Unknown status");
   } // switch
} // statusToString