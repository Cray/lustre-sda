/*! \file dta.cpp
    \brief Basic implementations of base class members from <dta/dta.h>.

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

//=================================
// Include files
//=================================
#include "dta.hpp"
#include "Ata.hpp" // nvn20110615
using namespace dta;

//=================================
// macro definitions
//=================================

//=================================
// typedefs and structures
//=================================

//=================================
// function implementations
//=================================

//=================================
// Global Variables
//=================================
/// A constant value for success.  It should be equal to zero.
const DTA_ERROR dta::Success = { 0 };

//=================================
// class implementations
//=================================

CDriveTrustBase::CDriveTrustBase()
: m_throwOnError( true )
{
}

DTA_ERROR CDriveTrustBase::Destroy()
{
   // Destroy can delete the 'this' operator.  The
   // normal macros wrapping catch aren't safe to
   // use because they may attempt to access 'this'.
   M_DriveTrustBaseTry()
   {
      delete this;
   }
   catch(...)
   {
      __result.Info.Category = eDtaCategoryGeneric;
      __result.Info.Detail   = eGenericMemoryError;
   }
   if ( M_DtaFail( __result ) && __throwOnError )
   {
      throw __result;
   }
   return __result;
}

bool CDriveTrustBase::GetThrowOnError() const
{
   return m_throwOnError;
}

bool CDriveTrustBase::SetThrowOnError( bool newVal )
{
   bool oldValue = m_throwOnError;
   m_throwOnError = newVal;
   return oldValue;
}

dta::DTA_ERROR CDriveTrustBase::AddLogEntry( 
   const dta::DTA_ERROR& error,
   const _tstring&
   )
{
   // Default implementation : ignore the log entry request.
   return error;

}
      
DTA_ERROR CDriveTrustSession::SecurityDataExchange( 
      const dta::tBytes &dataToSend,
      dta::tBytes &dataToRecv 
      )
{
   DTA_ERROR result;
   CSessionAutoLock<eLockTypeTxRx> lock( this );
   result = SecurityDataToDevice( dataToSend );
   if ( M_DtaSuccess( result ) )
   {
      result = SecurityDataFromDevice( dataToRecv );
   }
   return result;
}

DTA_ERROR CDriveTrustSession::SecurityDataExchange( 
      tUINT8 protocolID,
      tUINT16 spSpecific,
      const dta::tBytes &dataToSend,
      dta::tBytes &dataToRecv 
      )
{
   DTA_ERROR result;
   CSessionAutoLock<eLockTypeTxRx> lock( this );
   result = SecurityDataToDevice( protocolID, spSpecific, dataToSend );
   if ( M_DtaSuccess( result ) )
   {
      result = SecurityDataFromDevice( protocolID, spSpecific, dataToRecv );
   }
   return result;
}

DTA_ERROR CDriveTrustSession::StopUnit(dta::tBytes &dataToRecv)
{
   return Error(eGenericNotImplemented);
}

DTA_ERROR CDriveTrustSession::StartUnit(dta::tBytes &dataToRecv)
{
   return Error(eGenericNotImplemented);
}

DTA_ERROR CDriveTrustSession::Destroy()
{
   M_DriveTrustBaseTry()
   {
      // TODO : Release authentications against the
      //        device.  For SeaCOS devices, this means
      //        issuing a WARM RESET command.

      // Now, allow the base class to delete the object.
      CDriveTrustBase::Destroy();
   }
   // Destroy will delete the 'this' operator.  The
   // normal macros wrapping catch aren't safe to
   // use because they may attempt to access 'this'.
   catch( const dta::DTA_ERROR& err )
   {
      __result = err;
   }
   if ( M_DtaFail( __result ) && __throwOnError )
   {
      throw __result;
   }
   return __result;
}

CDevice::CDevice(const dta::DTIdentifier deviceIdentifier, tUINT8 protocol) :
                           m_identifier(deviceIdentifier), m_protocol(protocol), m_session(NULL)
{
} // CDevice

CDevice::~CDevice()
{
   if (m_session)
   {
      m_session->Destroy();
      m_session = NULL;
   }
} // ~CDevice

_tstring CDevice::serialNumber()
{
   if (!m_serialNumber.size())
   {
      // Create a session temporarily, if one has not been created
      bool hasSession = (m_session != NULL);
      if (!hasSession)
      {
         session();
      }

      try
      {
         m_session->GetAttribute(TXT("SerialNumber"), m_serialNumber);
      }
      catch (...)
      {
         m_serialNumber = TXT("Unknown Serial Number");
      }
      
      // Clean up if we had to create a session
      if (!hasSession)
      {
         m_session->Destroy();
         m_session = NULL;
      }
   } // if
   return m_serialNumber;
} // serialNumber

_tstring CDevice::protocolTag()
{
   if (!m_protocolTag.size())
   {
      m_protocolTag = m_identifier.substr(0, m_identifier.find_first_of(':') + 1);
   } // if

   return m_protocolTag;
} // protocolTag

dta::CDriveTrustSession* CDevice::session()
{
   if (m_session == NULL)
   {
      dta::CLocalSystem* localSystem;
      try
      {
         M_DtaSuccess(dta::CreateLocalSystemObject(localSystem));
         localSystem->CreateSession(m_identifier, m_protocol, TXT(""), m_session);
         localSystem->Destroy();
         localSystem = NULL;

         // If this is an ATA device, set the op-codes to DMA, if supported
         if (protocolTag() == BUS_TYPE_ATA)
         {
            // If the ATA device supports protocol 0x00, then it also supports TS/TR DMA mode on Seagate drives.
            supportedSecurityProtcols();
            if (m_supportedSecurityProtocols.size() && (m_supportedSecurityProtocols[0] == 0x00))
            {
               ata::CAta* pATA = dynamic_cast<ata::CAta*>(m_session);
               pATA->SetTrustedOpcodes(ata::evTrustedSendDMA, ata::evTrustedReceiveDMA);
            } // if
         } // if
      } // try
      catch (const dta::DTA_ERROR&)
      {
         localSystem->Destroy();
      }
   } // if
   return m_session;
} // CDevice

std::vector<tUINT8> CDevice::supportedSecurityProtcols()
{
   // Check if we've already populated this list
   if (m_supportedSecurityProtocols.size() == 0)
   {
      // Create a session temporarily, if one has not been created
      bool hasSession = (m_session != NULL);
      if (!hasSession)
      {
         session();
      } // if

      dta::tBytes receiveBuffer(512);
      try
      {
         // First, see if protocol 0 works
         m_session->SecurityDataFromDevice(0x00, 0x0000, receiveBuffer);

         // Now parse the list returned
         tUINT16 protocolListLength = (tUINT16) receiveBuffer[7];
         protocolListLength        |= (tUINT16)(receiveBuffer[6] << 8);
         m_supportedSecurityProtocols.clear(); // cleanup on ATA drives
         
         // Make sure we get back a valid length of protocols to read first
         if ((protocolListLength + 8) < (tUINT16)receiveBuffer.size())
         {
            for (unsigned int i = 0; i < protocolListLength; i++)
            {
               m_supportedSecurityProtocols.push_back(receiveBuffer[8 + i]);
            } // for
         }
      } // try
      catch(...)
      {
         // Might be a Cody (which doesn't support Protocol 0)
         _tstring modelNumber;
         try
         {
            m_session->GetAttribute( TXT("ProductIdentification"), modelNumber );

            // Check to see if it matches a Cody model number
            if ((modelNumber == TXT("ST9160824AS")) ||
                (modelNumber == TXT("ST9120827AS")) ||
                (modelNumber == TXT("ST980816AS")))
            {
               m_supportedSecurityProtocols.push_back(dta::eSPSeaCOS);
            } // if
         } // try
         catch (...)
         {
            // Do nothing, it doesn't support security...
         } // catch
      } // catch
      
      // Clean up if we had to create a session
      if (!hasSession)
      {
         m_session->Destroy();
         m_session = NULL;
      }
   } // if

   return m_supportedSecurityProtocols;
} // supportedSecurityProtcols

bool dta::isTransportSupported(const tUINT16 transportProtocol, const _tstring identifier)
{
   // If no transport protocol filter is given, then just return true
   if (transportProtocol)
   {
      // Get the protocol tag from the front of the identifier string (i.e. "ATA:")
      _tstring protocolTag = identifier.substr(0, identifier.find_first_of(':') + 1);

      return (((transportProtocol & TRANSPORT_PROTOCOL_BIT_ATA ) && (protocolTag == BUS_TYPE_ATA )) ||
              ((transportProtocol & TRANSPORT_PROTOCOL_BIT_SCSI) && (protocolTag == BUS_TYPE_SCSI)) ||
              ((transportProtocol & TRANSPORT_PROTOCOL_BIT_USB ) && (protocolTag == BUS_TYPE_USB )) ||
              ((transportProtocol & TRANSPORT_PROTOCOL_BIT_1394) && (protocolTag == BUS_TYPE_1394)) ||
              ((transportProtocol & TRANSPORT_PROTOCOL_BIT_RAID) && (protocolTag == BUS_TYPE_RAID)) ||
              ((transportProtocol & TRANSPORT_PROTOCOL_BIT_ES  ) && (protocolTag == BUS_TYPE_ES  )));
   }
   return true;
} // isTransportSupported

bool dta::isSecuritySupported(const tUINT16 securityProtocol, const std::vector<tUINT8> supportedSecurityProtocols)
{
   bool supported = (securityProtocol == 0);

   // If no filter is given (securityProtocol is 0), the just return true
   if (securityProtocol)
   {
      // Test each of the supported security protocols to see if it matches the filter
      for (unsigned int i = 0; i < supportedSecurityProtocols.size(); i++)
      {
         if (((securityProtocol & SECURITY_PROTOCOL_BIT_TCG     ) && (supportedSecurityProtocols[i] == eSPTCG     )) ||
             ((securityProtocol & SECURITY_PROTOCOL_BIT_IEEE1667) && (supportedSecurityProtocols[i] == eSPIEEE1667)) ||
             ((securityProtocol & SECURITY_PROTOCOL_BIT_SEACOS  ) && (supportedSecurityProtocols[i] == eSPSeaCOS  )))
         {
            // If we found a supported protocol, break the loop and return true
            supported = true;
            break;
         } // if
      } // for
   } // if

   return supported;
} // isSecuritySupported

std::vector<dta::CDevice> dta::GetDevices(const tUINT16 transportProtocol, const tUINT16 securityProtocol, const _tstring logFile)
{
   // Get the list of device identifiers
   dta::CLocalSystem* localSystem;
   M_DtaSuccess(dta::CreateLocalSystemObject(localSystem));
   dta::DTIdentifierCollection identifiers;
   localSystem->GetDriveTrustIdentifiers(identifiers, TXT("-bustype SCSI"), logFile);
   localSystem->Destroy();

    printf("***********dta::GetDevices*******\n");
   // Now loop through the devices, and find the transports we're looking for
   std::vector<CDevice> devices;
   while (!identifiers.empty())
   {
      // Create a CDevice object
      const dta::DTIdentifier id = identifiers.front();
      identifiers.pop_front();
      CDevice device(id);

      // See if it matches both the transport and security protocol filters
      if (isTransportSupported(transportProtocol, id) &&
          isSecuritySupported(securityProtocol, device.supportedSecurityProtcols()))
      {
         devices.push_back(device);
      } // if
   } // while

   return devices;
} // GetDevices

_tstring dta::Trim( const _tstring& str, bool trimLeft, bool trimRight )
{
   // As a favor, trim spaces from right and/or left.
   _tstring::const_iterator front = str.begin(), back = str.end();
   if ( trimLeft )
   {
      for ( front = str.begin(); 
         front != str.end() && isspace( *front ); 
         front++ )
      {
         // Do nothing!
      }
   }
   if ( trimRight )
   {
      for ( back = str.end(); 
         --back >= front && isspace( *back ); 
         )
      {
         // Do nothing!
      }
      ++back;
   }
   return _tstring( front, back );
}
