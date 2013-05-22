/*! \file osATAPT.cpp
    \brief Windows-specific implementation of COSLocalSystemObject.

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
#include "osATAPT.hpp"
#include <sstream>
#include <assert.h>
#include <dta/numstr.hpp>

using namespace dtad;
using namespace ata;

//=================================
// macro/constant definitions
//=================================
/// The maximum length of an auto-sense buffer.  
/// This length was specified
/// in the SPC-3 specification from T10.
static const size_t SPC3_SENSE_LEN   = 252;

//=================================
// typedefs and structures
//=================================

//=================================
// function implementations
//=================================

//=================================
// class implementations
//=================================

COSDTSessionATAPT::COSDTSessionATAPT()
: COSDTSession()
{
   m_supportedAttributes.push_back( txtProduct   );
   m_supportedAttributes.push_back( txtProdRev   );
   m_supportedAttributes.push_back( txtSerialNum );
   m_supportedAttributes.push_back( txtTransport );
   m_supportedAttributes.push_back( txtVendor    );  // jls 20120816
}

dta::DTA_ERROR COSDTSessionATAPT::SecurityDataToDevice( 
   const dta::tBytes &dataToSend 
   )
{
   M_DriveTrustBaseTry()
   {
      dta::CSessionAutoLock<dta::eLockTypeTxRx> lock( this );
      ata::CAta::SecurityDataToDevice(
         dataToSend,
         m_protocolID,
         m_spSpecific
         );
   }
   M_DriveTrustBaseSimpleEndTry()
}

dta::DTA_ERROR COSDTSessionATAPT::SecurityDataFromDevice( 
      dta::tBytes &dataToRecv
      )
{
   M_DriveTrustBaseTry()
   {
      dta::CSessionAutoLock<dta::eLockTypeTxRx> lock( this );
      ata::CAta::SecurityDataFromDevice(
         dataToRecv,
         m_protocolID,
         m_spSpecific
         );
   }
   M_DriveTrustBaseSimpleEndTry()
}

dta::DTA_ERROR COSDTSessionATAPT::SecurityDataToDevice( 
      tUINT8 protocolID,
      tUINT16 spSpecific,
      const dta::tBytes &dataToSend
   )
{
   M_DriveTrustBaseTry()
   {
      dta::CSessionAutoLock<dta::eLockTypeTxRx> lock( this );
      ata::CAta::SecurityDataToDevice(
         dataToSend,
         protocolID,
         spSpecific
         );
   }
   M_DriveTrustBaseSimpleEndTry()
}

dta::DTA_ERROR COSDTSessionATAPT::SecurityDataFromDevice( 
      tUINT8 protocolID,
      tUINT16 spSpecific,
      dta::tBytes &dataToRecv 
      )
{
   M_DriveTrustBaseTry()
   {
      dta::CSessionAutoLock<dta::eLockTypeTxRx> lock( this );
      ata::CAta::SecurityDataFromDevice(
         dataToRecv,
         protocolID,
         spSpecific
         );
   }
   M_DriveTrustBaseSimpleEndTry()
}

size_t COSDTSessionATAPT::GetBlockSize()
{
   size_t blockSize = 0;
   M_DriveTrustBaseTry()
   {
      blockSize = ata::CAta::GetBlockSize();
   }
   M_DriveTrustBaseCatch()

   // Always throw on error.  Our return code
   // is actually the block size.
   if (!M_DtaSuccess(__result))
   {
      throw __result;
   }
   return blockSize;
}

dta::DTA_ERROR COSDTSessionATAPT::AcquireTFR( 
   CTfr* &pTFR, 
   etAddressMode addressMode 
   )
{
   M_DriveTrustBaseTry()
   {
      try
      {
         pTFR = new dtad::CTfrATAPT( addressMode );
      }
      catch ( std::bad_alloc const& )
      {
         throw AddLogEntry(
            dta::Error( dta::eGenericMemoryError ),
            TXT("TFR allocation failed.")
            );
      }
   }
   M_DriveTrustBaseSimpleEndTry()
}

dta::DTA_ERROR COSDTSessionATAPT::ReleaseTFR( 
   CTfr* pTFR
   )
{
   M_DriveTrustBaseTry()
   {
      try
      {
         if ( NULL == dynamic_cast<dtad::CTfrATAPT*>(pTFR) )
         {
            // Whatever this is, it's not our TFR.
            throw AddLogEntry(
               dta::Error( dta::eGenericInvalidParameter ),
               TXT("ReleaseTFR() failed, TFR object not recognized.")
               );
         }
         delete pTFR;
      }
      catch ( ... )
      {
         throw dta::Error( dta::eGenericMemoryError );
      }
   }
   M_DriveTrustBaseSimpleEndTry()
}

dta::DTA_ERROR COSDTSessionATAPT::Execute( 
   ata::CTfr* pTFR,
   dta::tBytes& buffer,
   size_t timeout,
   ata::etProtocol protocol,
   ata::etDataDirection direction
   )
{
   M_DriveTrustBaseTry()
   {
      dtad::CTfrATAPT* myTfr = dynamic_cast<dtad::CTfrATAPT*>(pTFR);
      if ( NULL == myTfr )
      {
         // Whatever this is, it's not our TFR.
         throw AddLogEntry(
            dta::Error( dta::eGenericInvalidParameter ),
            TXT("Command terminated, TFR object not recognized.")
            );
      }

      if ( 0 == timeout )
      {
         timeout = m_timeout;
      }

      // You need the block size to validate the buffer size.  However,
      // you can't use the block size until you've successfully issued
      // an IDENTIFY command.  As a result, if the block size is not
      // available, we default it to 512 bytes.
      size_t blockSize = m_blockSize ? m_blockSize : 512;

      if ( buffer.size() % blockSize )
      {
         // Oops, not a multiple of the block size.  We can't do it.
         throw AddLogEntry(
            dta::Error( dta::eGenericInvalidParameter ),
            TXT("Command terminated, buffer not a multiple of block size.")
            );
      }

#ifdef BUILD_FOR_MARVELL_SEACOS
      //
      // SJ 03/19/2009: The following "adaption" for Marvell chip is conflicting with the definition and use of
      // the TCG's SP Specefic word and MS1667's SiloIndex/FunctionId, set in LBA-high and LBA-mid, by changing
      // bit15 of the field.
      //
      // This section, if necessary, should be put under Marvell-unique, rather than commonly applied, for the SeaCOS.
      // Marvell should have provided an TrustedOpCode-aware version of their firmware and re-flash the chip. They may already have.

      // The Marvell bridge uses the high-order bit of LBA
      // to determine if the data direction for unknown
      // commands is to disk or to host.
      switch ( myTfr->GetCommandStatus() )
      {
      case evTrustedSend:
      case evTrustedSendDMA:
      case evTrustedSendSeagateLegacy:
         myTfr->SetLBAHigh( myTfr->GetLBAHigh() & 0x7F );
         break;
      case evTrustedReceive:
	  case evTrustedReceiveDMA:
      case evTrustedReceiveSeagateLegacy:
         myTfr->SetLBAHigh( myTfr->GetLBAHigh() | 0x80 );
         break;
      default:
         break;
      }
#endif

      ATA_PASS_THROUGH_DIRECT *paptd = static_cast<ATA_PASS_THROUGH_DIRECT*>(
         myTfr->Prepare( buffer, timeout, protocol, direction ));
      DWORD aptdSize = sizeof(ATA_PASS_THROUGH_DIRECT);

      DWORD bytesReturned = 0;
      if (!DeviceIoControl( M_OsDevice,
            IOCTL_ATA_PASS_THROUGH_DIRECT,
            paptd, sizeof(ATA_PASS_THROUGH_DIRECT),
            paptd, sizeof(ATA_PASS_THROUGH_DIRECT),
            &bytesReturned, NULL ) )
      {
         throw AddLogEntry(
            dta::Error( static_cast<tOSError>(::GetLastError()) ),
            TXT("Error from IOCTL_ATA_PASS_THROUGH_DIRECT")
            );
      }

      if ( myTfr->GetCommandStatus() & 0x01 )
      {
         // Drive reported an error!
         tUINT16 error = myTfr->GetErrorFeature();
         if ( 0x02 & error )
         {
            throw AddLogEntry(
               dta::Error( dta::eDirectFatalError ),
               TXT("Device reported No Media (NM)")
               );
         }
         else if ( 0x04 & error )
         {
            throw AddLogEntry(
               dta::Error( dta::eDirectDeviceAbort ),
               TXT("Device reported Command Aborted (ABRT)")
               );
         }
         else if ( 0x10 & error )
         {
            throw AddLogEntry(
               dta::Error( dta::eDirectDeviceAddressNotFound ),
               TXT("Device reported address not found (IDNF)")
               );
         }
         else if ( 0x40 & error )
         {
            throw AddLogEntry(
               dta::Error( dta::eDirectFatalError ),
               TXT("Device reported data uncorrectable (UNC)")
               );
         }
         else
         {
            throw AddLogEntry(
               dta::Error( dta::eDirectFatalError ),
               TXT("Device reported error, but abort bit not set")
               );
         }
      }
   }
   M_DriveTrustBaseSimpleEndTry()
}


dta::DTA_ERROR COSDTSessionATAPT::GetAttribute(
   const _tstring& attribute,
   _tstring& value
   )
{
   M_DriveTrustBaseTry()
   {
      if ( txtBlockSize == attribute )
      {
         numstr( value, GetBlockSize() );
      }
      else if ( txtCapacity == attribute )
      {
         numstr( value, ata::CAta::GetCapacityInBytes() );
      }
      else if ( txtProduct == attribute )
      {
         value = ata::CAta::GetProductIdentification();
      }
      else if ( txtProdRev == attribute )
      {
         value = ata::CAta::GetProductRevisionLevel();
      }
      else if ( txtSerialNum == attribute )
      {
         value = ata::CAta::GetSerialNumber();
      }
      else if ( txtTransport == attribute )
      {
         value = txtATA;
      }
      else if ( txtVendor == attribute )     // jls 20120816  TXT("")
      {
         value = ata::CAta::GetVendor();     // jls 20120816  TXT("")
      }
      else
      {
         COSDTSession::GetAttribute(
            attribute, value );
      }
   }

   M_DriveTrustBaseSimpleEndTry()
}

dta::DTA_ERROR COSDTSessionATAPT::SetAttribute(
   const _tstring& attribute,
   const _tstring& value
   )
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
      else if ( txtTransport == attribute )
      {
         // Can't change the transport.
         throw AddLogEntry(
            dta::Error( dta::eGenericAttributeReadOnly ),
            TXT("Error: Transport attribute may not be changed")
            );
      }
      else
      {
         COSDTSession::SetAttribute(
            attribute, value );
      }
   }
   M_DriveTrustBaseSimpleEndTry()
}