/*! \file osSAT.cpp
    \brief Windows-specific implementation of COSLocalSystemObject.

    This implementation is specific to the Windows O/S.  It may include
    Windows-specific headers and definitions as necessary.
    
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

//=================================
// Include files
//=================================
#include <sstream>
#include "osSAT.hpp"
#include <assert.h>
#include <dta/numstr.hpp>
#include <dta/tfrSAT.hpp> // nvn20110628

using namespace dtad;
using namespace ata;

//=================================
// macro/constant definitions
//=================================
/// The maximum length of an auto-sense buffer.  
/// This length was specified
/// in the SPC-3 specification from T10.
static const size_t SPC3_SENSE_LEN   = 252;

#if defined (_WIN32) //TODO: // nvn20111007 - Remove it
//=================================
// typedefs and structures
//=================================

/// Alignment type.  This type is used only to force the 
/// compiler to align things on a particular boundary.
typedef tUINT64 tAlignment;

/// A Structure to align and place minimum requirements
/// for the SCSI_PASS_THROUGH_DIRECT structure, 
/// associated and aligned sense buffer, and associated
/// and aligned data buffer.
typedef struct EXT_SCSI_PASS_THROUGH_DIRECT
{
   SCSI_PASS_THROUGH_DIRECT sptd;   //!< MS passthru structure
   tAlignment reserved1;            //!< used to force alignment
   tUINT8     sense[SPC3_SENSE_LEN];//!< buffer for auto-sense data
   tAlignment reserved2;            //!< used to force alignment
   tUINT8     buffer[1];            //!< variable-length buffer for data
} *PEXT_SCSI_PASS_THROUGH_DIRECT;
#endif

//=================================
// function implementations
//=================================

//=================================
// class implementations
//=================================

COSDTSessionSAT::COSDTSessionSAT(bool useAtaPassThrough)
: COSDTSession()
, m_cdb()
, m_useAtaPassThrough( useAtaPassThrough )
{
   m_supportedAttributes.push_back( txtProduct   );
   m_supportedAttributes.push_back( txtProdRev   );
   m_supportedAttributes.push_back( txtSerialNum );
   m_supportedAttributes.push_back( txtTransport );
   m_supportedAttributes.push_back( txtVendor    );
}

void COSDTSessionSAT::ExecScsiCdb( 
   const dta::tBytes& cdb,
   dta::tBytes& buffer,
   bool bufferToDevice
   )
{
#if defined(_WIN32) //TODO: // nvn20110628 - REMOVE IT WIN32 SCSI - ATA specific
   dta::tBytes sptd_buffer;

   tUINT8 scsi_xfer = bufferToDevice
      ? ( buffer.size() ? SCSI_IOCTL_DATA_OUT : SCSI_IOCTL_DATA_UNSPECIFIED )
      : ( buffer.size() ? SCSI_IOCTL_DATA_IN  : SCSI_IOCTL_DATA_UNSPECIFIED )
      ;

   PSCSI_PASS_THROUGH_DIRECT psptd;
   psptd = InitScsiPassThruDirectBuffer(
      sptd_buffer, cdb, scsi_xfer, buffer.size() );

   DWORD bytesReturned = 0;
   DWORD bytesSent     = sizeof( EXT_SCSI_PASS_THROUGH_DIRECT );

   if ( bufferToDevice )
   {
      memcpy( psptd->DataBuffer, &buffer[0], buffer.size() );
   }
   else
   {
      memset( psptd->DataBuffer, 0xcd, psptd->DataTransferLength );
   }

   if (!DeviceIoControl( M_OsDevice,
         IOCTL_SCSI_PASS_THROUGH_DIRECT,
         psptd, bytesSent,
         psptd, bytesSent,
         &bytesReturned, NULL ) )
   {
      tOSError error = ::GetLastError();
      throw AddLogEntry(
         dta::Error( error ),
         TXT("Error from IOCTL_SCSI_PASS_THROUGH_DIRECT")
         );
   }

   switch ( psptd->ScsiStatus )
   {
   case 0:  // STATUS GOOD
      break;
   case 2:  // CHECK CONDITION
      throw AddLogEntry(
         dta::Error( dta::eDirectDeviceAbort ),
         TXT("Error: SCSI Check Condition received.")
         );
      break;
   default:
      throw AddLogEntry(
         dta::Error( dta::eDirectFatalError ),
         TXT("Error: Unknown value in SCSI Status field.")
         );
      break;
   }
   //
   // For device-to-host transfers, go and copy
   // the data back into our output.
   //
   if ( SCSI_IOCTL_DATA_IN == scsi_xfer )
   {
      if ( psptd->DataTransferLength > buffer.size() )
      {
         throw AddLogEntry(
            dta::Error( dta::eDirectFatalError ),
            TXT("Error: disk to host xfer length does not match.")
            );
      }
      memcpy( &buffer[0], psptd->DataBuffer, psptd->DataTransferLength );
   }
#else
   // nvn20110715
   tUINT8 sensep[32] = {0};
   tUINT8 cmnd[16] = {0};
   memcpy(&cmnd, &cdb[0], cdb.size());


   struct sg_io_hdr io_hdr;
   memset(&io_hdr, 0, sizeof(struct sg_io_hdr));
   io_hdr.interface_id = 'S';
   io_hdr.cmd_len = cdb.size(); //12;
   io_hdr.mx_sb_len = 32; //iop->max_sense_len;
   io_hdr.dxfer_len = buffer.size();//512; //iop->dxfer_len;

   //tUINT8 dxfertmp[1024] = {0};
   //if (bufferToDevice)
   //{
   //   memcpy(&dxfertmp, &buffer[0], buffer.size());
   //}
   //io_hdr.dxferp = dxfertmp;
   io_hdr.dxferp = &buffer[0];
   //io_hdr.dxferp = buffer;//iop->dxferp;

   io_hdr.cmdp = cmnd; //iop->cmnd;
   //io_hdr.cmdp = cdb; //iop->cmnd;

   io_hdr.sbp = sensep; //iop->sensep;
   /* sg_io_hdr interface timeout has millisecond units. Timeout of 0
   defaults to 60 seconds. */
   //io_hdr.timeout = 6000; //((0 == iop->timeout) ? 60 : iop->timeout) * 1000; // nvntry
   io_hdr.timeout = 500; // 5 seconds

   io_hdr.dxfer_direction = bufferToDevice ? SG_DXFER_TO_DEV : SG_DXFER_FROM_DEV;

   //iop->resp_sense_len = 0;
   //iop->scsi_status = 0;
   //iop->resid = 0;

   //timespec startTime, endTime;

   //clock_gettime(CLOCK_REALTIME, &startTime);
   int res = ioctl(M_OsDevice, SG_IO, &io_hdr);
   //clock_gettime(CLOCK_REALTIME, &endTime);
   if (res < 0)
   {
      printf("%d", res);
   }

#endif
}

dta::DTA_ERROR COSDTSessionSAT::SecurityDataToDevice( 
   const dta::tBytes &dataToSend 
   )
{
   M_DriveTrustBaseTry()
   {
      dta::CSessionAutoLock<dta::eLockTypeTxRx> lock( this );
      if ( m_useAtaPassThrough )
      {
         ata::CAta::SecurityDataToDevice(
            dataToSend,
            m_protocolID,
            m_spSpecific
            );
      }
      else
      {
         dta::CScsi::SecurityDataToDevice(
            dataToSend,
            m_protocolID,
            m_spSpecific
            );
      }
   }
   M_DriveTrustBaseSimpleEndTry()
}

dta::DTA_ERROR COSDTSessionSAT::SecurityDataFromDevice( 
      dta::tBytes &dataToRecv
      )
{
   M_DriveTrustBaseTry()
   {
      dta::CSessionAutoLock<dta::eLockTypeTxRx> lock( this );
      if ( m_useAtaPassThrough )
      {
         ata::CAta::SecurityDataFromDevice(
            dataToRecv,
            m_protocolID,
            m_spSpecific
            );
      }
      else
      {
         dta::CScsi::SecurityDataFromDevice(
            dataToRecv,
            m_protocolID,
            m_spSpecific
            );
      }
   }
   M_DriveTrustBaseSimpleEndTry()
}

dta::DTA_ERROR COSDTSessionSAT::SecurityDataToDevice( 
      tUINT8 protocolID,
      tUINT16 spSpecific,
      const dta::tBytes &dataToSend
      )
{
   M_DriveTrustBaseTry()
   {
      dta::CSessionAutoLock<dta::eLockTypeTxRx> lock( this );
      if ( m_useAtaPassThrough )
      {
         ata::CAta::SecurityDataToDevice(
            dataToSend,
            protocolID,
            spSpecific
            );
      }
      else
      {
         dta::CScsi::SecurityDataToDevice(
            dataToSend,
            protocolID,
            spSpecific
            );
      }
   }
   M_DriveTrustBaseSimpleEndTry()
}

dta::DTA_ERROR COSDTSessionSAT::SecurityDataFromDevice( 
      tUINT8 protocolID,
      tUINT16 spSpecific,
      dta::tBytes &dataToRecv 
      )
{
   M_DriveTrustBaseTry()
   {
      dta::CSessionAutoLock<dta::eLockTypeTxRx> lock( this );
      if ( m_useAtaPassThrough )
      {
         ata::CAta::SecurityDataFromDevice(
            dataToRecv,
            protocolID,
            spSpecific
            );
      }
      else
      {
         dta::CScsi::SecurityDataFromDevice(
            dataToRecv,
            protocolID,
            spSpecific
            );
      }
   }
   M_DriveTrustBaseSimpleEndTry()
}

size_t COSDTSessionSAT::GetBlockSize()
{
   size_t blockSize = 0;
   M_DriveTrustBaseTry()
   {
      if ( m_useAtaPassThrough )
      {
         blockSize = ata::CAta::GetBlockSize();
      }
      else
      {
         blockSize = dta::CScsi::GetBlockSize();
      }
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

dta::DTA_ERROR COSDTSessionSAT::AcquireTFR( 
   CTfr* &pTFR, 
   etAddressMode addressMode 
   )
{
   M_DriveTrustBaseTry()
   {
      try
      {
         pTFR = new sat::CTfr( addressMode );
      }
      catch ( std::bad_alloc const& )
      {
         throw dta::Error( dta::eGenericMemoryError );
      }
   }
   M_DriveTrustBaseSimpleEndTry()
}

dta::DTA_ERROR COSDTSessionSAT::ReleaseTFR( 
   CTfr* pTFR
   )
{
   M_DriveTrustBaseTry()
   {
      try
      {
         if ( NULL == dynamic_cast<sat::CTfr*>(pTFR) )
         {
            // Whatever this is, it's not our TFR.
            throw dta::Error( dta::eGenericInvalidParameter );
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

dta::DTA_ERROR COSDTSessionSAT::Execute( 
   ata::CTfr* pTFR,
   dta::tBytes& buffer,
   size_t timeout,
   ata::etProtocol protocol,
   ata::etDataDirection direction
   )
{
   M_DriveTrustBaseTry()
   {
      sat::CTfr* myTfr = dynamic_cast<sat::CTfr*>(pTFR);
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
      size_t blockSize = ata::CAta::m_blockSize ? ata::CAta::m_blockSize : 512;

      if ( buffer.size() % blockSize )
      {
         // Oops, not a multiple of the block size.  We can't do it.
         throw AddLogEntry(
            dta::Error( dta::eGenericInvalidParameter ),
            TXT("Command terminated, buffer not a multiple of block size.")
            );
      }

      tUINT8* ptr = (tUINT8*)myTfr->Prepare( 
         buffer, timeout, protocol, direction );

      // Copy our TFR to a tBytes, and send it off to be processed.
      dta::tBytes cdb;
      switch ( myTfr->GetAddressMode() )
      {
      case ata::ev48Bit:
         cdb.resize( 16 );
         break;
      case ata::ev28Bit:
         cdb.resize( 12 );
         break;
      default:
         throw AddLogEntry(
            dta::Error( dta::eGenericFatalError ),
            TXT("Error: Unknown ATA addressing mode")
            );
         break;
      }
      memcpy( &cdb[0], ptr, cdb.size() );
      ExecScsiCdb( cdb, buffer, evDataOut == direction );
   }
   M_DriveTrustBaseSimpleEndTry()
}

dta::DTA_ERROR COSDTSessionSAT::GetAttribute(
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
         m_useAtaPassThrough
         ?  numstr( value, ata::CAta::GetCapacityInBytes() )
         :  numstr( value, dta::CScsi::GetCapacityInBytes() )
         ;
      }
      else if ( txtProduct == attribute )
      {
         value = m_useAtaPassThrough
         ?  ata::CAta::GetProductIdentification()
         :  dta::CScsi::GetProductIdentification()
         ;
      }
      else if ( txtProdRev == attribute )
      {
         value = m_useAtaPassThrough
         ?  ata::CAta::GetProductRevisionLevel()
         :  dta::CScsi::GetProductRevisionLevel()
         ;
      }
      else if ( txtSerialNum == attribute )
      {
         value = m_useAtaPassThrough
         ?  ata::CAta::GetSerialNumber()
         :  dta::CScsi::GetSerialNumber()
         ;
      }
      else if ( txtTransport == attribute )
      {
         value = m_useAtaPassThrough
         ?  txtATA
         :  txtSCSI
         ;
      }
      else if ( txtVendor == attribute )
      {
         value = m_useAtaPassThrough
         ?  TXT("")
         :  dta::CScsi::GetVendor()
         ;
      }
      else
      {
         COSDTSession::GetAttribute(
            attribute, value );
      }
   }

   M_DriveTrustBaseSimpleEndTry()
}

dta::DTA_ERROR COSDTSessionSAT::SetAttribute(
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
         // For SAT (special case), you CAN change
         // the transport between SCSI and ATA.
         // throw dta::Error( dta::eGenericAttributeReadOnly );
         if ( _tstring(txtSCSI) == value )
         {
            m_useAtaPassThrough = false;
         }
         else if ( _tstring(txtATA) == value )
         {
            m_useAtaPassThrough = true;
         }
         else
         {
            throw AddLogEntry(
               dta::Error( dta::eGenericInvalidParameter ),
               TXT("Error: new Transport value not recognized")
               );
         }
      }
      else
      {
         COSDTSession::SetAttribute(
            attribute, value );
      }
   }
   M_DriveTrustBaseSimpleEndTry()
}

dta::DTA_ERROR COSDTSessionSAT::StartUnit(dta::tBytes &dataToRecv)
{
   M_DriveTrustBaseTry()
   {
      if (m_useAtaPassThrough)
      {
         ata::CAta::ReadVerifySectors(1, 0);
      }
      else
      {
         dta::CScsi::StartStopUnitCommand(dataToRecv, dta::ePowerConditionActivate);
      }
   }
   M_DriveTrustBaseSimpleEndTry()
} // StartUnit

dta::DTA_ERROR COSDTSessionSAT::StopUnit(dta::tBytes &dataToRecv)
{
   M_DriveTrustBaseTry()
   {
      if (m_useAtaPassThrough)
      {
         ata::CAta::StandbyImmediate();
      }
      else
      {
         dta::CScsi::StartStopUnitCommand(dataToRecv, dta::ePowerConditionStandby);
      }
   }
   M_DriveTrustBaseSimpleEndTry()
} // StopUnit

#if defined (_WIN32) //TODO: // nvn20110628 - REMOVE IT, WIN32 SCSI - ATA specific
PSCSI_PASS_THROUGH_DIRECT COSDTSessionSAT::InitScsiPassThruDirectBuffer(
   dta::tBytes &buffer,
   const dta::tBytes &cdb,
   tUINT8 dataDirection,
   dta::tBytes::size_type dataBytes
   )
{
   if (  ( 16 < cdb.size() )
      || ( static_cast<ULONG>(-1) < dataBytes )
      )
   {
      throw AddLogEntry(
         dta::Error( dta::eGenericInvalidParameter ),
         TXT("Error: CDB size or data byte count incorrect")
         );
   }


   buffer.clear();   // Drop any existing elements
   buffer.resize( dataBytes
      + sizeof(EXT_SCSI_PASS_THROUGH_DIRECT)
      + sizeof(tAlignment)
      - 1 // EXT_SCSI_PASS_THROUGH_DIRECT includes one byte for data
      , 0 );         // Resize, set all elements to zero.

   PEXT_SCSI_PASS_THROUGH_DIRECT pExtSptd = 
      static_cast<PEXT_SCSI_PASS_THROUGH_DIRECT>(
      M_AlignPtr( &buffer[0], sizeof(tAlignment) )
      );

   PSCSI_PASS_THROUGH_DIRECT pSptd = &(pExtSptd->sptd);

   pSptd->Length = sizeof( SCSI_PASS_THROUGH_DIRECT );
   pSptd->ScsiStatus = 0xFF; // Initial (should be bogus) result
   // pSptd->PathId;         // Not needed : left at zero
   // pSptd->TargetId;       // Not needed : left at zero
   // pSptd->Lun;            // Not needed : left at zero
   pSptd->CdbLength          = static_cast<UCHAR>(cdb.size());
   pSptd->SenseInfoLength    = SPC3_SENSE_LEN;
   pSptd->DataIn             = dataDirection;
   pSptd->DataTransferLength = static_cast<ULONG>(dataBytes);
   pSptd->TimeOutValue       = m_timeout;
   pSptd->DataBuffer         = &pExtSptd->buffer[0];
   pSptd->SenseInfoOffset    = static_cast<ULONG>(pExtSptd->sense-(BYTE*)pSptd);
   memcpy( pSptd->Cdb, &cdb[0], cdb.size() );

   return pSptd;
}
#endif
