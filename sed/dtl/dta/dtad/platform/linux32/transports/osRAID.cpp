/*! \file osRAID.cpp
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
#include "osRAID.hpp"
#include <assert.h>
#include <dta/numstr.hpp>

using namespace dtad;
using namespace ata;

/****************************************************************************/
/* macro/variable definitions                                               */
/****************************************************************************/
static CSMI_SAS_STP_PT_WITH_BUFFER  stPTBuff; // Buffer for doing Pass-Thru Ops
static int                          iDrive = 0;        // Number of CSMI drives present
                                                        // that support S.M.A.R.T.
static int                          iDrives = 0;  
static DRIVE_DATA                   stDriveData[SMART_MAX_DRIVES];// Info we need for
static DWORD                        dwReturned;
static DRIVE_ERROR                  stStatus;
//=================================
// function implementations
//=================================

//=================================
// support functions
//=================================

tBOOL CSMIInitialize( int *piDrives ) // nvn20110628
{
//   char        szDrive[16];
#if 0 // TODO: // nvn20110628 - RAID/SCSI drive
   int myDrives;
   unsigned    uPrevErrorMode = SetErrorMode( SEM_FAILCRITICALERRORS );
   if( !piDrives )
   {
       SetLastError( ERROR_INVALID_PARAMETER );
       return( FALSE );
   }
   
   if ( iDrives > 0)
   {
      for( iDrive = 0, myDrives = 0; iDrive < iDrives; iDrive++, myDrives++)
      {      
        CloseHandle( stDriveData[iDrives].hDevice ); 
        stDriveData[iDrive].hDevice = 0x00;
      }   
   }
   myDrives = 0;
   int myController = 0;
   int iPort = 0;
   iDrives = 0;
   for( iDrives; iDrives < SMART_MAX_DRIVES; iDrives++ )
   {
      // Attach to the controller
#if 0
      sprintf( szDrive, "\\\\.\\SCSI%d:", iDrives );
      wchar_t file[11];
      file[10] = '\0';
      mbstowcs(file, szDrive, strlen(szDrive));
#else
      _TCHAR file[11];
      _stprintf_s( file, sizeof(file)/sizeof(file[0]), __T("\\\\.\\SCSI%d:"), iDrives );
      file[10] = __T('\0');
#endif
      stDriveData[myDrives].hDevice = CreateFile( file, GENERIC_READ | GENERIC_WRITE,
                                                  FILE_SHARE_READ | FILE_SHARE_WRITE,
                                                  NULL, OPEN_EXISTING, 0, NULL );
      if ( iDrives == 0 )
      {
          stDriveData[myController].hDevice = stDriveData[myDrives].hDevice;
      }
      if( stDriveData[myDrives].hDevice == INVALID_HANDLE_VALUE )
      {
         stDriveData[iDrives].hDevice = stDriveData[myDrives].hDevice;
         memcpy(stDriveData[iDrives].bySASAddress, stDriveData[myDrives].bySASAddress, sizeof(stDriveData[myDrives].bySASAddress));  
         break; 
      }
      else
      {
         stDriveData[iDrives].hDevice = stDriveData[myController].hDevice;
         memcpy(stDriveData[iDrives].bySASAddress, stDriveData[myDrives].bySASAddress, sizeof(stDriveData[myDrives].bySASAddress));  
         stDriveData[iDrives].bySASAddress[CSMI_SAS_ADDRESS_PORT_ID] = iPort;
      }
      myDrives++;
      iPort++;
   }
   *piDrives = myDrives;
#endif
   return( 1 ); // nvn20110628
   //}
}


//=================================
// class implementations
//=================================

COSDTSessionRAID::COSDTSessionRAID()
: COSDTSession()
{
   m_supportedAttributes.push_back( txtProduct   );
   m_supportedAttributes.push_back( txtProdRev   );
   m_supportedAttributes.push_back( txtSerialNum );
   m_supportedAttributes.push_back( txtTransport );
}

dta::DTA_ERROR COSDTSessionRAID::SecurityDataToDevice( 
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

dta::DTA_ERROR COSDTSessionRAID::SecurityDataFromDevice( 
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

dta::DTA_ERROR COSDTSessionRAID::SecurityDataToDevice( 
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

dta::DTA_ERROR COSDTSessionRAID::SecurityDataFromDevice( 
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

size_t COSDTSessionRAID::GetBlockSize()
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

dta::DTA_ERROR COSDTSessionRAID::AcquireTFR( 
   CTfr* &pTFR, 
   etAddressMode addressMode 
   )
{
   M_DriveTrustBaseTry()
   {
      try
      {
         pTFR = new dtad::CTfrRAID( addressMode );
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

dta::DTA_ERROR COSDTSessionRAID::ReleaseTFR( 
   CTfr* pTFR
   )
{
   M_DriveTrustBaseTry()
   {
      try
      {
         if ( NULL == dynamic_cast<dtad::CTfrRAID*>(pTFR) )
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

dta::DTA_ERROR COSDTSessionRAID::Execute( 
   ata::CTfr* pTFR,
   dta::tBytes& buffer,
   size_t timeout,
   ata::etProtocol protocol,
   ata::etDataDirection direction
   )
{
   M_DriveTrustBaseTry()
   {
      dtad::CTfrRAID* myTfr = dynamic_cast<dtad::CTfrRAID*>(pTFR);
      if ( NULL == myTfr )
      {
         // Whatever this is, it's not our TFR.
         throw AddLogEntry(
            dta::Error( dta::eGenericInvalidParameter ),
            TXT("Command terminated, TFR object not recognized.")
            );
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

      int iDriveCount;
      tOSError error = 0L; //ERROR_SUCCESS; // nvn20110682
      if( !CSMIInitialize( &iDriveCount ) )
      {
        throw AddLogEntry(
            dta::Error( dta::eGenericInvalidParameter ),
            TXT("Command terminated, Could not Initialize RAID devices")
            );
      }   
      iDrive = int(this->m_deviceName[8]) - 48;

      pstCmdFIS = (H2D_RFIS *)stPTBuff.stPTB.Parameters.bCommandFIS;
      pstRspFIS = (D2H_RFIS *)stPTBuff.stPTB.Status.bStatusFIS;
  
      // Setup the IOCTL for a CSMI Pass-Thru operation   

      memset( &stPTBuff, 0, sizeof(CSMI_SAS_STP_PT_WITH_BUFFER) );
 
      stPTBuff.stPTB.IoctlHeader.HeaderLength   = sizeof(IOCTL_HEADER);
      stPTBuff.stPTB.IoctlHeader.Timeout        = CSMI_SAS_TIMEOUT;
      stPTBuff.stPTB.IoctlHeader.ControlCode    = CC_CSMI_SAS_STP_PASSTHRU;
   
      memcpy( stPTBuff.stPTB.IoctlHeader.Signature, CSMI_SAS_SIGNATURE, sizeof(CSMI_SAS_SIGNATURE) );
                                                 
      stPTBuff.stPTB.Parameters.bPhyIdentifier  = stDriveData[iDrive].bySASAddress[CSMI_SAS_ADDRESS_PORT_ID];
      
      memcpy( stPTBuff.stPTB.Parameters.bDestinationSASAddress, stDriveData[iDrive].bySASAddress, 8 );
      // Setup the Frame Information Structure (FIS) for the Operation
 

      // The Marvell bridge uses the high-order bit of LBA
      // to determine if the data direction for unknown
      // commands is to disk or to host.
#if 0 // TODO: // nvn20110628 - RAID/SCSI/FIS specific windows drive
      pstCmdFIS->Command         = myTfr->m_curRegs->bCommandReg;
      pstCmdFIS->CylinderHigh    = myTfr->m_curRegs->bCylHighReg;
      pstCmdFIS->CylinderHighExp = myTfr->m_prevRegs->bCylHighReg;
      pstCmdFIS->CylinderLow     = myTfr->m_curRegs->bCylLowReg;
      pstCmdFIS->CylinderLowExp  = myTfr->m_prevRegs->bCylLowReg;
      pstCmdFIS->SectorNumber    = myTfr->m_curRegs->bSectorNumberReg;
      pstCmdFIS->SectorNumberExp = myTfr->m_prevRegs->bSectorNumberReg;
      pstCmdFIS->DeviceHead      = myTfr->m_curRegs->bDriveHeadReg;
      pstCmdFIS->Features        = myTfr->m_curRegs->bFeaturesReg;
      pstCmdFIS->SectorCount     = myTfr->m_curRegs->bSectorCountReg;
      pstCmdFIS->SectorCountExp  = myTfr->m_prevRegs->bSectorCountReg;
      pstCmdFIS->FisType         = FIS_TYPE_REG_H2D;  
#endif
      ATA_PASS_THROUGH_DIRECT *paptd = static_cast<ATA_PASS_THROUGH_DIRECT*>(
         myTfr->Prepare( buffer, timeout, protocol, direction ));

      if ( direction == evDataOut )
      {
         stPTBuff.stPTB.Parameters.uFlags = CSMI_SAS_STP_WRITE;
         memcpy( &stPTBuff.stPTB.bDataBuffer[0], &buffer[0], buffer.size() );
      }
      else
      {
         stPTBuff.stPTB.Parameters.uFlags = CSMI_SAS_STP_READ;

      }
      if ( protocol == evPIO )
      {
         stPTBuff.stPTB.Parameters.uFlags |= CSMI_SAS_STP_PIO;
      }
      else
      {
         stPTBuff.stPTB.Parameters.uFlags |= CSMI_SAS_STP_DMA;
      }

#ifdef BUILD_FOR_MARVELL_SEACOS
      //
      // SJ 03/19/2009: The following "adaption" for Marvell chip is conflicting with the definition and use of
      // the TCG's SP Specefic word and MS1667's SiloIndex/FunctionId, set in LBA-high and LBA-mid, by changing
      // bit15 of the field.
      //
      // This section, if necessary, should be put under Marvell-unique, rather than commonly applied, for the SeaCOS.
      // Marvell should have provided an TrustedOpCode-aware version of their firmware and re-flash the chip. They may already have.

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

      stPTBuff.stPTB.Parameters.uDataLength     = (DWORD) buffer.size();
      stPTBuff.stPTB.IoctlHeader.Length         = (DWORD) (sizeof(CSMI_SAS_STP_PASSTHRU_BUFFER) - 1 - sizeof(IOCTL_HEADER) + buffer.size() );
#if 0 // TODO: // nvn20110628 - RAID/SCSI/FIS specific windows drive
      if( !DeviceIoControl( stDriveData[iDrive].hDevice, IOCTL_SCSI_MINIPORT, &stPTBuff, sizeof(CSMI_SAS_STP_PT_WITH_BUFFER),
                            &stPTBuff, sizeof(CSMI_SAS_STP_PT_WITH_BUFFER), &dwReturned, NULL ) )
      {
         throw AddLogEntry(
            dta::Error( static_cast<tOSError>(errno) ), // nvn20110628
            TXT("Error from IOCTL_SCSI_MINIPORT")
            );  
      }
#endif
      if( stPTBuff.stPTB.IoctlHeader.ReturnCode || stPTBuff.stPTB.Status.bConnectionStatus || (pstRspFIS->Status & 0x01) )
      {
         if ( pstRspFIS->Status & 0x01 )
         {
            // Drive reported an error!
            tUINT16 error = pstRspFIS->Error;
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
      if ( stPTBuff.stPTB.Status.uDataBytes > 0 )
      {
        memcpy( &buffer[0], stPTBuff.stPTB.bDataBuffer, stPTBuff.stPTB.Status.uDataBytes );
      }
   }
   M_DriveTrustBaseSimpleEndTry()
}


dta::DTA_ERROR COSDTSessionRAID::GetAttribute(
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
         ata::CAta::GetProductIdentification();
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
      else
      {
         COSDTSession::GetAttribute(
            attribute, value );
      }
   }

   M_DriveTrustBaseSimpleEndTry()
}

dta::DTA_ERROR COSDTSessionRAID::SetAttribute(
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
