/*! \file osSAT.hpp
    \brief Implementation of CDriveTrustSession via the SAT transport.

    TODO : Detailed description
    
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

#ifndef XPORT_SAT_HPP
#define XPORT_SAT_HPP

// !defined __cplusplus
//=================================
// Include files
//=================================
#include "../osDTSession.hpp"
#include <dta/Ata.hpp>
#include <dta/Scsi.hpp>
//#include <dta/platform/win32/OSIncludes.h>
#include <dta/SATCDB.hpp> // nvn20110628
#include "LinuxIncludes.h" // nvn20110628

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
///        an application and a SAT-based DriveTrust device.
///
/// TODO : Detailed description
///
//
class COSDTSessionSAT : public COSDTSession, public ata::CAta, public dta::CScsi
{
public:
   /// Constructor.
   COSDTSessionSAT(bool useAtaPassThrough=true);

   //================================================================
   // Implementations of methods defined in CDriveTrustSession
   //================================================================
   virtual dta::DTA_ERROR SecurityDataToDevice( 
      const dta::tBytes &dataToSend 
      );
   virtual dta::DTA_ERROR SecurityDataFromDevice( 
      dta::tBytes &dataToRecv 
      );
   virtual dta::DTA_ERROR SecurityDataToDevice( 
      tUINT8 protocolID,
      tUINT16 spSpecific,
      const dta::tBytes &dataToSend
      );
   virtual dta::DTA_ERROR SecurityDataFromDevice( 
      tUINT8 protocolID,
      tUINT16 spSpecific,
      dta::tBytes &dataToRecv 
      );
   virtual dta::DTA_ERROR GetAttribute(
      const _tstring& attribute,
      _tstring& value
      );
   virtual dta::DTA_ERROR SetAttribute(
      const _tstring& attribute,
      const _tstring& value
      );
   virtual dta::DTA_ERROR StartUnit(
      dta::tBytes &dataToRecv
      );
   virtual dta::DTA_ERROR StopUnit(
      dta::tBytes &dataToRecv
      );
protected:
   //================================================================
   // Implementations of methods defined in CAta
   //================================================================
   virtual dta::DTA_ERROR AcquireTFR( 
      ata::CTfr* &pTFR, 
      ata::etAddressMode addressMode 
      );

   virtual dta::DTA_ERROR ReleaseTFR( ata::CTfr* pTFR );

   virtual dta::DTA_ERROR Execute( 
      ata::CTfr* pTFR,
      dta::tBytes& buffer,
      size_t timeout,
      ata::etProtocol protocol,
      ata::etDataDirection direction
      );

   //================================================================
   // Implementations of methods defined in CScsi
   //================================================================
   virtual void ExecScsiCdb( 
      const dta::tBytes& cdb,
      dta::tBytes& buffer,
      bool bufferToDevice
      );

   //================================================================
   //
   /// Resizes a buffer to contain a SCSI_PASS_THROUGH_DIRECT
   /// structure with data and initializes the buffer with default
   /// values.
   ///
   /// In case of error, this method will throw a DTA_ERROR as an
   /// exception.  In most cases, this will be caught by methods
   /// above and either rethrown or returned as an error code.
   ///
   /// \param buffer - (IN,OUT)
   ///      A data buffer that will be resized and contains the
   ///      data pointed to by the return value.
   ///
   /// \param cdb - (IN)
   ///      A buffer containing the CDB to be used.  It will be
   ///      copied and placed in the structure as appropriate.
   ///
   /// \param dataDirection - (IN)
   ///      The direction of data transfer.  Valid values are as
   ///      follows:
   ///      SCSI_IOCTL_DATA_OUT
   ///      SCSI_IOCTL_DATA_IN
   ///      SCSI_IOCTL_DATA_UNSPECIFIED
   ///
   /// \param dataBytes - (IN)
   ///      The number of data bytes required for transfer in the
   ///      buffer.  The buffer member will be resized to contain
   ///      enough bytes for the structure, any alignment requirement,
   ///      and the data.
   ///
   /// \return A pointer to the beginning of the SCSI_PASS_THROUGH_DIRECT
   ///      data.  It will be aligned on a tUINT64 boundary.
   ///
   /// @pre  None
   ///
   /// @post None
   //
   //================================================================
   PSCSI_PASS_THROUGH_DIRECT InitScsiPassThruDirectBuffer(
      dta::tBytes &buffer,
      const dta::tBytes &cdb,
      tUINT8 dataDirection,
      dta::tBytes::size_type dataBytes
      );

   //================================================================
   //
   /// Get the current block size for the device, interrogating
   /// the device if necessary.  A DTA_ERROR will be thrown in
   /// case of error.
   ///
   /// \return the block size.
   //
   //================================================================
   virtual size_t GetBlockSize();

   //================================================================
protected:
   sat::CAtaPassThru12CDB m_cdb;  //!< Default CDB.
   bool     m_useAtaPassThrough;    //!< Use IDENTIFY or INQUIRY for attributes
};

//=================================
// function definitions
//=================================

}  // end namespace dtad
#endif // XPORT_SAT_HPP
