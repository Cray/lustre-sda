/*! \file SCSI.cpp
    \brief Definition of SCSI basic functionality.

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

#ifndef DTA_SCSI_HPP
#define DTA_SCSI_HPP

// !defined __cplusplus
//=================================
// Include files
//=================================
#include "dta.hpp"

namespace dta {
//=================================
// macro definitions
//=================================

//=================================
// constants
//=================================

//=================================
// typedefs and structures
//=================================
typedef enum ePowerCondition
{
   ePowerConditionStartValid     = 0x00,
   ePowerConditionActivate       = 0x01,
   ePowerConditionIdle           = 0x02,
   ePowerConditionStandby        = 0x03,
   ePowerConditionForceIdle0     = 0x0a,
   ePowerConditionForceStandby0  = 0x0b
} PowerCondition;
//=================================
// class definitions
//=================================

/// \brief Base class implementing common SCSI functionality.
///
/// This class implements common methods to build and
/// decode SCSI commands in a standardized way.
///
//
class CScsi
{
public:
   /// Constructor.
   CScsi();

   //================================================================
   // Implementations of methods defined in CDriveTrustSession
   //================================================================
   void SecurityDataToDevice( 
      const dta::tBytes &dataToSend,
      const dta::tByte   protocolId,
      const tUINT16     sp_specific
      );

   void SecurityDataFromDevice( 
      dta::tBytes     &dataToRecv,
      const dta::tByte protocolId,
      const tUINT16   sp_specific
      );

   //================================================================
   //
   /// Issue a start stop Unit command.  
   ///
   /// In case of error, this method will throw a DTA_ERROR as an
   /// exception.  In most cases, this will be caught by methods
   /// above and either rethrown or returned as an error code.
   ///
   ///
   //================================================================
   virtual void StartStopUnitCommand(
         dta::tBytes &dataToRecv,
         int startOrStop
      );

   //================================================================

   //================================================================
   //
   /// Retrieve the block size from the current device.  This will
   /// issue an READ CAPACITY (10) command to retrieve the block size.  
   ///
   /// In case of error, this method will throw a DTA_ERROR as an
   /// exception.  In most cases, this will be caught by methods
   /// above and either rethrown or returned as an error code.
   ///
   /// \return block size of the device in bytes
   //
   //================================================================
   virtual size_t GetBlockSize();

   //================================================================
   //
   /// Retrieve the maximum allowable user LBA from the 
   /// current device.  This may issue an IDENTIFY DEVICE command 
   /// if necessary to retrieve the numer of LBAs.  Any retrieved 
   /// value is cached for future requests.
   ///
   /// In case of error, this method will throw a DTA_ERROR as an
   /// exception.  In most cases, this will be caught by methods
   /// above and either rethrown or returned as an error code.
   ///
   /// \return maximum allowable user LBA from the current device.
   //
   //================================================================
   virtual tUINT64 GetMaxLBA();

   //================================================================
   //
   /// Retrieve the capacity from the current device.  This will
   /// issue an READ CAPACITY (10) command to retrieve the capacity.  
   ///
   /// In case of error, this method will throw a DTA_ERROR as an
   /// exception.  In most cases, this will be caught by methods
   /// above and either rethrown or returned as an error code.
   ///
   /// \return capacity of the device in bytes
   //
   //================================================================
   virtual tUINT64 GetCapacityInBytes();

   //================================================================
   //
   /// Retrieve the product id from the current device.  This may
   /// issue an INQUIRY command if necessary.  Any retrieved value 
   /// is cached for future requests.
   ///
   /// In case of error, this method will throw a DTA_ERROR as an
   /// exception.  In most cases, this will be caught by methods
   /// above and either rethrown or returned as an error code.
   ///
   /// \return product id (model number)
   //
   //================================================================
   virtual const _tstring& GetProductIdentification();

   //================================================================
   //
   /// Retrieve the product revision from the current device.  This may
   /// issue an INQUIRY command if necessary.  Any retrieved value 
   /// is cached for future requests.
   ///
   /// In case of error, this method will throw a DTA_ERROR as an
   /// exception.  In most cases, this will be caught by methods
   /// above and either rethrown or returned as an error code.
   ///
   /// \return product revision (firmware version)
   //
   //================================================================
   virtual const _tstring& GetProductRevisionLevel();

   //================================================================
   //
   /// Retrieve the serial number from the current device.  This may
   /// issue an INQUIRY command if necessary.  Any retrieved value 
   /// is cached for future requests.
   ///
   /// In case of error, this method will throw a DTA_ERROR as an
   /// exception.  In most cases, this will be caught by methods
   /// above and either rethrown or returned as an error code.
   ///
   /// \return serial number
   //
   //================================================================
   virtual const _tstring& GetSerialNumber();

   //================================================================
   //
   /// Retrieve the vendor from the current device.  This may
   /// issue an INQUIRY command if necessary.  Any retrieved value 
   /// is cached for future requests.
   ///
   /// In case of error, this method will throw a DTA_ERROR as an
   /// exception.  In most cases, this will be caught by methods
   /// above and either rethrown or returned as an error code.
   ///
   /// \return vendor
   //
   //================================================================
   virtual const _tstring& GetVendor();

   //================================================================
   //
   /// Execute a READ10 command.
   ///
   /// In case of error, this method will throw a DTA_ERROR as an
   /// exception.  In most cases, this will be caught by methods
   /// above and either rethrown or returned as an error code.
   ///
   /// \param dataToRecv (OUT) The data buffer to be filled with data
   ///      from the read command.  The buffer should have a length
   ///      that is a multiple of the block size.
   ///
   /// \param lba (IN) The starting LBA for the read request.  The 
   ///      last LBA to be read ( dataToRecv.size() / GetBlockSize() )
   ///      must be less than or equal to GetMaxLBA().
   ///
   /// \return None.
   //
   //================================================================
   void Read10( 
      dta::tBytes &dataToRecv,
      tUINT32 lba
      );

   //================================================================
   //
   /// Execute a WRITE10 command.
   ///
   /// In case of error, this method will throw a DTA_ERROR as an
   /// exception.  In most cases, this will be caught by methods
   /// above and either rethrown or returned as an error code.
   ///
   /// \param dataToSend (IN, OUT) The data buffer to be written to
   ///      the device.  If necessary, it will be padded to the next
   ///      multiple of the block size.
   ///
   /// \param lba (IN) The starting LBA for the write request.  The 
   ///      last LBA to be written ( dataToRecv.size() / GetBlockSize() )
   ///      must be less than or equal to GetMaxLBA().
   ///
   /// \return None.
   //
   //================================================================
   void Write10( 
      dta::tBytes &dataToSend,
      tUINT32 lba
      );

   //================================================================
   //
   /// Execute a READ16 command.
   ///
   /// In case of error, this method will throw a DTA_ERROR as an
   /// exception.  In most cases, this will be caught by methods
   /// above and either rethrown or returned as an error code.
   ///
   /// \param dataToRecv (OUT) The data buffer to be filled with data
   ///      from the read command.  The buffer should have a length
   ///      that is a multiple of the block size.
   ///
   /// \param lba (IN) The starting LBA for the read request.  The 
   ///      last LBA to be read ( dataToRecv.size() / GetBlockSize() )
   ///      must be less than or equal to GetMaxLBA().
   ///
   /// \return None.
   //
   //================================================================
   void Read16( 
      dta::tBytes &dataToRecv,
      tUINT64 lba
      );

   //================================================================
   //
   /// Execute a WRITE16 command.
   ///
   /// In case of error, this method will throw a DTA_ERROR as an
   /// exception.  In most cases, this will be caught by methods
   /// above and either rethrown or returned as an error code.
   ///
   /// \param dataToSend (IN, OUT) The data buffer to be written to
   ///      the device.  If necessary, it will be padded to the next
   ///      multiple of the block size.
   ///
   /// \param lba (IN) The starting LBA for the write request.  The 
   ///      last LBA to be written ( dataToRecv.size() / GetBlockSize() )
   ///      must be less than or equal to GetMaxLBA().
   ///
   /// \return None.
   //
   //================================================================
   void Write16( 
      dta::tBytes &dataToSend,
      tUINT64 lba
      );

   //================================================================
   //
   /// Execute a SCSI command.
   ///
   /// \param cdb - (IN)
   ///      The SCSI CDB to be sent to the device.
   ///
   /// \param buffer - (IN,OUT)
   ///      The data buffer.  Depending on bufferToDevice, data
   ///      will be taken from or placed in the buffer.
   ///
   /// \param bufferToDevice - (IN)
   ///      True if data is to be sent to the device, or false
   ///      of data is to be received from the device.  Ignored
   ///      if buffer.size() is zero.
   ///
   /// \return None.
   ///
   /// In case of error, this method will throw a DTA_ERROR as an
   /// exception.  In most cases, this will be caught by methods
   /// above and either rethrown or returned as an error code.
   //
   //================================================================
   virtual void ExecScsiCdb( 
      const dta::tBytes& cdb,
      dta::tBytes& buffer,
      bool bufferToDevice
      ) = 0;

   //================================================================
protected:
   size_t   m_blockSize;   //!< Block size from IDENTIFY data
   _tstring m_productId;   //!< Model number from IDENTIFY data
   _tstring m_productRev;  //!< Firmware revision from IDENTIFY data
   _tstring m_serialNumber;//!< Serial number from IDENITFY data
   _tstring m_vendor;      //!< Vendor string from INQUIRY data

private:
   //================================================================
   //
   /// Perform a SCSI INQUIRY command.  This will fill in class
   /// member values for vendor, product id, and product revision.
   ///
   /// \return None.
   ///
   /// In case of error, this method will throw a DTA_ERROR as an
   /// exception.  In most cases, this will be caught by methods
   /// above and either rethrown or returned as an error code.
   //
   //================================================================
   void ExecStandardInquiry();
};

//=================================
// function definitions
//=================================

}  // end namespace dta
#endif // DTA_SCSI_HPP