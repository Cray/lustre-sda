/*! \file tfr.hpp
    \brief Definition of a task file register (TFR) class.

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

#ifndef DTA_TFR_HPP
#define DTA_TFR_HPP

// !defined __cplusplus
//=================================
// Include files
//=================================
#include "dta.hpp"

//=================================
// macro definitions
//=================================

//=================================
// constants
//=================================

//=================================
// typedefs and structures
//=================================
namespace ata {

/// An enumeration of valid ATA address modes.
enum etAddressMode
{
   evNoAddressMode,  //!< Current addressing mode is unknown.
   ev28Bit,          //!< Current addressing mode is 28-bit
   ev48Bit           //!< Current addressing mode is 48-bit
};

/// An enumeration of settings for command protocols.
enum etProtocol
{
   evNoProtocol,  //!< No specified protocol
   evNonData,     //!< Non-data command
   evPIO,         //!< PIO command (in or out)
   evDMA,         //!< DMA command (in or out)
   evDMAQ,        //!< DMA QUEUED command (in or out)
   evReset,       //!< DEVICE RESET command
   evDiagnostic,  //!< EXECUTE DEVICE DIAGNOSTIC command
   evPacket,      //!< PACKET command
   evVendor       //!< Vendor specific command
};

/// An enumeration of settings for data transfers.
enum etDataDirection
{
   evNoDirection, //!< No data direction
   evDataOut,     //!< Data transfer is to device
   evDataIn       //!< Data transfer is from device
};

//=================================
// class definitions
//=================================

/// \brief Class defining task file register storage and retrieval.
///
/// This class is a base class, defining access methods to and
/// from a set of ATA task file registers.  It should be derived
/// from and overloaded for an individual transport for storage.
///
//
class CTfr
{
protected:
   //================================================================
   //
   /// Constructor.  This constructor automatically calls Initialize
   ///      to set up the tfr for a new command.
   ///
   /// \param addressMode  Should be set to the addressing mode
   ///      for this command.  The default value is ev28Bit.
   //
   //================================================================
   CTfr( etAddressMode addressMode = ev28Bit );

public:
   /// Virtual destructor.
   virtual ~CTfr() {}

   //================================================================
   //
   /// Initialization method.  On object creation this method will
   /// automatically be called.  If the user wishes to re-use the
   /// object, they may call Initialize() again to reset any memory
   /// contents appropriately.
   ///
   /// In case of error, this method will throw a DTA_ERROR as an
   /// exception.  In most cases, this will be caught by methods
   /// above and either rethrown or returned as an error code.
   ///
   /// \param addressMode  Should be set to the addressing mode
   ///      for this command.  The default value is ev28Bit.
   //
   /// \return None.
   //
   //================================================================
   virtual void Initialize( etAddressMode addressMode = ev28Bit );

   //================================================================
   //
   /// Retrieve the stored addressing mode.
   ///
   /// \return The stored addressing mode.
   //
   //================================================================
   virtual etAddressMode GetAddressMode() const;

   //================================================================
   //
   /// Retrieve the stored value for the command/status TFR.
   ///
   /// \return The stored value for the command/status TFR.
   //
   //================================================================
   virtual tUINT8 GetCommandStatus() const = 0;

   //================================================================
   //
   /// Retrieve the stored value for the error/feature TFR.  For 48-bit
   /// addressing, this value is stored as a 16-bit address.  See
   /// the ATA specification for more details.
   ///
   /// \return The stored value for the error/feature TFR.
   //
   //================================================================
   virtual tUINT16 GetErrorFeature() const = 0;

   //================================================================
   //
   /// Retrieve the stored value for the LBA low TFR.  For 48-bit
   /// addressing, this value is stored as a 16-bit address.  See
   /// the ATA specification for more details.
   ///
   /// \return The stored value for the LBA low TFR.
   //
   //================================================================
   virtual tUINT16 GetLBALow() const = 0;

   //================================================================
   //
   /// Retrieve the stored value for the LBA mid TFR.  For 48-bit
   /// addressing, this value is stored as a 16-bit address.  See
   /// the ATA specification for more details.
   ///
   /// \return he stored value for the LBA mid TFR.
   //
   //================================================================
   virtual tUINT16 GetLBAMid() const = 0;

   //================================================================
   //
   /// Retrieve the stored value for the LBA high TFR.  For 48-bit
   /// addressing, this value is stored as a 16-bit address.  See
   /// the ATA specification for more details.
   ///
   /// \return The stored value for the LBA high TFR.
   //
   //================================================================
   virtual tUINT16 GetLBAHigh() const = 0;

   //================================================================
   //
   /// Retrieve the stored value for the sector count TFR.  For 48-bit
   /// addressing, this value is stored as a 16-bit address.  See
   /// the ATA specification for more details.
   ///
   /// \return The stored value for the sector count TFR.
   //
   //================================================================
   virtual tUINT16 GetSectorCount() const = 0;

   //================================================================
   //
   /// Retrieve the stored value for the device/head TFR.
   ///
   /// \return The stored value for the device/head TFR.
   //
   //================================================================
   virtual tUINT8 GetDeviceHead() const = 0;

   //================================================================
   //
   /// Retrieves an LBA from LBA low, LBA mid, and LBA high.  This
   /// method is provided for user convenience.  It merely parses
   /// the TFR bytes and reconstructs the LBA.
   ///
   /// \return None.
   //
   //================================================================
   virtual tUINT64 GetLBA() const;

   //================================================================
   //
   /// Store the value for the command/status TFR.
   ///
   /// \param value  The new value to be placed.
   ///
   /// \return None.
   //
   //================================================================
   virtual void SetCommandStatus( tUINT8 value ) = 0;

   //================================================================
   //
   /// Store the value for the error/feature TFR.  For 48-bit
   /// addressing, this value is stored as a 16-bit address.  See
   /// the ATA specification for more details.
   ///
   /// \param value  The new value to be placed.
   ///
   /// \return None.
   //
   //================================================================
   virtual void SetErrorFeature( tUINT16 value ) = 0;

   //================================================================
   //
   /// Store the value for the LBA low TFR.  For 48-bit
   /// addressing, this value is stored as a 16-bit address.  See
   /// the ATA specification for more details.
   ///
   /// \param value  The new value to be placed.
   ///
   /// \return None.
   //
   //================================================================
   virtual void SetLBALow( tUINT16 value ) = 0;

   //================================================================
   //
   /// Store the value for the LBA mid TFR.  For 48-bit
   /// addressing, this value is stored as a 16-bit address.  See
   /// the ATA specification for more details.
   ///
   /// \param value  The new value to be placed.
   ///
   /// \return None.
   //
   //================================================================
   virtual void SetLBAMid( tUINT16 value ) = 0;

   //================================================================
   //
   /// Store the value for the LBA high TFR.  For 48-bit
   /// addressing, this value is stored as a 16-bit address.  See
   /// the ATA specification for more details.
   ///
   /// \param value  The new value to be placed.
   ///
   /// \return None.
   //
   //================================================================
   virtual void SetLBAHigh( tUINT16 value ) = 0;

   //================================================================
   //
   /// Store the value for the sector count TFR.  For 48-bit
   /// addressing, this value is stored as a 16-bit address.  See
   /// the ATA specification for more details.
   ///
   /// \param value  The new value to be placed.
   ///
   /// \return None.
   //
   //================================================================
   virtual void SetSectorCount( tUINT16 value ) = 0;

   //================================================================
   //
   /// Store the value for the device/head TFR.
   ///
   /// \param value  The new value to be placed.
   ///
   /// \return None.
   //
   //================================================================
   virtual void SetDeviceHead( tUINT8 value ) = 0;

   //================================================================
   //
   /// Stores an LBA into LBA low, LBA mid, and LBA high.  This
   /// method is provided for user convenience.  It merely parses
   /// the LBA and puts it into the appropriate TFR bytes as needed.
   ///
   /// \param value  The new value to be placed.
   ///
   /// \return None.
   //
   //================================================================
   virtual void SetLBA( tUINT64 value );

   //================================================================
   //
   /// Reinitializes the TFR object by the command TFR byte.  This
   /// method is provided for user convenience.  It provides the
   /// following functionality:
   ///
   /// 1) Determines if the command should use 28-bit or 48-bit
   ///    addressing based on the command TFR byte.
   ///
   /// 2) Reinitializes the TFR object appropriately for the address
   ///    mode determined.
   ///
   /// 3) Places the command TFR byte in the TFR object.
   ///
   /// \param command  The new command TFR byte to be placed.
   ///
   /// \return None.
   //
   //================================================================
   virtual void InitCommand( tUINT8 command );

   //================================================================
   //
   /// Prepares the command for execution.  This will provide
   /// defaults for parameters not provided, and then fill in
   /// related information structures for data not necessarily
   /// stored in a task file register (TFR).
   ///
   /// \param buffer  The user buffer associated with the TFR.
   ///      This buffer may be of size zero if no data is to be
   ///      transferred.
   ///
   /// \param timeout  The device timeout for this command in seconds.
   ///
   /// \param protocol  The ATA protocol used for this command.
   ///      If the value is evNoProtocol, a reasonable value
   ///      will be determined based on the TFR data and assigned.
   ///
   /// \param direction  The data direction of transfer.  If the value
   ///      is evNoDirection, a reasonable value will be determined
   ///      based on the TFR data and assigned.  
   ///
   /// \return A pointer to the O/S specific buffer used for
   ///      communication with the driver.
   //
   //================================================================
   void* Prepare( 
      dta::tBytes& buffer,
      size_t &timeout,
      etProtocol &protocol,
      etDataDirection &direction
      );

protected:
   //================================================================
   //
   /// Prepares the command for execution.  This method is called
   /// from Prepare() at its conclusion to fill in related
   /// information structures for fields not provided.
   ///
   /// \param buffer  The user buffer associated with the TFR.
   ///      This buffer may be of size zero if no data is to be
   ///      transferred.
   ///
   /// \param timeout  The device timeout for this command in seconds.
   ///
   /// \param protocol  The ATA protocol used for this command.
   ///
   /// \param direction  The data direction of transfer.
   ///
   /// \return A pointer to the O/S specific buffer used for
   ///      communication with the driver.
   //
   //================================================================
   virtual void* CompletePrepare( 
      dta::tBytes& buffer,
      size_t &timeout,
      etProtocol &protocol,
      etDataDirection &direction
      ) = 0;

   etAddressMode m_addressingMode;
};

//=================================
// function definitions
//=================================

}  // end namespace ata
#endif // DTA_TFR_HPP
