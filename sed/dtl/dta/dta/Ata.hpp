/*! \file Ata.cpp
    \brief Definition of ATA basic functionality.

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

#ifndef DTA_ATA_HPP
#define DTA_ATA_HPP

// !defined __cplusplus
//=================================
// Include files
//=================================
#include "tfr.hpp"

//=================================
// macro definitions
//=================================

//=================================
// constants
//=================================

namespace ata {
   //================================================================
   //
   /// An enumeration of used valid values for the command
   /// register (ATA command opcodes).  This is a small subset
   /// of the command codes listed in the ATA-8 command specification,
   /// available at www.t13.org.
   //
   //================================================================
   enum etOpCodes
   {
      /// ATA-8 command code for READ SECTOR(S)
      evReadSectors = 0x20,
      /// ATA-8 command code for READ SECTOR(S) EXT
      evReadSectorsExt = 0x24,
      /// ATA-8 command code for READ DMA EXT
      evReadDmaExt = 0x25,
      /// ATA-8 command code for WRITE SECTOR(S)
      evWriteSectors = 0x30,
      /// ATA-8 command code for WRITE SECTOR(S) EXT
      evWriteSectorsExt = 0x34,
      /// ATA-8 command code for WRITE DMA EXT
      evWriteDmaExt = 0x35,
      /// ATA-8 command code for READ VERIFY SECTORS
      evReadVerifySectors = 0x40,
      /// ATA-8 command code for DOWNLOAD MICROCODE
      evDownloadMicrocode = 0x92,
      /// ATA-8 command code for Trusted Non-Data (PIO)
      evTrustedNonData = 0x5B,
      /// ATA-8 command code for Trusted Receive (PIO)
      evTrustedReceive = 0x5C,
      /// ATA-8 command code for Trusted Receive (DMA)
      evTrustedReceiveDMA = 0x5D,
      /// ATA-8 command code for Trusted Send (PIO)
      evTrustedSend = 0x5E,
      /// ATA-8 command code for Trusted Send (DMA)
      evTrustedSendDMA = 0x5F,
      /// ATA-8 command code for Execute Device Diagnostic(DMA)
      evExecuteDeviceDiagnostic = 0x90,
      /// ATA-8 command code for SMART (SMART)
      evSMART = 0xB0,
      /// ATA-8 command code for Sanitize Device
      evSanitizeDevice = 0xB4,
      /// ATA-8 command code for NV CACHE
      evNVCache = 0xB6,
      /// ATA-8 command code for READ DMA
      evReadDma = 0xC8,
      /// ATA-8 command code for WRITE DMA
      evWriteDma = 0xCA,
      /// ATA-8 command code for STANDBY IMMEDIATE
      evStandbyImmediate = 0xE0,
      /// ATA-8 command code for IDENTIFY DEVICE
      evIdentifyDevice = 0xEC,
      /// ATA-8 command code for SET FEATURES
      evSetFeatures = 0xEF,
      /// ATA-8 command code for Security Set Password (PIO)
      evSecuritySetPassword = 0xF1,
      /// ATA-8 command code for Security Unlock (PIO)
      evSecurityUnlock = 0xF2,
      /// ATA-8 command code for Security Erase Prepare
      evSecurityErasePrepare = 0xF3,
      /// ATA-8 command code for Security Erase Unit (PIO)
      evSecurityEraseUnit = 0xF4,
      /// ATA-8 command code for Security Freeze Lock
      evSecurityFreezeLock = 0xF5,
      /// ATA-8 command code for Security Disable Password (PIO)
      evSecurityDisablePassword = 0xF6,
      /// Seagate-proprietary legacy Trusted Receive (PIO)
      evTrustedSendSeagateLegacy = 0xF7,
      /// Seagate-proprietary legacy Trusted Send (PIO)
      evTrustedReceiveSeagateLegacy = 0xFB,

      //
      // Old codes here!  Not in command code order.
      //
/***
      /// ATA-8 command code for SMART ext (EXT SMART)
      evEXTSMART = 0x2F,
 ***/
   };

   /// An enumeration of NV Cache Commands (ATA B6h sub commands)
   enum etNVCacheCommands
   {
      /// NV Cache command value for Setting NV Cache Power Mode
      evSetNVCachePowerMode            = 0x0000,
      /// NV Cache command value for Returning from NV Cache Power Mode
      evReturnFromNVCachePowerMode     = 0x0001,
      /// NV Cache command value for Adding LBAs to the NV Cache pinned set
      evAddLBAsToNVCachePinnedSet      = 0x0010,
      /// NV Cache command value for Removing LBAs to the NV Cache pinned set
      evRemoveLBAsFromNVCachePinnedSet = 0x0011,
      /// NV Cache command value for Querying the NV Cache pinned set
      evQueryNVCachePinnedSet          = 0x0012,
      /// NV Cache command value for Querying the NV Cache misses
      evQueryNVCacheMisses             = 0x0013,
      /// NV Cache command value for Flushing the NV Cache
      evFlushNVCache                   = 0x0014,
      /// NV Cache command value for Enabling the NV Cache
      evQueryNVCacheEnable             = 0x0015,
      /// NV Cache command value for Disabling the NV Cache
      evQueryNVCacheDisable            = 0x0016,
   };

   /// An enumeration of Download Microcode Features
   typedef enum _etDownloadMicrocodeFeature
   {
      evDownloadMicrocodeImmediateTemp    = 0x01,
      evDownloadMicrocodeWithOffsets      = 0x03,
      evDownloadMicrocodeWithoutOffsets   = 0x07
   } etDownloadMicrocodeFeature;

   /// An enumeration of ATA Security Password types
   typedef enum _etSecurityPasswordType
   {
      evUserPassword    = 0,
      evMasterPassword  = 1
   } etSecurityPasswordType;

   /// An enumeration of ATA Master Password Capability
   typedef enum _etMasterPasswordCapability
   {
      evHigh      = 0,
      evMaximum   = 1
   } etMasterPasswordCapability;
   
   /// An enumeration of ATA Security Erase Mode
   typedef enum _etSecurityEraseMode
   {
      evSecurityEraseModeNormal     = 0,
      evSecurityEraseModeEnhanced   = 1
   } etSecurityEraseMode;

   /// An enumeration of ATA Set Features Sub Command Codes
   typedef enum _etSetFeaturesSubCommandCode
   {
      evSetFeaturesEnableSATAFeature   = 0x10,
      evSetFeaturesDisableSATAFeature  = 0x90,
   } etSetFeaturesSubCommandCode;

   /// An enumeration of ATA Set FeaturesSub Command specific
   typedef enum _etSetFeaturesSubCommandSpecific
   {
      evSetFeaturesSATASubcommandSSP   = 0x06,
   } etSetFeaturesSubCommandSpecific;

   /// An enumeration of ATA Sanitize Device Mode specific (ATA B4h sub commands)
   typedef enum _etSanitizeDeviceMode
   {
      evSanitizeDeviceStatusExt         = 0x0000,
      evSanitizeDeviceCryptoScrambleExt = 0x0011,
      evSanitizeDeviceOverwriteExt      = 0x0012,
      evSanitizeDeviceFreezeLockExt     = 0x0013
   } etSanitizeDeviceMode;
   
   //=================================
// typedefs and structures
//=================================
#pragma pack(push, 2)
   /// Struct of ATA Security Set Password Data Content
   typedef struct tSecuritySetPasswordDataContent
   {
      tUINT16 identfier                : 1;  // Word 0:0
      tUINT16 reserved1                : 7;  // Word 0:1-7
      tUINT16 masterPasswordCapability : 1;  // Word 0:8
      tUINT16 reserved2                : 7;  // Word 0:9-15

      tUINT16 password[16];                  // Word 1-16
      tUINT16 masterPasswordIdentifer;       // Word 17
   } SecuritySetPasswordDataContent;

   /// Struct of ATA Security Unlock Data Content
   typedef struct tSecurityUnlockDataContent
   {
      tUINT16 identfier                : 1;  // Word 0:0
      tUINT16 reserved1                : 15; // Word 0:1-15

      tUINT16 password[16];                  // Word 1-16
   } SecurityUnlockDataContent;

   /// Structu of ATA Security Erase Unit Data Content
   typedef struct tSecurityEraseUnitDataContent
   {
      tUINT16 identfier : 1;  // Word 0:0
      tUINT16 eraseMode : 1;  // Word 0:1
      tUINT16 reserved1 : 14; // Word 0:2-15
      tUINT16 password[16];   // Word 1-16
   } SecurityEraseUnitDataContent;

   /// Struct of ATA Security Disabled Password Data Content
   typedef struct tSecurityDisablePasswordDataContent
   {
      tUINT16 identfier                : 1;  // Word 0:0
      tUINT16 reserved1                : 15; // Word 0:1-15

      tUINT16 password[16];                  // Word 1-16
   } SecurityDisablePasswordDataContent;

   typedef struct _PinData
   {
      tUINT64 lbaValue    : 48; // Byte 0-5 (Bits 47:0)
      tUINT64 rangeLength : 16; // Byte 6-7 (Bits 63:48)
   } PinData;
#pragma pack(pop)

   typedef std::pair<tUINT64, tUINT16> tPinData;

//=================================
// class definitions
//=================================

/// \brief Base class implementing common ATA functionality.
///
/// This class implements common methods to build and
/// decode ATA commands in a standardized way.
///
//
class CAta
{
public:
   /// Constructor.
   CAta();

   //================================================================
   //
   /// Retrieve the block size from the current device.  This may
   /// issue an IDENTIFY DEVICE command if necessary to retrieve
   /// the block size.  Any retrieved value is cached for future
   /// requests.
   ///
   /// In case of error, this method will throw a DTA_ERROR as an
   /// exception.  In most cases, this will be caught by methods
   /// above and either rethrown or returned as an error code.
   ///
   /// \return block size of the device in bytes
   //
   //================================================================
   virtual  size_t  GetBlockSize();

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
   /// issue an IDENTIFY DEVICE command if necessary to retrieve
   /// the capacity.  
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
   /// Retrieve the IEEE Registered World Wide Name field for the
   /// current device and compare the OUI field to the possible
   /// Seagate ID values. If a match is found, return "SEAGATE "
   /// as the Vendor ID. Otherwise, create an 8-char string with
   /// the hex OIU value. This may issue an IDENTIFY DEVICE command 
   /// if necessary to retrieve the 64-bit WWN value, but the Vendor
   /// ID value is cached for future requests.
   ///
   /// In case of error, this method will throw a DTA_ERROR as an
   /// exception.  In most cases, this will be caught by methods
   /// above and either rethrown or returned as an error code.
   ///
   /// \return Vendor ID or WorldWideName OUI field for the current device.
   //
   //================================================================
   virtual const _tstring& GetVendor();   // jls 20120810

   //================================================================
   //
   /// Retrieve the model number from the current device.  This may
   /// issue an IDENTIFY DEVICE command if necessary to retrieve
   /// the model number.  Any retrieved value is cached for future
   /// requests.
   ///
   /// In case of error, this method will throw a DTA_ERROR as an
   /// exception.  In most cases, this will be caught by methods
   /// above and either rethrown or returned as an error code.
   ///
   /// \return model number
   //
   //================================================================
   virtual const _tstring& GetProductIdentification();

   //================================================================
   //
   /// Retrieve the firmware revision from the current device.  This
   /// may issue an IDENTIFY DEVICE command if necessary to retrieve
   /// the firmware revision.  Any retrieved value is cached for future
   /// requests.
   ///
   /// In case of error, this method will throw a DTA_ERROR as an
   /// exception.  In most cases, this will be caught by methods
   /// above and either rethrown or returned as an error code.
   ///
   /// \return firmware revision
   //
   //================================================================
   virtual const _tstring& GetProductRevisionLevel();

   //================================================================
   //
   /// Retrieve the serial number from the current device.  This may
   /// issue an IDENTIFY DEVICE command if necessary to retrieve
   /// the serial number.  Any retrieved value is cached for future
   /// requests.
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
   /// Execute an IDENTIFY DEVICE command.
   ///
   /// In case of error, this method will throw a DTA_ERROR as an
   /// exception.  In most cases, this will be caught by methods
   /// above and either rethrown or returned as an error code.
   ///
   /// \param buffer (IN) The data buffer to be filled with data
   ///      from the IDENTIFY DEVICE command.  The buffer will
   ///      be sized properly to fit the data (512 bytes).
   ///
   /// \return None.
   //
   //================================================================
   void GetIDBuffer( dta::tBytes& buffer );

   //================================================================
   //
   /// Execute an SET FEATURES command.
   ///
   /// This command is used by the host to establish parameters that
   /// affect the execution of certain device features.
   ///
   /// \param subCommand         Sub-op code for the Set Features command.
   /// \param subCommandSpecific Specific field for sub command.
   ///
   /// \return None.
   //
   //================================================================
   void SetFeatures(tUINT8 subCommand, tUINT8 subCommandSpecific );

   //================================================================
   //
   /// Enables Software Setting Preservation.
   ///
   /// This command calls SetFeatures with appropriate sub command and 
   /// sub command feature to enable Software Setting Preservation.
   ///
   /// \return None.
   //
   //================================================================
   void EnableSSP();

   //================================================================
   //
   /// Disables Software Setting Preservation.
   ///
   /// This command calls SetFeatures with appropriate sub command and 
   /// sub command feature to disable Software Setting Preservation.
   ///
   /// \return None.
   //
   //================================================================
   void DisableSSP();

   //================================================================
   //
   /// Test a buffer and LBA against device parameters.  For reads
   /// and writes, it is a good idea to pre-test the parameters
   /// against known limitations of the device.  This routine does
   /// those tests and throws an exception if something is not valid.
   ///
   /// In case of error, this method will throw a DTA_ERROR as an
   /// exception.  In most cases, this will be caught by methods
   /// above and either rethrown or returned as an error code.
   ///
   /// \param buffer (OUT) The data buffer to be tested.  It must
   ///      be an even multiple of the device block size.  If it
   ///      is not, it will be resized to the next block size.
   ///
   /// \param lba (IN) The starting LBA for the request.  The 
   ///      starting lba and the maximum lba for the request must
   ///      be less than or equal to GetMaxLBA().
   ///
   /// \return The minimum addressing mode to reach the provided LBA.
   //
   //================================================================
   ata::etAddressMode ValidateLbaAndBuffer( 
      dta::tBytes &buffer,
      tUINT64 &lba
      );

   //================================================================
   //
   /// Execute a READ SECTOR(S) or READ SECTOR(S) EXT command.
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
   void ReadPIO( 
      dta::tBytes &dataToRecv,
      tUINT64 lba
      );

   //================================================================
   //
   /// Execute a READ DMA or READ DMA EXT command.
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
   void ReadDMA( 
      dta::tBytes &dataToRecv,
      tUINT64 lba
      );

   //================================================================
   //
   /// Execute a WRITE SECTOR(S) or WRITE SECTOR(S) EXT command.
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
   void WritePIO( 
      dta::tBytes &dataToSend,
      tUINT64 lba
      );

   //================================================================
   //
   /// Execute a WRITE DMA or WRITE DMA EXT command.
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
   void WriteDMA( 
      dta::tBytes &dataToSend,
      tUINT64 lba
      );

   //================================================================
   //
   /// Execute a STANDBY IMMEDIATE command.
   ///
   /// In case of error, this method will throw a DTA_ERROR as an
   /// exception.  In most cases, this will be caught by methods
   /// above and either rethrown or returned as an error code.
   ///
   /// \return None.
   //
   //================================================================
   void StandbyImmediate();

   //================================================================
   //
   /// Execute a READ VERIFY SECTORS command.
   ///
   /// In case of error, this method will throw a DTA_ERROR as an
   /// exception.  In most cases, this will be caught by methods
   /// above and either rethrown or returned as an error code.
   ///
   /// \param count  [in] The number of logical sectors to be verified.
   ///      A value of 00h indicates that 256 logical sectors
   ///      are to be verified
   ///
   /// \param lba    [in] LBA of first logical sector to be verified.
   ///
   /// \return None.
   //
   //================================================================
   void ReadVerifySectors(
      tUINT16 count,
      tUINT64 lba
      );

   //================================================================
   //
   /// Execute a EXECUTE DEVICE DIAGNOSTIC command.
   ///
   /// This command shall cause the device to perform internal diagnostic tests.
   ///
   /// In case of error, this method will throw a DTA_ERROR as an
   /// exception.  In most cases, this will be caught by methods
   /// above and either rethrown or returned as an error code.
   ///
   /// \return None.
   //
   //================================================================
   void ExecuteDeviceDiagnostic();


   //================================================================
   //
   /// Download a microcode file to the device..
   ///
   /// This command opens a given file, and updates the device’s microcode with it.
   ///
   /// In case of error, this method will throw a DTA_ERROR as an
   /// exception.  In most cases, this will be caught by methods
   /// above and either rethrown or returned as an error code.
   ///
   /// \param filename [in] Name of the microcode to download
   ///
   /// \return None.
   //
   //================================================================
   void DownloadMicrocode(
      _tstring filename
      );

   //================================================================
   //
   /// Execute a DOWNLOAD MICROCODE command.
   ///
   /// This command enables the host to alter the device’s microcode.
   ///
   /// In case of error, this method will throw a DTA_ERROR as an
   /// exception.  In most cases, this will be caught by methods
   /// above and either rethrown or returned as an error code.
   ///
   /// \param blockCount [in] The number of logical sectors to be 
   ///                   verified. A value of 00h indicates that 256 
   ///                   logical sectors are to be verified
   /// \param dataToSend [in] LBA of first logical sector to be verified.
   ///
   /// \param feature    [in] TODO: define
   ///
   /// \param bufferOffset [in] TODO: define
   ///
   /// \return None.
   //
   //================================================================
   void DownloadMicrocode(
      tUINT16 blockCount,
      dta::tBytes &dataToSend,
      etDownloadMicrocodeFeature feature=evDownloadMicrocodeWithoutOffsets,
      tUINT16 bufferOffset=0
      );

   //================================================================
   //
   /// Execute a NV CACHE command: Add LBAs to NV Cache Pinned Set.
   ///
   /// This command adds the logical blocks specified in the NV Cache
   /// Set Data to the NV Cache Pinned Set.
   ///
   /// \param pi  [in] If the PI (Populate Immediately) bit is set to
   ///       one, then the device shall add the logical blocks specified
   ///       in the Pin Request Data to the device's NV Pinned Cache
   ///       Set and populated with the specified data from the
   ///       rotating media before command completion.
   ///
   ///       If PI is cleared to zero, then the logical blocks specified
   ///       in the Pin Request Data shall be added to the device's
   ///       NV Pinned Cache Set and:
   ///          a) the LBA in the pinned set shall be populated with data
   ///             from a subsequent write operation; and
   ///          b) the LBA in the pinned set may be populated with data from
   ///             a subsequent read operation.
   ///
   /// \param dataToSend [in] Byte block with a list of individual LBA 
   ///      ranges to be pinned.
   ///
   /// \return Number of unpinned logical blocks remaining.
   //
   //================================================================
   tUINT64 NVCacheAddLBAsToPinnedSet(bool pi, dta::tBytes &dataToSend);

   //================================================================
   //
   /// Execute a NV CACHE command: Add LBAs to NV Cache Pinned Set.
   ///
   /// This command adds the logical blocks specified in the NV Cache
   /// Set Data to the NV Cache Pinned Set.
   ///
   /// \param pi  [in] If the PI (Populate Immediately) bit is set to 
   ///      one, then the device shall add the logical blocks specified
   ///      in the Pin Request Data to the device's NV Pinned Cache
   ///      Set and populated with the specified data from the
   ///      rotating media before command completion.
   ///
   ///      If PI is cleared to zero, then the logical blocks specified
   ///      in the Pin Request Data shall be added to the device's
   ///      NV Pinned Cache Set and:
   ///          a) the LBA in the pinned set shall be populated with data
   ///             from a subsequent write operation; and
   ///          b) the LBA in the pinned set may be populated with data from
   ///             a subsequent read operation.
   ///
   /// \param pinRequestData [in] List of individual LBA ranges to be pinned.
   ///
   /// \return Number of unpinned logical blocks remaining.
   //
   //================================================================
   tUINT64 NVCacheAddLBAsToPinnedSet(bool pi,
                                  const std::vector<PinData> &pinRequestData);

   //================================================================
   //
   /// Execute a NV CACHE command: Remove LBAs to NV Cache Pinned Set.
   ///
   /// This command Removes the logical blocks specified in the NV Cache
   /// Set Data to the NV Cache Pinned Set.
   ///
   /// \param dataToSend [in] Byte block list of individual LBA ranges to be pinned.
   ///
   /// \return Number of unpinned logical blocks remaining
   //
   //================================================================
   tUINT64 NVCacheRemoveLBAsFromPinnedSet(dta::tBytes& dataToSend);

   //================================================================
   //
   /// Execute a NV CACHE command: Remove LBAs to NV Cache Pinned Set.
   ///
   /// This command Removes the logical blocks specified in the NV Cache
   /// Set Data to the NV Cache Pinned Set.
   ///
   /// \param removePinData [in] List of individual LBA ranges to be pinned.
   ///
   /// \return Number of unpinned logical blocks remaining
   //
   //================================================================
   tUINT64 NVCacheRemoveLBAsFromPinnedSet(const std::vector<PinData> &removePinData);

   //================================================================
   //
   /// Execute a NV CACHE command: Remove LBAs to NV Cache Pinned Set
   /// with the Unpin All bit set to true.
   ///
   /// This command Removes all the logical blocks in the NV Cache
   /// Set Data to the NV Cache Pinned Set.
   ///
   /// \return Number of unpinned logical blocks remaining
   //
   //================================================================
   tUINT64 NVCacheUnpinAllLBAs();

   //================================================================
   //
   /// Execute a NV CACHE command: Flush NV Cache
   ///
   /// The command provides at least as many logical blocks as are
   /// specified in LBA (31:0) for use by the NV Cache Pinned Set.
   ///
   /// \param minNumBlocks [in] Minimum number of logical blocks to flush.
   ///
   /// \return Number of unflushed logical blocks remaining
   //
   //================================================================
   tUINT64 NVCacheFlush(tUINT32 minNumBlocks);

   //================================================================
   //
   /// Execute a NV CACHE command: NV Cache Disable
   ///
   /// The command disables the NV Cache.
   ///
   /// \return None.
   //
   //================================================================
   void NVCacheDisable();

   //================================================================
   //
   /// Execute a NV CACHE command: NV Cache Enable
   ///
   /// The command enables the NV Cache.
   ///
   /// \return None.
   //
   //================================================================
   void NVCacheEnable();

   //================================================================
   //
   /// Execute a NV CACHE command: Query NV Cache Misses
   ///
   /// This command requests the device to report Cache Miss Data in
   /// LBA Ranges in a single 512-byte block.
   ///
   /// \param dataToRecv [out] Block of data to receive the query list.
   ///
   /// \return Number of unpinned logical blocks remaining
   //
   //================================================================
   tUINT64 NVCacheQueryMisses(dta::tBytes &dataToRecv);

   //================================================================
   //
   /// Execute a NV CACHE command: Query NV Cache Pinned Set
   ///
   /// This command requests the device to send the LBA Ranges currently
   /// in the NV Cache Pinned Set in one or more 512-byte blocks equal
   /// to the number in Block Count. If a device does not have as many
   /// LBA Ranges as are requested in the transfer, the unused LBA
   /// Range Entries shall be filled with zero.
   ///
   /// \param numBlocks [in] Number of 512-byte data blocks to be transferred.
   /// \param startingDataBlock [in] Starting 512-byte data block.
   /// \param dataToRecv [out] Block of data to receive the query list.
   ///
   /// \return Number of unpinned logical blocks remaining
   //
   //================================================================
   tUINT64 NVCacheQueryPinnedSet(tUINT16 numBlocks,
                                 tUINT64 startingDataBlock,
                                 dta::tBytes &dataToRecv);

   //================================================================
   //
   /// Execute a Security Set Password Command on the User Password
   ///
   /// This command sets the User account Security Password.
   ///
   /// \param newPassword [in] New Password for the user account.
   /// \param masterCapability [in]  0=High, 1=Maximum (Master Password Capability)
   ///
   /// \return None
   //
   //================================================================
   void SecuritySetPasswordUser(const dta::tBytes &newPassword,
                                etMasterPasswordCapability masterCapability=evHigh);

   //================================================================
   //
   /// Execute a Security Set Password Command on the Master Password
   ///
   /// This command sets the Master account Security Password.
   ///
   /// \param newPassword [in] New Password for the Master account.
   /// \param masterPasswordIdentifier [in] 16-bit Master Password Identifer field.
   ///
   /// \return None
   //
   //================================================================
   void SecuritySetPasswordMaster(dta::tBytes &newPassword,
                                  tUINT16 masterPasswordIdentifier=0x0000);

   //================================================================
   //
   /// Execute a Security Unlock Command
   ///
   /// When security is disabled and the Identifier bit is set to User,
   /// then the device shall return command aborted.
   /// When Security is Enabled, and the Master Password Capability is 
   /// set to High, then:
   ///    a) if the Identifier bit is set to Master, then the password 
   ///       supplied shall be compared with the stored Master password; or
   ///    b) if the Identifier bit is set to User, then the password 
   ///       supplied shall be compared with the stored User password.
   ///
   /// When Security is Enabled and the Master Password Capability is 
   /// set to Maximum, then:
   ///    a) if the Identifier bit is set to Master, then the device 
   ///       shall return command aborted; or
   ///    b) if the Identifier bit is set to User, then the password 
   ///       supplied shall be compared with the stored User password.
   ///
   /// \param password [in] Password to be check for the security unlock.
   /// \param passwordType [in] Password account to be verified (User or Master).
   ///
   /// \return None
   //
   //================================================================
   void SecurityUnlock(dta::tBytes &password,
                       etSecurityPasswordType passwordType=evUserPassword);

   //================================================================
   //
   /// Execute a Security Erase Prepare.
   ///
   /// This command performs a Security Erase Prepare (F3h).
   ///
   /// \return None
   //
   //================================================================
   void SecurityErasePrepare();

   //================================================================
   //
   /// Execute a Security Erase Unit.
   ///
   /// This command performs a Security Erase Unit (F4h).
   ///
   /// \param identifer [in] Either user or master password used for compare
   /// \param password  [in] Password used for compare
   /// \param eraseMode [in] Erase mode, either normal or enhanced.
   ///
   /// \return None
   //
   //================================================================
   void SecurityEraseUnit(etSecurityPasswordType identifer,
                          dta::tBytes &password,
                          etSecurityEraseMode eraseMode=evSecurityEraseModeEnhanced);

   //================================================================
   //
   /// Execute a Security Freeze Lock.
   ///
   /// The SECURITY FREEZE LOCK command shall set the device to Frozen mode. After command completion
   /// any other commands that update the device Lock mode shall be command aborted. Frozen mode shall
   /// be disabled by power-off or hardware reset. If SECURITY FREEZE LOCK is issued when the device
   /// is in Frozen mode, the command executes and the device shall remain in Frozen mode.
   ///
   /// \return None
   //
   //================================================================
   void SecurityFreezeLock();

   //================================================================
   //
   /// Execute a Security Disable Password.
   ///
   /// If the password selected by word 0 matches the password previously saved by the device, the
   /// device shall disable the User password, and return the device to the SEC1 state.
   /// This command shall not change the Master password or the Master Password Identifier.
   ///
   /// \param password [in] Password to be check for the security unlock.
   /// \param passwordType [in] Password account to be verified (User or Master).
   ///
   /// \return None
   //
   //================================================================
   void SecurityDisablePassword(dta::tBytes &password,
                                etSecurityPasswordType passwordType=evUserPassword);

   //================================================================
   //
   /// TODO: Describe GetSmartStatus
   ///
   /// \return TODO : Describe output parameter.
   //
   //================================================================
   bool GetSmartStatus();

   //================================================================
   //
   /// TODO: Describe SmartReadLog
   ///
   /// \param buffer (OUT)  TODO : Describe output parameter
   ///
   /// \param logAddress (IN)  TODO : Describe input parameter
   ///
   /// \return TODO : Describe output parameter.
   //
   //================================================================
   void SmartReadLog(
      dta::tBytes& buffer,
      tUINT8 logAddress
      );

   /***
   void Start_DST(
      int &run_type,
      dta::tBytes& buffer
      );

   void Check_DST_Completion(
      bool &myresult,
      dta::tBytes& buffer
      );
   ***/

   //================================================================
   // Implementations of methods defined in CDriveTrustSession
   //================================================================
   void SecurityDataToDevice( 
      const dta::tBytes &dataToSend,
      const dta::tByte  protocolId,
      const tUINT16     sp_specific
      );

   void SecurityDataFromDevice( 
      dta::tBytes       &dataToRecv,
      const dta::tByte  protocolId,
      const tUINT16     sp_specific
      );


   //================================================================
   //
   /// Set opcodes to be used when SecurityDataToDevice 
   /// and SecurityDataFromDevice are called.
   ///
   /// \param opSend - (IN)
   ///      The ATA opcode used for SecurityDataToDevice
   ///
   /// \param opRecv - (IN)
   ///      The ATA opcode used for SecurityDataFromDevice
   ///
   /// \return None.
   //
   //================================================================
   void SetTrustedOpcodes( ata::etOpCodes opSend, ata::etOpCodes opRecv );

   //================================================================
   //
   /// Send Sanitize device, asking drive to sanitize it's data
   ///
   /// \param sanitizeDevMode [in]  Sanitize mode, or status.
   ///
   /// \return None.
   //
   //================================================================
   void SanitizeDevice(etSanitizeDeviceMode sanitizeDevMode = evSanitizeDeviceStatusExt);

   //================================================================
   //
   /// Translates a PinData structure to a tPinData pair, which manages
   /// the 48-bit LBAs to 64-bit values.
   ///
   /// \param data [in]  PinData structure to be translated.
   ///
   /// \return tPinData with 64-bit lba value.
   //
   //================================================================
   static inline tPinData fromPinData(PinData data)
   {
      return tPinData((tUINT64)data.lbaValue, (tUINT16)data.rangeLength);
   };

   //================================================================
   //
   /// Translates a tPinData pair to a PinData structure, which manages
   /// the 64-bit LBA values to 48-bit values.
   ///
   /// \param data [in] PinData structure to be translated.
   ///
   /// \return PinData with 48-bit lba value.
   //
   //================================================================
   static PinData toPinData(tPinData data);

   //================================================================
   //
   /// Translates a data values to a PinData structure, which manages
   /// the 64-bit LBA values to 48-bit values.
   ///
   /// \param lba [in] LBA Values
   /// \param rangeLength [in] Range Length Value
   ///
   /// \return PinData with 48-bit lba value.
   //
   //================================================================
   static PinData toPinData(tUINT64 lba, tUINT16 rangeLength)
   {
      PinData pinData;
      pinData.lbaValue = lba;
      pinData.rangeLength = rangeLength;
      return pinData;
   };

public:
   //================================================================
   //
   /// Request a useable CTfr object.  This is used when the caller
   /// wants to build his own task file register set (TFR) to pass
   /// to ExecCommand().
   ///
   /// \param pTFR - (OUT)
   ///      Will be filled with a pointer to a useable CTfr object.
   ///
   /// \param addressMode - (IN)
   ///      The addressing mode for this TFR.  Default is ev28Bit.
   ///
   /// \return DTA_ERROR - Return success (0) or error code.
   ///
   /// @pre None.
   ///
   /// @post ReleaseTFR() should be called when use of the CTfr
   ///      object is complete.  If not, there will be a memory
   ///      leak until the program is closed.
   //
   //================================================================
   virtual dta::DTA_ERROR AcquireTFR( 
      ata::CTfr* &pTFR, 
      ata::etAddressMode addressMode = ata::ev28Bit
      ) = 0;

   //================================================================
   //
   /// Release a CTfr object.  The user must use AcquireTFR() to
   /// be given a CTfr pointer.  When done, the user should call
   /// this method to release the resource back to the device.
   ///
   /// \param pTFR - (IN)
   ///      The pointer to the CTfr object that is no longer in use.
   ///
   /// \return DTA_ERROR - Return success (0) or error code.
   ///
   /// @pre pTFR must have been acquired with AcquireTFR().
   ///
   /// @post pTFR should not be cached by the caller or used again.
   //
   //================================================================
   virtual dta::DTA_ERROR ReleaseTFR( ata::CTfr* pTFR ) = 0;

   //================================================================
   //
   /// Send a TFR block to the device and receive a response.
   ///
   /// \param pTFR (IN)
   ///      The pointer to the CTfr block to be used.
   ///
   /// \param buffer (IN,OUT)
   ///      A data buffer to be sent to or received from the device.
   ///      For non-data commands, this buffer may be empty.
   ///
   /// \param timeout (IN)
   ///      The device timeout for this command in seconds.
   ///
   /// \param protocol (IN)
   ///      The ATA protocol used for this command. If the value 
   ///      is evNoProtocol, a reasonable value will be determined 
   ///      based on the TFR data and assigned.
   ///
   /// \param direction (IN)
   ///      The data direction of transfer.  If the value is 
   ///      evNoDirection, a reasonable value will be determined
   ///      based on the TFR data and assigned.  
   ///
   /// \return DTA_ERROR - Return success (0) or error code.
   ///
   /// @pre pTFR must have been acquired with AcquireTFR().
   ///
   /// @post ReleaseTFR( pTFR ) should be called when use of the TFR
   ///      data is complete.
   //
   //================================================================
   virtual dta::DTA_ERROR Execute( 
      ata::CTfr* pTFR,
      dta::tBytes& buffer,
      size_t timeout = 0,
      ata::etProtocol protocol = ata::evNoProtocol,
      ata::etDataDirection direction = ata::evNoDirection
      ) = 0;

protected:
   size_t   m_blockSize;   //!< Block size from IDENTIFY data
   tUINT64  m_maxLba;      //!< Max LBA from IDENTIFY data
   tUINT64  m_WWName;      //!< 64 bit field with unique device name // jls 20120810
   ata::etOpCodes m_sendOp;  //!< Opcode to use for trusted send
   ata::etOpCodes m_recvOp;  //!< Opcode to use for trusted receive
   _tstring m_productId;   //!< Model number from IDENTIFY data
   _tstring m_productRev;  //!< Firmware revision from IDENTIFY data
   _tstring m_serialNumber;//!< Serial number from IDENITFY data
   _tstring m_vendorId;    //!< From WorldWideName OUI Field         // jls 20120810

   //================================================================
   //
   /// Execute a standard ATA read or write command.  This is a helper
   /// method used by other calls like ReadPIO, WriteDMAExt, etc.
   ///
   /// In case of error, this method will throw a DTA_ERROR as an
   /// exception.  In most cases, this will be caught by methods
   /// above and either rethrown or returned as an error code.
   ///
   /// \param data (IN,OUT) The data buffer to be used for a read
   ///      or write command.  The buffer should have a length
   ///      that is a multiple of the block size.
   ///
   /// \param lba (IN) The starting LBA for the read request.  The 
   ///      last LBA to be read ( dataToRecv.size() / GetBlockSize() )
   ///      must be less than or equal to GetMaxLBA().
   ///
   /// \param op28 (IN)
   ///      The ATA opcode used for 28-bit addressing
   ///
   /// \param op48 (IN)
   ///      The ATA opcode used for 48-bit addressing
   ///
   /// \return None.
   //
   //================================================================
   void ReadOrWrite( 
      dta::tBytes &data,
      tUINT64 lba,
      ata::etOpCodes op28,
      ata::etOpCodes op48
      );

private:
   //================================================================
   //
   /// Take the data from IDENTIFY DEVICE, and extract a string.
   /// The ATA standard puts strings in a very 'backward' format,
   /// and this method makes it easy to extract the string properly.
   ///
   /// In case of error, this method will throw a DTA_ERROR as an
   /// exception.  In most cases, this will be caught by methods
   /// above and either rethrown or returned as an error code.
   ///
   /// \param buffer (IN)
   ///      A data buffer where the IDENTIFY DEVICE result data
   ///      is located.  It must be 512 bytes in length.
   /// \param lowWord (IN)
   ///      The low word index ( 0-255 ) where the string begins
   /// \param highWord (IN)
   ///      The high word index ( 0-255 ) where the string ends
   ///
   /// \return String data extracted from buffer
   //
   //================================================================
#if defined(_WIN32) // nvn20110614
   _tstring ata::CAta::ExtractIdText(
#else
   _tstring ExtractIdText(
#endif
      const dta::tBytes& buffer,
      tUINT8 lowWord,
      tUINT8 highWord
      );
};

/// \brief inline class to deal with TFR acquisition and release.
///
/// This class provides a standard way to acquire and release
/// a TFR object from the CAta class.  This is helpful to
/// prevent memory leaks in the case of exceptions.
//
class CAutoTFR
{
public:
   CAutoTFR( ata::CAta* ata, ata::etAddressMode mode= ata::ev28Bit ) 
      : m_ata(ata), m_tfr(NULL) 
   { 
      m_ata->AcquireTFR( m_tfr, mode ); 
   }
   ~CAutoTFR()
   {
      m_ata->ReleaseTFR( m_tfr );
   }
   ata::CTfr* operator->()
   {
      return m_tfr;
   }
   operator ata::CTfr*()
   {
      return m_tfr;
   }
protected:
   CAta *m_ata;
   CTfr *m_tfr;
};

//=================================
// function definitions
//=================================

}  // end namespace ata
#endif // DTA_ATA_HPP
