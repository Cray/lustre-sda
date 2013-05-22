/*! \file SATCDB.hpp
    \brief Declaration of SAT CDB helper classes.

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

#ifndef XPORT_SAT_CDB_HPP
#define XPORT_SAT_CDB_HPP

// !defined __cplusplus
//=================================
// Include files
//=================================
#include <dta/dta.hpp>

namespace sat {
//=================================
// macro definitions
//=================================

//=================================
// constants and enumerations
//=================================

/// Valid values for the PROTOCOL bits in the ATA PASS-THROUGH CDB.
typedef enum
{
   eProtocolATAHardwareReset   =  0,   //!< Hard Reset(PATA) or COMRESET(SATA)
   eProtocolSRST               =  1,   //!< Soft Reset (no data)
   eProtocolNonData            =  3,   //!< Non-Data Command
   eProtocolPioDataIn          =  4,   //!< PIO Data In
   eProtocolPioDataOut         =  5,   //!< PIO Data Out
   eProtocolDma                =  6,   //!< DMA command
   eProtocolDmaQueued          =  7,   //!< DMA Queued Command
   eProtocolDeviceDiagnostic   =  8,   //!< Device Diagnostic
   eProtocolDeviceReset        =  9,   //!< Device Reset
   eProtocolUdmaDataIn         = 10,   //!< UDMA Data In
   eProtocolUdmaDataOut        = 11,   //!< UDMA Data Out
   eProtocolFPDMA              = 12,   //!< First-party DMA
   eProtocolReturnResponseInfo = 15,   //!< Return (shadow) TFRs
   eProtocolMaxValue           = 15    //!< Maximum allowed value
   // Additional error enumerations TBD.
} eProtocol;

///  Valid values for the OFFLINE bits in the ATA PASS-THROUGH CDB.
typedef enum
{
   eOffLine0Seconds  = 0,  //!< Expect immediate response to command
   eOffLine2Seconds  = 1,  //!< Allow device to be offline 2 seconds
   eOffLine6Seconds  = 2,  //!< Allow device to be offline 6 seconds
   eOffLine14Seconds = 3,  //!< Allow device to be offline 14 seconds
   eOffLineMaxValue  = 3   //!< Maximum allowed value
} eOffLine;

/// Valid values for the T_DIR bit in the ATA PASS-THROUGH CDB.
typedef enum
{
   eTransferHostToDisk = 0, //!<Data transfer is from host(PC) to drive
   eTransferDiskToHost = 1, //!<Data transfer is from drive to host(PC)
   eTransferMaxValue   = 1  //!<Maximum allowed value
} eTransferDirection;

/// Valid values for the BYTE_BLOCK bit in the ATA PASS-THROUGH CDB.
typedef enum
{
   eTLengthIsBytes    = 0, //!<T_LENGTH holds number of bytes
   eTLengthIsBlocks   = 1, //!<T_LENGTH holds number of blocks
   eByteBlockMaxValue = 1  //!<Maximum allowed value
} eByteBlock;

/// Valid values for the T_LENGTH bits in the ATA PASS-THROUGH CDB.
typedef enum
{
   /// No data is transferred
   eTLengthNoData      = 0,
   /// The transfer length is specified in the FEATURES (7:0) field.
   eTLengthUseFeatures = 1,
   /// The transfer length is specified in the SECTOR_COUNT (7:0) field.
   eTLengthUseSectors  = 2,
   /// The transfer length is specified in the TPSIU
   eTLengthUseTPSIU    = 3,
   /// Maximum allowed value for enumeration
   eTLengthMaxValue    = 3
} eTLength;

//=================================
// typedefs and structures
//=================================

//=================================
// class definitions
//=================================

//================================================================
//
/// \brief Base class for TFRs embedded in a SAT CDB.
///
/// This class is derived from by CAtaPassThruCDB12 
/// and CAtaPassThruCDB16.  It defines common
/// functionality between the two forms of SAT CDBs.
//
//================================================================
class CAtaPassThruCDB : public dta::tBytes
{
protected:
   /// Default constructor.
   CAtaPassThruCDB() { this->Initialize(); } // nvn20110629 - implicit dependent member
   /// Virtual destructor.
   virtual ~CAtaPassThruCDB();

public:
   /// Reset memory contents.
   virtual void Initialize() = 0;

};

/// \brief helper class used to get/set CDB field values.
///
/// This class provides accessor methods to more easily set
/// values in an ATA PASS-THROUGH(12) command as specified
/// in the SAT-2 specification (Revision 01a).
///
//
class CAtaPassThru12CDB : public dta::tBytes
{
public:
   CAtaPassThru12CDB();

   // Reset memory contents.
   void Initialize();

   // MultipleCount : byte 1, bits 5-7
   size_type GetMultipleCount() const;
   size_type SetMultipleCount( size_type sectors );

   // Protocol      : byte 1, bits 1-4
   eProtocol GetProtocol() const;
   eProtocol SetProtocol( eProtocol newProtocol );

   // OffLine       : byte 2, bits 6-7
   eOffLine GetOffLine() const;
   eOffLine SetOffLine( eOffLine newVal );

   // CheckCondition: byte 2, bit  5
   bool GetCheckCondition() const;
   bool SetCheckCondition( bool newVal );

   // TDir          : byte 2, bit  3
   eTransferDirection GetTransferDirection() const;
   eTransferDirection SetTransferDirection( eTransferDirection newVal );

   // ByteBlock     : byte 2, bit  2
   eByteBlock GetByteBlock() const;
   eByteBlock SetByteBlock( eByteBlock newVal );

   // TLength       : byte 2, bits 0-1
   eTLength GetTLength() const;
   eTLength SetTLength( eTLength newVal );

   tUINT8 GetFeatures()    const;
   tUINT8 GetSectorCount() const;
   tUINT8 GetLbaLow()      const;
   tUINT8 GetLbaMid()      const;
   tUINT8 GetLbaHigh()     const;
   tUINT8 GetDevice()      const;
   tUINT8 GetCommand()     const;
   tUINT8 GetControl()     const;

   tUINT8 SetFeatures   ( tUINT8 newVal );
   tUINT8 SetSectorCount( tUINT8 newVal );
   tUINT8 SetLbaLow     ( tUINT8 newVal );
   tUINT8 SetLbaMid     ( tUINT8 newVal );
   tUINT8 SetLbaHigh    ( tUINT8 newVal );
   tUINT8 SetDevice     ( tUINT8 newVal );
   tUINT8 SetCommand    ( tUINT8 newVal );
   tUINT8 SetControl    ( tUINT8 newVal );

   // Generic get helper methods with size checking.
   tUINT8  GetByteValue( size_type offset ) const;
   tUINT8& GetByte( size_type offset );

   // Generic set helper method with size checking.
   tUINT8 SetByte( size_type offset, tUINT8 newVal );

};

//=================================
// function definitions
//=================================

}  // end namespace sat
#endif // XPORT_SAT_CDB_HPP