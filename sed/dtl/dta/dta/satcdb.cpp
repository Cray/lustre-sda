/*! \file satcdb.cpp
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
#include "SATCDB.hpp" // nvn20110615
#include <dta/errors.h>
#include <assert.h>
using namespace sat;

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

//=================================
// inline methods
//=================================

//================================================================
//
/// Return a single bit value from a source.
///
/// \param value (IN) Source data used for bit extraction.
///
/// \param bitNum (IN) Offset to the high bit for extraction.
///         This offset is zero-based.
///
/// \return A boolean value noting if the bit was set (true)
///         or not set (false)
//
//================================================================
template < class T > bool GetBit( 
                       const T value, 
                       const size_t bitNum
                       )
{
   T temp = 1;
   temp <<= bitNum;
   return ( 0 != ( value & temp ) );
}

//================================================================
//
/// Sets a single bit value from a source.
///
/// \param value (IN, OUT) Source data used for bit extraction.
///
/// \param bitNum (IN) Offset to the high bit for extraction.
///         This offset is zero-based.
///
/// \param setBitTo1 (IN) Boolean to determine if bit is set (true)
///         or cleared (false)
///
/// \return A boolean noting if the bit was previously set (true)
///         or cleared (false).
//
//================================================================
template < class T > bool SetBit( 
                       T& value, 
                       const size_t bitNum, 
                       bool  setBitTo1
                       )
{
   bool retVal = GetBit( value, bitNum );
   T temp = 1;
   temp <<= bitNum;
   if ( setBitTo1 )
   {
      value |= temp;
   }
   else
   {
      value &= (~temp);
   }
   return retVal;
}

//================================================================
//
/// Shift and return a subset of bits in a uint8.
///
/// \param value (IN) The source data used for bit extraction.
///         All bits between the low and high indexes inclusive
///         will be copied, right-shifted, and returned.
///
/// \param high (IN) The offset to the high bit for extraction.
///         This offset is zero-based, and should be not
///         less than the value of 'low'.
///
/// \param low (IN) The offset to the low bit for extraction.
///         This offset is zero-based, and should be
///         less than the value of 'high'.
///
/// \return An 8-bit value containing the masked and shifted result.
//
//================================================================
inline tUINT8 GetBits( const tUINT8 value, 
                       const unsigned int high, 
                       const unsigned int low 
                       )
{
   tUINT8 temp = value >> low;
   tUINT8 mask   = 0x00;
   switch ( high - low )
   {
   case 7: mask |= 0x80;
   case 6: mask |= 0x40;
   case 5: mask |= 0x20;
   case 4: mask |= 0x10;
   case 3: mask |= 0x08;
   case 2: mask |= 0x04;
   case 1: mask |= 0x02;
   case 0: mask |= 0x01;
      break;
   }
   assert( 0 != mask && high <= 7 );
   return temp & mask;
}

//================================================================
//
/// Shift and assign a subset of bits in a uint8.
///
/// \param dest (IN,OUT) The destination byte, where the bits will
//          be placed. All bits between the low and high indexes 
///         inclusive will be left-shifted and assigned into this
///         destination.
///
/// \param src  (IN) The source bits to be used.  They will be
///         left-shifted as appropriate and then placed into
///         the destination buffer.
///
/// \param high (IN) The offset to the high bit for extraction.
///         This offset is zero-based, and should be not
///         less than the value of 'low'.
///
/// \param low (IN) The offset to the low bit for extraction.
///         This offset is zero-based, and should be
///         less than the value of 'high'.
///
/// \return Returns the bits in dest prior to modification.
//
//================================================================
inline tUINT8 SetBits( tUINT8 &dest, 
                       const tUINT8 src,
                       const unsigned int high, 
                       const unsigned int low 
                       )
{
   tUINT8 result = GetBits( dest, high, low );
   tUINT8 temp = src << low;
   tUINT8 mask   = 0x00;
   switch ( high - low )
   {
   case 7: mask |= 0x80;
   case 6: mask |= 0x40;
   case 5: mask |= 0x20;
   case 4: mask |= 0x10;
   case 3: mask |= 0x08;
   case 2: mask |= 0x04;
   case 1: mask |= 0x02;
   case 0: mask |= 0x01;
      break;
   }
   mask <<= low;
   dest &= (~mask);  // zero out the old data.
   dest |= temp;     // and then or in the new data.

   return result;    // return the shifted previous contents.
}

//=================================
// class implementations
//=================================

CAtaPassThru12CDB::CAtaPassThru12CDB()
: dta::tBytes(12)
{
   Initialize();
}

//================================================================
//
/// Reset the CDB data default values.  This will assign the
/// appropraite SCSI OPERATION CODE (A1h) and zero everything
/// else in the CDB buffer.
///
/// \return None
//
//================================================================
void CAtaPassThru12CDB::Initialize()
{
   clear();
   resize(12);
   SetByte(0, 0xA1 );   // ATA PASS-THROUGH(12)
   SetByteBlock( sat::eTLengthIsBytes );
   SetTLength( sat::eTLengthUseTPSIU );
}

//================================================================
//
/// Range-check and return an arbitrary byte from the class data.
///
/// This method is just a simple accessor to extract the relevant
/// data from the class data buffer after range checking.  It
/// will throw a DTA_ERROR if the offset is out of range.
///
/// \return An 8-bit value containing the contents of the
///         class buffer at the specified offset.
//
//================================================================
tUINT8& CAtaPassThru12CDB::GetByte( size_type offset )
{
   if ( size() <= offset )
   {
      throw dta::Error( dta::eGenericInvalidParameter );
   }
   return operator[](offset);
}

//================================================================
//
/// Return the contents of an arbitrary byte from the class data.
///
/// This method is just a simple accessor to extract the relevant
/// data from the class data buffer after range checking.  It
/// will throw a DTA_ERROR if the offset is out of range.
///
/// \return An 8-bit value containing the contents of the
///         class buffer at the specified offset.
//
//================================================================
tUINT8 CAtaPassThru12CDB::GetByteValue( size_type offset ) const
{
   if ( size() <= offset )
   {
      throw dta::Error( dta::eGenericInvalidParameter );
   }
   return at( offset );
}

//================================================================
//
/// Return the contents of the FEATURES data (8 bits) 
/// embedded in the CDB data.
///
/// This method is just a simple accessor to extract the relevant
/// data from the CDB payload without the user having to refer
/// to the SAT specification for the appropriate byte and offset.
///
/// \return An 8-bit value containing the contents of the
///         FEATURES member of the ATA PASS-THROUGH structure.
//
//================================================================
tUINT8 CAtaPassThru12CDB::GetFeatures() const
{
   return GetByteValue( 3 );
}

//================================================================
//
/// Return the contents of the SECTOR_COUNT data (8 bits) 
/// embedded in the CDB data.
///
/// This method is just a simple accessor to extract the relevant
/// data from the CDB payload without the user having to refer
/// to the SAT specification for the appropriate byte and offset.
///
/// \return An 8-bit value containing the contents of the
///         SECTOR_COUNT member of the ATA PASS-THROUGH structure.
//
//================================================================
tUINT8 CAtaPassThru12CDB::GetSectorCount() const
{
   return GetByteValue( 4 );
}

//================================================================
//
/// Return the contents of the LBA_LOW data (8 bits) 
/// embedded in the CDB data.
///
/// This method is just a simple accessor to extract the relevant
/// data from the CDB payload without the user having to refer
/// to the SAT specification for the appropriate byte and offset.
///
/// \return An 8-bit value containing the contents of the
///         LBA_LOW member of the ATA PASS-THROUGH structure.
//
//================================================================
tUINT8 CAtaPassThru12CDB::GetLbaLow() const
{
   return GetByteValue( 5 );
}

//================================================================
//
/// Return the contents of the LBA_MID data (8 bits) 
/// embedded in the CDB data.
///
/// This method is just a simple accessor to extract the relevant
/// data from the CDB payload without the user having to refer
/// to the SAT specification for the appropriate byte and offset.
///
/// \return An 8-bit value containing the contents of the
///         LBA_MID member of the ATA PASS-THROUGH structure.
//
//================================================================
tUINT8 CAtaPassThru12CDB::GetLbaMid() const
{
   return GetByteValue( 6 );
}

//================================================================
//
/// Return the contents of the LBA_HIGH data (8 bits) 
/// embedded in the CDB data.
///
/// This method is just a simple accessor to extract the relevant
/// data from the CDB payload without the user having to refer
/// to the SAT specification for the appropriate byte and offset.
///
/// \return An 8-bit value containing the contents of the
///         LBA_HIGH member of the ATA PASS-THROUGH structure.
//
//================================================================
tUINT8 CAtaPassThru12CDB::GetLbaHigh() const
{
   return GetByteValue( 7 );
}

//================================================================
//
/// Return the contents of the DEVICE data (8 bits) 
/// embedded in the CDB data.
///
/// This method is just a simple accessor to extract the relevant
/// data from the CDB payload without the user having to refer
/// to the SAT specification for the appropriate byte and offset.
///
/// \return An 8-bit value containing the contents of the
///         DEVICE member of the ATA PASS-THROUGH structure.
//
//================================================================
tUINT8 CAtaPassThru12CDB::GetDevice() const
{
   return GetByteValue( 8 );
}

//================================================================
//
/// Return the contents of the COMMAND data (8 bits) 
/// embedded in the CDB data.
///
/// This method is just a simple accessor to extract the relevant
/// data from the CDB payload without the user having to refer
/// to the SAT specification for the appropriate byte and offset.
///
/// \return An 8-bit value containing the contents of the
///         COMMAND member of the ATA PASS-THROUGH structure.
//
//================================================================
tUINT8 CAtaPassThru12CDB::GetCommand() const
{
   return GetByteValue( 9 );
}

//================================================================
//
/// Return the contents of the CONTROL data (8 bits) 
/// embedded in the CDB data.
///
/// This method is just a simple accessor to extract the relevant
/// data from the CDB payload without the user having to refer
/// to the SAT specification for the appropriate byte and offset.
///
/// \return An 8-bit value containing the contents of the
///         CONTROL member of the ATA PASS-THROUGH structure.
//
//================================================================
tUINT8 CAtaPassThru12CDB::GetControl() const
{
   return GetByteValue( 11 );
}

//================================================================
//
/// Set the contents of any single arbitrary byte from the CDB data.
///
/// This will set the new value after range-checking to ensure
/// that the data length is sufficient.  If insufficient, a
/// DTA_ERROR is thrown prior to attempting the change.
///
/// \param offset (IN) Offset where the new value should be set.
///
/// \param newVal (IN) New value for the appropriate data byte.
///
/// \return An 8-bit value containing the previous contents of the
///         buffer at the appropriate offset.
//
//================================================================
tUINT8 CAtaPassThru12CDB::SetByte( size_type offset, tUINT8 newVal )
{
   if ( size() <= offset )
   {
      throw dta::Error( dta::eGenericInvalidParameter );
   }
   tUINT8 oldVal( at(offset) );
   at(offset) = newVal;
   return oldVal;
}

//================================================================
//
/// Set the contents of the FEATURES data (8 bits) 
/// embedded in the CDB data.
///
/// This method is just a simple accessor to set the relevant
/// data in the CDB payload without the user having to refer
/// to the SAT specification for the appropriate byte and offset.
///
/// \param newVal (IN) New value for the FEATURES member of the
///         ATA PASS_THROUGH(12) structure.
///
/// \return An 8-bit value containing the previous contents of the
///         FEATURES member of the ATA PASS-THROUGH structure.
//
//================================================================
tUINT8 CAtaPassThru12CDB::SetFeatures( tUINT8 newVal )
{
   return SetByte( 3, newVal );
}

//================================================================
//
/// Set the contents of the SECTOR_COUNT data (8 bits) 
/// embedded in the CDB data.
///
/// This method is just a simple accessor to set the relevant
/// data in the CDB payload without the user having to refer
/// to the SAT specification for the appropriate byte and offset.
///
/// \param newVal (IN) New value for the SECTOR_COUNT member of the
///         ATA PASS_THROUGH(12) structure.
///
/// \return An 8-bit value containing the previous contents of the
///         SECTOR_COUNT member of the ATA PASS-THROUGH structure.
//
//================================================================
tUINT8 CAtaPassThru12CDB::SetSectorCount( tUINT8 newVal )
{
   return SetByte( 4, newVal );
}

//================================================================
//
/// Set the contents of the LBA_LOW data (8 bits) 
/// embedded in the CDB data.
///
/// This method is just a simple accessor to set the relevant
/// data in the CDB payload without the user having to refer
/// to the SAT specification for the appropriate byte and offset.
///
/// \param newVal (IN) New value for the LBA_LOW member of the
///         ATA PASS_THROUGH(12) structure.
///
/// \return An 8-bit value containing the previous contents of the
///         LBA_LOW member of the ATA PASS-THROUGH structure.
//
//================================================================
tUINT8 CAtaPassThru12CDB::SetLbaLow( tUINT8 newVal )
{
   return SetByte( 5, newVal );
}

//================================================================
//
/// Set the contents of the LBA_MID data (8 bits) 
/// embedded in the CDB data.
///
/// This method is just a simple accessor to set the relevant
/// data in the CDB payload without the user having to refer
/// to the SAT specification for the appropriate byte and offset.
///
/// \param newVal (IN) New value for the LBA_MID member of the
///         ATA PASS_THROUGH(12) structure.
///
/// \return An 8-bit value containing the previous contents of the
///         LBA_MID member of the ATA PASS-THROUGH structure.
//
//================================================================
tUINT8 CAtaPassThru12CDB::SetLbaMid( tUINT8 newVal )
{
   return SetByte( 6, newVal );
}

//================================================================
//
/// Set the contents of the LBA_HIGH data (8 bits) 
/// embedded in the CDB data.
///
/// This method is just a simple accessor to set the relevant
/// data in the CDB payload without the user having to refer
/// to the SAT specification for the appropriate byte and offset.
///
/// \param newVal (IN) New value for the LBA_HIGH member of the
///         ATA PASS_THROUGH(12) structure.
///
/// \return An 8-bit value containing the previous contents of the
///         LBA_HIGH member of the ATA PASS-THROUGH structure.
//
//================================================================
tUINT8 CAtaPassThru12CDB::SetLbaHigh( tUINT8 newVal )
{
   return SetByte( 7, newVal );
}

//================================================================
//
/// Set the contents of the DEVICE data (8 bits) 
/// embedded in the CDB data.
///
/// This method is just a simple accessor to set the relevant
/// data in the CDB payload without the user having to refer
/// to the SAT specification for the appropriate byte and offset.
///
/// \param newVal (IN) New value for the DEVICE member of the
///         ATA PASS_THROUGH(12) structure.
///
/// \return An 8-bit value containing the previous contents of the
///         DEVICE member of the ATA PASS-THROUGH structure.
//
//================================================================
tUINT8 CAtaPassThru12CDB::SetDevice( tUINT8 newVal )
{
   return SetByte( 8, newVal );
}

//================================================================
//
/// Set the contents of the COMMAND data (8 bits) 
/// embedded in the CDB data.
///
/// This method is just a simple accessor to set the relevant
/// data in the CDB payload without the user having to refer
/// to the SAT specification for the appropriate byte and offset.
///
/// \param newVal (IN) New value for the COMMAND member of the
///         ATA PASS_THROUGH(12) structure.
///
/// \return An 8-bit value containing the previous contents of the
///         COMMAND member of the ATA PASS-THROUGH structure.
//
//================================================================
tUINT8 CAtaPassThru12CDB::SetCommand( tUINT8 newVal )
{
   return SetByte( 9, newVal );
}

//================================================================
//
/// Set the contents of the CONTROL data (8 bits) 
/// embedded in the CDB data.
///
/// This method is just a simple accessor to set the relevant
/// data in the CDB payload without the user having to refer
/// to the SAT specification for the appropriate byte and offset.
///
/// \param newVal (IN) New value for the CONTROL member of the
///         ATA PASS_THROUGH(12) structure.
///
/// \return An 8-bit value containing the previous contents of the
///         CONTROL member of the ATA PASS-THROUGH structure.
//
//================================================================
tUINT8 CAtaPassThru12CDB::SetControl( tUINT8 newVal )
{
   return SetByte( 11, newVal );
}


//================================================================
//
/// Return the contents of the PROTOCOL data (4 bits) 
/// embedded in the CDB data.
///
/// This method is just a simple accessor to extract the relevant
/// data from the CDB payload without the user having to refer
/// to the SAT specification for the appropriate byte and offset.
///
/// \return A 4-bit value containing the contents of the
///         PROTOCOL member of the ATA PASS-THROUGH structure.
//
//================================================================
eProtocol CAtaPassThru12CDB::GetProtocol() const
{
   return static_cast<eProtocol>(
      GetBits( GetByteValue(1), 4, 1 )
      );
}
//================================================================
//
/// Set the contents of the PROTOCOL data (4 bits) 
/// embedded in the CDB data.
///
/// This method is just a simple accessor to set the relevant
/// data in the CDB payload without the user having to refer
/// to the SAT specification for the appropriate byte and offset.
///
/// PROTOCOL is located at byte 1, bits 1 to 4 inclusive.
///
/// \param newVal (IN) New value for the PROTOCOL member of the
///         ATA PASS_THROUGH(12) structure.
///
/// \return An 4-bit value containing the previous contents of the
///         PROTOCOL member of the ATA PASS-THROUGH structure.
//
//================================================================
eProtocol CAtaPassThru12CDB::SetProtocol( eProtocol newVal )
{
   if ( newVal > eProtocolMaxValue )
   {
      throw dta::Error( dta::eGenericInvalidParameter );
   }
   eProtocol result = static_cast<eProtocol>(
      SetBits( GetByte(1), newVal, 4, 1 )
      );
   return result;
}

//================================================================
//
/// Return the number of sectors reported in MULTIPLE_COUNT
/// in the CDB data.
///
/// This method is just a simple accessor to extract the relevant
/// data from the CDB payload without the user having to refer
/// to the SAT specification for the appropriate byte and offset.
///
/// \return The number of sectors set in the MULTIPLE_COUNT 
///      member of the ATA PASS-THROUGH structure.  Note
///      that this count will be zero or a power of two.
//
//================================================================
CAtaPassThru12CDB::size_type 
   CAtaPassThru12CDB::GetMultipleCount() const
{
   size_type result = 0;
   tUINT8 multipleCount = GetBits( GetByteValue(1), 7, 5 );
   if ( multipleCount )
   {
      // multipleCount is actually a sector count in powers of 2.
      result = 2;
      while ( --multipleCount )
      {
         result <<= 1;
      }
   }
   return result;
}

//================================================================
//
/// Sets the number of sectors reported in MULTIPLE_COUNT
/// in the CDB data.
///
/// This method is just a simple accessor to set the relevant
/// data in the CDB payload without the user having to refer
/// to the SAT specification for the appropriate byte and offset.
///
/// MULTIPLE_COUNT is located at byte 1, bits 5 to 7 inclusive.
///
/// \param sectors (IN) The number of sectors to be reported in
///         MULTIPLE_COUNT.  This value must be zero or a power
///         of 2.
///
/// \return An 4-bit value containing the previous contents of the
///         PROTOCOL member of the ATA PASS-THROUGH structure.
//
//================================================================
CAtaPassThru12CDB::size_type 
   CAtaPassThru12CDB::SetMultipleCount( size_type sectors )
{
   tUINT8 multipleCount = 0;
   while ( sectors > 1 )
   {
      multipleCount++;
      sectors /= 2;
   }
   tUINT8 result = SetBits( GetByte(1), multipleCount, 7, 5 );
   return result;
}

//================================================================
//
/// Returns the bits associated with OFF_LINE in the CDB data.
///
/// See the SAT-2 specification or the SetOffLine() method for
/// more detailed information.
///
/// \return A 4-bit value containing the current contents of the
///         OFF_LINE member of the ATA PASS-THROUGH structure.
//
//================================================================
eOffLine CAtaPassThru12CDB::GetOffLine() const
{
   return static_cast<eOffLine>(
      GetBits( GetByteValue(2), 7, 6 )
      );
}

//================================================================
//
/// Sets the bits associated with OFF_LINE in the CDB data.
///
/// From the SAT-2 (r01a) specification:
///
/// The OFF_LINE field specifies the time period during which 
/// the ATA Status register and the ATA Alternate Status 
/// register may be invalid after command acceptance. 
/// 
/// In a  SATL with a PATA device attached, some commands may 
/// cause the PATA device to place the ATA bus in an 
/// indeterminate state. This may cause the ATA host to see 
/// command completion before the command is completed. When 
/// the application client issues a command that is capable 
/// of placing the bus in an indeterminate state, it shall 
/// set the OFF_LINE field to a value that specifies the 
/// maximum number of seconds from the time a command is 
/// issued until the ATA Status register is valid. 
///
/// The SATL shall not use the ATA Status register or ATA 
/// Alternate Status register to determine ATA command 
/// completion status until this time has elapsed. The valid 
/// status is available (2off_line+1 - 2) seconds 
/// (i.e., 0, 2, 6, and 14 seconds) after the command 
/// register is stored.
///
/// \param newVal (IN) The new value to be placed into the OFF_LINE
///         member of the ATA PASS-THROUGH structure.
///
/// \return A 4-bit value containing the previous contents of the
///         OFF_LINE member of the ATA PASS-THROUGH structure.
//
//================================================================
eOffLine CAtaPassThru12CDB::SetOffLine( eOffLine newVal )
{
   // Range check.
   if ( newVal > eOffLineMaxValue )
   {
      throw dta::Error( dta::eGenericInvalidParameter );
   }
   eOffLine result = static_cast<eOffLine>(
      SetBits( GetByte(2), newVal, 7, 6 )
      );
   return result;
}

//================================================================
//
/// Returns whether CK_COND is set in the CDB data.
///
/// See the SAT-2 specification or the SetCheckCondition() method for
/// more detailed information.
///
/// \return A boolean value noting if the OFF_LINE member of the
/// ATA PASS-THROUGH structure is set(true) or cleared(false).
//
//================================================================
bool CAtaPassThru12CDB::GetCheckCondition() const
{
   return GetBit( GetByteValue(2), 5);
}

//================================================================
//
/// Sets the CK_COND bit in the CDB data.
///
/// From the SAT-2 (r01a) specification:
///
/// The CK_COND (Check Condition) bit may be used to request 
/// the SATL to return a copy of ATA register information 
/// in the sense data upon command completion. 
///
/// If the CK_COND bit is set to one the SATL shall return a 
/// status of CHECK CONDITION when the ATA command completes, 
/// even if the command completes successfully, and return 
/// the ATA Normal Output fields (see ATA8-ACS) in the sense 
/// data using the ATA Return descriptor. 
///
/// If the CK_COND bit is set to zero, then the SATL shall 
/// terminate the command with CHECK CONDITION status only 
/// if an error occurs in processing the command.
///
/// \param newVal (IN) A boolean denoting if the CK_COND bit 
///         should be set(tue) or cleared(false) in the 
///         ATA PASS-THROUGH structure.
///
/// \return A boolean value noting if the previous value of the
/// OFF_LINE member in the ATA PASS-THROUGH structure was 
/// set(true) or cleared(false).
//
//================================================================
bool CAtaPassThru12CDB::SetCheckCondition( bool newVal )
{
   return SetBit( GetByte(2), 5, newVal );
}

//================================================================
//
/// Returns the value of T_DIR in the CDB data.
///
/// See the SAT-2 specification or the SetTransferDirection() method for
/// more detailed information.
///
/// \return The current value of T_DIR in the CDB data.
//
//================================================================
eTransferDirection CAtaPassThru12CDB::GetTransferDirection() const
{
   return GetBit( GetByteValue(2), 3)
      ? eTransferDiskToHost
      : eTransferHostToDisk
      ;
}

//================================================================
//
/// Sets the T_DIR bit in the CDB data.
///
/// From the SAT-2 (r01a) specification:
///
/// If the T_DIR bit is set to zero, then the SATL shall transfer 
/// data from the application client to the ATA device. If
/// the T_DIR bit is set to one, then the SATL shall transfer 
/// data from the ATA device to the application client. 
///
/// \param newVal (IN) A boolean denoting if the CK_COND bit 
///         should be set(tue) or cleared(false) in the 
///         ATA PASS-THROUGH structure.
///
/// \return The previous value of T_DIR from the CDB data.
//
//================================================================
eTransferDirection CAtaPassThru12CDB::SetTransferDirection( 
   eTransferDirection newVal )
{
   return SetBit( GetByte(2), 3, 0 != newVal )
      ? eTransferDiskToHost
      : eTransferHostToDisk
      ;
}

//================================================================
//
/// Returns the value of BYTE_BLOCK in the CDB data.
///
/// See the SAT-2 specification or the SetByteBlock() 
/// method for more detailed information.
///
/// \return The current value of BYTE_BLOCK in the CDB data.
//
//================================================================
eByteBlock CAtaPassThru12CDB::GetByteBlock() const
{
   return GetBit( GetByteValue(2), 2)
      ? eTLengthIsBlocks
      : eTLengthIsBytes
      ;
}

//================================================================
//
/// Sets the BYTE_BLOCK bit in the CDB data.
///
/// From the SAT-2 (r01a) specification:
///
/// The BYTE_BLOCK (Byte/Block) bit specifies whether the 
/// transfer length in the location specified by the T_LENGTH 
/// field specifies the number of bytes to transfer or the 
/// number of blocks to transfer. 
///
/// If the value in the BYTE_BLOCK bit is set to zero, then 
/// the SATL shall transfer the number of bytes specified in 
/// the location specified by the T_LENGTH field. 
///
/// If the value in the BYTE_BLOCK bit is set to one the SATL 
/// shall transfer the number of blocks specified in the 
/// location specified by the T_LENGTH field. 
///
/// The SATL shall ignore the BYTE_BLOCK bit when the 
/// T_LENGTH field is set to zero.
///
/// \param newVal (IN) A boolean denoting if the CK_COND bit 
///         should be set(tue) or cleared(false) in the 
///         ATA PASS-THROUGH structure.
///
/// \return The previous value of BYTE_BLOCK from the CDB data.
//
//================================================================
eByteBlock CAtaPassThru12CDB::SetByteBlock( 
   eByteBlock newVal )
{
   return SetBit( GetByte(2), 2, 0 != newVal )
      ? eTLengthIsBlocks
      : eTLengthIsBytes
      ;
}

//================================================================
//
/// Returns the bits associated with T_LENGTH in the CDB data.
///
/// See the SAT-2 specification or the GetTLength() method for
/// more detailed information.
///
/// \return A 2-bit value containing the current contents of the
///         T_LENGTH member of the ATA PASS-THROUGH structure.
//
//================================================================
eTLength CAtaPassThru12CDB::GetTLength() const
{
   return static_cast<eTLength>(
      GetBits( GetByteValue(2), 1, 0 )
      );
}

//================================================================
//
/// Sets the bits associated with T_LENGTH in the CDB data.
///
/// The Transfer Length (T_LENGTH) field specifies where in 
/// the CDB the SATL shall locate the transfer length for
/// the command.
///
/// See the eTLength enumeration for a description of valid values.
///
/// \param newVal (IN) The new value to be placed into the OFF_LINE
///         member of the ATA PASS-THROUGH structure.
///
/// \return A 2-bit value containing the previous contents of the
///         T_LENGTH member of the ATA PASS-THROUGH structure.
//
//================================================================
eTLength CAtaPassThru12CDB::SetTLength( eTLength newVal )
{
   // Range check.
   if ( newVal > eTLengthMaxValue )
   {
      throw dta::Error( dta::eGenericInvalidParameter );
   }
   eTLength result = static_cast<eTLength>(
      SetBits( GetByte(2), newVal, 1, 0 )
      );
   return result;
}
