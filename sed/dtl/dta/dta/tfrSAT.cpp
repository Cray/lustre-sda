/*! \file osTfrATAPT.cpp
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
#include "tfrSAT.hpp"
#include <dta/splitjoin.hpp>

//=================================
// macro/constant definitions
//=================================
/// CDB byte 1 bit ranges
#define EXTEND                     0
#define PROTOCOL_LOW               1
#define PROTOCOL_HIGH              4
#define MULTIPLE_COUNT_LOW         5
#define MULTIPLE_COUNT_HIGH        7

/// CDB byte 2 bit ranges
#define T_LENGTH_LOW               0
#define T_LENGTH_HIGH              1
#define BYTE_BLOCK                 2
#define T_DIR                      3
#define CK_COND                    4
#define OFF_LINE                   5

/// Valid values for the PROTOCOL bits in the ATA PASS-THROUGH CDB.
enum etSatProtocol
{
   evProtocolATAHardwareReset   =  0,   //!< Hard Reset(PATA) or COMRESET(SATA)
   evProtocolSRST               =  1,   //!< Soft Reset (no data)
   evProtocolNonData            =  3,   //!< Non-Data Command
   evProtocolPioDataIn          =  4,   //!< PIO Data In
   evProtocolPioDataOut         =  5,   //!< PIO Data Out
   evProtocolDma                =  6,   //!< DMA command
   evProtocolDmaQueued          =  7,   //!< DMA Queued Command
   evProtocolDeviceDiagnostic   =  8,   //!< Device Diagnostic
   evProtocolDeviceReset        =  9,   //!< Device Reset
   evProtocolUdmaDataIn         = 10,   //!< UDMA Data In
   evProtocolUdmaDataOut        = 11,   //!< UDMA Data Out
   evProtocolFPDMA              = 12,   //!< First-party DMA
   evProtocolReturnResponseInfo = 15,   //!< Return (shadow) TFRs
   evProtocolInvalid            = 16    //!< Invalid protocol, error
};

//=================================
// typedefs and structures
//=================================

//=================================
// function implementations
//=================================

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
///         not more than the value of 'high'.
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
/// \param high (IN) The offset to the low bit for extraction.
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

//================================================================
sat::CTfr::CTfr( ata::etAddressMode addressMode )
: ata::CTfr( addressMode )
{
   CTfr::Initialize( addressMode );
}

//================================================================
sat::CTfr::~CTfr()
{
}

//================================================================
void sat::CTfr::Initialize( ata::etAddressMode addressMode )
{
   ata::CTfr::Initialize( addressMode );
   memset( &m_cdb, 0, sizeof(m_cdb) );
   switch ( GetAddressMode() )
   {
   case ata::ev48Bit:
      m_cdb[0] = 0x85;
      break;
   case ata::ev28Bit:
      m_cdb[0] = 0xA1;
      break;
   default:
      // Unknown addressing mode.
      throw dta::Error( dta::eGenericInvalidParameter );
      break;
   }
}

//================================================================
tUINT8 sat::CTfr::GetTFRValue( tUINT8 index48, tUINT8 index28 ) const
{
   tUINT8 result = 0;
   switch ( GetAddressMode() )
   {
   case ata::ev48Bit:
      result = m_cdb[index48];
      break;
   case ata::ev28Bit:
      result = m_cdb[index28];
      break;
   default:
      // Unknown addressing mode.
      throw dta::Error( dta::eGenericFatalError );
      break;
   }
   return result;
}

//================================================================
tUINT16 sat::CTfr::GetTFRValue(tUINT8 highIndex, 
                          tUINT8 lowIndex, tUINT8 index ) const
{
   tUINT16 result = 0;
   switch ( GetAddressMode() )
   {
   case ata::ev48Bit:
      result = dta::Join( m_cdb[highIndex], m_cdb[lowIndex] );
      break;
   case ata::ev28Bit:
      result = m_cdb[index];
      break;
   default:
      // Unknown addressing mode.
      throw dta::Error( dta::eGenericFatalError );
      break;
   }
   return result;
}

//================================================================
tUINT16 sat::CTfr::GetErrorFeature() const
{
   return GetTFRValue( 3, 4, 3 );
}

//================================================================
tUINT16 sat::CTfr::GetSectorCount() const
{
   return GetTFRValue( 5, 6, 4 );
}

//================================================================
tUINT16 sat::CTfr::GetLBALow() const
{
   return GetTFRValue( 7, 8, 5 );
}

//================================================================
tUINT16 sat::CTfr::GetLBAMid() const
{
   return GetTFRValue( 9, 10, 6 );
}

//================================================================
tUINT16 sat::CTfr::GetLBAHigh() const
{
   return GetTFRValue( 11, 12, 7 );
}

//================================================================
tUINT8 sat::CTfr::GetDeviceHead() const
{
   return GetTFRValue( 13, 8 );
}

//================================================================
tUINT8 sat::CTfr::GetCommandStatus() const
{
   return GetTFRValue( 14, 9 );
}

//================================================================
void sat::CTfr::SetTFRValue( tUINT8 value, tUINT8 index48, tUINT8 index28 )
{
   switch ( GetAddressMode() )
   {
   case ata::ev48Bit:
      m_cdb[index48] = value;
      break;
   case ata::ev28Bit:
      m_cdb[index28] = value;
      break;
   default:
      // Unknown addressing mode.
      throw dta::Error( dta::eGenericFatalError );
      break;
   }
}

//================================================================
void sat::CTfr::SetTFRValue(tUINT16 value, tUINT8 highIndex, 
                            tUINT8 lowIndex, tUINT8 index )
{
   tUINT8 high, low;
   dta::Split( high, low, value );

   switch ( GetAddressMode() )
   {
   case ata::ev48Bit:
      m_cdb[highIndex] = high;
      m_cdb[lowIndex]  = low;
      break;
   case ata::ev28Bit:
      m_cdb[index] = low;
      if ( 0 != high )
      {
         // Provided value too large.
         throw dta::Error( dta::eGenericInvalidParameter );
      }
      break;
   default:
      // Unknown addressing mode.
      throw dta::Error( dta::eGenericFatalError );
      break;
   }
}


//================================================================
void sat::CTfr::SetErrorFeature( tUINT16 value )
{
   SetTFRValue( value, 3, 4, 3 );
}

//================================================================
void sat::CTfr::SetSectorCount( tUINT16 value )
{
   SetTFRValue( value, 5, 6, 4 );
}

//================================================================
void sat::CTfr::SetLBALow( tUINT16 value )
{
   SetTFRValue( value, 7, 8, 5 );
}

//================================================================
void sat::CTfr::SetLBAMid( tUINT16 value )
{
   SetTFRValue( value, 9, 10, 6 );
}

//================================================================
void sat::CTfr::SetLBAHigh( tUINT16 value )
{
   SetTFRValue( value, 11, 12, 7 );
}

//================================================================
void sat::CTfr::SetDeviceHead( tUINT8 value )
{
   SetTFRValue( value, 13, 8 );
}

//================================================================
void sat::CTfr::SetCommandStatus( tUINT8 value )
{
   SetTFRValue( value, 14, 9 );
}

//================================================================
void* sat::CTfr::CompletePrepare( 
   dta::tBytes& buffer,
   size_t &timeout,
   ata::etProtocol &protocol,
   ata::etDataDirection &direction
   )
{
   bool testBufferExists = false;

   // Set T_LENGTH to use length in TPSIU.  Some bridges seem
   // to have problems with other settings.
   SetBits( m_cdb[2], 3, T_LENGTH_HIGH, T_LENGTH_LOW );

   if ( ata::ev48Bit == GetAddressMode() )
   {
      SetBits( m_cdb[1], 1, EXTEND, EXTEND );
   }
   else
   {
      SetBits( m_cdb[1], 0, EXTEND, EXTEND );
   }

   switch( direction )
   {
   case ata::evNoDirection:
      break;
   case ata::evDataOut:
      SetBits( m_cdb[2], 0, T_DIR, T_DIR );
      break;
   case ata::evDataIn:
      SetBits( m_cdb[2], 1, T_DIR, T_DIR );
      break;
   }

   etSatProtocol satProtocol = evProtocolInvalid;
   switch( protocol )
   {
   case ata::evNonData:
      satProtocol = evProtocolNonData;
      break;
   case ata::evPIO:
      if ( ata::evDataOut == direction )
      {
         satProtocol = evProtocolPioDataOut;
      }
      else
      {
         satProtocol = evProtocolPioDataIn;
      }
      break;
   case ata::evDMA:
      // Don't know why this isn't the right translation.
      // satProtocol = evProtocolDma;
      // Instead, I'll use the UDMA enumeration.
      if ( ata::evDataOut == direction )
      {
         satProtocol = evProtocolUdmaDataOut;
      }
      else
      {
         satProtocol = evProtocolUdmaDataIn;
      }
      break;
   case ata::evDMAQ:
      satProtocol = evProtocolDmaQueued;
      break;
   case ata::evReset:
      satProtocol = evProtocolDeviceReset;
      break;
   case ata::evDiagnostic:
      satProtocol = evProtocolDeviceDiagnostic;
      break;
   }
   SetBits( m_cdb[1], satProtocol, PROTOCOL_HIGH, PROTOCOL_LOW  );

   return &m_cdb[0];
}

