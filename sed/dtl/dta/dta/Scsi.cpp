/*! \file Scsi.cpp
    \brief Implementation of CScsi

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
#include "Scsi.hpp"

//=================================
// macro/constant definitions
//=================================

//=================================
// typedefs and structures
//=================================
/// Fixed SCSI Vital Product Data result format.
typedef struct _SPC3_VITAL_PRODUCT_DATA
{
   tUINT8 PeripheralDevTypeQual;     //!< Identifies device connected to LUN
   tUINT8 PageCode;                  //!< Page code of returned data
   tUINT8 Byte2Reserved;             //!< Reserved
   tUINT8 PageLength;                //!< Length of the returned data
   tUINT8 Data[1];                   //!< Pointer to first byte of data
} SPC3_VITAL_PRODUCT_DATA;

//=================================
// function implementations
//=================================

//=================================
// class implementations
//=================================

dta::CScsi::CScsi()
: m_blockSize( 0 )
{
}

//================================================================
void dta::CScsi::SecurityDataToDevice( 
      const dta::tBytes &dataToSend,
      const dta::tByte  protocolId,
      const tUINT16     sp_specific
      )
{
   size_t blockSize = GetBlockSize();

   // Round our input size up to the next block size.
   tUINT16 blocks = static_cast<tUINT16>(
      (dataToSend.size() + m_blockSize - 1) / m_blockSize);

   // Pad if necessary.
   dta::tBytes buffer( blocks * blockSize, 0 );
   memcpy( &buffer[0], &dataToSend[0], dataToSend.size() );

   // Build the CDB
   dta::tBytes cdb(12, 0);
   cdb[0] = 0xB5;
   cdb[1] = protocolId;
   cdb[2] = static_cast<tUINT8>(sp_specific >> 8);
   cdb[3] = static_cast<tUINT8>(sp_specific);

   // Copy in the allocation length in big-endian
   tUINT32 allocationLength = blocks; //(tUINT32)dataToSend.size();
   cdb[4] = blocks ? 0x80 : 0x00; // INC_512(bit7), always in blocks
   cdb[6] = static_cast<tUINT8>(allocationLength >> 24);
   cdb[7] = static_cast<tUINT8>(allocationLength >> 16);
   cdb[8] = static_cast<tUINT8>(allocationLength >> 8);
   cdb[9] = static_cast<tUINT8>(allocationLength >> 0);

   // Exchange the CDB
   ExecScsiCdb(cdb, buffer, true);
}

void dta::CScsi::StartStopUnitCommand(
         dta::tBytes &dataToRecv,
         int startOrStop
      )
{
   dta::tBytes cdb(6,0);
   
   cdb[0] = 0x1B;       // Start Stop Unit Command Operation Code
   cdb[1] = 0x00;       // Ignored
   cdb[2] = 0x00;       // Ignored
   cdb[3] = 0x00;       // Ignored
   cdb[4] = startOrStop << 4; // Power Condition field
   cdb[5] = 0x00;       // Ignored
   // Exchange the CDB
   ExecScsiCdb(cdb, dataToRecv, false);
}

//================================================================
void dta::CScsi::SecurityDataFromDevice( 
      dta::tBytes &dataToRecv,
      const dta::tByte  protocolId,
      const tUINT16     sp_specific
      )
{
   size_t blockSize = GetBlockSize();

   // round our input size up to the next block size.
   tUINT16 blocks = static_cast<tUINT16>(
      (dataToRecv.size() + m_blockSize - 1) / m_blockSize);

   // Pad if necessary.
   dataToRecv.resize(blocks * blockSize);

   // Build the CDB
   dta::tBytes cdb(12, 0);
   cdb[0] = 0xA2;
   cdb[1] = protocolId;
   cdb[2] = static_cast<tUINT8>(sp_specific >> 8);
   cdb[3] = static_cast<tUINT8>(sp_specific);

   // Copy in the allocation length in big-endian
   tUINT32 allocationLength = blocks; //(tUINT32)dataToRecv.size();
   cdb[4] = blocks ? 0x80 : 0x00; // INC_512(bit7), always in blocks
   cdb[6] = static_cast<tUINT8>(allocationLength >> 24);
   cdb[7] = static_cast<tUINT8>(allocationLength >> 16);
   cdb[8] = static_cast<tUINT8>(allocationLength >> 8);
   cdb[9] = static_cast<tUINT8>(allocationLength >> 0); 
   
    // Exchange the CDB
   ExecScsiCdb(cdb, dataToRecv, false);
}
//================================================================
size_t dta::CScsi::GetBlockSize()
{
   if ( 0 == m_blockSize )
   {
      GetCapacityInBytes();
   }
   return m_blockSize;
}

//================================================================
tUINT64 dta::CScsi::GetMaxLBA()
{
   return GetCapacityInBytes() / GetBlockSize() - 1;
}

//================================================================
tUINT64 dta::CScsi::GetCapacityInBytes()
{
   dta::tBytes cdb(10,0), buffer(8);
   cdb[0] = 0x25; // READ CAPACITY (10)
   ExecScsiCdb( cdb, buffer, false );

   m_blockSize = 0;
   tUINT64 capacity  = 0;
   int i;
   dta::tByte* data = &buffer[0];
   for ( i = 0; i <= 3; i++ )
   {
      capacity = ( capacity << 8 ) + data[i];
   }
   for ( i = 4; i <= 7; i++ )
   {
      m_blockSize = ( m_blockSize << 8 ) + data[i];
   }

   // Since capacity is in bytes, not blocks, we need to
   // convert it here.
   capacity *= m_blockSize;
   return capacity;
}

//================================================================
const _tstring& dta::CScsi::GetProductIdentification()
{
   if ( 0 == m_productId.size() )
   {
      ExecStandardInquiry();
   }
   return m_productId;
}

//================================================================
const _tstring& dta::CScsi::GetProductRevisionLevel()
{
   if ( 0 == m_productRev.size() )
   {
      ExecStandardInquiry();
   }
   return m_productRev;
}

//================================================================
const _tstring& dta::CScsi::GetVendor()
{
   if ( 0 == m_vendor.size() )
   {
      ExecStandardInquiry();
   }
   return m_vendor;
}

//================================================================
const _tstring& dta::CScsi::GetSerialNumber()
{
   if ( 0 == m_serialNumber.size() )
   {
      // SPC-3 says maximum length of vpd page 80h is 24 bytes.
      dta::tBytes cdb(6,0), buffer( 24 );

      cdb[0] = 0x12; // INQUIRY
      cdb[1] = 0x01; // EVPD (vital product data) bit set
      cdb[2] = 0x80; // Unit Serial Number
      cdb[3] = 0x00; // High order allocation length
      cdb[4] = (tUINT8)buffer.size(); // Low order allocation length

      ExecScsiCdb( cdb, buffer, false );

      SPC3_VITAL_PRODUCT_DATA *vpd = reinterpret_cast<
         SPC3_VITAL_PRODUCT_DATA*>( &buffer[0] );

      m_serialNumber.clear();
      m_serialNumber.reserve( vpd->PageLength );
      char *pData = reinterpret_cast<char*>( vpd->Data );
      while ( vpd->PageLength-- )
      {
         m_serialNumber.push_back( *pData );
         pData++;
      }
   }
   m_serialNumber = dta::Trim( m_serialNumber, true, true );
   return m_serialNumber;
}

//================================================================
void dta::CScsi::ExecStandardInquiry()
{
   // We're only interested in the first 36 bytes of INQUIRY data.
   dta::tBytes cdb(6,0), buffer(36);

   cdb[0] = 0x12; // INQUIRY
   cdb[1] = 0x00; // EVPD (vital product data) bit NOT set
   cdb[2] = 0x00; // No page code (must be zero when EVPD bit zero)
   cdb[3] = 0x00; // High order allocation length
   cdb[4] = (tUINT8)buffer.size(); // Low order allocation length

   ExecScsiCdb( cdb, buffer, false );

   m_vendor.clear();
   m_productId.clear();
   m_productRev.clear();

   const dta::tByte* p = &buffer[0];
   unsigned i;
   for ( i = 8; i <=15; i++ )
   {
      m_vendor.push_back( p[i] );
   }
   for ( i = 16; i <=31; i++ )
   {
      m_productId.push_back( p[i] );
   }
   for ( i = 32; i <=35; i++ )
   {
      m_productRev.push_back( p[i] );
   }

   m_vendor     = dta::Trim( m_vendor,     true, true );
   m_productId  = dta::Trim( m_productId,  true, true );
   m_productRev = dta::Trim( m_productRev, true, true );
}

//================================================================
void dta::CScsi::Read10( 
      dta::tBytes &dataToRecv,
      tUINT32 lba
      )
{
   dta::tBytes cdb( 10, 0 );

   // Build the CDB
   cdb[0] = 0x28; // Read10
   cdb[1] = 0x00; // Protect(bit5->7)|DPO(bit4)|FUA(bit3)|FUA_NV(bit1) not set
   for( int ii=0; ii<4; ii++ ) // 4-byte LBA in big-endian, cbd[2->5]
      cdb[2+ii] = (tUINT8)( lba >> ((3-ii) * 8) );

   cdb[6] = 0; // GroupNumber (bit 0->4)

   tUINT32 blks = (tUINT32) ( dataToRecv.size() / GetBlockSize() );
   cdb[7] = (tUINT8) ( blks >> 8 ); // 2-byte TransferLength in big-endian, cbd[7->8]
   cdb[8] = (tUINT8) ( blks );
   cdb[9] = 0; // CONTROL
   
   ExecScsiCdb( cdb, dataToRecv, false );
}

//================================================================
void dta::CScsi::Write10( 
      dta::tBytes &dataToSend,
      tUINT32 lba
      )
{
   dta::tBytes cdb( 10, 0 );

   // Build the CDB
   cdb[0] = 0x2A; // Write10
   cdb[1] = 0x00; // Protect(bit5->7)|DPO(bit4)|FUA(bit3)|FUA_NV(bit1) not set
   for( int ii=0; ii<4; ii++ ) // 4-byte LBA in big-endian, cbd[2->5]
      cdb[2+ii] = (tUINT8)( lba >> ((3-ii) * 8) );

   cdb[6] = 0; // GroupNumber (bit 0->4)

   tUINT32 blks = (tUINT32) ( dataToSend.size() / GetBlockSize() );
   cdb[7] = (tUINT8) ( blks >> 8 ); // 2-byte TransferLength in big-endian, cbd[7->8]
   cdb[8] = (tUINT8) ( blks );
   cdb[9] = 0; // CONTROL
   
   ExecScsiCdb( cdb, dataToSend, true );
}

//================================================================
void dta::CScsi::Read16( 
      dta::tBytes &dataToRecv,
      tUINT64 lba
      )
{
   dta::tBytes cdb( 16, 0 );
   // Build the CDB
   cdb[0] = 0x88; // Read16
   cdb[1] = 0x00; // Protect(bit5->7)|DPO(bit4)|FUA(bit3)|FUA_NV(bit1) not set
   for( int ii=0; ii<8; ii++ ) // 8-byte LBA in big-endian, cbd[2->9]
      cdb[2+ii] = (tUINT8)( lba >> ((7-ii) * 8) );

   tUINT32 blks = (tUINT32) ( dataToRecv.size() / GetBlockSize() );
   for( int ii=0; ii<4; ii++ ) // 4-byte TransferLength in big-endian, cbd[10->13]
      cdb[10+ii] = (tUINT8) ( blks >> ((3-ii) * 8) );
   
   cdb[14] = 0; // GroupNumber(bit0->4)
   cdb[15] = 0; // CONTROL
   
   ExecScsiCdb( cdb, dataToRecv, false );
}

//================================================================
void dta::CScsi::Write16( 
      dta::tBytes &dataToSend,
      tUINT64 lba
      )
{
   dta::tBytes cdb( 16, 0 );

   // Build the CDB
   cdb[0] = 0x8A; // Write16
   cdb[1] = 0x00; // Protect(bit5->7)|DPO(bit4)|FUA(bit3)|FUA_NV(bit1) not set
   for( int ii=0; ii<8; ii++ ) // 8-byte LBA in big-endian, cbd[2->9]
      cdb[2+ii] = (tUINT8)( lba >> ((7-ii) * 8) );

   tUINT32 blks = (tUINT32) ( dataToSend.size() / GetBlockSize() );
   for( int ii=0; ii<4; ii++ ) // 4-byte TransferLength in big-endian, cbd[10->13]
      cdb[10+ii] = (tUINT8) ( blks >> ((3-ii) * 8) );
   
   cdb[14] = 0; // GroupNumber(bit0->4)
   cdb[15] = 0; // CONTROL
   
   ExecScsiCdb( cdb, dataToSend, true );
}
