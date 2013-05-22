/*! \file Ata.cpp
    \brief Implementation of CAta

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

// Disabled Microsoft warnings on C-style functions
#if defined (_WIN32)
#pragma warning(disable : 4996)
#endif

//=================================
// Include files
//=================================
#include "Ata.hpp"

//=================================
// macro/constant definitions
//=================================

//=================================
// typedefs and structures
//=================================

//=================================
// function implementations
//=================================

//=================================================================================================
//
/// Return whether or not a particular LBA requires 28-bit or
/// 48-bit addressing.  This is an inline method used frequently
/// by reads and writes to determine what type of mode to use.
///
/// \param lba  The lba to be tested for 28-bit or 48-bit addressing.
//
/// \return The minimum required mode for reaching this address.
//
//=================================================================================================
inline ata::etAddressMode GetMinimumMode( tUINT64 lba )
{
   ata::etAddressMode mode;
   if ( lba > 0x0FFFFFFF ) // is 48 bit lba?
   {
      mode = ata::ev48Bit;
   }
   else
   {
      mode = ata::ev28Bit;
   }
   return mode;
}

//=================================
// class implementations
//=================================

ata::CAta::CAta()
: m_blockSize( 0 )
, m_maxLba( 0 )
, m_WWName( 0 ) // jls 20120810
, m_sendOp( ata::evTrustedSend )
, m_recvOp( ata::evTrustedReceive )
{
}

//=================================================================================================
void ata::CAta::GetIDBuffer( dta::tBytes& buffer )
{
   // IDENTIFY DEVICE is always 512 bytes of data.  Always.
   buffer.resize( 512 );
   CAutoTFR tfr( this );
   tfr->InitCommand( ata::evIdentifyDevice );

   dta::DTA_ERROR result = Execute( tfr, buffer );
   if ( M_DtaFail( result ) )
   {
      throw result;
   }

   tUINT16* idwords = (tUINT16*)(&buffer[0]);

   tUINT16 w106 = idwords[106];
   if (  (0 == (w106 >> 15))   // Bit 15 MUST BE zero
      && (1  & (w106 >> 14))   // Bit 14 MUST BE 1
      && (1  & (w106 >> 12))   // Device Logical Sector > 256 Words
      )
   {
      // Get number of words in block, multiply by word size.
      m_blockSize  = *reinterpret_cast<tUINT32*>(&idwords[117]);
      m_blockSize *= sizeof(tUINT16);
   }
   else
   {
      m_blockSize = 512;
   }

   if ( idwords[83] & ( 1 << 10 ) )
   {
      // 48-bit address feature set is supported.  Use words 
      // 100-103 as defined in ATA-8 section 4.11.4
      m_maxLba = *(tUINT64*)(&idwords[100]);
   }
   else
   {
      // 48-bit address feature set is NOT supported.  Use 
      // words 60-61 as defined in ATA-8 section 4.11.4
      m_maxLba = *(tUINT32*)(&idwords[60]);
   }

   if ( m_maxLba )
   {
      // If reported, the max LBA is actually one less than
      // the number of user accessible LBAs, which is what
      // is reported in the respective ID word values.
      --m_maxLba;
   }

   m_productId    = ExtractIdText( buffer, 27, 46 );
   m_productRev   = ExtractIdText( buffer, 23, 26 );
   m_serialNumber = ExtractIdText( buffer, 10, 19 );

   // We are using the WorldWideName field since it provides Vendor ID and unique Vendor Product ID.
   // The WWN has been required in drives since AT8, leaving only some older DriveTrust drives where
   // it is not implemented.

   // Extract World-Wide-Name 64-bit field.   // jls 20120810
   m_WWName = ( ((tUINT64)idwords[108] << 48) | ((tUINT64)idwords[109] << 32) |
                ((tUINT64)idwords[110] << 16) | (tUINT64)idwords[111] );

}

//=================================================================================================
size_t ata::CAta::GetBlockSize()
{
   if ( 0 == m_blockSize )
   {
      dta::tBytes idData( 512 );
      GetIDBuffer( idData );
   }
   return m_blockSize;
}

//=================================================================================================
tUINT64 ata::CAta::GetMaxLBA()
{
   if ( 0 == m_maxLba )
   {
      dta::tBytes idData( 512 );
      GetIDBuffer( idData );
   }
   return m_maxLba;
}

//=================================================================================================
_tstring ata::CAta::ExtractIdText(
   const dta::tBytes& buffer,
   tUINT8 lowWord,
   tUINT8 highWord
   )
{
   if ( 512 != buffer.size() )
   {
      throw dta::Error( dta::eGenericInvalidParameter );
   }

   tUINT16 *iddata = (tUINT16*)( &buffer[0] );
   
   _tstring result;
   result.reserve( (highWord - lowWord + 1) * 2 );

   tUINT8 i;
   for ( i = lowWord; i <= highWord; i++ )
   {
      result += static_cast<tUINT8>( iddata[i] >> 8 );
      result += static_cast<tUINT8>( iddata[i] );
   }

   return dta::Trim( result, true, true );
}

//=================================================================================================
tUINT64 ata::CAta::GetCapacityInBytes()
{
   tUINT64 result = 0;
   dta::tBytes idData;
   GetIDBuffer( idData );

   tUINT16* idwords = (tUINT16*)(&idData[0]);

   tUINT16 w83 = idwords[83];
   if (  (0 == (w83 >> 15))   // Bit 15 MUST BE zero
      && (1  & (w83 >> 14))   // Bit 14 MUST BE 1
      && (1  & (w83 >> 10))   // Bit 10 is '48-bit addr. supported'
      )
   {
      result = *reinterpret_cast<tUINT64*>(&idwords[100]);
   }
   else
   {
      result = *reinterpret_cast<tUINT32*>(&idwords[60]);
   }

   result *= GetBlockSize();

   return result;
}

//=================================================================================================
const _tstring& ata::CAta::GetVendor()   // jls 20120810
{
   if ( 0 == m_WWName )
   {
      dta::tBytes idData( 512 );
      GetIDBuffer( idData );
   }

   // Parse the WorldWideName field into m_vendorId string
   if ( 0 == m_vendorId.size() )
   {
      // Verify WWN is NAA protocol 5 in high nibble. For now, other protocols not supported.
      if( ( (m_WWName >> 60) & 0xf ) == 0x05 )
      {
         // Vendor ID code is next 24 bits after NAA protocol
         tUINT32 vendor = (m_WWName >> 36) & 0xffffff;

         // Use list of IEEE Vendor IDs specified in: http://standards.ieee.org/develop/regauth/oui/oui.txt 
         // to match Seagate IDs with this device's Vendor ID field.
         
         const tUINT32 seagateIds[] = { 0x00040C, 0x000C50, 0x0011C6, 0x0014C3, 0x001862, 0x001D38, 0x002037,
            0x0024B5, 0xB45253 };

         for( tUINT16 i = 0; i < sizeof(seagateIds)/sizeof(seagateIds[0]); i++ )
         {
            if( vendor != seagateIds[i] )
               continue;
            m_vendorId = TXT("SEAGATE");
            return m_vendorId;
         }

         // We could check the Vendor ID for other drive Mfgrs and return their names, but
         // for now, we'll just return UNKNOWN vendor since the main purpose of this function 
         // is to detect Seagate SEDs so we can utilize proprietary features.

         const tUINT32 fujitsuIds[] = { 0x00000E, 0x0002DC, 0x000AE0, 0x000B5D, 0x001055, 0x00108C, 0x001742,
            0x001999, 0x002326, 0x003005, 0x00A077, 0x00A0CA, 0x00E000, 0x2CD444, 0x502690 };

         for( tUINT16 i = 0; i < sizeof(fujitsuIds)/sizeof(fujitsuIds[0]); i++ )
         {
            if( vendor != fujitsuIds[i] )
               continue;
            m_vendorId = TXT("FUJITSU");
            return m_vendorId;
         }

         const tUINT32 toshibaIds[] = { 0x000039, 0x000600, 0x380197, 0x986DC8, 0xFC0012 };

         for( tUINT16 i = 0; i < sizeof(toshibaIds)/sizeof(toshibaIds[0]); i++ )
         {
            if( vendor != toshibaIds[i] )
               continue;
            m_vendorId = TXT("TOSHIBA");
            return m_vendorId;
         }

         const tUINT32 hitachiIds[] = { 0x000087, 0x000185, 0x000205, 0x000346, 0x0004D5, 0x0006FB, 0x0008F7,
            0x000A56, 0x000C09, 0x000E66, 0x00102D, 0x001480, 0x001F67, 0x001FC7, 0x0021BF, 0x004066, 0x0060CB,
            0x0060E8, 0x0080BC, 0x2C8BF2, 0xA497BB, 0xD05FCE, 0xDC175A };
         
         for( tUINT16 i = 0; i < sizeof(hitachiIds)/sizeof(hitachiIds[0]); i++ )
         {
            if( vendor != hitachiIds[i] )
               continue;
            m_vendorId = TXT("HITACHI");
            return m_vendorId;
         }

         const tUINT32 westdigIds[] = { 0x0000C0, 0x000CCA, 0x0014EE, 0x0090A9 };
  
         for( tUINT16 i = 0; i < sizeof(westdigIds)/sizeof(westdigIds[0]); i++ )
         {
            if( vendor != westdigIds[i] )
               continue;
            m_vendorId = TXT("WESTERN DIGITAL");
            return m_vendorId;
         }

         const tUINT32 samsungIds[] =   { 0x000278, 0x0007AB, 0x000918, 0x000DAE, 0x000DE5, 0x001247, 0x0012FB,
            0x001377, 0x001599, 0x0015B9, 0x001632, 0x00166B, 0x00166C, 0x0016DB, 0x0017C9, 0x0017D5, 0x0018AF,
            0x001A8A, 0x001B98, 0x001C43, 0x001D25, 0x001DF6, 0x001E7D, 0x001EE1, 0x001EE2, 0x001FCC, 0x001FCD,
            0x002119, 0x00214C, 0x0021D1, 0x0021D2, 0x002339, 0x00233A, 0x0023C2, 0x0023D6, 0x0023D7, 0x002454,
            0x002490, 0x002491, 0x0024E9, 0x002538, 0x002566, 0x002567, 0x002637, 0x00265D, 0x00265F, 0x00E064,
            0x04180F, 0x04FE31, 0x0C715D, 0x0CDFA4, 0x101DC0, 0x183F47, 0x184617, 0x18E2C2, 0x1C62B8, 0x1C66AA,
            0x2013E0, 0x206432, 0x28987B, 0x2C4401, 0x34C3AC, 0x380197, 0x380A94, 0x3816D1, 0x38AA3C, 0x38ECE4,
            0x3C5A37, 0x3C6200, 0x3C8BFE, 0x444E1A, 0x44F459, 0x4844F7, 0x5001BB, 0x50B7C3, 0x50CCF8, 0x5492BE,
            0x549B12, 0x58C38B, 0x5C0A5B, 0x5CE8EB, 0x606BBD, 0x60A10A, 0x60D0A9, 0x68EBAE, 0x6C8336, 0x70F927,
            0x74458A, 0x7825AD, 0x78471D, 0x78D6F0, 0x8018A7, 0x840B2D, 0x8425DB, 0x8C71F8, 0x8C7712, 0x8CC8CD,
            0x945103, 0x9463D1, 0x980C82, 0x9852B1, 0x9C0298, 0xA00798, 0xA00BBA, 0xA07591, 0xA8F274, 0xB0D09C,
            0xB0EC71, 0xB407F9, 0xB46293, 0xB8C68E, 0xB8D9CE, 0xBC4760, 0xBC851F, 0xBCB1F3, 0xC4731E, 0xC819F7,
            0xC87E75, 0xCC051B, 0xCCF9E8, 0xCCFE3C, 0xD0176A, 0xD0667B, 0xD0C1B1, 0xD0DFC7, 0xD487D8, 0xD48890,
            0xD4E8B2, 0xD857EF, 0xDC7144, 0xE47CF9, 0xE4B021, 0xE4E0C5, 0xE8039A, 0xE81132, 0xE8E5D6, 0xECE09B,
            0xF008F1, 0xF0E77E, 0xF49F54, 0xF4D9FB, 0xF8D0BD, 0xFC0012, 0xFCA13E, 0xFCC734 };

         for( tUINT16 i = 0; i < sizeof(samsungIds)/sizeof(samsungIds[0]); i++ )
         {
            if( vendor != samsungIds[i] )
               continue;
            m_vendorId = TXT("SAMSUNG");
            return m_vendorId;
         }

         // Add other vendor identification here


      } // NAA Protocol 5
      else
      {
         m_vendorId = TXT("UNKNOWN");
      }
   }

   return m_vendorId;
}

//=================================================================================================
const _tstring& ata::CAta::GetProductIdentification()
{
   if ( 0 == m_productId.size() )
   {
      dta::tBytes idData;
      GetIDBuffer(idData);
   }
   return m_productId;
}

//=================================================================================================
const _tstring& ata::CAta::GetProductRevisionLevel()
{
   if ( 0 == m_productRev.size() )
   {
      dta::tBytes idData;
      GetIDBuffer(idData);
   }
   return m_productRev;
}

//=================================================================================================
const _tstring& ata::CAta::GetSerialNumber()
{
   if ( 0 == m_serialNumber.size() )
   {
      dta::tBytes idData;
      GetIDBuffer(idData);
   }
   return m_serialNumber;
}

//=================================================================================================
void ata::CAta::SetFeatures(tUINT8 subCommand, tUINT8 subCommandSpecific)
{
   CAutoTFR tfr ( this );
   tfr->InitCommand(evSetFeatures);
   tfr->SetErrorFeature(subCommand);
   tfr->SetSectorCount(subCommandSpecific);
   tfr->SetLBA(subCommandSpecific);

   // Now send the command
   dta::tBytes dataToSend;
   dta::DTA_ERROR result = Execute( tfr, dataToSend, 0, ata::evNonData, ata::evNoDirection);
   if ( M_DtaFail( result ) )
   {
      throw result;
   }
}

//=================================================================================================
void ata::CAta::EnableSSP()
{
   SetFeatures(evSetFeaturesEnableSATAFeature, evSetFeaturesSATASubcommandSSP);
}

//=================================================================================================
void ata::CAta::DisableSSP()
{
   SetFeatures(evSetFeaturesDisableSATAFeature, evSetFeaturesSATASubcommandSSP);
}

//=================================================================================================
void ata::CAta::SecurityDataToDevice( 
   const dta::tBytes &dataToSend,
   const dta::tByte  protocolId,
   const tUINT16     sp_specific
   )
{
   size_t blockSize = GetBlockSize();

   // round our input size up to the next block size.
   tUINT16 blocks = static_cast<tUINT16>(
      ( dataToSend.size() + m_blockSize - 1 ) / m_blockSize
      );

   // Pad if necessary.
   dta::tBytes buffer( blocks * blockSize, 0 );
   memcpy( &buffer[0], &dataToSend[0], dataToSend.size() );

   CAutoTFR tfr( this );
   tfr->InitCommand( m_sendOp );
   tfr->SetErrorFeature( protocolId );
   tfr->SetSectorCount( static_cast<tUINT8>( blocks ) );
   tfr->SetLBALow( static_cast<tUINT8>( blocks >> 8 ) );
   tfr->SetLBAMid( static_cast<tUINT8>( sp_specific ) );
   tfr->SetLBAHigh(static_cast<tUINT8>( sp_specific >> 8 ) );

   dta::DTA_ERROR result = Execute( tfr, buffer );
   if ( M_DtaFail( result ) )
   {
      throw result;
   }
}

//=================================================================================================
void ata::CAta::SecurityDataFromDevice( 
   dta::tBytes       &dataToRecv,
   const dta::tByte  protocolId,
   const tUINT16     sp_specific
   )
{
   size_t blockSize = GetBlockSize();

   // round our input size up to the next block size.
   tUINT16 blocks = static_cast<tUINT16>(
      ( dataToRecv.size() + m_blockSize - 1 ) / m_blockSize
      );

   // Pad if necessary.
   dataToRecv.resize( blocks * blockSize );

   CAutoTFR tfr( this );
   tfr->InitCommand( m_recvOp );
   tfr->SetErrorFeature( protocolId );
   tfr->SetSectorCount( static_cast<tUINT8>( blocks ) );
   tfr->SetLBALow( static_cast<tUINT8>( blocks >> 8 ) );
   tfr->SetLBAMid( static_cast<tUINT8>( sp_specific ) );
   tfr->SetLBAHigh(static_cast<tUINT8>( sp_specific >> 8 ) );

   dta::DTA_ERROR result = Execute( tfr, dataToRecv );
   if ( M_DtaFail( result ) )
   {
      throw result;
   }
}

//=================================================================================================
void ata::CAta::SetTrustedOpcodes( 
    ata::etOpCodes opSend, 
    ata::etOpCodes opRecv 
    )
{
   m_sendOp = opSend;
   m_recvOp = opRecv;
}

//=================================================================================================
ata::etAddressMode ata::CAta::ValidateLbaAndBuffer( 
   dta::tBytes &buffer,
   tUINT64 &lba
   )
{
   tUINT64 maxLba     = GetMaxLBA();
   size_t  blockSize  = GetBlockSize();

   if ( 0 == blockSize )
   {
      // Don't have a blockSize.  Something BAD has happened.
      throw dta::Error( dta::eGenericFatalError );
   }

   //
   // Round up to the next block if not on a block size boundary.  
   // If buffer is of zero length, ensure that it is at least
   // one block in length.
   //
   size_t blocks = buffer.size()
      ? ( buffer.size() + blockSize - 1 ) / blockSize
      : 1
      ;

   const size_t totalBytes = blocks * blockSize;
   if ( totalBytes != buffer.size() )
   {
      buffer.resize( totalBytes );
   }

   tUINT64 highLba = lba + blocks - 1;

   if ( highLba > maxLba )
   {
      // LBA out of range!
      throw dta::Error( dta::eGenericInvalidParameter );
   }

   return GetMinimumMode( highLba );
}

//=================================================================================================
void ata::CAta::ReadOrWrite( 
   dta::tBytes &data,
   tUINT64 lba,
   ata::etOpCodes op28,
   ata::etOpCodes op48
   )
{
   ata::etAddressMode mode = ValidateLbaAndBuffer( data, lba );

   CAutoTFR tfr( this, mode );

   if ( ata::ev28Bit == mode )
   {
      tfr->InitCommand( op28 );
   }
   else
   {
      tfr->InitCommand( op48 );
   }
   tfr->SetLBA( lba );
   tfr->SetSectorCount( tUINT16(data.size() / GetBlockSize()) );

   dta::DTA_ERROR result = Execute( tfr, data );
   if ( M_DtaFail( result ) )
   {
      throw result;
   }
}

//=================================================================================================
void ata::CAta::ReadPIO( 
   dta::tBytes &dataToRecv,
   tUINT64 lba
   )
{
   ReadOrWrite( dataToRecv, lba, 
      ata::evReadSectors, 
      ata::evReadSectorsExt 
      );
}

//=================================================================================================
void ata::CAta::ReadDMA( 
   dta::tBytes &dataToRecv,
   tUINT64 lba
   )
{
   ReadOrWrite( dataToRecv, lba, 
      ata::evReadDma,
      ata::evReadDmaExt
      );
}

//=================================================================================================
void ata::CAta::WritePIO( 
   dta::tBytes &dataToSend,
   tUINT64 lba
   )
{
   ReadOrWrite( dataToSend, lba, 
      ata::evWriteSectors, 
      ata::evWriteSectorsExt 
      );
}

//=================================================================================================
void ata::CAta::WriteDMA( 
   dta::tBytes &dataToSend,
   tUINT64 lba
   )
{
   ReadOrWrite( dataToSend, lba, 
      ata::evWriteDma,
      ata::evWriteDmaExt
      );
}

//=================================================================================================
void ata::CAta::StandbyImmediate()
{
   CAutoTFR tfr( this );
   tfr->InitCommand(evStandbyImmediate);
   dta::tBytes unused;
   dta::DTA_ERROR result = Execute( tfr, unused );

   if ( M_DtaFail( result ) )
   {
      throw result;
   }
}

//=================================================================================================
void ata::CAta::ReadVerifySectors(tUINT16 count, tUINT64 lba)
{
   CAutoTFR tfr( this );
   tfr->InitCommand(evReadVerifySectors);
   tfr->SetSectorCount(count);
   tfr->SetLBA(lba);
   dta::tBytes unused;
   dta::DTA_ERROR result = Execute( tfr, unused );

   if ( M_DtaFail( result ) )
   {
      throw result;
   }
}

//=================================================================================================
void ata::CAta::ExecuteDeviceDiagnostic()
{
   CAutoTFR tfr( this );
   tfr->InitCommand(evExecuteDeviceDiagnostic);
   dta::tBytes dataToSend;
   dta::DTA_ERROR result = Execute( tfr, dataToSend);

   if ( M_DtaFail( result ) )
   {
      throw result;
   }
}

//=================================================================================================
void ata::CAta::DownloadMicrocode(_tstring filename)
{
   // Open the file for reading
   FILE* file = _tfopen(filename.c_str(), TXT("rb"));

   if (!file)
   {
      throw dta::eGenericInvalidParameter;
   }

   fseek (file, 0, SEEK_END);
   const unsigned int fileSize = ftell(file);
   rewind (file); // reset file pointer to begining of file

   // Now compute the number of time we need to send it
   const unsigned int maxWriteSize      = 0x10000;
   const unsigned int maxWriteNumBlocks = maxWriteSize / 512;
   unsigned int numWrites      = fileSize / maxWriteSize;
   unsigned int bytesRemaining = fileSize % maxWriteSize;

   // Now download the file
   dta::tBytes writeBuffer (maxWriteSize);
   for (unsigned int i = 0; i < numWrites; i++)
   {
      // Read in the bytes
      fread(&writeBuffer[0], sizeof(unsigned char), size_t(maxWriteSize), file);
      DownloadMicrocode(maxWriteNumBlocks, writeBuffer, ata::evDownloadMicrocodeWithOffsets, (i * maxWriteNumBlocks));
   } // for

   // Now pick up the remaining bytes
   writeBuffer.resize(bytesRemaining);
   fread(&writeBuffer[0], sizeof(unsigned char), size_t(bytesRemaining), file);
   DownloadMicrocode((bytesRemaining / 512), writeBuffer, ata::evDownloadMicrocodeWithOffsets, (numWrites * maxWriteNumBlocks));

   // Close the file
   fclose(file);
}

//=================================================================================================
void ata::CAta::DownloadMicrocode(
      tUINT16 blockCount,
      dta::tBytes &dataToSend,
      etDownloadMicrocodeFeature feature,
      tUINT16 bufferOffset
      )
{
   CAutoTFR tfr( this );
   tfr->InitCommand(evDownloadMicrocode);
   tfr->SetSectorCount((tUINT8)blockCount);
   tfr->SetLBALow((tUINT16)blockCount >> 8);
   tfr->SetLBAMid((tUINT8)bufferOffset);
   tfr->SetLBAHigh(bufferOffset >> 8);
   tfr->SetErrorFeature((tUINT16) feature);
   tfr->SetDeviceHead(0x40);
   dta::DTA_ERROR result = Execute( tfr, dataToSend, 0, ata::evPIO,
                                  ((dataToSend.size()) ? ata::evDataOut : ata::evNoDirection) );

   if ( M_DtaFail( result ) )
   {
      throw result;
   }
}

//=================================================================================================
tUINT64 ata::CAta::NVCacheAddLBAsToPinnedSet(bool pi,
                                          dta::tBytes& dataToSend)
{
   CAutoTFR tfr ( this, ata::ev48Bit);
   tfr->InitCommand(evNVCache);
   tfr->SetErrorFeature(evAddLBAsToNVCachePinnedSet);
   tfr->SetLBALow((tUINT16)pi);
   tUINT16 numBlocks = tUINT16(dataToSend.size() ? ((dataToSend.size() - 1) / 512) : 0);
   tfr->SetSectorCount(numBlocks);

   dta::DTA_ERROR result = Execute( tfr, dataToSend, 0, ata::evDMA, ata::evDataOut);

   if ( M_DtaFail( result ) )
   {
      throw result;
   }

   try
   {
      return tfr->GetLBA();
   }
   catch(...)
   {
      return 0;
   }
}

//=================================================================================================
tUINT64 ata::CAta::NVCacheAddLBAsToPinnedSet(bool pi,
                                          const std::vector<PinData> &pinRequestData)
{
   CAutoTFR tfr ( this, ata::ev48Bit);
   tfr->InitCommand(evNVCache);
   tfr->SetErrorFeature(evAddLBAsToNVCachePinnedSet);
   tfr->SetLBALow((tUINT16)pi);
   tfr->SetSectorCount(1);
   dta::tBytes bytesToSend(512);
   memcpy(&bytesToSend[0], &pinRequestData[0],
      min(pinRequestData.size() * sizeof(PinData), bytesToSend.size()));

   dta::DTA_ERROR result = Execute( tfr, bytesToSend, 0, ata::evDMA, ata::evDataOut);

   if ( M_DtaFail( result ) )
   {
      throw result;
   }

   try
   {
      return tfr->GetLBA();
   }
   catch(...)
   {
      return 0;
   }
}

//=================================================================================================
tUINT64 ata::CAta::NVCacheRemoveLBAsFromPinnedSet(dta::tBytes& dataToSend)
{
   CAutoTFR tfr ( this, ata::ev48Bit);
   tfr->InitCommand(evNVCache);
   tfr->SetErrorFeature(evRemoveLBAsFromNVCachePinnedSet);
   tUINT16 numBlocks = tUINT16(dataToSend.size() ? ((dataToSend.size() - 1) / 512) : 0);
   tfr->SetSectorCount(numBlocks);

   dta::DTA_ERROR result = Execute( tfr, dataToSend, 0, ata::evDMA, ata::evDataOut);

   if ( M_DtaFail( result ) )
   {
      throw result;
   }

   try
   {
      return tfr->GetLBA();
   }
   catch(...)
   {
      return 0;
   }
}

//=================================================================================================
tUINT64 ata::CAta::NVCacheRemoveLBAsFromPinnedSet(const std::vector<PinData> &removePinData)
{
   CAutoTFR tfr ( this, ata::ev48Bit);
   tfr->InitCommand(evNVCache);
   tfr->SetErrorFeature(evRemoveLBAsFromNVCachePinnedSet);
   tfr->SetSectorCount(1);
   dta::tBytes bytesToSend(512);
   memcpy(&bytesToSend[0], &removePinData[0],
      min(removePinData.size() * sizeof(PinData), bytesToSend.size()));

   dta::DTA_ERROR result = Execute( tfr, bytesToSend, 0, ata::evDMA, ata::evDataOut);

   if ( M_DtaFail( result ) )
   {
      throw result;
   }

   try
   {
      return tfr->GetLBA();
   }
   catch(...)
   {
      return 0;
   }
}

//=================================================================================================
tUINT64 ata::CAta::NVCacheUnpinAllLBAs()
{
   CAutoTFR tfr ( this, ata::ev48Bit);
   tfr->InitCommand(evNVCache);
   tfr->SetErrorFeature(evRemoveLBAsFromNVCachePinnedSet);
   tfr->SetLBALow(1);

   dta::tBytes emptyBlock(0);
   dta::DTA_ERROR result = Execute( tfr, emptyBlock, 0, ata::evNonData, ata::evNoDirection);

   if ( M_DtaFail( result ) )
   {
      throw result;
   }

   try
   {
      return tfr->GetLBA();
   }
   catch(...)
   {
      return 0;
   }
}

//=================================================================================================
tUINT64 ata::CAta::NVCacheFlush(tUINT32 minNumBlocks)
{
   CAutoTFR tfr ( this, ata::ev48Bit);
   tfr->InitCommand(evNVCache);
   tfr->SetErrorFeature(evFlushNVCache);
   tfr->SetLBA((tUINT64)minNumBlocks);

   dta::tBytes emptyBlock;
   dta::DTA_ERROR result = Execute( tfr, emptyBlock, 0, ata::evNonData, ata::evDataOut);

   if ( M_DtaFail( result ) )
   {
      throw result;
   }

   try
   {
      return tfr->GetLBA();
   }
   catch(...)
   {
      return 0;
   }
}

//=================================================================================================
void ata::CAta::NVCacheDisable()
{
   CAutoTFR tfr ( this, ata::ev48Bit);
   tfr->InitCommand(evNVCache);
   tfr->SetErrorFeature(evQueryNVCacheDisable);

   dta::tBytes emptyBlock;
   dta::DTA_ERROR result = Execute( tfr, emptyBlock, 0, ata::evNonData, ata::evNoDirection);

   if ( M_DtaFail( result ) )
   {
      throw result;
   }
}

//=================================================================================================
void ata::CAta::NVCacheEnable()
{
   CAutoTFR tfr ( this, ata::ev48Bit);
   tfr->InitCommand(evNVCache);
   tfr->SetErrorFeature(evQueryNVCacheEnable);

   dta::tBytes emptyBlock;
   dta::DTA_ERROR result = Execute( tfr, emptyBlock, 0, ata::evNonData, ata::evNoDirection);

   if ( M_DtaFail( result ) )
   {
      throw result;
   }
}

//=================================================================================================
tUINT64 ata::CAta::NVCacheQueryMisses(dta::tBytes &dataToRecv)
{
   CAutoTFR tfr ( this, ata::ev48Bit);
   tfr->InitCommand(evNVCache);
   tfr->SetErrorFeature(evQueryNVCacheMisses);
   tfr->SetSectorCount(1);
   dataToRecv.resize(512);

   dta::DTA_ERROR result = Execute( tfr, dataToRecv, 0, ata::evDMA, ata::evDataIn);

   if ( M_DtaFail( result ) )
   {
      throw result;
   }

   try
   {
      return tfr->GetLBA();
   }
   catch(...)
   {
      return 0;
   }
}

//=================================================================================================
tUINT64 ata::CAta::NVCacheQueryPinnedSet(tUINT16 numBlocks,
                                 tUINT64 startingDataBlock,
                                 dta::tBytes &dataToRecv)
{
   CAutoTFR tfr ( this, ata::ev48Bit);
   tfr->InitCommand(evNVCache);
   tfr->SetErrorFeature(evQueryNVCachePinnedSet);
   tfr->SetSectorCount(numBlocks);
   tfr->SetLBA(startingDataBlock);
   dataToRecv.resize(numBlocks * 512);

   dta::DTA_ERROR result = Execute( tfr, dataToRecv, 0, ata::evDMA, ata::evDataIn);

   if ( M_DtaFail( result ) )
   {
      throw result;
   }

   try
   {
      return tfr->GetLBA();
   }
   catch(...)
   {
      return 0;
   }
}

//=================================================================================================
void ata::CAta::SecuritySetPasswordUser(const dta::tBytes &newPassword,
                                        etMasterPasswordCapability masterCapability)
{
   CAutoTFR tfr ( this );
   tfr->InitCommand(evSecuritySetPassword);

   // Create the command payload
   dta::tBytes dataToSend(512);
   SecuritySetPasswordDataContent* payload = (SecuritySetPasswordDataContent*)&dataToSend[0];

   // Fill in the command payload structure
   payload->identfier = evUserPassword;
   payload->masterPasswordCapability = masterCapability;
   if (newPassword.size())
   {
      memcpy(&payload->password, &newPassword[0], min(32, newPassword.size()));
   }

   // Now send the command
   dta::DTA_ERROR result = Execute( tfr, dataToSend, 0, ata::evPIO, ata::evDataOut );
   if ( M_DtaFail( result ) )
   {
      throw result;
   }
} // SecuritySetPasswordUser

//=================================================================================================
void ata::CAta::SecuritySetPasswordMaster(dta::tBytes &newPassword,
                                          tUINT16 masterPasswordIdentifier)
{
   CAutoTFR tfr ( this );
   tfr->InitCommand(evSecuritySetPassword);

   // Create the command payload
   dta::tBytes dataToSend(512);
   SecuritySetPasswordDataContent* payload = (SecuritySetPasswordDataContent*)&dataToSend[0];

   // Fill in the command payload structure
   payload->identfier = evMasterPassword;
   if (newPassword.size())
   {
      memcpy(&payload->password, &newPassword[0], min(32, newPassword.size()));
   }

   // Set the Master Password Identifier
   payload->masterPasswordIdentifer = masterPasswordIdentifier;

   // Now send the command
   dta::DTA_ERROR result = Execute( tfr, dataToSend );
   if ( M_DtaFail( result ) )
   {
      throw result;
   }
} // SecuritySetPasswordMaster

//=================================================================================================
void ata::CAta::SecurityUnlock(dta::tBytes &password, etSecurityPasswordType passwordType)
{
   CAutoTFR tfr ( this );
   tfr->InitCommand(evSecurityUnlock);

   // Create the command payload
   dta::tBytes dataToSend(512);
   SecurityUnlockDataContent* payload = (SecurityUnlockDataContent*)&dataToSend[0];

   // Fill in the command payload structure
   payload->identfier = passwordType;
   if (password.size())
   {
      memcpy(&payload->password, &password[0], min(32, password.size()));
   }

   // Now send the command
   dta::DTA_ERROR result = Execute( tfr, dataToSend, 0, ata::evPIO, ata::evDataOut );
   if ( M_DtaFail( result ) )
   {
      throw result;
   }
} // SecurityUnlock

//=================================================================================================
void ata::CAta::SecurityErasePrepare()
{
   CAutoTFR tfr ( this );
   tfr->InitCommand(evSecurityErasePrepare);

   // Create the command payload
   dta::tBytes dataToSend;

   // Now send the command
   dta::DTA_ERROR result = Execute( tfr, dataToSend, 0, ata::evNonData );
   if ( M_DtaFail( result ) )
   {
      throw result;
   }
} // SecurityErasePrepare

//=================================================================================================
void ata::CAta::SecurityEraseUnit(etSecurityPasswordType identifer,
                                  dta::tBytes &password,
                                  etSecurityEraseMode eraseMode)
{
   CAutoTFR tfr ( this );
   tfr->InitCommand(evSecurityEraseUnit);

   // Create the command payload
   dta::tBytes dataToSend(512);
   SecurityEraseUnitDataContent* payload = (SecurityEraseUnitDataContent*)&dataToSend[0];

   // Fill in the command payload structure
   payload->identfier = identifer;
   payload->eraseMode = eraseMode;
   if (password.size())
   {
      memcpy(&payload->password, &password[0], min(32, password.size()));
   }

   // Now send the command
   dta::DTA_ERROR result = Execute( tfr, dataToSend, 0, ata::evPIO, ata::evDataOut );
   if ( M_DtaFail( result ) )
   {
      throw result;
   }
} // SecurityEraseUnit

//=================================================================================================
void ata::CAta::SecurityFreezeLock()
{
   CAutoTFR tfr ( this );
   tfr->InitCommand(evSecurityFreezeLock);

   // Create the command payload
   dta::tBytes dataToSend;

   // Now send the command
   dta::DTA_ERROR result = Execute( tfr, dataToSend, 0, ata::evNonData);
   if ( M_DtaFail( result ) )
   {
      throw result;
   }
} // SecurityFreezeLock

//=================================================================================================
void ata::CAta::SecurityDisablePassword(dta::tBytes &password, etSecurityPasswordType passwordType)
{
   CAutoTFR tfr ( this );
   tfr->InitCommand(evSecurityDisablePassword);

   // Create the command payload
   dta::tBytes dataToSend(512);
   SecurityDisablePasswordDataContent* payload = (SecurityDisablePasswordDataContent*)&dataToSend[0];

   // Fill in the command payload structure
   payload->identfier = passwordType;
   if (password.size())
   {
      memcpy(&payload->password, &password[0], min(32, password.size()));
   }

   // Now send the command
   dta::DTA_ERROR result = Execute( tfr, dataToSend, 0, ata::evPIO, ata::evDataOut );
   if ( M_DtaFail( result ) )
   {
      throw result;
   }
} // SecurityDisablePassword

//=================================================================================================
bool ata::CAta::GetSmartStatus()
{
   bool smartStatus;
   CAutoTFR tfr( this );
   tfr->InitCommand( evSMART );
   tfr->SetErrorFeature( 0xDA ); // SMART RETURN STATUS
   tfr->SetLBAMid( 0x4F );       // required for SMART RETURN STATUS
   tfr->SetLBAHigh(0xC2 );       // required for SMART RETURN STATUS
   tfr->SetDeviceHead( 0xA0 );

   dta::tBytes unused;
   dta::DTA_ERROR result = Execute( tfr, unused );
   if ( M_DtaFail( result ) )
   {
      throw result;
   }

   switch ( tfr->GetLBAMid() )
   {
   case 0x4F:
      if ( 0xC2 == tfr->GetLBAHigh() )
      {
         // mid == 0x4f, high == 0xc2 means not threshold exceeded.
         smartStatus = false;
      }
      else
      {
         // Device returned something not in the spec.
         throw dta::Error( dta::eGenericFatalError );
      }
      break;
   case 0xF4:
      if ( 0x2C == tfr->GetLBAHigh() )
      {
         // mid == 0xf4, high == 0x2c means not threshold exceeded.
         smartStatus = true;
      }
      else
      {
         // Device returned something not in the spec.
         throw dta::Error( dta::eGenericFatalError );
      }
      break;
   default:
      // Device returned something not in the spec.
      throw dta::Error( dta::eGenericFatalError );
      break;
   }

   return smartStatus;
}

//=================================================================================================
void ata::CAta::SmartReadLog(
      dta::tBytes& buffer,
      tUINT8 logAddress
      )
{
   size_t  blockSize  = GetBlockSize();

   if ( 0 == blockSize )
   {
      // Don't have a blockSize.  Something BAD has happened.
      throw dta::Error( dta::eGenericFatalError );
   }

   //
   // Round up to the next block if not on a block size boundary.  
   // If buffer is of zero length, ensure that it is at least
   // one block in length.
   //
   tUINT16 blocks = (tUINT16)(buffer.size()
      ? ( buffer.size() + blockSize - 1 ) / blockSize
      : 1
      );

   const size_t totalBytes = blocks * blockSize;
   if ( totalBytes != buffer.size() )
   {
      buffer.resize( totalBytes );
   }

   
   CAutoTFR tfr( this );
   tfr->InitCommand( evSMART );
   tfr->SetErrorFeature( 0xD5 ); // SMART READ LOG
   tfr->SetSectorCount( blocks );
   tfr->SetLBALow( logAddress );
   tfr->SetLBAMid( 0x4F );       // required for SMART READ LOG
   tfr->SetLBAHigh(0xC2 );       // required for SMART READ LOG

   dta::DTA_ERROR result = Execute( tfr, buffer );
   if ( M_DtaFail( result ) )
   {
      throw result;
   }
}

//=================================================================================================
ata::PinData ata::CAta::toPinData(tPinData data)
{
   PinData pinDataStruct;
   pinDataStruct.lbaValue    = data.first;
   pinDataStruct.rangeLength = data.second;
   return pinDataStruct;
}

//=================================================================================================
void ata::CAta::SanitizeDevice(etSanitizeDeviceMode sanitizeDevMode)
{
   CAutoTFR tfr ( this );
   tfr->InitCommand(evSanitizeDevice);
   if (sanitizeDevMode == evSanitizeDeviceCryptoScrambleExt)
   {
      tfr->SetErrorFeature(sanitizeDevMode);
      tfr->SetSectorCount(0x0000);
      tfr->SetLBA(0x0000000043727970);
      tfr->SetDeviceHead(0xA0);
   }
   else if (sanitizeDevMode == evSanitizeDeviceOverwriteExt)
   {
      tfr->SetErrorFeature(sanitizeDevMode);
      tfr->SetSectorCount(0x0002); // no pattern invert, 2 x overwrite
      tfr->SetLBA(0x4F570A0B0C0D0E0F); // pattern: 0a0b0c0d0e0f
      tfr->SetDeviceHead(0xA0);
   }
   else if (sanitizeDevMode == evSanitizeDeviceFreezeLockExt)
   {
      tfr->SetErrorFeature(sanitizeDevMode);
      tfr->SetSectorCount(0x0000); 
      tfr->SetLBA(0x0000000046724C6B);
      tfr->SetDeviceHead(0xA0);
   }
   else if (sanitizeDevMode == evSanitizeDeviceStatusExt)
   {
      tfr->SetErrorFeature(sanitizeDevMode);
      tfr->SetSectorCount(0x0000);
      tfr->SetLBA(0x0000000000000000);
      tfr->SetDeviceHead(0xA0);
   }
   else
   {
      // should not come in here
   }

   // Now send the command
   dta::tBytes dataToSend;
   dta::DTA_ERROR result = Execute( tfr, dataToSend, 0, ata::evNonData, ata::evNoDirection);
   if ( M_DtaFail( result ) )
   {
      throw result;
   }

   if (sanitizeDevMode == evSanitizeDeviceStatusExt)
   {
      tUINT16 val = tfr->GetSectorCount();
      //if (!((val >> 15) & 0x01) )
      // TODO: handle the return status for pooling
      if (((val >> 14) & 0x01) ) 
      {
         throw result;
      }
   }

} // SecurityDisablePassword