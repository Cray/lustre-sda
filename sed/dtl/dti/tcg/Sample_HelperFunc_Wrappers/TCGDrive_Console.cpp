//=================================================================================================
//  TCGDrive.cpp
//  Demonstrates how TCG Enterprise and Opal SSC storage security features work on a Seagate enterprise 
//  or Opal security drive (Hurricane/Firefly SAS/FC, Julius SATA) through the use of Segate TCG Library APIs.
//
//  \legal 
//   All software, source code, and any additional materials contained
//   herein (the "Software") are owned by Seagate Technology LLC and are 
//   protected by law and international treaties.  No rights to the 
//   Software, including any rights to distribute, reproduce, sell, or 
//   use the Software, are granted unless a license agreement has been 
//   mutually agreed to and executed between Seagate Technology LLC and 
//   an authorized licensee. 
//
//   The Software contains SEAGATE CONFIDENTIAL INFORMATION AND SEAGATE 
//   TRADE SECRET INFORMATION that must be protected as such.
//
//   Copyright © 2009-2012.  Seagate Technology LLC  All Rights Reserved.
//
//  The Software is provided under the Agreement No. 134849 between Seagate
//  Technology and Calsoft. All Intellectual Property rights to the Software,
//  as between Calsoft and Seagate, will be governed under the terms of the 
//  Agreement No. 134849; no other rights to the Software are granted.
//    
//=================================================================================================

#if defined(_WIN32) // nvn20110726
#include <iostream>
#include <sstream>
#elif (__linux__) 
#include <unistd.h> // nvn20110901
#include <iostream> // nvn20110719 // try to be portable by using ostreamstring instead of sprintf_s
#include <sstream>
#define _stricmp(s1, s2) strcasecmp(s1, s2)
#define _strnicmp(s1, s2, n) strncasecmp(s1, s2, (n))
#include <stdio.h>
#else // not WIN32
#endif
#include "TCGDrive_Console.hpp"

#define wcout cout

extern char* _version_;

bool progressUpdate( tUINT64 total, tUINT64 start, tUINT64 current, tUINT64 pace );

CTcgDrive::CTcgDrive( const _tstring protocolLogFileName, const _tstring deviceEnumerationLogFileName,
                      const _tstring &driveSerialNumber )
          : m_pATA(NULL), m_tperSN(0), m_maxLba(0), m_blockSize(512), m_numberBands(0), m_device(NULL), m_session(NULL), m_localSystem(NULL)
{
   try
   {
      // Set up the local system object (OS-specific)
      if( !M_DtaSuccess( CreateLocalSystemObject( m_localSystem ) ) )
      {
         std::wcerr << TXT("Failed to CreateLocalSystemObject.") << std::endl;
         throw 1;
      }

      // Indicate we want the SDK LIBs to throw errors rather than have us monitor returned status.
      m_localSystem->SetThrowOnError( true );

      // Start out with no protocols valid - Protocol 0 discovery will update these.
      m_bTCGprotocol = false;    // TCG Protocols 1-6
      m_bSeaCOSprotocol = false; // SeaCOS Protocol 0xF0
      m_bIEEEprotocol = false;   // 1667 Protocol 0xEE

      // Enumerate currently available Trusted drives, and if a matching drive SerialNumber
      // isn't found, or if there are more than one trusted drive, have user select one.
      
      DTIdentifier id = selectDevice( m_localSystem, driveSerialNumber, deviceEnumerationLogFileName );

      if( id.size() == 0 )
      {
         std::wcerr << TXT("No Trusted Devices could be found.") << std::endl;
#if (__linux__)
         std::wstring wtmp(deviceEnumerationLogFileName.length(), L' ');
         std::copy(deviceEnumerationLogFileName.begin(), deviceEnumerationLogFileName.end(), wtmp.begin());
         if( deviceEnumerationLogFileName.size() > 0 )
            std::wcerr << TXT("See logfile \"") << wtmp << TXT("\" for details.") << std::endl;
#else
         if( deviceEnumerationLogFileName.size() > 0 )
            std::wcerr << TXT("See logfile \"") << deviceEnumerationLogFileName << TXT("\" for details.") << std::endl;
#endif
         throw 2;
      }

      // Set up a local "session" for the selected drive. Local System throws error if failure..
      m_localSystem->CreateSession( id, 0x01, TXT("-log ") + deviceEnumerationLogFileName, m_session );
      m_session->SetThrowOnError( true );
      m_session->SetAttribute( TXT("Timeout"), TXT("30") );

      // Initialize class information.
      _tstring attrValue;
      m_session->GetAttribute( TXT("BlockSize"), attrValue );
      m_blockSize = _tatoi( attrValue.c_str() );
      m_session->GetAttribute( TXT("CapacityInBytes"), attrValue );
      m_maxLba = _tstoi64( attrValue.c_str() )/m_blockSize;
      
      m_session->GetAttribute( TXT("Transport" ), attrValue );
      if( attrValue == TXT("ATA") )
         m_pATA = dynamic_cast<ata::CAta*>( m_session );
      else if( attrValue == TXT("SCSI") )
         m_pSCSI = dynamic_cast<dta::CScsi*>( m_session );
      else
      {
         std::wcerr << TXT("Unknown Transport Bus for Device. Can go no further!") << std::endl;
      }

      int sscType = -1;    // -1 means don't know, 1=Enterprise, 2=Opal, 3= other.

      // Before instantiating a TCGInterface, make sure that the drive 
      // can support this, based on whether the TCG feature set is present 
      // and enabled in the drive's IdentifyDevice data (ATA) or by another
      // method if drive is SCSI.

      if( m_pATA )
      {
         // Read the Identify_Device data from drive
         dta::tBytes buffer;
         m_pATA->GetIDBuffer( buffer );
         tUINT16 *pw = (tUINT16 *) &buffer[0];

         // Word 48 holds the Trusted Computing feature set options.
         if( pw[48] & 0x0001 )
         {
            m_device = ITCGInterface::CreateTCGInterface( m_session, protocolLogFileName, sscType );

            if( NULL == m_device )
            {
               std::wcerr << TXT("Can't create ITCGInterface object for SATA device") << std::endl;
               throw 3;
            }
         } // TC Feature set
      } // if m_pATA
      else if( m_pSCSI )
      {
         // Unknown how SCSI devices indicate TCG support before doing equivalent 
         // of a Protocol Discovery, but should do whatever here is needed.
         if( true )
         {
            m_device = ITCGInterface::CreateTCGInterface( m_session, protocolLogFileName, sscType );

            if( NULL == m_device )
            {
               std::wcerr << TXT("Can't create ITCGInterface object for SCSI device") << std::endl;
               throw 3;
            }
         } // true
      }
      else
         throw 4;
   }
   catch( ... )
   {
      std::wcerr << TXT("CTcgDrive initialization failed, program exits.") << std::endl;
      exit( 1 );
   }
} // CTcgDrive()

//=======================================================================================
CTcgDrive::~CTcgDrive()
{
   try
   {
      if( NULL != m_device )
      {
         delete m_device;
      }

      if( NULL != m_session )
      {
         m_session->Destroy();
      }

      if( NULL != m_localSystem )
      {
         if( !M_DtaSuccess( m_localSystem->Destroy() ) )
         {
            std::wcerr << TXT("Couldn't free the CLocalSystem object!") << std::endl;
            throw 1;
         }
      }
   }
   catch( ... )
   {
      std::wcerr << TXT("TCG drive uninitialization failed, program exits.") << std::endl;
      //exit( 2 );
   }
} // ~CTcgDrive()

//=======================================================================================
bool CTcgDrive::showBasicDriveInfo( bool verbose, bool seagateInfo )
{
   M_WTry()
   {
      _tstring attrValue;
      _tstring vendorName;
      _tstring serialNo;
      _tstring firmwareNo;
      _tstring modelNo;
      size_t   blkSize;
      tUINT64  capacity;

      if( m_pATA )
      {

         // Read the basic data from IDentifyDevice
         vendorName  = m_pATA->GetVendor();
         serialNo    = m_pATA->GetSerialNumber();
         firmwareNo  = m_pATA->GetProductRevisionLevel();
         modelNo     = m_pATA->GetProductIdentification();
         capacity    = m_pATA->GetCapacityInBytes();
         m_maxLba    = m_pATA->GetMaxLBA();
         blkSize     = m_pATA->GetBlockSize();

         std::wcout << TXT("ATA IDENTIFY_DEVICE:") << std::endl;
         std::wcout << TXT("  VendorName (WWN)   = ") << vendorName.c_str() << std::endl;
         std::wcout << TXT("  SerialNumber       = ") << serialNo.c_str() << std::endl;
         std::wcout << TXT("  ModelNumber        = ") << modelNo.c_str() << std::endl;
         std::wcout << TXT("  FirmwareRev        = ") << firmwareNo.c_str() << std::endl;
         std::wcout << TXT("  Capacity           = ") << capacity << TXT(" Bytes (") << (m_maxLba +1) << TXT(" LBAs)") << std::endl;
         std::wcout << TXT("  Logical Block Size = ") << INT(blkSize) << TXT(" Bytes") << std::endl;

         if( verbose )
         {
            // Read and display the IdentifyDevice data related to security
            dta::tBytes buffer;
            m_pATA->GetIDBuffer( buffer );
            tUINT16 *pw = (tUINT16 *) &buffer[0];

            // Here we could do a hex dump of the entire ID data, but that
            // will have to wait for later.

            // Look to see if the ATA Security Feature Set is supported
            if( pw[128] & 0x0001 )  //  Word 128, bit 0 is identical to Word 82 bit 2)
            {
               std::wcout << TXT("  ATASecurityFeatSet = ") << ((pw[128] & 0x0001) ? TXT("Supported") : TXT("Not Supported"))
                          << TXT(", ") << ((pw[128] & 0x0002) ? TXT("Enabled") : TXT("Disabled"))  // same as W85:b1
                          << TXT(", ") << ((pw[128] & 0x0004) ? TXT("Locked") : TXT("Unlocked")) << TXT("  (ID:W128:b0,b1,b2)")
                          << std::endl;

               std::wcout << TXT("                       ") << ((pw[128] & 0x0008) ? TXT("Frozen") : TXT("Not Frozen"))
                          << TXT(", ") << ((pw[128] & 0x0010) ? TXT("Count expired") : TXT("Count not expired")) << TXT("  (ID:W128:b3,4)")
                          << std::endl;

               std::wcout << TXT("                       ") << ((pw[128] & 0x0020) ? TXT("Enhanced Erase") : TXT("Std ATA Erase"))
                          << TXT(", ") << ((pw[128] & 0x0100) ? TXT("Master:MAX") : TXT("Master:HIGH")) << TXT("  (ID:W128:b5,8)")
                          << std::endl;
            }
            else
            {
               std::wcout << TXT("  ATASecurityFeatSet = Not Supported  (ID:W128 = ") << hex << tUINT64(pw[128]) << dec << TXT(")")
                           << std::endl;
            }

            // Word 48 holds the Trusted Computing feature set options (i.e. supports Trusted I/O cmds).
            if( pw[48] & 0x0001 )
            {
               std::wcout << TXT("  TrustedCmdsFeatSet = Supported  (ID:W48:b0)") << std::endl; 
            }
            else
            {
               std::wcerr << TXT(" *** WARNING *** This drive does not support Trusted Commands Feature Set!") << std::endl;
            }

            // Word 59 is ATA EraseConfig: B12=1 (Sanitize Supported), B13=1 (CryptoScrambleExt Supported),
            //      B14=1 (Overwrite Ext Supported), B15=1 (BlockErase Supported)
            if (pw[59] & 0xF000)
            {
               std::wcout << TXT("  ATAEraseSupport    = ") << ((pw[59] & 0x1000) ? TXT("Sanitize") : TXT("No Sanitize"))
                          << TXT(", ") << ((pw[59] & 0x2000) ? TXT("CryptoScramble") : TXT("No CryptoScramble"))
                          << TXT(", ") << ((pw[59] & 0x4000) ? TXT("OverwriteExtended") : TXT("No OverwriteExtended"))
                          << std::endl << TXT("                       ")
                          << ((pw[59] & 0x8000) ? TXT("BlockErase") : TXT("No BlockErase")) << TXT(" (ID:W59:b12-15)") 
                          << std::endl;
            }

            // Word 69 Add'l Support: Bit4=1 (EncryptsUserData), Bit7=1 (IEEE1667)
            if ((pw[69] >> 4) & 0x0001)
               std::wcout << TXT("  SelfEncryptingDrv  = Supported  (ID:W69:b4)") << std::endl; //ACS2/3

            if ((pw[69] >> 7) & 0x0001)
               std::wcout << TXT("  ProtocolIEEE1667   = Supported  (ID:W69:b7)") << std::endl; //ACS3 only

            // For Seagate-proprietary DriveTrust SeaCOS drives, word 150 in vendor-specific area has bits 
            // 'supported' and 'enabled' for DriveTrust drives. These should only be valid for Seagate FDE.
            if( isSeagateDrive() )
            {
               std::wcout << TXT("  DriveTrust/SeaCOS  = ") << ((pw[150] & 0x0010) ? TXT("Supported") : TXT("Not Supported"))
                          << ((pw[150] & 0x1000) ? TXT(", Enabled") : TXT(", Disabled")) << TXT("  (ID:W150:b4,12)")
                          << std::endl;

               // Additionally, Seagate-proprietary DriveTrust/SeaCOS drives also used word 243 to
               // provide security state used for S3-resume implemented in DELL E1 BIOS. NOTE: THIS IS
               // NOT A VENDOR-SPECIFIC WORD AND CONFLICTS WITH T13 ASSIGNMENTS. Unfortunately, most
               // newer Seagate Opal and Enterprise drives implement these bits as well, even though 
               // Dell BIOS has deprecated this behavior and no longer looks at these bits.

               if( pw[243] & 0x4000 )
               {
                  std::wcout << TXT("  DeprecatedS3Resume = FDE Drive")<< TXT(" (ID:W243:b14)");
                  std::wcout << ((pw[243] & 0x2000) ? TXT(", PreBoot Enabled") : TXT(", PreBoot Disabled"));
                  std::wcout << TXT(" (ID:W243:b13)") << std::endl;
               }

               // Some Julius drives indicate FIPS validation may be in process or has been completed by
               // setting bit 0 of Word 159, or leaving bit 0 clear if drive is not intended to be FIPS.

               if( pw[159] & 0x0001 )
               {
                  std::wcout << TXT("  SeagateFIPS (hint) = SED might be FIPS 140-2 Level2 Capable.") << TXT(" (ID:W159:b01)") << std::endl;
               }

               // Add any other seagate-specific discovery here ....

            } // if SeagateInfo

         } // if verbose
      } 
      else if ( m_pSCSI )  // if pATA else pSCSI
      {
         // Read the INQUIRY data
         vendorName  = m_pSCSI->GetVendor();
         serialNo    = m_pSCSI->GetSerialNumber();
         firmwareNo  = m_pSCSI->GetProductRevisionLevel();
         modelNo     = m_pSCSI->GetProductIdentification();
         capacity    = m_pSCSI->GetCapacityInBytes();
         m_maxLba    = m_pSCSI->GetMaxLBA();
         blkSize     = m_pSCSI->GetBlockSize();

         std::wcout << TXT("SCSI INQUIRY DATA:") << std::endl;
         std::wcout << TXT("  VendorName (WWN)   = ") << vendorName.c_str() << std::endl;
         std::wcout << TXT("  SerialNumber       = ") << serialNo.c_str() << std::endl;
         std::wcout << TXT("  ModelNumber        = ") << modelNo.c_str() << std::endl;
         std::wcout << TXT("  FirmwareRev        = ") << firmwareNo.c_str() << std::endl;
         std::wcout << TXT("  Capacity           = ") << capacity << TXT(" Bytes (") << (m_maxLba +1) << TXT(" LBAs)") << std::endl;
         std::wcout << TXT("  Logical Block Size = ") << INT(blkSize) << TXT(" Bytes") << std::endl;
         
         if( verbose )
         {
            // If asked for additional information, display all relevant SCSI info
            std::wcout << std::endl << TXT("SCSI MODE PAGES:") << std::endl;

            std::wcout << TXT("  DETAILED DATA FOR SCSI DRIVES NOT YET SUPPORTED IN THIS TOOL.") << std::endl;
            // TODO: Implement same for SCSI devices

         } // if verbose
      } // if m_pSCSI
   } // try
   M_WCatch();

   if( !M_OK() )
   {
      std::wcerr << TXT("Error during showBasicDriveInfo:") << std::endl << tcgErrorMsg( M_CODE() ) << std::endl;
      return false;
   }

   return true;
} // showBasicDriveInfo



//=======================================================================================
// Perform ATA Security Protocol 00 Query

bool CTcgDrive::protocol0Discovery( bool verbose, bool seagateInfo )
{
   M_WTry()
   {
      // If constructor didn't create a TCGInterface, then drive does not
      // support TCG Protocol Commands and we should just return immediately. 
      if( (m_device == NULL) )
      {
         return false;
      }

      std::wcout << std::endl << TXT("SECURITY PROTOCOL 0:") << std::endl;

      // Get Security Protocol list from drive

      tUINT16 numberIDs;
      dta::tBytes IDs;

      // NOTE: Some older drives will lock up if this command is issued on a non-TCG-supporting 
      // drive. Make sure to examine Bit 0 of Word 48 of IDENTIFY_DEVICE to insure that the TCG
      // protocol is supported before issuing this call!
      m_device->getSupportedProtocolIDs( numberIDs, IDs );

      std::wcout << TXT("  SupportedProtocols = ");

      for( int ii=0; ii<numberIDs; )
      {
         if ( IDs[ii] == 0xf0 )
         {
            m_bSeaCOSprotocol = true;
            std::wcout << TXT("F0(SeaCOS)");
         }
         else if ( IDs[ii] > 0 && IDs[ii] <= 5)
         {
            m_bTCGprotocol = true;
            std::wcout << IDs[ii] << TXT("(TCG)");
         }
         else if ( IDs[ii] == 0xee )
         {
            m_bIEEEprotocol = true;
            std::wcout << TXT("EE(1667)");
         }
         else // unassigned protocol
         {
            std::wcout << INT(IDs[ii]);
         }
         if (++ii == numberIDs)
            std::wcout << std::endl;
         else
            std::wcout << TXT(", ");
      } // for each protocol

      
      // SecurityProtocol:00 SP-Specific:01 returns Drive Certificate stuff.
      // For now, we don't implement this.

      
      // SecurityProtocol:00 SP-Specific:02 returns Security Compliance Information
      // if the drive supports this. (Only newer FIPS drives support this.)
      char Revision;
      char OverallLevel;
      std::string HardwareVer;
      std::string FirmwareVer;
      std::string ModuleName;

      TCG_STATUS status = m_device->getFipsComplianceInfo(
                              Revision, OverallLevel, HardwareVer, FirmwareVer, ModuleName );

      if( status == TS_DTL_ERROR )
      {
         // Error occurred in the DTL functionality rather than drive aborting command. This
         // is uncommon but should be handled.
         std::wcout << std::endl << TXT("*** ERROR while querying SecurityCompliance info") << std::endl;
      }
      else if( status == TS_FAIL )
      {
         // This implies that the drive aborted the command, which indicates that the device 
         // doesn't support the Security Compliance SP00 command and cannot return FIPS 
         // compliance info.
         
         // In this case, it is possible to inspect the Seagate proprietary FIPS-capable hint 
         // (bit 0 in word 159 of IDENTIFY_DEVICE data) supplied by some Seagate drives. This
         // hint only means the SED may be scheduled for FIPS validation, be in process of FIPS
         // validation, may have completd FIPS validation, or may have had its' FIPS validation
         // revoked. It is very important to verify the NIST certifiate for this drive!!!

#if 0 // Possible code to inspect this hint when the SED can't report SecurityCompliance.
         if( m_pATA )
         {
            dta::tBytes buffer;
            m_pATA->GetIDBuffer( buffer );
            tUINT16 *pw = (tUINT16 *) &buffer[0];

            if( pw[159] & 0x0001 )  //  Word 159, bit 0 is set to hint that drive may be FIPS-Capable
               std::wcout << TXT("SED Might Be FIPS 140-2 Level 2 Capable") << std::endl;
            else
               std::wcout << TXT("SED Is Not FIPS-Capable") << std::endl;         
         }
         // else if( m_PSCSI )  // For now, we just assume SCSI device is NOT FIPS
#endif // Possible code
      }
      else if( status == TS_SUCCESS )
      {
         std::wcout << TXT("  SecurityCompliance = ");

         // The drive either returned meaningful Security Compliance data, or it returned a zero-
         // length descriptor indicating the drive is not FIPS-Capable. For the latter case, the
         // returned chars are blanks and the strings are length 0.
         if( Revision == ' ' || OverallLevel == ' ' )
         {
            std::wcout << TXT("SED Reports It Is Not FIPS-Capable")  << std::endl;
         }
         else
         {
            // Info was obtained from the drive using the Trusted Security Compliance SP00 command.
            std::wcout << TXT("SED claims to be FIPS 140-") << Revision << TXT(" Level ") << OverallLevel << TXT(" Capable, but a") 
                       << std::endl << TXT("                       ") << TXT("Crypto Officer MUST verify a NIST Certificate for:");
         
            // Identifying strings may have been provided if size is non-zero.
            if( HardwareVer.size() > 0 )
               std::wcout << std::endl << TXT("                         - FIPS Hardware = ") << (char *)HardwareVer.data();

            if( FirmwareVer.size() > 0 )
               std::wcout << std::endl << TXT("                         - FIPS Firmware = ") << (char *)FirmwareVer.data();

            if( ModuleName.size() > 0 )
            {
               std::wcout << std::endl << TXT("                         - Module = "); 
               for( tUINT16 i = 0; i < ModuleName.size(); i++ )
               {
                  if( i % 40 == 39 ) std::wcout << std::endl << TXT("                                    ");
                  std::wcout << *(char*) &ModuleName[i];
               }
            }
            else
               std::wcout << std::endl;
         } // Drive reports FIPS-Capable
      } // Status TS_SUCCESS
      

      // Add any additional Security Protocol 00 query results here:


   }
   M_WCatch();

   if( !M_OK() )
   {
      std::wcerr << TXT("Error occured during Security Protocol-00 discovery:")  << std::endl << tcgErrorMsg( M_CODE() ) << std::endl;
      return false;
   }
   else
   {
      return true;
   }
} // protocol-0-Discovery


//=======================================================================================
// Perform TCG PROTOCOL 1 Discovery for supported features sets.

bool CTcgDrive::performTCGDiscovery( bool seagateInfo, bool verbose )
{
   M_WTry()
   {
      // If constructor didn't create the TCGInterface, then drive does not
      // support TCG and we should just return immediately. 
      if( (m_device == NULL) )
         return false;

      // Using Protocol 1, perform Level 0 Discovery on TCG Drives. The TPer
      // returns a header plus multiple feature descriptors. Header contains
      // some vendor-specific data, as follows:
      //     Byte 16: Vendor Version
      //     Byte 17: Drive Lifecycle (0x80 == USE)
      //     Byte 18: reserved.
      //     Byte 19: Supported features B7: MultMethods, B6: MultBands,
      //              B4: Unified Debug System (UDS), B3: Diagnostic Port, 
      //              B2: Firmware Download, B1: Locking, B0: FDE.
      //     Byte 21: Enabled features described in Byte 19 supported features.
      //
      // At least three feature descriptors must follow the header, each 
      // identified by a 4-digit hex value, in the following order. Note
      // that the third descriptor must be an SSC descriptor, but it can
      // be Enterprise, Opal, etc.
      //
      // (0001) is TPER Info descriptor with byte 4 showing support for:
      //     B0: Sync Protocol, B1: Async Protocol, B2: Ack/Nak Protocol,
      //     B3: Buffer Mgmt, B4: Streaming, B6: ComID Mgmg, B5,B7: Reserved.
      // (0002) is Locking feature descriptor with following bits:
      //     B0: Locking supported, B1: Locking enabled, B2: Locked (1 or more bands)
      //     B4: MediaEncryption,  B5: MBR Enabled, B6: MBR Done, B7,8: Reserved
      // (0100) is Enterprise SSC feature descriptor (def is ??)
      // (0200) is Opal SSC 1.0 feature descriptor, with following feature bits:
      //     Bytes 4/5: Base ComID, Bytes 6/7: # of ComIDs,
      //     Byte 8:B0: Range Crossing (1 - no range crossing allowed).
      // (0203) is Opal SSC-2 feature descriptor, same as 0200, adding:
      //     Bytes 9-10: Max LockingSP Admins, Bytes 11-12: MaxLockingSP Users,
      //     Byte 13: initial 0x00(SID = MSID) or 0xff(SID=unknown),
      //     Byte 14: on Revert, 0x00(SID=MSID) or 0xff(SID=unknown).
      //
      // An arbitrary number of feature descriptors follow the first three,
      // each identified by a 4-digit hex value. Some or all of the following 
      // may be found during discovery:
      //
      // (0003) is Geometry Feature Descriptor (TCG1) Byte 4:B0: AlignRequired,
      //     Bytes 12-15: LogicalBlockSize, Bytes 16-23: AlignmentGranularity,
      //     Bytes 24-31: Lowest Aligned LBA.
      // (0201) Single-User-Mode descriptor, Bytes 4-7: #LockingObjectsAllowed,
      //     Byte 8: B0: AnyBandSUM, B1: AllBandsSUM, B2: AdminSetsStart&Length
      // (0202) Additional DataStoreTable descriptor, Bytes 4-7: MaxDSTables,
      //     Bytes 8-11: Total DS Table size, Bytes 12-15: Min size alignment.
      //
      // (C001) is Seagate proprietary Logical Port Descriptor, with bytes 4-N
      //     holding list of Port Descriptors, each 8 bytes long. First 4 bytes
      //     are Port ID (last 4 bytes of locking UID, byte 5 is enable/disable.
      //

      // **************** COMMON TO ALL TCG DEVICES *********************

      // Log with blank line to separate from preceeding output
      std::wcout << std::endl << TXT("TCG LEVEL 0 DISCOVERY:") << std::endl;

      std::wcout << TXT("  TCG-SSC Discovery  = ");

      // Identify the SSC that this device is providing

      if( m_device->isDeviceEnterpriseSSC() )
         std::wcout << TXT("Enterprise SSC 1.0");
      else if( m_device->isDeviceOpalSSCVersion2() )
         std::wcout << TXT("Opal SSC 2.0");
      else if( m_device->isDeviceOpalSSC() )
         std::wcout << TXT("Opal SSC 1.0");
      else if( m_device->isDeviceMarbleSSC() )
         std::wcout << TXT("Marble SSC");
      else
         std::wcout << TXT("Unknown SSC");

      std::wcout << (m_device->isDeviceTCGCoreVersion1() ? TXT(" (TCG Core 1.0)") : TXT(" (TCG Core 2.0)"))
                 << std::endl;

      // General info obtained during Level-0 discovery of device 

      std::wcout << TXT("                       ");
      std::wcout << TXT("BaseComID:0x0") << std::hex << INT(m_device->getBaseComID()) << std::dec 
                 << TXT(", NumberComIDs:") << INT(m_device->getNumberOfComIDs()) << std::endl

                 << TXT("                       RangeCrossing: ") 
                 << (m_device->getRangeCrossingAllowed() == 1 ? TXT("Not Allowed") : TXT("Allowed"))
                 << std::endl;

      // Opal SSC 2.0 has addition info in the feature descriptor
      if( m_device->isDeviceOpalSSCVersion2() )
      {
         std::wcout << TXT("                       ");
         std::wcout << TXT("MaxLockingSPAdmins:") << INT(m_device->getMaxLockingSPAdmins())
                    << TXT(", MaxLockingSPUsers:") << INT(m_device->getMaxLockingSPUsers())
                    << std::endl
                    << TXT("                       Default SID=") 
                    << ( m_device->getSIDdefaultValue() == 0 ? TXT("MSID") : TXT("???") )
                    << TXT(", AfterRevert SID=") 
                    << ( m_device->getSIDOnRevertValue() == 0 ? TXT("MSID") : TXT("???") )
                    << std::endl;
      }



      // Display vendor-proprietary (Seagate-specific) Level-0 HEADER information.

      if( isSeagateDrive() )
      {
         // Show current proprietary Seagate SOM state
         std::wcout << TXT("  VendorDriveState   = SOM:0") << tUINT64(m_device->getSOM());

         switch( m_device->getSOM() )
         {
         case 0:
            std::wcout << TXT(" (Undeclared)");
            break;
         case 1:
            std::wcout << TXT(" (ATA Security Mode)");
            break;
         case 2:
            std::wcout << TXT(" (TCG Security Mode)");
            break;
         default:
            std::wcout << TXT(" (Unrecognized Security Operating Mode)");
         };
         std::wcout << std::endl;

         // Query Opal vs Enterprise vs XXXX SSCs

         if( m_device->isDeviceOpalSSC() )
         {
            // These features are only in Opal SSC 1.0 and 2.0 Drives!!!
            std::wcout << TXT("                       MBRDone:") << m_device->isDeviceMBRDone() 
                       << TXT(", MBREnabled:") << m_device->isDeviceMBREnabled() << std::endl;
         }
         else if( m_device->isDeviceEnterpriseSSC() )
         {
            // TODO: Add any Enterprise state that is important to show.
         }
         else
         {
            // TODO: For future expansion
         }

         // Proprietary info from Level0 Header

         std::wcout << TXT("                       ");

         // Drive Life-Cycle state from header byte 17.
         std::wcout << TXT("SED LifeCycleState: 0x") << hex << m_device->getLifeCycleState( true ) << dec;
         switch( m_device->getLifeCycleState( false ) )
         {
            case 0x80: 
               std::wcout << TXT(" (USE state)");
               break;
            case 0x01:
               std::wcout << TXT(" (Diagnostics state)");
               break;
            case 0x00:
               std::wcout << TXT(" (Setup state)");
               break;
            case 0x81:
               std::wcout << TXT(" (Manufacturing state)");
               break;
            case 0xff:
               std::wcout << TXT(" (Failed state)");
               break;
         }
         std::wcout << std::endl;

         // Proprietary Vendor feature bits in Level-0 header, present in both Opal and Enterprise
         // NOTE: rather than using these bits to determine logical port state, see LogicalPorts below.

         std::wcout << TXT("                       ");

         tUINT8 supported = m_device->getVendorFeatureSupported();
         tUINT8 enabled = m_device->getVendorFeatureEnabled();

         // FDE_e: This bit is set to 1 if one or more bands on the device have encryption enabled.
         if( (supported & 0x01) && (enabled & 0x01) ) //bit 0: FDE supported/enabled.
            std::wcout << TXT("FDE Enabled, ");

         // Locking_e: This bit shall be set to one if one or more LBA ranges in the Locking table have 
         // either (ReadLockEnabled=True and ReadLocked=True) or (WriteLockEnabled=True and WriteLocked=True).
         if( (supported & 0x02) && (enabled & 0x02) ) //bit 1: Locking Objects supported/enabled
            std::wcout << TXT("ReadLocked True,");
         else
            std::wcout << TXT("ReadLocked False,");

         std::wcout << std::endl << TXT("                       ");

         // FDPL_e:  This bit shall be set to 1 if firmware download is prohibited via the FWDownload logical port 
         if( (supported & 0x04) && (enabled & 0x04) ) //bit 2: FWDownload Logical Port
            std::wcout << TXT("FWDownload Prohibited,");
         else
            std::wcout << TXT("FWDownload Allowed,");

         // DPL_e: This bit shall be set to 1 if the Diagnostics commands are prohibited via the Diagnostics logical port
         if( (supported & 0x08) && (enabled & 0x08) ) //bit 3: Diagnostics Logical Port
            std::wcout << TXT(" Diagnostics Disabled,");
         else
            std::wcout << TXT(" Diagnostics Enabled,");

         // Multiple Bands: This bit shall be set to 1 if more than one band contains at least one LBA.
         if( enabled & 0x40 ) //bit 6
            std::wcout << std::endl << TXT("                       Multiple Bands Active");

         std::wcout << std::endl;

         // Logical Port Feature Descriptor ID 0xC001 shows logical port Lock status
         // Present in both Opal and Enterprise Seagate drives. The ports include:
         // 0101 - Diagnostics / Serial Port
         // 0102 - FWDownload
         // 0103 - Internal UDS (Universal Debug Service )
         // 0105 - ChangeDef (Deprecated)
         // 010D - DCO (Deprecated)
         // 010E - CS FW Download (Internal Configuration port)

         tUINT16 ports = m_device->getLogicalPortsAvailable();

         if( ports > 0 )
         {
            std::wcout << TXT("  VendorLogicalPorts = ");

            dta::tBytes data = m_device->getLogicalPortData();

            for( int ii = 0, jj = 0; ii < ports; ii++, jj+=8 )
            {
               tUINT32 port = data[jj] << 12 | data[jj+1] << 8 | data[jj+2] << 4 | data[jj+3];
               
               if( ii > 0 )         // Not first line
               {
                 if( ii % 2 == 0 )
                     std::wcout << TXT(", ") << std::endl << TXT("                       ");
                  else
                     std::wcout << TXT(", ");
               }

               std::wcout << (port == 0x0101 ? TXT("Diagnostic(0") :
                             (port == 0x0102 ? TXT("FWDownload(0") :
                             (port == 0x0103 ? TXT("SecureUDS(0") : 
                             (port == 0x0105 ? TXT("ChangeDef(0") :
                             (port == 0x010D ? TXT("DCO(0") :
                             (port == 0x010E ? TXT("CSFWDnld(0") :
                                               TXT("Unknown (0") ))))))
                          << hex << (tUINT32)port << dec << TXT("):")
                          << (data[jj+4] == 1 ? TXT("Locked") : TXT("Unlocked"));
            }
            std::wcout << std::endl;
         }

         // Although the proprietary _AllowATAUnlock is not a TCG Level-0 feature, it is
         // reported here by checking state of the _AllowATAUnlock row in Global LockingTable.
#if 0 // do this later
         IOTableLocking row(false);
         AuthenticationParameter authent(0);
         if( !isEnterpriseSSC() )
            authent.AuthorityName = (char*)"Admin1";

         if( getLockingInfo( 0, row, authent, false, false ) )
         {
            if( row.AllowATAUnlock_isValid )
               std::wcout << row.AllowATAUnlock << std::endl;
         }
#endif // 0

      } // if( isSeagateDrive() )

      // DataStore Table Feature Descriptor is only available on Opal SSC 2.0
      if( m_device->isDataStoreTableFeatureSupported() )
      {
          std::wcout << TXT("  DataStoreTables    = MaxDataStoreTables:") << tUINT64(m_device->getMaxNumberOfDataStoreTables())
                    << TXT(", DataStoreTableAlignment:") << m_device->getDataStoreTableSizeAlignment()
                    << std::endl;

         std::wcout << TXT("                       ")
                    << TXT("MaxTotalSizeOfDataStoreTables:") << m_device->getMaxTotalSizeOfDataStoreTables()
                    << std::endl;
      }

      // Single-user mode is only available on Opal SSC 2.0
      if( m_device->isSingleUserModeSupported() )
      {
         bool isAdminOwner = m_device->isSingleUserModePolicyOwnedByAdmin( false );

         std::wcout << TXT("  SingleUserMode     = ");
         if( m_device->areAllInSingleUserMode(false) )
            std::wcout << (isAdminOwner ? TXT("All Ranges Admin-Owned") : TXT("All Ranges User-Owned"));
         else if( m_device->isAnyInSingleUserMode( false ) )
            std::wcout << (isAdminOwner ? TXT("Some Ranges Admin-Owned") : TXT("Some Ranges User-Owned") );
         else
            std::wcout << TXT("No Single-Mode Ranges Enabled" );
         std::wcout << std::endl;
      }
        
      // Query for Band Alignment values, if drive reported them, otherwise default values used.
      // Implemented on Opal and Enterprise, although defaults may be different on Enterprise.

      std::wcout << TXT("  Geometry/Alignment = LogicalBlockSize:") << m_device->getGeometryLogicalBlockSize()
                 << TXT(" bytes, Alignment is ") << (m_device->isGeometryAlignmentRequired() ? TXT("Required!") : TXT("Suggested.") ) 
                 << std::endl
                 << TXT("                       Granularity:") << tINT64(m_device->getGeometryAlignmentGranularity()) 
                 << TXT(" LBAs, LowestAlignedLBA:") << tINT64(m_device->getGeometryLowestAlignedLBA())
                 << std::endl;
      


      // Query TPer for communication properties present on Opal and Enterprise Seagate drives.

      std::wcout << std::endl << TXT("TCG LEVEL 1 DISCOVERY:") << std::endl;

      TPerProperties tperProperties;
      HostProperties hostProperties;
      m_device->properties( NULL, &tperProperties, &hostProperties );

      std::wcout << TXT("  TPer Properties    = MaxSessions:") << (tperProperties.MaxSessions_isValid ? tperProperties.MaxSessions : 0) 
                 << TXT(", MaxPackets:") << (tperProperties.MaxPackets_isValid ? tperProperties.MaxPackets : 0) 
                 << TXT(", MaxMethods:") << (tperProperties.MaxMethods_isValid ? tperProperties.MaxMethods : 0)
                 << std::endl;

      std::wcout << TXT("                       MaxComPacketSize:") << (tperProperties.MaxComPacketSize_isValid ? tperProperties.MaxComPacketSize : 0) << TXT(" bytes")
                 << TXT(", MaxPacketSize:") << (tperProperties.MaxPacketSize_isValid ? tperProperties.MaxPacketSize : 0) << TXT(" bytes")
                 << std::endl;

      std::wcout << TXT("                       DefSessionTimeout:") << (tperProperties.DefSessionTimeout_isValid ? tperProperties.DefSessionTimeout : 0) << TXT(" seconds")
                 << std::endl;


      std::wcout << std::endl;


      std::wcout << TXT("TCG LEVEL 2 DISCOVERY:") << std::endl;

      // Dump the MSID value
      tUINT8 mSID[33];
      if( getMSID( mSID ) )
      {
         std::wcout << TXT("  MSID               = ") << (char*)mSID << std::endl;
      }

      // If Opal device has an activated LOCKING SP, show locking stuff.
      if( !isEnterpriseSSC() && !isSPInactive((char*)"Locking") ) // nvn
      {
         int bands;
         if( getMaxBands( &bands ) )
            std::wcout << TXT("  ConfigurableRamges = ") << bands << TXT(", plus Global Range.") << std::endl;
      }

   }
   M_WCatch();


   if( !M_OK() )
   {
      std::wcerr << TXT("Error occured during TCG SSC feature discovery, ") << tcgErrorMsg( M_CODE() ) << std::endl;
      return false;
   }
   else
   {
      //std::wcout << TXT("================ End of TCG SSC feature discovery =========") << std::endl;
      return true;
   }
} // protocolFeatureDiscovery

//=================================================================================
bool CTcgDrive::securityState( bool variable )
{
   std::wcout << TXT("  SecurityState      =")
              << TXT( " MBRDone:") << m_device->isDeviceMBRDone()
              << TXT(", MBREnabled:") << m_device->isDeviceMBREnabled()
              << TXT(", Locked:") << m_device->isDeviceLocked()
              << std::endl;

   return true;

} // securityState


//=======================================================================================
bool CTcgDrive::isSPInactive( char *targetSPName )
{
   AuthenticationParameter authent; // Not required though
   IOTableSP state(true);
   getSPState( targetSPName, state, authent );
   if( !state.LifeCycleState_isValid )
   {
      std::wcerr << TXT("SP's Life Cycle State is not available, something went wrong.\n") << std::endl;
      return false;
   }

   if( evManufactured_Inactive == state.LifeCycleState )
      return true;

   return false;
} // isSPInactive

//=======================================================================================
bool CTcgDrive::isSPManufactured( char *targetSPName )
{
   AuthenticationParameter authent; // Not required though
   IOTableSP state(true);
   getSPState( targetSPName, state, authent );
   if( !state.LifeCycleState_isValid )
   {
      std::wcerr << TXT("SP's Life Cycle State is not available, something went wrong.\n") << std::endl;
      return false;
   }

   if( evManufactured == state.LifeCycleState )
      return true;

   return false;
} // isSPManufactured

//=======================================================================================
bool CTcgDrive::getSPState( char *targetSP, IOTableSP & spState, AuthenticationParameter & authent )
{
   if( !( _stricmp( targetSP, "Admin" ) == 0 || _stricmp( targetSP, "AdminSP" ) == 0 ||
          _stricmp( targetSP, "Locking" ) == 0 || _stricmp( targetSP, "LockingSP" ) == 0 ) )
   {
      std::wcout << std::endl << TXT("Only Admin SP or Locking SP is supported.\n") << std::endl;
      return false;
   }

   M_WTry()
   {
      m_device->getSPRow( spState, targetSP, authent );
   }
   M_WCatch();

   if( !M_OK() )
   {
      std::wcout << std::endl << TXT("Error of response with GetSPState, ") << tcgErrorMsg( M_CODE() ) << std::endl;
      return false;
   }

   return true;
} // getSPState

//=======================================================================================
bool CTcgDrive::reportSPState( char *targetSP )
{
   AuthenticationParameter authent; // Not required
   IOTableSP spState(true);
   bool result = getSPState( targetSP, spState, authent );

   if( spState.LifeCycleState_isValid )
   {
      switch( spState.LifeCycleState )
      {
         case evIssued:
            std::wcout << TXT("Isssued");
            break;
         case evIssued_Disabled:
            std::wcout << TXT("Issued-Disabled");
            break;
         case evIssued_Frozen:
            std::wcout << TXT("Issued-Frozen");
            break;
         case evIssued_Disabled_Frozen:
            std::wcout << TXT("Issued-Disabled-Frozen");
            break;
         case evIssued_Failed:
            std::wcout << TXT("Issued-Failed");
            break;
         case evManufactured_Inactive:
            std::wcout << TXT("Manufactured-Inactive");
            break;
         case evManufactured:
            std::wcout << TXT("Manufactured");
            break;
         case evManufactured_Disabled:
            std::wcout << TXT("Manufactured-Disabled");
            break;
         case evManufactured_Frozen:
            std::wcout << TXT("Manufactured-Frozen");
            break;
         case evManufactured_Disabled_Frozen:
            std::wcout << TXT("TXT(Manufactured-Disabled-Frozen");
            break;
         case evManufactured_Failed:
            std::wcout << TXT("Manufactured-Failed");
            break;
         default:
            std::wcout << TXT("Unknown (") << hex << spState.LifeCycleState << dec << TXT(")");
      }

      if( spState.Frozen )
         std::wcout << TXT(", Frozen(True).");
      else
         std::wcout << TXT(", Frozen(False).");
   }

   std::wcout << std::endl;
   return result;
} // reportSPState

//=======================================================================================
bool CTcgDrive::activateSP( char *targetSP, AuthenticationParameter & authent, TCG_BANDNOs *pSingleUserModeList, int rangeStartLengthPolicy, UINT64VALs *pDataStoreTableSizes )
{
   if( !( _stricmp( targetSP, "Admin" ) == 0 || _stricmp( targetSP, "Locking" ) == 0 ) ||
          _stricmp( targetSP, "AdminSP" ) == 0 || _stricmp( targetSP, "LockingSP" ) == 0 )
   {
      std::wcout << std::endl << TXT("Only AdminSP or LockingSP is supported by this command.\n") << std::endl;
      return false;
   }

   if( !isSPInactive( targetSP ) )
   {
      std::wcout << std::endl << TXT("Not in Manufactured-Inactive state. The SP should be in this state to be activated.\n") << std::endl;
      return false;
   }

   if( NULL != pSingleUserModeList )
   {
      for( unsigned int ii=0; ii < (*pSingleUserModeList).size(); ii++ )
      {
         if( !( -1 == (*pSingleUserModeList)[ii] || ( (*pSingleUserModeList)[ii] >= 0 && (tUINT32)(*pSingleUserModeList)[ii] < m_device->getSingleUserModeNumLockingObjects() ) ) )
         {
            std::wcout << std::endl << TXT("Out-of-range value in SingleUserMode list, item#") << (ii + 1) << TXT("=") 
                       << (*pSingleUserModeList)[ii] << TXT(".\n") << std::endl;
            return false;
         }
      }
   }

   if( !isRequestedParameterOfDataStoreTablesOK( pDataStoreTableSizes ) )
      return false;

   M_WTry()
   {
      m_device->activate( targetSP, authent, pSingleUserModeList, rangeStartLengthPolicy, pDataStoreTableSizes );
   }
   M_WCatch();

   if( !M_OK() )
   {
      std::wcout << std::endl << TXT("Error of response with ActivateSP, ") << tcgErrorMsg( M_CODE() ) << std::endl;
      return false;
   }

   // Check to make sure the SP is now in Manufactured state
   if( !isSPManufactured( targetSP ) )
   {
      std::wcerr << std::endl << TXT("Activated, but still not in Manufactured state.\n")  << std::endl;
      return false;
   }

   return true;
} // activateSP

//=======================================================================================
bool CTcgDrive::reactivateSP( AuthenticationParameter & authent, TCG_BANDNOs *pSingleUserModeList, int rangeStartLengthPolicy, dta::tBytes *pAdmin1PIN, UINT64VALs *pDataStoreTableSizes )
{
   if( isSPInactive( (char*)"Locking" ) )
   {
      std::wcerr << TXT("Not in Manufactured state. The SP should be in this state to be reactivated.\n")  << std::endl;
      return false;
   }

   if( NULL != pSingleUserModeList )
   {
      for( unsigned int ii=0; ii < (*pSingleUserModeList).size(); ii++ )
      {
         if( !( -1 == (*pSingleUserModeList)[ii] || ( (*pSingleUserModeList)[ii] >= 0 && (tUINT32)(*pSingleUserModeList)[ii] < m_device->getSingleUserModeNumLockingObjects() ) ) )
         {
            std::wcerr << TXT("Out-of-range value in SingleUserMode list, item#") << (ii + 1) << TXT("=") << (*pSingleUserModeList)[ii] << TXT(".\n")  << std::endl;
            return false;
         }
      }
   }

   if( !isRequestedParameterOfDataStoreTablesOK( pDataStoreTableSizes ) )
      return false;

   M_WTry()
   {
      m_device->reactivate( authent, pSingleUserModeList, rangeStartLengthPolicy, pAdmin1PIN, pDataStoreTableSizes );
   }
   M_WCatch();

   if( !M_OK() )
   {
      std::wcerr << TXT("Error of response with ReactivateSP, ") << tcgErrorMsg( M_CODE() ) << std::endl;
      return false;
   }

   return true;
} // reactivateSP

//=======================================================================================
bool CTcgDrive::getSingleUserModeInfo( AuthenticationParameter & authent, dta::tBytes & singleUserModeList, int & rangeStartLengthPolicy )
{
   // set each SingleUserMode list entry to "invalid"
   for( unsigned int ii=0; ii < singleUserModeList.size(); ii++ ) 
      singleUserModeList[ii] = -1;

   // Access the LockingInfo table to get the SUM data.
   IOTableLockingInfo row;

   M_WTry()
   {
      m_device->getLockingInfoRow( row, authent );
   }
   M_WCatch();

   if( !M_OK() )
   {
      std::wcerr << TXT("GetLockingInfoRow: ") << tcgErrorMsg( M_CODE() ) << std::endl;
      return false;
   }

   // Depending on the level of authentication allowed, see what was returned.

   // There can be no valid Start/Length policy if no valid SUM.
   if( !row.SingleUserModeRanges_isValid || !row.RangeStartLengthPolicy_isValid )
   {
      rangeStartLengthPolicy = -1;
   }
   else
   {
      rangeStartLengthPolicy = row.RangeStartLengthPolicy;

      for( unsigned int ii=0; ii < row.SingleUserModeRanges.size(); ii++ )
      {
         if( UID_TABLE_LOCKING == row.SingleUserModeRanges[0] )
         {
            for( unsigned int jj=0; jj < singleUserModeList.size(); jj++ )
               singleUserModeList[jj] = rangeStartLengthPolicy;

            break;
         }

         if( UID_LOCKING_RANGE0 == row.SingleUserModeRanges[ii] )
         {
            singleUserModeList[0] = rangeStartLengthPolicy;
         }
         else
         {
            if( row.SingleUserModeRanges[ii] >= (TCG_UID) UID_LOCKING_RANGE1_OM && row.SingleUserModeRanges[ii] <= ((TCG_UID) UID_LOCKING_RANGE1_OM + singleUserModeList.size() -2 ) )
            {
               singleUserModeList[ (int)(row.SingleUserModeRanges[ii] - UID_LOCKING_RANGE1_OM + 1) ] = rangeStartLengthPolicy;
            }
            else
            {
               std::wcerr << TXT("Error parsing SingleUserMode list- out of range UID.") << std::endl;
               return false;
            }
         }
      }
   }

   return true;
} // getSingleUserModeInfo

//=======================================================================================
bool CTcgDrive::getMaxBands( int *pMaxBands )
{
   m_numberBands = 0;

   M_WTry()
   {
      m_numberBands = m_device->getMaxBands();
   }
   M_WCatch();

   if( !M_OK() )
   {
      std::wcerr << TXT("GetMaxBands failed, ") << tcgErrorMsg( M_CODE() ) << std::endl;
      m_numberBands = 0;
      return false;
   }

   if( NULL != pMaxBands )
      *pMaxBands = m_numberBands;

   return true;
} // getMaxBands

//=======================================================================================
bool CTcgDrive::isBandNoValid( int bandNo )
{
   if( 0 == m_numberBands )
      getMaxBands();

   return bandNo >=0 && bandNo <= m_numberBands;

} // isBandNoValid

//=======================================================================================
bool CTcgDrive::getGeometryAlignment( bool & bRequired,
                                     tINT64 & alignment,
                                     tINT64 & lowestLBA,
                                     int & blockSize )
{
   M_WTry()
   {
      bRequired = m_device->isGeometryAlignmentRequired();
      alignment = m_device->getGeometryAlignmentGranularity();
      lowestLBA = m_device->getGeometryLowestAlignedLBA();
      blockSize = m_device->getGeometryLogicalBlockSize();
   }
   M_WCatch();

   if( !M_OK() )
   {
      std::wcerr << TXT("GetGeometryAlignment failed, ") << tcgErrorMsg( M_CODE() ) << std::endl;
      return false;
   }

   return true;
} // getGeometryAlignment


//=======================================================================================
bool CTcgDrive::getMSID( tUINT8 *mSID )
{
   if( NULL == mSID )
      return false;

   memset( mSID, 0, 33 ); // 33-byte pre-requsite

   M_WTry()
   {
      dta::tBytes data;
      m_device->getMSID( data );
      memcpy( mSID, &data[0], (( data.size() < 32 ) ? data.size() : 32 ) );
   }
   M_WCatch();

   if( !M_OK() )
   {
      std::wcerr << TXT("GetMSID failed, ") << tcgErrorMsg( M_CODE() ) << std::endl;
      return false;
   }

   return true;
} // getMSID


//=======================================================================================
// Get a Range's LockingInfo. This requires authentication for almost all meaningful
// data -- Enterprise needs EraseMaster, while Opal needs Admin1 credentials except
// when the range is in SingleUser Mode which requres User(X+1) credential for range X.
//=======================================================================================
bool CTcgDrive::getLockingInfo( int rangeNo, IOTableLocking & info,
                                AuthenticationParameter & authent,
                                bool toStartSession, bool toCloseSession )
{
   info.setStateAll( false );    // Start out with no valid locking info

   M_WTry()
   {
      if( toStartSession )       // If not already in an active session, caller wants to start session
      {
         if( m_device->isDeviceEnterpriseSSC() )
         {
            m_device->_startSession( UID_SP_LOCKING_E );

            // GET on Authority table requires "EraseMaster" authentication in Ent-SSC
            if( NULL != authent.AuthorityName )
               m_device->_authenticate( authent ); // or each BM
         }
         else // Opal/Marble
         {
            // In Opal SEDs, GET on Authority table doesn't require authentication, 
            // but GET on Locking table with meaninful returns (more than "UID"/"Name"/"CommonName",
            // ie. "RangeStart", "RangeLength", etc)does need "Admin1" authentication.
            m_device->_startSession( UID_SP_LOCKING_OM, authent );
         }
      }

#if 0
      // Test to see the ACL
      if( m_device->isDeviceEnterpriseSSC() )
         m_device->_authenticate( UID_AUT_BANDMASTER0 + bandNo, authent.Pin, authent.PinLength ); // each BM

      TCG_UIDs acl;
     if( bandNo > 0 )
        m_device->_getACL( (m_device->isDeviceEnterpriseSSC() ? UID_LOCKING_RANGE1_E : UID_LOCKING_RANGE1_OM) + bandNo -1, (m_device->isCoreSpec1() ? UID_M_GET1 : UID_M_GET2), acl );
     else
         m_device->_getACL( UID_LOCKING_RANGE0, (m_device->isCoreSpec1() ? UID_M_GET1 : UID_M_GET2), acl );
#endif

      m_device->_getLocking( rangeNo, info ); 
/*
     // Authentication required for getting "meaningful" data ("RangeStart/Length", etc) with Opal SEDs, but not Ent-SSC.
      IOTableAuthority authRow( false );
      authRow.Enabled_isValid = true;

      // Read from Authority table
      if( m_device->isDeviceEnterpriseSSC() )
      {
         m_device->_getAuthority( UID_AUT_BANDMASTER0 + rangeNo, authRow ); // EraseMaster or BandMaster authentication required for Ent-SSC here.
      }
      else
      {
         //m_device->_getAuthority( UID_AUT_ADMIN1, authRow );
         authRow.Enabled = true;
         authRow.Enabled_isValid = true;
      }

      info.rangeEnabled = authRow.Enabled;
      info.rangeEnabled_isValid = authRow.Enabled_isValid;

      if( info.lockingRange.ActiveKey_isValid && UID_NULL != info.lockingRange.ActiveKey )
      {
         info.encryptionMode_isValid = m_device->_getK_AES( info.lockingRange.ActiveKey, info.encryptionMode ) == TS_SUCCESS; // from K_AES_128/256 table
      }
      else
      {
         info.encryptionMode = -1;
         info.encryptionMode_isValid = false;
      }
*/
      if( toCloseSession )
         m_device->_closeSession();
   }
   M_WCatch();

   if( !M_OK() )
   {
      std::wcerr << TXT("Error during getLockingInfo, ") << tcgErrorMsg( M_CODE() ) << std::endl;
      M_CLEANUPSESSION();
      return false;
   }

   return true;
} // getLockingInfo




//=======================================================================================
// This is an example on how to use individual method calls to form your own session.
//=======================================================================================
bool CTcgDrive::getRangeInfo( int rangeNo, TCGRANGE_INFO & info, AuthenticationParameter & authent, bool toStartSession, bool toCloseSession )
{
   memset( &info, 0, sizeof(TCGRANGE_INFO) );
   info.lockingRange.setStateAll( true ); // To have ALL

   M_WTry()
   {
      if( toStartSession )
      {
         //m_device->_startSession( m_device->isDeviceEnterpriseSSC() ? UID_SP_LOCKING_E : UID_SP_LOCKING_OM );
         if( m_device->isDeviceEnterpriseSSC() )
         {
            m_device->_startSession( UID_SP_LOCKING_E );

            // GET on Authority table requires "EraseMaster" authentication in Ent-SSC
            if( NULL != authent.AuthorityName )
               m_device->_authenticate( authent ); // or each BM
         }
         else // Opal/Marble
         {
            // In Opal SEDs, GET on Authority table doesn't require authentication, 
            // but GET on Locking table with meaninful returns (more than "UID"/"Name"/"CommonName", ie. "RangeStart", "RangeLength", etc)
            // does need "Admin1" authentication.
            m_device->_startSession( UID_SP_LOCKING_OM, authent );
         }
      }

#if 0
      // Test to see the ACL
      if( m_device->isDeviceEnterpriseSSC() )
         m_device->_authenticate( UID_AUT_BANDMASTER0 + bandNo, authent.Pin, authent.PinLength ); // each BM

      TCG_UIDs acl;
     if( bandNo > 0 )
        m_device->_getACL( (m_device->isDeviceEnterpriseSSC() ? UID_LOCKING_RANGE1_E : UID_LOCKING_RANGE1_OM) + bandNo -1, (m_device->isCoreSpec1() ? UID_M_GET1 : UID_M_GET2), acl );
     else
         m_device->_getACL( UID_LOCKING_RANGE0, (m_device->isCoreSpec1() ? UID_M_GET1 : UID_M_GET2), acl );
#endif

      m_device->_getLocking( rangeNo, info.lockingRange ); // Authentication required for getting "meaningful" data ("RangeStart/Length", etc) with Opal SEDs, but not Ent-SSC.

      IOTableAuthority authRow( false );
      authRow.Enabled_isValid = true;

      // Read from Authority table
      if( m_device->isDeviceEnterpriseSSC() )
      {
         m_device->_getAuthority( UID_AUT_BANDMASTER0 + rangeNo, authRow ); // EraseMaster or BandMaster authentication required for Ent-SSC here.
      }
      else
      {
         //m_device->_getAuthority( UID_AUT_ADMIN1, authRow );
         authRow.Enabled = true;
         authRow.Enabled_isValid = true;
      }

      info.rangeEnabled = authRow.Enabled;
      info.rangeEnabled_isValid = authRow.Enabled_isValid;

      if( info.lockingRange.ActiveKey_isValid && UID_NULL != info.lockingRange.ActiveKey )
      {
         info.encryptionMode_isValid = m_device->_getK_AES( info.lockingRange.ActiveKey, info.encryptionMode ) == TS_SUCCESS; // from K_AES_128/256 table
      }
      else
      {
         info.encryptionMode = -1;
         info.encryptionMode_isValid = false;
      }

      if( toCloseSession )
         m_device->_closeSession();
   }
   M_WCatch();

   if( !M_OK() )
   {
      std::wcerr << TXT("Error upon getRangeInfo, ") << tcgErrorMsg( M_CODE() ) << std::endl;
      M_CLEANUPSESSION();
      return false;
   }

   return true;
} // getRangeInfo

//=======================================================================================
bool CTcgDrive::setLockingRange( int rangeNo, IOTableLocking & lockingRow, AuthenticationParameter & authent, bool toStartSession, bool toCloseSession )
{
   char defAuthName[40];
#if !defined(_WIN32) // nvn20110727
   std::wostringstream strStream;
#endif
   if( m_device->isDeviceEnterpriseSSC() && NULL == authent.AuthorityName )
   {
#if defined(_WIN32) // nvn20110727
      sprintf_s( defAuthName, sizeof(defAuthName), "BandMaster%d", rangeNo );
#else
     /* strStream << "BandMaster" <<rangeNo;
      if ((strStream.str()).length() >= (uint)40)
      {
         memcpy( defAuthName, &(strStream.str())[0], (strStream.str()).length() );
      }
      else
      {
         memcpy( defAuthName, &(strStream.str())[0], 40 );
      }*/
      snprintf(defAuthName, sizeof(defAuthName), "BandMaster%d", rangeNo);
#endif 
      authent.AuthorityName = defAuthName;
   }

   if( !m_device->isDeviceEnterpriseSSC() && NULL == authent.AuthorityName )
      authent.AuthorityName = (char*)"Admin1";

   M_WTry()
   {
      m_device->setLockingRow( lockingRow, rangeNo, authent, toStartSession, toCloseSession );
      //
      // Addtionally, if we want to show the disk-erased effect through Windows Control Panel or Explorer,
      // we need to notify the OS to invalidate its cache of disk partition table and re-enumerate the device.
      //
      if( toCloseSession )
      {
         //
         // Addtionally, if we want to show the disk-erased effect through Windows Control Panel or Explorer,
         // we need to notify the OS to invalidate its cache of disk partition table and re-enumerate the device.
         //
         refreshOS();
      }
   }
   M_WCatch();

   if( !M_OK() )
   {
      std::wcerr << TXT("SetLockingRange failed, ") << tcgErrorMsg( M_CODE() ) << std::endl;
      return false;
   }

   return true;
} // setLockingRange

//=======================================================================================
bool CTcgDrive::setCredential( char *target, IOTableC_PIN & pin, AuthenticationParameter & authent )
{
   if( NULL == authent.AuthorityName )
      authent.AuthorityName = target;

   M_WTry()
   {
      m_device->setC_PINRow( pin, target, authent );
   }
   M_WCatch();

   if( !M_OK() )
   {
      std::wcerr << TXT("SetCredential failed, ") << tcgErrorMsg( M_CODE() ) << std::endl;
      return false;
   }

   return true;
} // setCredential

//=======================================================================================
bool CTcgDrive::eraseBand( int startBandNo, int endBandNo, AuthenticationParameter & authent, bool resetACL )
{
   if( m_device->isDeviceEnterpriseSSC() && NULL == authent.AuthorityName )
      authent.AuthorityName = (char*)"EraseMaster";

   if( !m_device->isDeviceEnterpriseSSC() && NULL == authent.AuthorityName )
      authent.AuthorityName = (char*)"Admin1";

   M_WTry()
   {
      m_device->eraseBand( startBandNo, endBandNo, authent, resetACL );

      //
      // Addtionally, if we want to show the disk-erased effect through Windows Control Panel or Explorer,
      // we need to notify the OS to invalidate its cache of disk partition table and re-enumerate the device.
      //
      refreshOS();
   }
   M_WCatch();

   if( !M_OK() )
   {
      std::wcerr << TXT("EraseBand failed, ") << tcgErrorMsg( M_CODE() ) << std::endl;
      return false;
   }

   return true;
} // eraseBand

//=======================================================================================
bool CTcgDrive::enableDisableBand( bool isToEnable, int bandNo, AuthenticationParameter & authent )
{
   if( !m_device->isDeviceEnterpriseSSC() ) // applies to Enterprise-SSC only
      return false;

    if( NULL == authent.AuthorityName )
      authent.AuthorityName = (char*)"EraseMaster";

   char targetName[80];
#if defined(_WIN32) // nvn20110727
   sprintf_s( targetName, sizeof(targetName), "BandMaster%d", bandNo );
#else
   std::wostringstream strStream;
   strStream << "BandMaster" << bandNo;
   memcpy( targetName, &(strStream.str())[0], strStream.str().length() );
#endif

   M_WTry()
   {
      if( isToEnable )
         m_device->enableAuthority( targetName, authent );
      else
         m_device->disableAuthority( targetName, authent );

      //
      // Addtionally, if we want to show the disk-erased effect through Windows Control Panel or Explorer,
      // we need to notify the OS to invalidate its cache of disk partition table and re-enumerate the device.
      //
      refreshOS();
   }
   M_WCatch();

   if( !M_OK() )
   {
      std::wcerr << TXT("EnableDisableBand failed, ") << tcgErrorMsg( M_CODE() ) << std::endl;
      return false;
   }

   return true;
} // enableDisableBand

//=======================================================================================
bool CTcgDrive::readMBR( dta::tBytes & data, AuthenticationParameter & authent, tINT64 startRow, tINT64 endRow, tUINT32 *pDurationMS )
{
   M_WTry()
   {
      m_device->readMBR( data, authent, startRow, endRow, progressUpdate, pDurationMS );
   }
   M_WCatch();

   if( !M_OK() )
   {
      std::wcerr << TXT("ReadMBR failed, ") << tcgErrorMsg( M_CODE() ) << std::endl;
      if( M_CODE().Error == dta::Error(eGenericMemoryError).Error )
         std::wcerr << TXT("Not enough memory to receive data, close running applications and try again.") << std::endl;

      return false;
   }

   if( data.size() == 0 )
   {
      std::wcerr << TXT("No data read back (Forgot authentication?)") << std::endl;
      return false;
   }

   return true;
} // readMBR

//=======================================================================================
bool CTcgDrive::writeMBR( dta::tBytes & data, AuthenticationParameter & authent, tINT64 startRow, tINT64 endRow, tUINT32 *pDurationMS )
{
   if( NULL == authent.AuthorityName )
      authent.AuthorityName = isEnterpriseSSC() ? (char*)"BandMaster0" : (char*)"Admin1"; // nvn20110727

   M_WTry()
   {
      unsigned int currentPollingDelay = m_device->setPollSleepTime( 3 );
      m_device->writeMBR( data, authent, startRow, endRow, progressUpdate, pDurationMS );
      m_device->setPollSleepTime( currentPollingDelay );
   }
   M_WCatch();

   if( !M_OK() )
   {
      std::wcerr << TXT("WriteMBR failed, ") << tcgErrorMsg( M_CODE() ) << std::endl;
      return false;
   }

   return true;
} // writeMBR

//=======================================================================================
bool CTcgDrive::readMBR( char * fileName, AuthenticationParameter & authent, tINT64 startRow, tINT64 endRow, tUINT32 *pDurationMS )
{
   if( m_device->isDeviceEnterpriseSSC() )
      return false;

   dta::tBytes data;
   if( readMBR( data, authent, startRow, endRow, pDurationMS ) )
   {
      if( data.size() == 0 )
         return false;

      FILE *mbrFile;
#if defined(_WIN32) // nvn20110727
      if ( fopen_s( &mbrFile, fileName, "wb" ) != 0 )
#else
      mbrFile = fopen( fileName, "wb" );
      if ( !mbrFile  )
#endif
      {
         std::wcerr << TXT("Cannot create file \"") << fileName << TXT("\".") << std::endl;
         return false;
      }

      if( fwrite( &data[0], data.size(), 1, mbrFile ) != 1 )
      {
         fclose( mbrFile );
         std::wcerr << TXT("Unable to save data to file \"") << fileName << TXT("\".") << std::endl;
         return false;
      }

      fclose( mbrFile );
   }
   else
      return false;

   return true;
} // readMBR

//=======================================================================================
bool CTcgDrive::writeMBR( char * fileName, AuthenticationParameter & authent, tINT64 startRow, tINT64 endRow, tUINT32 *pDurationMS )
{
   if( m_device->isDeviceEnterpriseSSC() )
      return false;

   dta::tBytes data;
   FILE *mbrFile;
#if defined(_WIN32) // nvn20110727
   if ( fopen_s( &mbrFile, fileName, "rb" ) != 0 )
#else
   mbrFile = fopen( fileName, "rb" );
   if ( !mbrFile )
#endif
   {
      std::wcerr << TXT("Cannot open file \"") << fileName << TXT("\".") << std::endl;
      return false;
   }

   fseek( mbrFile, 0, SEEK_END );
   tINT64 size = ftell(mbrFile);
   tINT64 rows = -1;
   if( -1 != endRow )
   {
      if( -1 != startRow && endRow >= startRow )
         rows = endRow - startRow +1;
      else if( -1 == startRow )
         rows = endRow +1;
      else
         rows = 0;
   }

   if( -1 != rows )
      size = size > rows ? rows : size;

   data.resize( (unsigned long) size );
   if( data.size() != size )
   {
      fclose( mbrFile );
      std::wcerr << TXT("Not enough memory for data, close running applications and try again.") << std::endl;
      return false;
   }

   fseek( mbrFile, 0, SEEK_SET );
   if( fread( &data[0], data.size(), 1, mbrFile ) != 1 )
   {
      fclose( mbrFile );
      std::wcerr << TXT("Unable to read data from file \"") << fileName << TXT("\".") << std::endl;
      return false;
   }

   fclose( mbrFile );

   if( writeMBR( data, authent, startRow, endRow, pDurationMS ) )
      return true;
   else
      return false;
} // writeMBR

//=======================================================================================
bool CTcgDrive::getMBRControl( IOTableMBRControl & row, AuthenticationParameter & authent )
{
   if( m_device->isDeviceEnterpriseSSC() )
      return false;

   M_WTry()
   {
      m_device->readMBRControl( row, authent );
   }
   M_WCatch();

   if( !M_OK() )
   {
      std::wcerr << TXT("GetMBRControl failed, ") << tcgErrorMsg( M_CODE() ) << std::endl;
      return false;
   }

   return true;
} // getMBRControl

//=======================================================================================
bool CTcgDrive::setMBRControl( IOTableMBRControl & row, AuthenticationParameter & authent )
{
   if( m_device->isDeviceEnterpriseSSC() )
      return false;

   if( NULL == authent.AuthorityName )
      authent.AuthorityName = (char*)"Admin1";

   M_WTry()
   {
      m_device->writeMBRControl( row, authent );
   }
   M_WCatch();

   if( !M_OK() )
   {
      std::wcerr << TXT("SetMBRControl failed, ") << tcgErrorMsg( M_CODE() ) << std::endl;
      return false;
   }

   return true;
} // setMBRControl

//=======================================================================================
bool CTcgDrive::readDataStore( dta::tBytes & data, AuthenticationParameter & authent, int targetDS, tINT64 startRow, tINT64 endRow, tUINT32 *pDurationMS )
{
   if( NULL == authent.AuthorityName )
      authent.AuthorityName = isEnterpriseSSC() ? NULL : (char *)"Admin1"; // nvn20110727

   M_WTry()
   {
      m_device->readDataStore( data, targetDS, startRow, endRow, convertToAuthorityUID( authent.AuthorityName ), authent.Pin, authent.PinLength, progressUpdate, pDurationMS );
   }
   M_WCatch();

   if( !M_OK() )
   {
      std::wcerr << TXT("ReadDataStore failed, ") << tcgErrorMsg( M_CODE() ) << std::endl;
      if( M_CODE().Error == dta::Error(eGenericMemoryError).Error )
         std::wcerr << TXT("Not enough memory to receive data, close running applications and try again.") << std::endl;

      return false;
   }

   if( data.size() == 0 )
   {
      std::wcerr << TXT("No data read back (Forgot authentication?)") << std::endl;
      return false;
   }

   return true;
} // readDataStore

//=======================================================================================
bool CTcgDrive::writeDataStore( dta::tBytes & data, AuthenticationParameter & authent, int targetDS, tINT64 startRow, tINT64 endRow, tUINT32 *pDurationMS )
{
   if( NULL == authent.AuthorityName )
      authent.AuthorityName = isEnterpriseSSC() ? (char*)"BandMaster0" : (char*)"Admin1"; // nvn20110727

   M_WTry()
   {
      m_device->writeDataStore( data, targetDS, startRow, endRow, convertToAuthorityUID( authent.AuthorityName ), authent.Pin, authent.PinLength, progressUpdate, pDurationMS );
   }
   M_WCatch();

   if( !M_OK() )
   {
      std::wcerr << TXT("WriteDataStore failed, ") << tcgErrorMsg( M_CODE() ) << std::endl;
      return false;
   }

   return true;
} // writeDataStore

//=======================================================================================
bool CTcgDrive::readDataStore( char * fileName, AuthenticationParameter & authent, int targetDS, tINT64 startRow, tINT64 numRow, tUINT32 *pDurationMS )
{
   dta::tBytes data;
   tINT64 endRow = -1;

   if( numRow > 0 && startRow >= 0 )
      endRow = startRow + endRow -1;

   if( readDataStore( data, authent, targetDS, startRow, endRow, pDurationMS ) )
   {
      if( data.size() == 0 )
         return false;

      FILE *dsFile;
#if defined(_WIN32) // nvn20110727
      if ( fopen_s( &dsFile, fileName, "wb" ) != 0 )
#else
      dsFile = fopen( fileName, "wb" );
      if ( !dsFile )
#endif
      {
         std::wcerr << TXT("Cannot create file \"") << fileName << TXT("\".") << std::endl;
         return false;
      }

      if( fwrite( &data[0], data.size(), 1, dsFile ) != 1 )
      {
         fclose( dsFile );
         std::wcerr << TXT("Unable to save data to file \"") << fileName << TXT("\".") << std::endl;
         return false;
      }

      fclose( dsFile );

      std::wcout << data.size() << TXT(" bytes written to file \"") << fileName << TXT("\".") << std::endl 
                 << std::endl;
   }
   else
      return false;

   return true;
} // readDataStore

//=======================================================================================
bool CTcgDrive::writeDataStore( char * fileName, AuthenticationParameter & authent, int targetDS, tINT64 startRow, tINT64 endRow, tUINT32 *pDurationMS )
{
   dta::tBytes data;
   FILE *dsFile;
#if defined(_WIN32) // nvn20110727
   if ( fopen_s( &dsFile, fileName, "rb" ) != 0 )
#else
   dsFile = fopen( fileName, "rb" );
   if ( dsFile );
#endif
   {
      std::wcerr << TXT("Cannot open file \"") << fileName << TXT("\".") << std::endl;
      return false;
   }

   fseek( dsFile, 0, SEEK_END );
   tINT64 size = ftell(dsFile);
   tINT64 rows = -1;
   if( -1 != endRow )
   {
      if( -1 != startRow && endRow >= startRow )
         rows = endRow - startRow +1;
      else if( -1 == startRow )
         rows = endRow +1;
      else
         rows = 0;
   }

   if( -1 != rows )
      size = size > rows ? rows : size;

   data.resize( (unsigned long) size );
   if( data.size() != size )
   {
      fclose( dsFile );
      std::wcerr << TXT("Not enough memory for data, close running applications and try again.") << std::endl;
      return false;
   }

   fseek( dsFile, 0, SEEK_SET );
   if( fread( &data[0], data.size(), 1, dsFile ) != 1 )
   {
      fclose( dsFile );
      std::wcerr << TXT("Unable to read data from file \"") << fileName << TXT("\".") << std::endl;
      return false;
   }

   fclose( dsFile );

   if( writeDataStore( data, authent, targetDS, startRow, endRow, pDurationMS ) )
   {
      std::wcout << data.size() << TXT(" bytes written from file \"") << fileName << TXT("\" to DS") << std::endl; 
      return true;
   }
   else
      return false;
} // writeDataStore


//=======================================================================================
bool CTcgDrive::showAuthorities( char * securityProvider, AuthenticationParameter & authent )
{
/* 
   // m_device->mapUIDToName( TCG_UID uid, char *pBuffer, int maxLength ); }
   if( m_device->mapAuthorityNameToUID(targetAuthority) == UID_NULL )
   {
      std::wcerr << TXT("Unrecognized authority name") << std::endl;
      return false;
   }

   if( isEnterpriseSSC() && NULL == authent.AuthorityName )
      authent.AuthorityName = (char*)"EraseMaster";

   if( !isEnterpriseSSC() && NULL == authent.AuthorityName )
      authent.AuthorityName = (char*)"Admin1";

   M_WTry()
   {
      if( toEnable )
         m_device->enableAuthority( targetAuthority, authent );
      else
         m_device->disableAuthority( targetAuthority, authent );
   }
   M_WCatch();

   if( !M_OK() )
   {
      std::wcerr << TXT("Enable/DisableAuthority failed, ") << tcgErrorMsg( M_CODE() ) << std::endl;
      return false;
   }
*/
   std::wcout << TXT(" *** Not Implemented Yet") << std::endl;
   return false;

} // showAuthorities



//=======================================================================================
bool CTcgDrive::enableDisableAuthority( bool toEnable, char *targetAuthority, AuthenticationParameter & authent )
{
   if( m_device->mapAuthorityNameToUID(targetAuthority) == UID_NULL )
   {
      std::wcerr << TXT(" *** Unrecognized authority name") << std::endl;
      return false;
   }

   if( isEnterpriseSSC() && NULL == authent.AuthorityName )
      authent.AuthorityName = (char*)"EraseMaster";

   if( !isEnterpriseSSC() && NULL == authent.AuthorityName )
      authent.AuthorityName = (char*)"Admin1";

   M_WTry()
   {
      if( toEnable )
         m_device->enableAuthority( targetAuthority, authent );
      else
         m_device->disableAuthority( targetAuthority, authent );
   }
   M_WCatch();

   if( !M_OK() )
   {
      std::wcerr << ( toEnable ? TXT(" *** EnableAuthority failed, ") : TXT(" *** DisableAuthority failed, ") )
         << std::endl << tcgErrorMsg( M_CODE() ) << std::endl;
      return false;
   }

   return true;
} // enableDisableAuthority

//=======================================================================================
bool CTcgDrive::setAuthorityAccess( TCG_UID ace, int maxCount, char* targetAuthorities[], AuthenticationParameter & authent )
{
   if( UID_NULL == ace )
      return false;

   TCG_UIDs authUIDs( maxCount );
   int count =0;
   for( int ii=0; ii<maxCount; ii++ )
   {
      if( '-' == targetAuthorities[ii][0] ) // stops upon the last optional parameters like "-a<Auth> -p<Passwd>"
         break;

      if( UID_NULL != ( authUIDs[count] = convertToAuthorityUID( targetAuthorities[ii] ) ) )
         count++;
   }
   if( 0 == count )
      return false;

   authUIDs.resize( count );

   if( !isEnterpriseSSC() && NULL == authent.AuthorityName )
      authent.AuthorityName = (char*)"Admin1";

   M_WTry()
   {
      m_device->setAuthorityACE( ace, authUIDs, convertToCredentialUID(authent.AuthorityName), authent.Pin, authent.PinLength );
   }
   M_WCatch();

   if( !M_OK() )
   {
      std::wcerr << TXT("SetAuthorityAccess failed, ") << tcgErrorMsg( M_CODE() ) << std::endl;
      return false;
   }

   return true;
} // setAuthorityAccess

//=======================================================================================
bool CTcgDrive::setAuthorityAccess( char *ace, int sequenceNo, int maxCount, char* targetAuthorities[], AuthenticationParameter & authent )
{
   TCG_UID aceUID = convertToACEUID( ace, sequenceNo );
   if( UID_NULL == aceUID )
      return false;

   return setAuthorityAccess( aceUID, maxCount, targetAuthorities, authent );
} // setAuthorityAccess

//=======================================================================================
bool CTcgDrive::revertSP( char *target, AuthenticationParameter & authent )
{
   if( NULL == authent.AuthorityName )
   {
      if( _stricmp( target, "Admin" ) == 0 || _stricmp( target, "AdminSP" ) == 0 )
         authent.AuthorityName = (char*)"PSID"; // Earlier Hurricane drives may still use SID.
      else
         authent.AuthorityName = (char*)"Admin1"; // Reverting Locking SP.
   }

   M_WTry()
   {
      unsigned int currentPollingDelay = m_device->setPollSleepTime( 10 );
      m_device->revertSP( target, authent );
      m_device->setPollSleepTime( currentPollingDelay );

      //
      // Addtionally, if we want to show the disk-erased effect through Windows Control Panel or Explorer,
      // we need to notify the OS to invalidate its cache of disk partition table and re-enumerate the device.
      //
      refreshOS();
   }
   M_WCatch();

   if( !M_OK() )
   {
      std::wcerr << TXT("RevertSP failed, ") << tcgErrorMsg( M_CODE() ) << std::endl;
      return false;
   }

   return true;
} // revertSP

//=======================================================================================
// This is an example on how to use individual method calls to form your own command.
//=======================================================================================
bool CTcgDrive::generateRandom( char *target, dta::tBytes & randomData )
{
   M_WTry()
   {
      if( !_stricmp( target, "Admin" ) || !_stricmp( target, "AdminSP" ) )
      {
         m_device->_startSession( UID_SP_ADMIN );
      }
      else if( !_stricmp( target, "Locking" ) || !_stricmp( target, "LockingSP" ) )
      {
         m_device->_startSession( m_device->isDeviceEnterpriseSSC() ? UID_SP_LOCKING_E : UID_SP_LOCKING_OM );
      }
      else
      {
         std::wcerr << TXT("Invalid request, you can only choose either Admin or Locking.") << std::endl;
         return false;
      }

      m_device->_random( randomData );
      m_device->_closeSession();
   }
   M_WCatch();

   if( !M_OK() )
   {
      std::wcerr << TXT("GenerateRandom failed, ") << tcgErrorMsg( M_CODE() ) << std::endl;
      M_CLEANUPSESSION();
      return false;
   }

   return true;
} // generateRandom

//=======================================================================================
bool CTcgDrive::protocolStackReset( int comChannel, bool syncHostTPerProperties )
{
   M_WTry()
   {
      m_device->protocolStackReset( comChannel, syncHostTPerProperties );
   }
   M_WCatch();

   if( !M_OK() )
   {
      std::wcerr << TXT("ProtocolStackReset failed, ") << tcgErrorMsg( M_CODE() ) << std::endl;
      return false;
   }

   return true;
} // protocolStackReset

//=======================================================================================
bool CTcgDrive::tperReset( bool syncHostTPerProperties )
{
   M_WTry()
   {
      if( !m_device->isTPerResetSupported() )
      {
         std::wcerr << TXT(" *** TPerReset not supported.") << std::endl;        
         return false;
      }
      else if( !m_device->isTPerResetEnabled() )
      {
         std::wcerr << TXT(" *** TPerReset not enabled.") << std::endl;
         return false;
      }
      else
      {
         m_device->TPerReset( syncHostTPerProperties );
      }
   }
   M_WCatch();

   if( !M_OK() )
   {
      std::wcerr << TXT(" *** TPerReset failed, ") << tcgErrorMsg( M_CODE() ) << std::endl;
      return false;
   }

   return true;
} // tperReset

//=======================================================================================
bool CTcgDrive::setTperResetEnable( AuthenticationParameter & authent, bool enable )
{
   M_WTry()
   {
      if( !m_device->isTPerResetSupported() )
      {
         std::wcerr << TXT(" *** TPerReset not supported.") << std::endl;        
         return false;
      }
      
      // Set TPerReset to Enabled or Disabled
      else if( m_device->setTPerResetEnable( authent, enable ) )
      {
         std::wcerr << TXT(" *** setTPerResetEnable failed.") << std::endl;        
         return false;
      }
   }
   M_WCatch();

   if( !M_OK() )
   {
      std::wcerr << TXT(" *** setTPerResetEnable failed, ") << tcgErrorMsg( M_CODE() ) << std::endl;
      return false;
   }

   return true;
} // setTperResetEnable


//=======================================================================================
bool CTcgDrive::selectComChannel( int comChannel, bool syncHostTPerProperties )
{
   M_WTry()
   {
      m_device->selectComChannel( comChannel, syncHostTPerProperties );
   }
   M_WCatch();

   if( !M_OK() )
   {
      std::wcerr << TXT("SelectComChannel failed, ") << tcgErrorMsg( M_CODE() ) << std::endl;
      return false;
   }

   return true;
} // selectComChannel

//=======================================================================================
tUINT64 CTcgDrive::getNumberRows( TCG_UID targetTable )
{
   // Within an opened session
   tUINT64 numRows = 0;
   m_device->_getNumberOfRows( targetTable, numRows );

   return numRows;
} // getNumberRows

//=======================================================================================
bool CTcgDrive::isATADevice()
{
   _tstring attrValue;
   M_WTry()
   {
      m_session->GetAttribute( TXT("Transport" ), attrValue );
   }
   M_WCatch();

   if( !M_OK() )
      std::wcerr << TXT("Error RetrieveTransportInfo, ") << tcgErrorMsg( M_CODE() ) << std::endl;

   if( attrValue == TXT("ATA") )
      return true;
   else
      return false;
} // isATADevice

//=======================================================================================
bool CTcgDrive::isSeagateDrive()
{
   _tstring modelNo;
   _tstring attrValue;
   
   M_WTry()
   {
      // Starting with SDK TCG2_2_0, VendorID attribute is suppported on both SCSI and ATA
      m_session->GetAttribute( TXT("VendorIdentification" ), attrValue );

      if( attrValue == TXT("SEAGATE") ) 
         return true;
   }
   M_WCatch();
   
   if( M_OK() )
      std::wcerr << TXT("Error VendorIdentification Attribute, ") << tcgErrorMsg( M_CODE() ) << std::endl;

   return false;     // If not SEAGATE, the either UNKNOWN or error.

#if 0 // This was the old way of determining if drive was Seagate, and not reliable.
      m_session->GetAttribute( TXT("Transport" ), attrValue );

      if( attrValue == TXT("ATA") )
      {
         ata::CAta* pATA = dynamic_cast<ata::CAta*>( m_session );
         if ( pATA )
         {
            // Read the IDentifyDevice data
            modelNo = pATA->GetProductIdentification();
         }
      }
      else
      {
         dta::CScsi* pSCSI = dynamic_cast<dta::CScsi*>( m_session );
         if ( pSCSI )
         {
            // Read the INQUIRY data
            modelNo = pSCSI->GetProductIdentification();
         }
      }
   }
   M_WCatch();

   if( !M_OK() )
      std::wcerr << TXT("Error RetrieveModelInfo, ") << tcgErrorMsg( M_CODE() ) << std::endl;
#if defined(_WIN32) // nvn20110727
   if( modelNo.size() > 2 && modelNo[0] == _T('S') && modelNo[1] == _T('T') ) // generic STX drives
      return true;
   if( modelNo.size() > 2 && modelNo[0] == _T('D') && modelNo[1] == _T('E') ) // a batch for Hitachi
      return true;
   else if ( 0 == modelNo.compare( _T("HP Secure Hard Disk")) )               // a batch for HP
#else
   if( modelNo.size() > 2 && modelNo[0] == TXT('S') && modelNo[1] == TXT('T') ) // generic STX drives
      return true;
   if( modelNo.size() > 2 && modelNo[0] == TXT('D') && modelNo[1] == TXT('E') ) // a batch for Hitachi
      return true;
   else if ( 0 == modelNo.compare( TXT("HP Secure Hard Disk")) )               // a batch for HP
#endif
      return true;
   else
      return false;
#endif // old method

} // isSeagateDrive


//=======================================================================================
bool CTcgDrive::showFIPSCapable( char & Revision, char & OverallLevel, std::string &HardwareVer,
                            std::string &FirmwareVer, std::string &ModuleName )
{
   // Determine if drive is FIPS-Capable and possibly FIPS-Validated

   // Call into SDK to get Security Compliance data if command is supported by drive.
   TCG_STATUS status = m_device->getFipsComplianceInfo(
                           Revision, OverallLevel, HardwareVer, FirmwareVer, ModuleName );

   if( status == TS_SUCCESS )
   {
      // The drive either returned meaningful Security Compliance data, or it returned a zero-
      // length descriptor verifying that the drive is not FIPS-Capable. For the latter case,
      // the returned chars are blanks.

      if( Revision == ' ' && OverallLevel == ' ' )
      {
         std::wcout << TXT(" FAIL") << std::endl << TXT("      * SED reports that it is NOT FIPS-Capable.") << std::endl;
         return false;
      }
      else
      {
         // Info was obtained from the drive using the Trusted Security Compliance SP00 command.
         std::wcout << TXT(" PASS") << std::endl << TXT("      * SED reports that it is FIPS 140-") 
                    << Revision << TXT(" Level ") << OverallLevel << TXT(" Capable.") << std::endl;
         return true;
      }
   }
   else if ( status == TS_FAIL )
   {
      // Security Compliance command was aborted, so we know drive does not support this command. 
      // If this is a Seagate ATA SED, then inspect the proprietary FIPS-possible bit in word 159
      // of IDENTIFY_DEVICE data, and if set, drive MIGHT be FIPS-capable.

      if( isSeagateDrive() )
      {
         // Get ID data and check word 159 bit 0.
         if( m_pATA )
         {
            // Read the Identify_Device data from drive
            dta::tBytes buffer;
            m_pATA->GetIDBuffer( buffer );
            tUINT16 *pw = (tUINT16 *) &buffer[0];

            // Word 159 Bit 0 holds the Seagate maybe-FIPS bit
            if( pw[159] & 0x0001 )
            {
               std::wcout << TXT(" PASS") << std::endl 
                          << TXT("      * SED might be FIPS 140-2 Level 2 Capable.") 
                          << std::endl;

               // Set the FIPS level, HWVer, FWVer and Model from default Identify_Device values
               Revision = '2';
               OverallLevel = '2'; 
               HardwareVer.resize( m_pATA->GetProductIdentification().length() + 1);
               FirmwareVer.resize( m_pATA->GetProductRevisionLevel().length() + 1);

               for( tUINT16 i = 0; i < (m_pATA->GetProductIdentification()).length(); i++ )
                  HardwareVer[i] = (tByte)(m_pATA->GetProductIdentification())[i];
               for( tUINT16 i = 0; i < (m_pATA->GetProductRevisionLevel()).length(); i++ )
                  FirmwareVer[i] = (tByte)(m_pATA->GetProductRevisionLevel())[i];
               ModuleName = "Seagate Momentus Thin Self-Encrypting Drive";

               return true;
            } // if Word 159 ane bit 0
         } // if m_pATA IDENTIFY_DEVICE data
         else if( m_pSCSI )
         {
            // Unknown how SCSI devices indicate FIPS support if not not done by a
            // Security Compliance reporting mechanism.
            std::wcout << TXT(" SCSI DEVICE ") << std::endl;
         } // m_pSCSI 

         std::wcout << TXT(" FAIL") << std::endl << TXT("      * SED does not appear to be FIPS-Capable.") << std::endl;
         return false;

      } // if Seagate SED
   }
   else if( status == TS_DTL_ERROR )
   {
      // DTL Error indicates some problem other than the command was aborted, so we interpret 
      // this to suggest that the drive is not FIPS-capable. Report an error and bail out.

      std::wcout << TXT(" ERROR") << std::endl << TXT("      * SED failed to report whether it is IPS-Capable.");
      std::wcout << std::endl;
      
      return false;
   } // elif

   std::wcout << std::endl;
   return true;
} // showFIPSCapable


//=======================================================================================
bool CTcgDrive::isRequestedParameterOfDataStoreTablesOK( UINT64VALs *pDataStoreTableSizes )
{
   if( NULL != pDataStoreTableSizes )
   {
      tUINT16 maxDStables = m_device->getMaxNumberOfDataStoreTables();
      tUINT32 maxTotalSizeDStables = m_device->getMaxTotalSizeOfDataStoreTables();
      tUINT32 alignmentDStableSize = m_device->getDataStoreTableSizeAlignment();

      if( 0 != maxDStables && 0 != maxTotalSizeDStables && 0 != alignmentDStableSize )
      {
         if( (*pDataStoreTableSizes).size() > maxDStables )
         {
            std::wcerr << TXT("The specified number of DataStore Tables, ") << (*pDataStoreTableSizes).size() 
                       << TXT(", is too big. Max=") << maxDStables << TXT(".\n") << std::endl;
            return false;
         }

       tUINT64 totalSize = 0;
         for( unsigned int ii=0; ii < (*pDataStoreTableSizes).size(); ii++ )
         {
            if( ( (*pDataStoreTableSizes)[ii] % alignmentDStableSize ) != 0 )
            {
               std::wcerr << TXT("The #") << ii << TXT(" specified size of DataStore Table, ") 
                          << (*pDataStoreTableSizes)[ii] << TXT(", is not aligned in ")
                          << alignmentDStableSize << TXT(".\n")  << std::endl;
               return false;
            }

            totalSize += (*pDataStoreTableSizes)[ii];
         }

         if( totalSize > maxTotalSizeDStables )
         {
            std::wcerr << TXT("The total specified size of DataStore Tables, ") << totalSize 
                       << TXT(", is too big. Max=") << maxTotalSizeDStables << TXT(".\n") << std::endl;
            return false;
         }
      }
   }

   return true;
} // isRequestedParameterOfDataStoreTablesOK

//=======================================================================================
void CTcgDrive::setUseSilo( const bool newUseSilo )
{
   if( m_device->hasSilo() )
   {
      m_device->setUseSilo( newUseSilo );

      if( newUseSilo && m_device->getPreferenceToUseDynamicComID() )
         m_device->setPreferenceToUseDynamicComID( false );
   }
   else
   {
      std::wcerr << TXT("Your device or library does not support Silo feature, request ignored.") << std::endl;
   }
} // setUseSilo

//=======================================================================================
TCG_UID CTcgDrive::convertToACEUID( char *ace, int sequenceNo )
{
   TCG_UID aceID = UID_NULL;

   if( NULL == ace )
      return aceID;

   if( _stricmp( ace, "SRL" ) == 0 ) // Set_ReadLocked
      aceID = UID_ACE_LOCKING_RANGE0_SET_RDLOCKED + sequenceNo;
   else if( _stricmp( ace, "SWL" ) == 0 ) // Set_WriteLocked
      aceID = UID_ACE_LOCKING_RANGE0_SET_WRLOCKED + sequenceNo;
   else if( _stricmp( ace, "SMBRCDone" ) == 0 ) // Set_MBRControl_Done
      aceID = UID_ACE_MBRCONTROL_SET_DONE;
   else if( _strnicmp( ace, "SDS", sizeof("SDS") -1 ) == 0 ) // Set_DataStore_All
      aceID = UID_ACE_DATASTORE1_SET_ALL + (sequenceNo * 2);
   else if( _strnicmp( ace, "GDS", sizeof("GDS") -1 ) == 0 ) // Get_DataStore_All
      aceID = UID_ACE_DATASTORE1_GET_ALL + (sequenceNo * 2);

   return aceID;
} // convertToACEUID

//=======================================================================================
#if defined(_WIN32) // nvn20110727
_tstring CTcgDrive::tcgErrorMsg( dta::DTA_ERROR status )
#else
char* CTcgDrive::tcgErrorMsg( dta::DTA_ERROR status )
#endif
{
#if defined(_WIN32) // nvn20110727
   std::wostringstream stream;
   stream << TXT("ErrorCode=") << TXT("0x") << std::hex << std::uppercase << std::setw(10) << setfill(_T('0')) << status.Error;
#else
   std::ostringstream stream;
   stream << TXT("ErrorCode=") << TXT("0x") << std::hex << std::uppercase << std::setw(10) << setfill(TXT('0')) << status.Error;
#endif
//   stream << TXT(" (") << m_device->dtlErrorToString( status ) << TXT(").");
#if defined(_WIN32) // nvn20110727
   return stream.str();
#else
   return (char*)stream.str().c_str();
#endif

} // tcgErrorMsg

//=======================================================================================
void CTcgDrive::printData( dta::tBytes & buffer, int bytesToShow )
{
   if( bytesToShow > 2048 )
      bytesToShow = 2048;

   printf( "\n");

   for( int ii=0; ii < bytesToShow/16; ii++ )
   {
       printf( "  %3X:", ii*16 );
       for( int jj=0; jj<16; jj++ )
          printf( " %02X", buffer[ii*16+jj] );

       std::wcout << TXT("    ");

       for( int jj=0; jj<16; jj++ )
       {
          if( buffer[ii*16+jj] == '\n' || buffer[ii*16+jj] == '\b' || buffer[ii*16+jj] == '\t' || buffer[ii*16+jj] == '\r' || buffer[ii*16+jj] == '\a' )
             printf( " " );
          else
             printf( "%C", buffer[ii*16+jj] );
       }

       std::wcout << std::endl;
   }
} // printData

//=======================================================================================
void CTcgDrive::refreshOS()
{
   _tstring devName;
   m_session->GetAttribute( TXT("DeviceName"), devName );
#if defined(_WIN32) // nvn20110727
   HANDLE hand = ::CreateFile( devName.c_str(),
                               GENERIC_READ  | GENERIC_WRITE,
                               FILE_SHARE_READ | FILE_SHARE_WRITE, 
                               NULL, OPEN_EXISTING, 0, NULL );

   if( INVALID_HANDLE_VALUE != hand )
   {
      DWORD bytesReturned;
      if( ! ::DeviceIoControl( hand,                     // handle to device
                         IOCTL_DISK_UPDATE_PROPERTIES,   // dwIoControlCode
                         NULL,                           // lpInBuffer
                         0,                              // nInBufferSize
                         NULL,                           // lpOutBuffer
                         0,                              // nOutBufferSize
                         &bytesReturned,                 // lpBytesReturned
                         0 ) )                           // lpOverlapped
      {
         std::wcerr << TXT("Warning: Unable to do IOCTL_DISK_UPDATE_PROPERTIES: ") << GetLastError() << TXT(", Wondows may not get refreshed!") << std::endl;
      }

      ::CloseHandle( hand );
   }
#else
   // TODO: refreshOS // nvn20110727
#endif
} // refreshOS

//=======================================================================================
vector<pair<_tstring, DTIdentifier> > CTcgDrive::enumerateTrustedDevices( CLocalSystem* localSystem, const _tstring & deviceEnumerationLogFileName )
{
   vector<pair<_tstring, DTIdentifier> > trustedDevices(0);
   DTIdentifierCollection devices;
   _tstring attrValue;

   try
   {
      localSystem->GetDriveTrustIdentifiers( devices, TXT("-bustype SCSI"), TXT("deleteme.log") );
//      localSystem->GetDriveTrustIdentifiers( devices, TXT(""), deviceEnumerationLogFileName );
   }
   catch( ... )
   {
      // Not much we can do except return with an empty device list
      return trustedDevices;
   }
   
   // Loop through and look for trusted devices
   while ( !devices.empty() )
   {
      const DTIdentifier id = devices.front();
      devices.pop_front();

      CDriveTrustSession* session = NULL;
      
      try
      {
         localSystem->CreateSession( id, 0x01, TXT("-log ") + deviceEnumerationLogFileName, session );
      }
      catch( ... )
      {
         // An un-recognized or so-far unsupported bus may get thrown
         continue;   // while()
      }

      try
      {
         // Drives supporting Trusted I/O can be recognized by the ability
         // to generate a valid response to a Protocol-0 inquiry that uses
         // Security-Data-From-Device (either Trusted Recieve for ATA
         // or Security-Protocol-In (SCSI)).

         // We need to know how much data will be returned in one "block".
         session->GetAttribute( TXT("BlockSize"), attrValue );

         // Allocate a temp array of this block-size
         tBytes temp( _tatoi(attrValue.c_str()) );
         
         // In case the drive doesn't understand Security-Data-From-Device
         // and hangs, set the OS timelimit to 5 seconds to minimize lockups.
         session->SetAttribute( TXT("Timeout"), TXT("5") );

/*
         // Set to DMA mode Trusted Snd/Rcv for ATA SEDs, just for workaround due 
         // to some proto drive issues where Trusted I/O didn't work in PIO mode.

         session->GetAttribute( TXT("Transport" ), attrValue );
         if( attrValue == TXT("ATA") )
         {
            ata::CAta* pATA = dynamic_cast<ata::CAta*>( session );
            if ( pATA )
               pATA->SetTrustedOpcodes( ata::evTrustedSendDMA, ata::evTrustedReceiveDMA );
         }
*/
         // Ask drive for a response to Security Protocol 0.
         session->SecurityDataFromDevice( SECURITY_PROTOCOLID_INFORMATION_DISCOVERY,
                  SPSPECIFIC_P00_SUPPORTED_SECURITY_PROTOCOL_LIST, temp );

         // If no error was thrown above, then drive at least supports Security
         // Data From Device on protocol 0, which every Seagate SED does except 
         // Cody SeaCOS drives (which are hard-wired to protocol 0xf0).

         // The valid response from a TCG-based SED is list of the security 
         // protocols supported. Bytes 6 and 7 make a 16-bit count of the 
         // supported protocols, and byte 8 is the beginning of the supported
         // protocol list.
         tUINT16 numProto = (((tUINT16)temp[6]) << 8) + temp[7];
         
         // See if there is at least one trusted protocol supported, and
         // if so, see if the TCG Protocol 0x01 is in the list.

         while( numProto-- > 0 )
         {
            if( temp[numProto + 8] == 0x01 )
            {
               // Found it; add this drive's SerialNumber to the return list.
               session->GetAttribute( TXT("SerialNumber"), attrValue );
               trustedDevices.push_back( pair<_tstring, DTIdentifier>( attrValue, id ) );
               break;
            }
         }

         session->Destroy();
      }
      catch( ... )
      {
         // if we get here, the drive doesn't support trusted command, ignore it.
         session->Destroy();
      }
   } // while

   return trustedDevices;
} // enumerateTrustedDevices

//=======================================================================================
DTIdentifier CTcgDrive::selectDevice( CLocalSystem* localSystem, const _tstring & driveSerialNumber, 
                                     const _tstring & deviceEnumerationLogFileName )
{
   vector<pair<_tstring, DTIdentifier> > devices = enumerateTrustedDevices( localSystem, deviceEnumerationLogFileName );

   // Make sure a list of devices is available
   if( devices.size() == 0 )
      return TXT("");



   // If user specified a particular drive by serial number, see if it was enumerated as a trusted device.
   if( driveSerialNumber.size() > 0 )
   {
      for( unsigned int ii = 0; ii < devices.size(); ii++ )
      {
         if( devices[ii].first.compare( driveSerialNumber ) == 0 )
         {
#if defined(_WIN32) // nvn20110902 - use printf, cout flush issue(?)
            std::wcout << TXT("Trusted device: ");
            std::wcout << devices[ii].first.c_str() 
               << TXT(" [") << devices[ii].second.substr(0,devices[ii].second.find(L':')).c_str()
               << TXT("]") << std::endl << std::endl;
#else
            printf("Trusted device: ");
            printf("%s [%s]\n\n", devices[ii].first.c_str(),
                   devices[ii].second.substr(0,devices[ii].second.find(L':')).c_str() );
#endif
            return devices[ii].second;
         } // if compare
      } // for ii

      // If matching drive was not found in enumeration, don't blindly apply cmd to another drive!
#if 0
   #if defined(_WIN32) // nvn20110902 - use printf, cout flush issue(?)
      std::wcout << TXT("Could not locate Trusted Drive with SerialNumber: ") << driveSerialNumber << std::endl
                 << std::endl;                 
      return TXT("");   // Indicates no drive found.
   #else
      //printf("Could not locate Trusted Drive with SerialNumber: %s \n", driveSerialNumber ); // nvn
      std::wstring wtmp(driveSerialNumber.length(), L' ');
      std::copy(driveSerialNumber.begin(), driveSerialNumber.end(), wtmp.begin());
      std::wcout << TXT("Could not locate Trusted Drive with SerialNumber: ") << wtmp << std::endl
                 << std::endl;
   #endif
#endif
   } // if driveSerialNumber
      
   // No serial number was specified, or if specified, no match to drives found.

   if( devices.size() == 1 )
   {
#if defined(_WIN32) // nvn20110902 - use printf, cout flush issue(?)
      std::wcout << TXT("Trusted device: ")
                 << devices[0].first.c_str() 
                 << TXT(" [") << devices[0].second.substr(0,devices[0].second.find(L':')).c_str()
                 << TXT("]") << std::endl << std::endl;
#else
      printf("Trusted device: %s [%s]\n\n", devices[0].first.c_str(),
                 devices[0].second.substr(0,devices[0].second.find(L':')).c_str() );
#endif
      return devices[0].second;
   }

   // If there're more than one devices, have user select one

#if defined(_WIN32) // nvn20110902 - use printf, cout flush issue(?)
   std::wcout << TXT("Trusted devices detected:") << std::endl;
#else
   printf("Trusted devices detected:\n");
#endif

   while( true )
   {
      int selection = (int)devices.size();  // Init 1 more than valid selection

      for( unsigned int ii = 0; ii < devices.size(); ii++ )
      {
#if defined(_WIN32) // nvn20110902 - use printf, cout flush issue(?)
         std::wcout << TXT("[") << ii << TXT("] ")<< devices[ii].first.c_str() 
                    << TXT(" [") << devices[ii].second.substr(0,devices[ii].second.find(L':')).c_str()
                    << TXT("]") << std::endl;
#else
         printf("[%d] %s [%s]\n", ii, devices[ii].first.c_str(),
                   devices[ii].second.substr(0,devices[ii].second.find(L':')).c_str() );
#endif
      } // for ii

#if defined(_WIN32) // nvn20110902 - use printf, cout flush issue(?)
      std::wcout << TXT("Enter selection or Ctrl-C to quit: ") << flush;

//      wchar_t ch;
       cin >> selection;

      if( selection < (int) devices.size() )
      {
         std::wcout << flush << std::endl; // nvn20110902 - don't forget to flush
         return devices[selection].second; // User has picked a device
      }
#else
      printf("Enter selection: ");   
      scanf("%d",&selection);
      if( selection < (int) devices.size() )
      {
        return devices[selection].second;
            // User has picked a device
      }
#endif

      // Bad selection, try again!
#if defined(_WIN32) // nvn20110902 - use printf, cout flush issue(?)
      std::wcout << flush << TXT("Invalid entry") << std::endl;
#else
      printf("%d is Invalid entry\n",selection);
#endif
   } // while
} // selectDevice


#if defined(_WIN32) // nvn20110727
#else
int kbhit (void)
{
  struct timeval tv;
  fd_set rdfs;

  tv.tv_sec = 0;
  tv.tv_usec = 0;

  FD_ZERO(&rdfs);
  FD_SET (STDIN_FILENO, &rdfs);

  select(STDIN_FILENO+1, &rdfs, NULL, NULL, &tv);
  return FD_ISSET(STDIN_FILENO, &rdfs);

}
#endif

//=================================================================================
/// \brief User defined/supplied lengthy process progress update callback routine (eg., used with DataStore or MBR table read/write).
///
/// \param total      [IN]  The total amount of data access of workload (in bytes) during the process.
/// \param start      [IN]  The starting point of addressing (byte index).
/// \param current    [IN]  The present point of addessing (byte index) to be processed.
/// \param pace       [IN]  The length of data (interval, in bytes) for the current step.
///
/// \return boolean flag indicating if the user wants to continue the process. True to continue, and false to abort.
//=================================================================================
bool progressUpdate( tUINT64 total, tUINT64 start, tUINT64 current, tUINT64 pace )
{
#if defined(_WIN32) // nvn20110727
   if( _kbhit() )
   {
      if( _getch() == 0x1B ) // [Esc] \001B
         return false;
   }
#else
   if( kbhit() )
   {
      if( getchar() == 0x1B ) // [Esc] \001B
         return false;
   }
#endif

   static int length =0;

   if( 0 == total )
      return true;

   int percentage = (int)(((float)( current - start +1)) / total * 100.0);

   if( current == start )
   {
      if( total > 1 )
         percentage = 0;

      length = 0;
   }
   else
   {
      for( int ii=0; ii<length; ii++ )
         printf( "\b" );
   }

#if defined(_WIN32) // nvn20110727
   char buff[80];
   sprintf_s( buff, sizeof(buff), "%3d%% (%I64X of %I64X-%I64X, %Xh) ", percentage, current, start, start + total -1, pace );
   printf( "%s", buff );
   length = (int) strlen(buff);
#else
   char buff[80];
   int n = 0;
   //n = sprintf(buff, "%3d%% (%I64X of %I64X-%I64X, %Xh) ", percentage, current, start, start + total -1, pace );
   n = sprintf(buff, "%3d%% (%X of %X-%X, %Xh) ", percentage, current, start, start + total -1, pace ); // nvntry
   printf( "%s", buff );
   length = (int) strlen(buff);
#endif

   return true;
} // progressUpdate

//=======================================================================================
bool CTcgDrive::readUserLBA( char * fileName, tUINT64 startLBA, tUINT32 lengthLBA )
{
   dta::tBytes data( 0 );
   M_WTry()
   {
      _tstring attrValue;
      m_session->GetAttribute( TXT("Transport" ), attrValue );

      if( attrValue == TXT("ATA") )
      {
         ata::CAta* pATA = dynamic_cast<ata::CAta*>( m_session );
         if ( pATA )
         {
            std::wcerr << TXT(" **DEBUG** ReadLBA using ATA ReadDMA().") << std::endl;
            data.resize( (size_t) lengthLBA * 512 );
            pATA->ReadDMA( data, startLBA );
            std::wcerr << TXT(" **DEBUG** ReadLBA completed ATA ReadDMA().") << std::endl;
         }
      }
      else
      {
         dta::CScsi* pSCSI = dynamic_cast<dta::CScsi*>( m_session );
         if ( pSCSI )
         {
            std::wcerr << TXT(" **DEBUG** ReadLBA using SCSI Read16().") << std::endl;
            data.resize( (size_t) lengthLBA * 512 );
            pSCSI->Read16( data, startLBA );
            //pSCSI->Read10( data, (tUINT32) startLBA );
            std::wcerr << TXT(" **DEBUG** ReadLBA completed SCSI Read16().") << std::endl;
         }
      }
   }
   M_WCatch();

   if( !M_OK() )
   {
      std::wcerr << TXT("Error ReadLBA, ") << tcgErrorMsg( M_CODE() ) << std::endl;
      return false;
   }

   if( data.size() == 0 )
      return false;

   // If no filename, then dump the first sector to the display
   if( strlen( fileName ) == 0 )
   {
      printData( data, tINT32(data.size()) );
      return true;
   }

   FILE *pFile;
#if defined(_WIN32) // nvn20110727
   if ( fopen_s( &pFile, fileName, "wb" ) != 0 )
#else
   pFile = fopen( fileName, "wb" );
   if ( !pFile )
#endif
   {
      std::wcerr << TXT("Cannot create file \"") << fileName << TXT("\".") << std::endl;
      return false;
   }

   if( fwrite( &data[0], data.size(), 1, pFile ) != 1 )
   {
      fclose( pFile );
      std::wcerr << TXT("Unable to save data to file \"") << fileName << TXT("\".") << std::endl;
      return false;
   }

   fclose( pFile );
   return true;
} // readUserLBA

//=======================================================================================
bool CTcgDrive::writeUserLBA( char * fileName, tUINT64 startLBA, tUINT32 lengthLBA )
{
   dta::tBytes data;

   // If no filename passed, then write a fill char to all data in output sectors.

   if( strlen( fileName ) == 0 )
   {
      dta::tBytes value;
      int fillbyte;

//#if defined(_WIN32) // nvn20110902 - use printf, cout flush issue(?)
      std::wcout << TXT("Enter hex byte value to write to drive: ");
      cin >> hex >> fillbyte >> dec;
      //unsigned int fillbyte = atoi( value );
            
      std::wcout << TXT("Filling ") << lengthLBA << TXT(" sectors with constant '0x") << hex << fillbyte << dec << TXT("'") << std::endl;

      data.resize( lengthLBA * 512 );
      if( data.size() != lengthLBA * 512 )
      {
         std::wcerr << TXT("Not enough memory for data, close running applications and try again.") << std::endl;
         return false;
      }
      memset( &data[0], fillbyte, data.size() );
//#else
// BUGBUG: todo: port to linux.
//#endif
   }
   else // strlen(fileName) > 0
   {
      FILE *pFile;
#if defined(_WIN32) // nvn20110727
      if ( fopen_s( &pFile, fileName, "rb" ) != 0 )
      {
         std::wcerr << TXT("Cannot open file \"") << fileName << TXT("\".") << std::endl;
#else
      pFile = fopen( fileName, "rb" );
      if ( !pFile )
      {
         printf( "Cannot open file \"%s\".\n", fileName );
#endif
         return false;
      }

      fseek( pFile, 0, SEEK_END );
      tUINT64 size = ftell(pFile);

      if( size > lengthLBA * 512 )
         size = lengthLBA * 512;

      data.resize( (size_t) size );

      if( data.size() != size )
      {
         fclose( pFile );
         std::wcerr << TXT("Not enough memory for data, close running applications and try again.") << std::endl;
         return false;
      }

      fseek( pFile, 0, SEEK_SET );
      if( fread( &data[0], data.size(), 1, pFile ) != 1 )
      {
         fclose( pFile );
         std::wcerr << TXT("Unable to read data from file \"") << fileName << TXT("\".") << std::endl;
         return false;
      }

      fclose( pFile );

   } // if fileName == ""

   M_WTry()
   {
      _tstring attrValue;
      m_session->GetAttribute( TXT("Transport" ), attrValue );

      if( attrValue == TXT("ATA") )
      {
         ata::CAta* pATA = dynamic_cast<ata::CAta*>( m_session );
         if ( pATA )
            pATA->WriteDMA( data, startLBA );
      }
      else
      {
         dta::CScsi* pSCSI = dynamic_cast<dta::CScsi*>( m_session );
         if ( pSCSI )
            pSCSI->Write16( data, startLBA );
            pSCSI->Write10( data, (tUINT32) startLBA );
      }
   }
   M_WCatch();

   if( !M_OK() )
   {
      std::wcerr << TXT("Error WriteLBA, ") << tcgErrorMsg( M_CODE() ) << std::endl;
      return false;
   }

   return true;
} // writeUserLBA


//=======================================================================================
bool CTcgDrive::getUDSPort( IOTable_PortLocking & row, AuthenticationParameter & authent )
{
   M_WTry()
   {
      m_device->getSecureUDS( row, authent );
   }
   M_WCatch();

   if( !M_OK() )
   {
      std::wcerr << TXT("GetPortState_UDSPort failed, ") << tcgErrorMsg( M_CODE() ) << std::endl;
      return false;
   }

   return true;
} // getUDSPort

//=======================================================================================
bool CTcgDrive::setUDSPort( IOTable_PortLocking & row, AuthenticationParameter & authent )
{
   if( row.isEmpty() )
   {
      std::wcerr << TXT("No parameters given to set the port state.")  << std::endl;
      return false;
   }

   M_WTry()
   {
      m_device->setSecureUDS( row, authent );
   }
   M_WCatch();

   if( !M_OK() )
   {
      std::wcerr << TXT("SetPortState_UDSPort failed, ") << tcgErrorMsg( M_CODE() ) << std::endl;
      return false;
   }

   return true;
} // setUDSPort



//=======================================================================================
bool CTcgDrive::getFWDownload( IOTable_PortLocking & row, AuthenticationParameter & authent )
{
   M_WTry()
   {
      m_device->getFWDownload( row, authent );
   }
   M_WCatch();

   if( !M_OK() )
   {
      std::wcerr << TXT("GetPortState_FWDownload failed, ") << tcgErrorMsg( M_CODE() ) << std::endl;
      return false;
   }

   return true;
} // getFWDownload

//=======================================================================================
bool CTcgDrive::setFWDownload( IOTable_PortLocking & row, AuthenticationParameter & authent )
{
   if( row.isEmpty() )
   {
      std::wcerr << TXT("No parameters given to set the port state.")  << std::endl;
      return false;
   }

   M_WTry()
   {
      m_device->setFWDownload( row, authent );
   }
   M_WCatch();

   if( !M_OK() )
   {
      std::wcerr << TXT("SetPortState_FWDownload failed, ") << tcgErrorMsg( M_CODE() ) << std::endl;
      return false;
   }

   return true;
} // setFWDownload

//=======================================================================================
bool CTcgDrive::firmwareDownload( char * fileName )
{
   FILE *pFile;

   // Insure the file exists and can be opened for reading.
#if defined(_WIN32) // nvn20110727
   if ( fopen_s( &pFile, fileName, "rb" ) != 0 )
#else
   pFile = fopen( fileName, "rb" );
   if ( !pFile )
#endif
   {
      std::wcerr << TXT("Cannot open file \"") << fileName << TXT("\".") << std::endl;
      return false;
   }

   fseek( pFile, 0, SEEK_END );
#if defined(_WIN32) // nvn20110728 - unused variable
   tUINT64 size = ftell(pFile);
#endif

   // To do additional verification of file contents before loading the
   // microcode, add it here before closing the file.

   fclose( pFile );

   M_WTry()
   {
      // For now, the only download Microcode functionality supported is for
      // SATA-mode drives. Verify that we are indeed an ATA-mode drive that
      // understands ATA-8 commands.

      _tstring attrValue;
      m_session->GetAttribute( TXT("Transport" ), attrValue );

      if( attrValue != TXT("ATA") )
      {
         // Can't update firmware on this drive!
         std::wcerr << TXT("Drive does not support ATA-8 Download Microcode Command.") << std::endl;
         throw eGenericNotImplemented;
      }

      // DTA Pathnames should be tstring, so convert fileName.
      wchar_t wPathName[512];
      size_t numch;

#if defined(_WIN32) // nvn20110727
      mbstowcs_s( &numch, wPathName, 512, fileName, strlen(fileName)+1 );
      _tstring pathName = wPathName;
#else
      numch = mbstowcs( wPathName, fileName, 512 );
      _tstring pathName = fileName;
#endif

      // Firmware download can take longer than the default timeout, so
      // to avoid a false timeout error, set the limit higher before doing
      // the Firmware update.
      m_session->SetAttribute( TXT("Timeout"), TXT("90") );

      // If we can create an ATA session, perform the microcode update operation.
      ata::CAta* pATA = dynamic_cast<ata::CAta*>( m_session );
      if ( pATA )
      {
         pATA->DownloadMicrocode( pathName );

         // When firmware update is complete, the drive waits
         // to be power-cycled. The drive, however, is waiting
         // for the command to "complete", and just times out
         // waiting for completion that will never happen.
      }
   }
   M_WCatch();

   if( !M_OK() )
   {
      std::wcerr << TXT("Error performing downloadFirmware, ") << tcgErrorMsg( M_CODE() ) << std::endl;
      return false;
   }

   return true;

} // downloadFirmware

//=======================================================================================
bool CTcgDrive::ataSecuritySetPasswordUser( dta::tBytes &newPassword, bool masterPwdCapabilityHigh )
{
   M_WTry()
   {
      _tstring attrValue;
      m_session->GetAttribute( TXT("Transport" ), attrValue );

      if( attrValue == TXT("ATA") )
      {
         ata::CAta* pATA = dynamic_cast<ata::CAta*>( m_session );
         if ( pATA )
         {
            pATA->SecuritySetPasswordUser(newPassword, (masterPwdCapabilityHigh ? ata::evHigh : ata::evMaximum));
         }
         else
         {
            std::wcerr << TXT("Error getting ATA device handle.") << std::endl;
            return false;
         }
      }
      else
      {
         std::wcerr << TXT("ATA Security commands do not work with non-ATA devices.") << std::endl;
         return false;
      }
   }
   M_WCatch();

   if( !M_OK() )
   {
      std::wcerr << TXT("ATA Security Set User Password failed, ") << tcgErrorMsg( M_CODE() ) << std::endl;
      return false;
   }

   return true;
} // ataSecuritySetPasswordUser

//=======================================================================================
bool CTcgDrive::ataSecuritySetPasswordMaster( dta::tBytes &newPassword, tUINT16 masterPwdIdentifier )
{
   M_WTry()
   {
      _tstring attrValue;
      m_session->GetAttribute( TXT("Transport" ), attrValue );

      if( attrValue == TXT("ATA") )
      {
         ata::CAta* pATA = dynamic_cast<ata::CAta*>( m_session );
         if ( pATA )
         {
            pATA->SecuritySetPasswordMaster(newPassword, masterPwdIdentifier);
         }
         else
         {
            std::wcerr << TXT("Error getting ATA device handle.") << std::endl;
            return false;
         }
      }
      else
      {
         std::wcerr << TXT("ATA Security commands do not work with non-ATA devices.") << std::endl;
         return false;
      }
   }
   M_WCatch();

   if( !M_OK() )
   {
      std::wcerr << TXT("ATA Security Set Master Password failed, ") << tcgErrorMsg( M_CODE() ) << std::endl;
      return false;
   }

   return true;
} // ataSecuritySetPasswordMaster

//=======================================================================================
bool CTcgDrive::ataSecurityUnlock( dta::tBytes &password, bool userPassword )
{
   M_WTry()
   {
      _tstring attrValue;
      m_session->GetAttribute( TXT("Transport" ), attrValue );

      if( attrValue == TXT("ATA") )
      {
         ata::CAta* pATA = dynamic_cast<ata::CAta*>( m_session );
         if ( pATA )
         {
            pATA->SecurityUnlock(password, (userPassword ? ata::evUserPassword : ata::evMasterPassword));
         }
         else
         {
            std::wcerr << TXT("Error getting ATA device handle.") << std::endl;
            return false;
         }
      }
      else
      {
         std::wcerr << TXT("ATA Security commands do not work with non-ATA devices.") << std::endl;
         return false;
      }
   }
   M_WCatch();

   if( !M_OK() )
   {
      std::wcerr << TXT("ATA Security Unlock failed, ") << tcgErrorMsg( M_CODE() ) << std::endl;
      return false;
   }

   return true;
} // ataSecurityUnlock

//=======================================================================================
bool CTcgDrive::ataSecurityFreezeLock()
{
   M_WTry()
   {
      _tstring attrValue;
      m_session->GetAttribute( TXT("Transport" ), attrValue );

      if( attrValue == TXT("ATA") )
      {
         ata::CAta* pATA = dynamic_cast<ata::CAta*>( m_session );
         if ( pATA )
         {
            pATA->SecurityFreezeLock();
         }
         else
         {
            std::wcerr << TXT("Error getting ATA device handle.") << std::endl;
            return false;
         }
      }
      else
      {
         std::wcerr << TXT("ATA Security commands do not work with non-ATA devices.") << std::endl;
         return false;
      }
   }
   M_WCatch();

   if( !M_OK() )
   {
      std::wcerr << TXT("ATA Security Freeze Lock failed, ") << tcgErrorMsg( M_CODE() ) << std::endl;
      return false;
   }

   return true;
} // ataSecurityFreezeLock

//=======================================================================================
bool CTcgDrive::ataSecurityDisablePassword( dta::tBytes &password, bool userPassword )
{
   M_WTry()
   {
      _tstring attrValue;
      m_session->GetAttribute( TXT("Transport" ), attrValue );

      if( attrValue == TXT("ATA") )
      {
         ata::CAta* pATA = dynamic_cast<ata::CAta*>( m_session );
         if ( pATA )
         {
            pATA->SecurityDisablePassword(password, (userPassword ? ata::evUserPassword : ata::evMasterPassword));
         }
         else
         {
            std::wcerr << TXT("Error getting ATA device handle.") << std::endl;
            return false;
         }
      }
      else
      {
         std::wcerr << TXT("ATA Security commands do not work with non-ATA devices.") << std::endl;
         return false;
      }
   }
   M_WCatch();

   if( !M_OK() )
   {
      std::wcerr << TXT("ATA Security Disable Password failed, ") << tcgErrorMsg( M_CODE() ) << std::endl;
      return false;
   }

   return true;
} // ataSecurityDisablePassword

//=======================================================================================
bool CTcgDrive::ataSecurityEraseDevice( dta::tBytes &password, bool userPassword, bool enhancedErase )
{
   M_WTry()
   {
      _tstring attrValue;
      m_session->GetAttribute( TXT("Transport" ), attrValue );

      if( attrValue == TXT("ATA") )
      {
         ata::CAta* pATA = dynamic_cast<ata::CAta*>( m_session );
         if ( pATA )
         {
            pATA->SecurityErasePrepare();
         pATA->SecurityEraseUnit((userPassword ? ata::evUserPassword : ata::evMasterPassword), password, (enhancedErase ? ata::evSecurityEraseModeEnhanced : ata::evSecurityEraseModeNormal));
         }
         else
         {
            std::wcerr << TXT("Error getting ATA device handle.") << std::endl;
            return false;
         }
      }
      else
      {
         std::wcerr << TXT("ATA Security commands do not work with non-ATA devices.") << std::endl;
         return false;
      }
   }
   M_WCatch();

   if( !M_OK() )
   {
      std::wcerr << TXT("ATA Security ErasePrepare/EraseUnit failed, ") << tcgErrorMsg( M_CODE() ) << std::endl;
      return false;
   }

   return true;
} // ataSecurityEraseDevice



//=======================================================================================
bool CTcgDrive::setATAFIPS( dta::tBytes &masterPwd, dta::tBytes &userPwd, bool masterPwdCapabilityHigh )
{
   // 1. Check to be sure security mode is SOM0 (and assume MSID PIN is for all default PINs, especually SID PIN, because it's a "new" SED)
   std::wcout << TXT("\n Step 1 - Check to be sure security mode is SOM0,") << std::endl;
   if( getSOM() != 0 )
   {
      std::wcerr << TXT("Prerequisite condition to transition to FIPS compliance mode is not met - not in SOM0\n") << std::endl;
      return false;
   }

   // 2. Disable "Makers" authority
   std::wcout << TXT(" Step 2 - Disable \"Makers\" authority,") << std::endl;
   AuthenticationParameter authent;
   authent.AuthorityName = "SID";
   if( !enableDisableAuthority( false, "Makers", authent ) )
      return false;

   // 3. Set FW Download Port to “Power Cycle” (LockOnReset)
   std::wcout << TXT(" Step 3 - Set FW Download Port to \"Power Cycle\",") << std::endl;
   IOTable_PortLocking portState;
   portState.LockOnReset_length = 1;
   portState.LockOnReset[0] = 0;  // Lock-on-Power-Reset
   authent.AuthorityName = "SID";
   if( !setFWDownload( portState, authent ) )
      return false;

   // 4. Set ATA User Password
   std::wcout << TXT(" Step 4 - Set ATA User Password to \"");
   for(int ii=0; ii<(int)userPwd.size(); ii++)
      std::wcout << wchar_t (userPwd[ii]);
   std::wcout << TXT("\",") << std::endl;
   if( !ataSecuritySetPasswordUser( userPwd, masterPwdCapabilityHigh ) )
      return false;

   // 5. Set ATA Master Password
   std::wcout << TXT(" Step 5 - Set ATA Master Password to \"");
   for(int ii=0; ii<(int)masterPwd.size(); ii++)
      std::wcout << masterPwd[ii];
   std::wcout << TXT("\",") << std::endl;
   if( !ataSecuritySetPasswordMaster( masterPwd, 0 ) )
      return false;

   // 6. Check/confirm security mode is in SOM1
   std::wcout << TXT(" Step 6 - Check and confirm security mode is in SOM1.") << std::endl;
   if( getSOM() != 1 )
   {
      std::wcerr << TXT("Error: Final security mode is not SOM1.\n") << std::endl;
      return false;
   }

   return true;
} // setATAFIPS

//=======================================================================================
bool CTcgDrive::setFIPSPolicy( dta::tBytes &sidPIN, dta::tBytes &admin1PIN )
{
   bool result = true;  // Assume PASS, but any failure will change to false.

   // Here we begin applying typical FIPS Security Compliance Policy document requirements
   std::wcout << TXT("\n  Step 1: FIPS Security Policy Compliance typically requires the following:\n");

   // *** Check/confirm Seagate SED is in USE mode (0x80)

   // Since this tool might be run on non-Seagate drives, make sure we only test this on ours.
   if( isSeagateDrive() )
   {
      std::wcout << TXT("  - the Seagate LifeCycle State must be USE (0x80).");

      if( 0x80 == m_device->getLifeCycleState( true ) )
      {
         std::wcout << TXT(" PASS") << std::endl; 
      }
      else
      {
         std::wcout << TXT(" FAIL") << std::endl
                    << TXT("      * LifeCycle State (") << hex << m_device->getLifeCycleState( false )
                    << TXT(") doesn't comply.") << std::endl;
         result = false;
      }
   }

   // *** Device must be a FIPS-capable drive.
   
   std::wcout << TXT("  - the device must be a FIPS-Capable SED.");

   // FIPS variables reported by or obtained from SED
   char Revision;
   char OverallLevel;
   std::string HardwareVer;
   std::string FirmwareVer;
   std::string ModuleName;

   // For newer SEDs, query the Security Compliance descriptor. For older Seagate ATA FIPS 
   // drives (Julius), query the Identify_Device word 159 bit 0 for FIPS hinting. Returns
   // false if definitely not a FIPS-capable drive.

   result &= showFIPSCapable( Revision, OverallLevel, HardwareVer, FirmwareVer, ModuleName );
   
   // *** Device must have a NIST FIPS certificate matching HW, FW and Model 

   std::wcout << TXT("  - the device must have appropriate NIST Certificate for:") << std::endl;   

   std::wcout << TXT("      * Hardware Version = ") << HardwareVer.c_str() << std::endl;
   std::wcout << TXT("      * Firmware Version = ") << FirmwareVer.c_str() << std::endl;
   std::wcout << TXT("      * Module Name = \""); 
   for( tUINT16 i = 0; i < ModuleName.size(); i++ )
   {
      if( i % 52 == 51 ) std::wcout << std::endl << TXT("                       ");
      std::wcout << *(char*) &ModuleName[i];
   }
   std::wcout << TXT("\"") << std::endl;

      
   // *** Device must be in security mode SOM0 (and assume MSID is PIN for all default PINs,
   //     especially SID PIN and Admin1 PIN, because it's a "new" or freshly-reverted SED)

   std::wcout << TXT("  - Device must be in Security Operating Mode SOM0 (new or reverted).");
   if( getSOM() == 0 )
   {
      std::wcout << TXT(" PASS") << std::endl;
   }
   else
   {
      std::wcout << TXT(" FAIL") << std::endl 
                 << TXT("     * Device is in SOM") << getSOM() << TXT(". SOM0 is a prerequisite mode.\n") << std::endl;
      result = false;
   }

   // If requirements aren't met, then stop.
   if( result == false )
      return false;

   // *** Step 2: Activate Locking_SP using default MSID

   std::wcout << TXT("  Step 2: Activate Locking_SP using MSID");
   AuthenticationParameter authent;
   if( activateSP( "Locking", authent ) )
   {
      std::wcout << TXT(" SUCCESS") << std::endl;
   }
   else
   {
      std::wcout << TXT(" FAIL") << std::endl
                 << TXT("   *** Could not activate Locking_SP.") << std::endl;
      return false;
   }

   // Step 3: Set SID PIN to supplied secret value

   IOTableC_PIN pin(false);
   pin.PIN_length = (tINT8) sidPIN.size();
   pin.PIN_length = (( pin.PIN_length < sizeof(pin.PIN) ) ? pin.PIN_length : (sizeof(pin.PIN) -1) );
   memcpy( pin.PIN, &sidPIN[0], pin.PIN_length );
   pin.PIN[pin.PIN_length] = 0;
   authent.AuthorityName = NULL; // "SID"
   std::wcout << TXT("  Step 3: Set SID PIN to \"") << (char*)pin.PIN << TXT("\",") ;
   if( setCredential( "SID", pin, authent ) )
   {
      std::wcout << TXT(" SUCCESS") << std::endl;
   }
   else
   {
      std::wcout << TXT(" FAIL") << std::endl
                 << TXT(" *** Failed to set SID credential to new value.") << std::endl;
      return false;
   }
   
   // Step 4: Set Admin1 PIN to supplied secret value

   pin.PIN_length = (tINT8) admin1PIN.size();
   pin.PIN_length = (( pin.PIN_length < sizeof(pin.PIN) ) ? pin.PIN_length : (sizeof(pin.PIN) -1) );
   memcpy( pin.PIN, &admin1PIN[0], pin.PIN_length );
   pin.PIN[pin.PIN_length] = 0;
   authent.AuthorityName = NULL; // "Admin1"
   std::wcout << TXT("  Step 4: Set Admin1 PIN to \"") << (char*)pin.PIN << TXT("\"");
   
   if( setCredential( "Admin1", pin, authent ) )
   {
      std::wcout << TXT(" SUCCESS") << std::endl;
   }
   else
   {
      std::wcout << TXT(" FAIL") << std::endl
                 << TXT(" *** Failed to set Admin1 credential to new value.") << std::endl;
      return false;
   }

   // Step 5: Lock Global Range and set to LockOnRerset to “Power Cycle”

   // TODO: see if there are other active ranges, and if so, fail this step.

   std::wcout << TXT("  Step 5: Lock Global Range for Read/Write, LOR to PowerCycle.") ;
   IOTableLocking row(false);
   row.ReadLockEnabled = true;
   row.ReadLockEnabled_isValid = true;
   row.WriteLockEnabled = true;
   row.WriteLockEnabled_isValid = true;
   row.ReadLocked = true;
   row.ReadLocked_isValid = true;
   row.WriteLocked = true;
   row.WriteLocked_isValid = true;
   row.LockOnReset_length = 1;
   row.LockOnReset[0] = 0;  // Lock-on-Power-Reset

   authent.AuthorityName = NULL; // "Admin1"
   authent.Pin = &admin1PIN[0];
   authent.PinLength = (tUINT8) admin1PIN.size();
   if( setLockingRange( 0, row, authent ) )
   {
      std::wcout << TXT(" SUCCESS") << std::endl;
   }
   else
   {
      std::wcout << TXT(" FAIL") << std::endl
                 << TXT(" *** Could not lock Global Range.") << std::endl;
      return false;
   }
   
   // Step 6: Disable "Makers" authority
   std::wcout << TXT("  Step 6: Disable \"Makers\" authority,");
   authent.AuthorityName = "SID";
   authent.Pin = &sidPIN[0];
   authent.PinLength = (tUINT8) sidPIN.size();
   
   if( enableDisableAuthority( false, "Makers", authent ) )
   {
      std::wcout << TXT(" SUCCESS") << std::endl;
   }
   else
   {
      std::wcout << TXT(" FAIL") << std::endl
                 << TXT(" *** Failed to disable Makers authority.") << std::endl;
      return false;
   }

   // Step 7: Set FW Download Port to “Power Cycle” (LockOnReset)

   std::wcout << TXT("  Step 7: Disable FW Download Port, set LOR to \"Power Cycle\".");
   IOTable_PortLocking portState;
   portState.LockOnReset_length = 1;
   portState.LockOnReset[0] = 0;  // Lock-on-Power-Reset
   authent.AuthorityName = "SID";
   authent.Pin = &sidPIN[0];
   authent.PinLength = (tUINT8) sidPIN.size();
   if( setFWDownload( portState, authent ) )
   {
      std::wcout << TXT(" SUCCESS") << std::endl;
   }
   else
   {
      std::wcout << TXT(" FAIL") << std::endl << TXT(" *** Failed to disable Firmware Download Port.") << std::endl;
      return false;
   }


   // Step 8: Check/confirm security mode is in SOM2

   std::wcout << TXT("  Step 8: Check and confirm security mode is in SOM2.");
   if( getSOM() == 2 )
   {
      std::wcout << TXT(" SUCCESS") << std::endl;
   }
   else
   {
      std::wcout << TXT(" FAIL") << std::endl
                 << TXT(" Error: Final security mode is not SOM2.\n") << std::endl;
      return false;
   }

   return true;
} // setFIPSPolicy

//=======================================================================================
bool CTcgDrive::getFIPSPolicy( void )
{
   bool result = true;  // Assume PASS, but any failure will change to false.

   // Here we test the device state against typical FIPS Security Compliance Policy document requirements
   std::wcout << TXT("\n  FIPS Security Policy Compliance typically requires at least the following:\n");

   // *** Check/confirm Seagate SED is in USE mode (0x80)

   // Since this tool might encounter non-Seagate drives, make sure we only test this on ours.
   if( isSeagateDrive() )
   {
      std::wcout << TXT("  - the Seagate LifeCycle State must be USE (0x80).");

      if( 0x80 == m_device->getLifeCycleState( true ) )
      {
         std::wcout << TXT(" PASS") << std::endl; 
      }
      else
      {
         std::wcout << TXT(" FAIL") << std::endl;
         std::wcerr << TXT("      * LifeCycle State (") << hex << m_device->getLifeCycleState( false )
                    << TXT(") doesn't comply.") << std::endl;
         result = false;
      }
   }

   // *** Device must be a FIPS-capable drive.
   
   std::wcout << TXT("  - the device must be a FIPS-Capable SED.");

   // FIPS variables reported by or obtained from SED
   char Revision;
   char OverallLevel;
   std::string HardwareVer;
   std::string FirmwareVer;
   std::string ModuleName;

   // For newer SEDs, query the Security Compliance descriptor. For older Seagate ATA FIPS 
   // drives (Julius), query the Identify_Device word 159 bit 0 for FIPS hinting. Returns
   // false if definitely not a FIPS-capable drive.

   result &= showFIPSCapable( Revision, OverallLevel, HardwareVer, FirmwareVer, ModuleName );
   
   // *** Device must have a NIST FIPS certificate matching HW, FW and Model 

   std::wcout << TXT("  - the device must have appropriate NIST Certificate for:") << std::endl;   

   std::wcout << TXT("      * Hardware Version = ") << HardwareVer.c_str() << std::endl;
   std::wcout << TXT("      * Firmware Version = ") << FirmwareVer.c_str() << std::endl;
   std::wcout << TXT("      * Module Name = \""); 
   for( tUINT16 i = 0; i < ModuleName.size(); i++ )
   {
      if( i % 52 == 51 )
         std::wcout << std::endl << TXT("                       ");
      std::wcout << *(char*) &ModuleName[i];
   }
   std::wcout << TXT("\"") << std::endl;

   // *** Check to insure security mode is SOM2

   std::wcout << TXT("  - the device must be in SOM2 state.");
   {
      M_WTry()
      {
         if( getSOM() == 2 )
         {
            std::wcout << TXT(" PASS ") << std::endl;
         }
         else
         {
            std::wcout << TXT(" FAIL (Device is in SOM") << getSOM() << TXT(" state).") << std::endl;
            result = false;
         }
      }
      M_WCatch();

      if( ! M_OK() )
      {
         // Yikes - Could not get SOM - some type of problem in channel.
//         std::wcout << TXT(" FAIL - ERROR: ") << m_device->M_MSG() << std::endl;
         m_device->protocolStackReset();
         result = false;
      }
   }

   // *** Locking_SP is Activated (Manufactured)

   std::wcout << TXT("  - the Locking_SP must be Activated (Manufactured).");
   if( isSPManufactured( "Locking" ) )
   {
      std::wcout << TXT(" PASS ") << std::endl;
   }
   else
   {
      std::wcout << TXT(" FAIL, not Activated.") << std::endl;
      result = false;
   }

   // *** Credentials must be secret (i.e. SID not equal to MSID, etc.)
   
   std::wcout << TXT("  - all enabled Credentials/PINS must be secret.") << std::endl;
   
   AuthenticationParameter authent;
   dta::tBytes mSID;

   // Read the mSID value, which is the Default AdminSP.SID and LockingSP.Admin1
   m_device->getMSID( mSID );

   { // Enclose WTry/WCatch within a code block
      M_WTry()
      {
         // See if we can use mSID to authenticate as SID
         std::wcout << TXT("      * mSID should not Authenticate AdminSP: ");

         authent.AuthorityName = "SID";
         // Attempt Session Authentication as SID authority using mSID.
         if( m_device->isDeviceEnterpriseSSC() )
         {
            m_device->_startSession( UID_SP_ADMIN );
            m_device->_authenticate( authent );
            m_device->_closeSession();
         }
         else // Opal/Marble
         {
            m_device->_startSession( UID_SP_ADMIN, authent );
            m_device->_closeSession();
         }
      }
      M_WCatch();

      if( M_OK() )
      {
         // Yikes - looks like SID isn't a secret value
         std::wcout << TXT(" FAIL - SID still same as mSID") << std::endl;
         result = false;
      }
      else if( M_CODE().Info.Category == 0x05 && M_CODE().Info.Detail == TS_NOT_AUTHORIZED )    // category 5 is eDtaCategoryProtocol 
      {
         // Expect TCG AUTHENTICATE failure
//         std::wcout << TXT(" PASS: ") << m_device->M_MSG() << std::endl;
      }
      else
      {
         // Unexpected failure
//         std::wcout << TXT(" FAIL: ") << m_device->M_MSG() << std::endl;
         m_device->protocolStackReset();
         result = false;
      }
   } // Enclose WTry/WCatch within a code block

   { // Enclose WTry/WCatch within a code block
      M_WTry()
      {
         // See if we can use mSID to authenticate as Admin1
         std::wcout << TXT("      * mSID should not Authenticate LockingSP: ");

         authent.AuthorityName = "Admin1";
         // Attempt Session Authentication as SID authority using mSID.
         if( m_device->isDeviceEnterpriseSSC() )
         {
            m_device->_startSession( UID_SP_LOCKING_E );
            m_device->_authenticate( authent );
            m_device->_closeSession();
         }
         else // Opal/Marble
         {
            m_device->_startSession( UID_SP_LOCKING_OM, authent );
            m_device->_closeSession();
         }
      }
      M_WCatch();

      if( M_OK() )
      {
         // Yikes - looks like Admin1 isn't a secret value
         std::wcout << TXT(" FAIL - Admin1 still same as mSID.") << std::endl;
         result = false;
      }
      else if( M_CODE().Info.Category == 0x05 && M_CODE().Info.Detail == TS_NOT_AUTHORIZED )    // category 5 is eDtaCategoryProtocol 
      {
         // Expect TCG AUTHENTICATE failure
         std::wcout << TXT(" PASS: ") << m_device->M_MSG() << std::endl;
      }
      else
      {
         // Unexpected failure
         std::wcout << TXT(" FAIL: ") << m_device->M_MSG() << std::endl;
         result = false;
      }
   } // Enclose WTry/WCatch within a code block

   // *** Global Range is locked and set to “Power Cycle” (LockOnReset)

   std::wcout << TXT("  - Global Range must be Read/Write Locked with POR enabled.");
   {
      TCGRANGE_INFO info;
      authent.AuthorityName = NULL; // Default uses mSID as "Admin1" PIN

      M_WTry()
      {
         getRangeInfo( 0, info, authent );
      }
      M_WCatch();

      if( M_OK() )
      {
         if( !info.lockingRange.ReadLockEnabled_isValid || !info.lockingRange.WriteLockEnabled_isValid ||
             !info.lockingRange.ReadLocked_isValid || !info.lockingRange.WriteLocked_isValid )
         {
            // Unable to determine state of lock info
            std::wcout << TXT(" INDETERMINATE") << std::endl
                       << TXT("      * Cannot access range info - needs Admin1 authentication ") << std::endl;
            result = false;
         }
         else if ( !info.lockingRange.ReadLockEnabled || !info.lockingRange.WriteLockEnabled ||
                   !info.lockingRange.ReadLocked || !info.lockingRange.WriteLocked )
         {
            // Range is not locked for Read & Write
            std::wcout << TXT(" FAIL - Not R/W Locked.") << std::endl;
            result = false;
         }
         else if( info.lockingRange.LockOnReset_length == 0 || info.lockingRange.LockOnReset[0] != 0 )
         {
            // Range LockOnReset is not correctly set
            std::wcout << TXT(" FAIL - LockOnReset not set.") << std::endl;
            result = false;
         }
      } // M_OK()
      else
      {
         // Unexpected failure
         std::wcout << TXT(" FAILURE: ") << m_device->M_MSG() << std::endl;
         result = false;
      }
   } // block for try/catch

   // *** "Makers" authority must be disabled

   std::wcout << TXT("  - \"Makers\" authority must be disabled. INDETERMINATE") << std::endl << TXT("      ");
   authent.AuthorityName = "SID";

   // TODO: instead of showing all authorities, just show Makers.
   showAuthorities( "SID", authent );

   // *** FW Download Port must be disabled with “Power Cycle” (LockOnReset)

   std::wcout << TXT("  - FW Download Port must be disabled with LOR.");
   {
      IOTable_PortLocking row(false);

      M_WTry()
      {
         m_device->getFWDownload( row, authent );
      }
      M_WCatch();

      if( M_OK() )
      {
         if( (row.PortLocked_isValid && row.PortLocked) &&
            (row.LockOnReset_length > 0 && row.LockOnReset[0] == 1) )
         {
            std::wcout << TXT(" PASS ") << std::endl;
         }
         else
         {
            std::wcout << TXT(" FAIL - Port is not Disabled.") << std::endl;
            result = false;
         }
      }
      else
      {
         std::wcout << TXT(" ERROR: ") << m_device->M_MSG() << std::endl;
         result = false;
      }
   }

   return result;
} // getFIPSPolicy



//=======================================================================================
bool interpretResetType( tINT8 reset_length, tUINT8 *pReset )
{
   bool result = true;

   switch( reset_length )
   {
   case -1:
      std::wcout << TXT("   -   ");  // Not Applicable
      return false;
   case 0:
      std::wcout << TXT(" [ ]   ");  // 3 whitespace after empty list
      return true;             
   case 1:
      std::wcout << TXT(" ");    // add 1 whitespace before bracket
   default:
      std::wcout << TXT("[");    // add no whitespace before bracket
   }

   // Walk thru the list
   for( int ii=0; ii<reset_length; ii++ )
   {
      if( ii > 0 )
         std::wcout << TXT(",");

      if( 0 == *(pReset+ii) )
         std::wcout << TXT("P");    // Power-Reset
      else if( 1 == *(pReset+ii) )
         std::wcout << TXT("H");    // Hardware
      else if( 2 == *(pReset+ii) )
         std::wcout << TXT("G");    // HotPlug
      else if( 3 == *(pReset+ii) )
         std::wcout << TXT("T");    // TPerReset (programatic)
      else
         std::wcout << hex << *(pReset+ii) << dec << TXT("?");

      if( ii > 3 )   // No more than 4 entries currently possible
         break;
   }

   std::wcout << TXT("]");
    
   if( 3 == reset_length )
      std::wcout << TXT(" ");      // 1 Trailing space
   if( 2 == reset_length )
      std::wcout << TXT("  ");      // 2 Trailing space
   else if( 1 == reset_length )
      std::wcout << TXT("   ");     // 3 trailing spaces

   return result;
} // interpretResetType


#if defined(_WIN32) // nvn20110901
#define  ACCESS_READ     1   
#define  ACCESS_WRITE    2
#endif

bool IsAdmin()
{
#if defined(_WIN32) // nvn20110901
   HANDLE  hToken;
   DWORD   dwStatus;
   DWORD   dwAccessMask;
   DWORD   dwAccessDesired;
   DWORD   dwACLSize;
   DWORD   dwStructureSize = sizeof(PRIVILEGE_SET);
   PACL    pACL = NULL;
   PSID    psidAdmin = NULL;
   BOOL    bReturn = FALSE;
    
   PRIVILEGE_SET   ps;
   GENERIC_MAPPING   GenericMapping;

   PSECURITY_DESCRIPTOR       psdAdmin = NULL;
   SID_IDENTIFIER_AUTHORITY   SystemSidAuthority = SECURITY_NT_AUTHORITY;

   __try{
      // AccessCheck() requires an impersonation token.
      ImpersonateSelf(SecurityImpersonation);

      if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, FALSE, &hToken))
      {
         if (::GetLastError()   !=   ERROR_NO_TOKEN)
            __leave;

         // If the thread does not have an access token, we'll
         // examine the access token associated with the process.
         if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
            __leave;
      }
    
      if (!AllocateAndInitializeSid(&SystemSidAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0, &psidAdmin))
         __leave;

      psdAdmin = LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH);
      if (psdAdmin == NULL)
         __leave;   

      if (!InitializeSecurityDescriptor(psdAdmin, SECURITY_DESCRIPTOR_REVISION))
         __leave;   

      // Compute size needed for the ACL.
      dwACLSize = sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE) + GetLengthSid(psidAdmin) - sizeof(DWORD);

      // Allocate memory for ACL.
      pACL = (PACL)LocalAlloc(LPTR, dwACLSize);
      if (pACL == NULL)
         __leave;
    
      // Initialize the new ACL.
      if (!InitializeAcl(pACL, dwACLSize, ACL_REVISION2))
         __leave;

      dwAccessMask = ACCESS_READ | ACCESS_WRITE;

      // Add the access-allowed ACE to the DACL.
      if (!AddAccessAllowedAce(pACL, ACL_REVISION2, dwAccessMask, psidAdmin))
         __leave;   
    
      // Set our DACL to the SD.
      if (!SetSecurityDescriptorDacl(psdAdmin, TRUE, pACL, FALSE))
         __leave;   
    
      // AccessCheck is sensitive about what is in the SD; set the group and owner.
      SetSecurityDescriptorGroup(psdAdmin, psidAdmin, FALSE);
      SetSecurityDescriptorOwner(psdAdmin, psidAdmin, FALSE);

      if (!IsValidSecurityDescriptor(psdAdmin))
         __leave;

      dwAccessDesired = ACCESS_READ;

      // Initialize GenericMapping structure even though we won't be using generic rights.
      GenericMapping.GenericRead = ACCESS_READ;
      GenericMapping.GenericWrite = ACCESS_WRITE;
      GenericMapping.GenericExecute = 0;
      GenericMapping.GenericAll = ACCESS_READ | ACCESS_WRITE;

      if (!AccessCheck(psdAdmin, hToken, dwAccessDesired, &GenericMapping, &ps, &dwStructureSize, &dwStatus, &bReturn)) {
         std::wcout << TXT("AccessCheck() failed with error ") << ::GetLastError() << std::endl;
         __leave;
      }
      
      RevertToSelf();

   }
   __finally {
      // Cleanup
      if (pACL) LocalFree(pACL);
      if (psdAdmin) LocalFree(psdAdmin);
      if (psidAdmin) FreeSid(psidAdmin);
   }   
   return (bReturn == TRUE);
#else
   bool  bReturn = true; // nvn20110901
   if (geteuid() != 0)
   {
      bReturn = false;
   }
   return bReturn;
#endif
}
