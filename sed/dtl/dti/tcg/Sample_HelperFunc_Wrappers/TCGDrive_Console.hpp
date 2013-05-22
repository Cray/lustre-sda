//=================================================================================================
//  TCGDrive.hpp
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

#ifndef _TCGDRIVE_HPP
#define _TCGDRIVE_HPP
//#define SED_INIT 0x00000000
//#define SED_GET_PASSWORD_FROM_AD 0x00000001
//#define SED_UNLOCK 0x00000002
//#define SED_LR 0x00000003
//#define SED_END 0x00000004

#if defined(_WIN32) // nvn20110726
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <conio.h>
#include <stdio.h>
#include <winioctl.h>
#include <Mmsystem.h>
#include <time.h>
#include <sys/timeb.h>
#include <tchar.h>
#include <iomanip>
#include <iostream>

#include "dtl/dta/ata.hpp"
#include "dtl/dta/scsi.hpp"

#include "TCG/TCGInterface.hpp"
#include "TCG/TokenProcessor.hpp"
#else
#include <iostream>
#include "dta/Ata.hpp"
#include "dta/Scsi.hpp"

#include "TCG/TCGInterface.hpp"
#include "TCG/TokenProcessor.hpp"

#include <stdio.h>
#include <time.h>
#include <sys/timeb.h>
#include <iomanip>

#endif


using namespace std;
using namespace dta;
using namespace dti;


/// Simple macro to save off current throw or return behavior and enter a try block. Used once within a block/routine.
#define M_WTry()                                                                      \
   dta::DTA_ERROR __result;                                                           \
   __result.Error = 0;                                                                \
   bool __throwOnError = m_session->SetThrowOnError(true);                            \
   try { 

#define M_WCatch()   }                                                                \
   catch( const dta::DTA_ERROR & err )                                                \
   {                                                                                  \
      __result = err;                                                                 \
   }                                                                                  \
   catch( const TCG_STATUS status )                                                   \
   {                                                                                  \
      __result = dta::Error(static_cast<dta::eDtaProtocolError>( status ));           \
   }                                                                                  \
   catch(...)                                                                         \
   {                                                                                  \
   }                                                                                  \
   m_session->SetThrowOnError(__throwOnError); 

#define M_OK() ( 0 == __result.Error )
#define M_CODE() ( __result )
#define M_MSG() dtlErrorToString( __result )

#define M_CLEANUPSESSION()    { try { m_device->_closeSession(); } catch(...) {} }


//=======================================================================================
// Function Declarations
//=======================================================================================
bool interpretResetType( tINT8 reset_length, tUINT8 *pReset );
bool IsAdmin(); // nvn20110822

//=======================================================================================
// struct/class definitions
//=======================================================================================

typedef struct _TCGRANGE_INFO
{
   // from Locking table
   IOTableLocking lockingRange;

   // from Authority table
   bool    rangeEnabled;
   bool    rangeEnabled_isValid;

   // from K_AES_128/256
   tUINT8  encryptionMode;
   bool    encryptionMode_isValid;

} TCGRANGE_INFO, *PTCGRANGE_INFO;


class CTcgDrive
{
public:

   const static int temp = 1001;
   CTcgDrive( const _tstring protocolLogFileName = TXT("TCGProtocolLog.xml"),
              const _tstring deviceEnumerationLogFileName = TXT("DeviceEnumerationLog.txt"),
              const _tstring &driveSerialNumber =TXT("") );
   ~CTcgDrive();

   bool tcgDriveExist() { return NULL != m_device; }

   bool showBasicDriveInfo( bool verbose =false, bool seagateInfo =false );
   bool protocol0Discovery( bool verbose =false, bool seagateInfo =false );
   bool supportsSeaCOSprotocol( void ) { return m_bSeaCOSprotocol; };
   bool supportsTCGprotocol( void ) { return m_bTCGprotocol; };
   bool supportsIEEE1667protocol( void ) { return m_bIEEEprotocol; };
   bool performTCGDiscovery( bool verbose =false, bool seagateInfo =false );

   bool synchronizeHostTPerProperties() { return m_device->synchronizeHostTPerProperties(); }
   bool isCoreSpec1() { return m_device->isDeviceTCGCoreVersion1(); }
   bool isEnterpriseSSC() { return m_device->isDeviceEnterpriseSSC(); }
   bool isOpalSSC() { return m_device->isDeviceOpalSSC(); }
   bool isOpalSSCVersion2() { return m_device->isDeviceOpalSSCVersion2(); }
   bool isSingleUserModeSupported() { return m_device->isSingleUserModeSupported(); }
   bool isSPInactive( char *targetSPName );
   bool isSPManufactured( char *targetSPName );
   bool getSPState( char *targetSP, IOTableSP & spState, AuthenticationParameter & authent );
   bool reportSPState( char *targetSP );
   bool securityState( bool variable );
   bool activateSP( char *targetSP, AuthenticationParameter & authent, TCG_BANDNOs *pSingleUserModeList =NULL, int rangeStartLengthPolicy =-1, UINT64VALs *pDataStoreTableSizes =NULL );
   bool reactivateSP( AuthenticationParameter & authent, TCG_BANDNOs *pSingleUserModeList =NULL, int rangeStartLengthPolicy =-1, dta::tBytes *pAdmin1PIN =NULL, UINT64VALs *pDataStoreTableSizes =NULL );
   bool getSingleUserModeInfo( AuthenticationParameter & authent, dta::tBytes & singleUserModeList, int & rangeStartLengthPolicy );
   bool getGeometryAlignment( bool & bRequired, tINT64 & alignment, tINT64 & lowestLBA, int & blockSize );
   bool getMaxBands(  int *pMaxBands =NULL );
   bool isBandNoValid( int bandNo );
   bool getMSID( tUINT8 *mSID );
   bool getLockingInfo( int rangeNo, IOTableLocking & info, AuthenticationParameter & authent, bool toStartSession, bool toCloseSession );
   bool getRangeInfo( int rangeNo, TCGRANGE_INFO & info, AuthenticationParameter & authent, bool toStartSession=true, bool toCloseSession=true );
   bool setLockingRange( int rangeNo, IOTableLocking & lockingRow, AuthenticationParameter & authent, bool toStartSession=true, bool toCloseSession=true );
   bool setCredential( char *target, IOTableC_PIN & pin, AuthenticationParameter & authent );
   bool eraseBand( int startBandNo, int endBandNo, AuthenticationParameter & authent, bool resetACL =true );
   bool enableDisableBand( bool isToEnable, int bandNo, AuthenticationParameter & authent );
   bool readMBR( dta::tBytes & data, AuthenticationParameter & authent, tINT64 startRow =-1, tINT64 endRow =-1, tUINT32 *pDurationMS =NULL );
   bool writeMBR( dta::tBytes & data, AuthenticationParameter & authent, tINT64 startRow, tINT64 endRow, tUINT32 *pDurationMS =NULL );
   bool readMBR( char * fileName, AuthenticationParameter & authent, tINT64 startRow =-1, tINT64 endRow =-1, tUINT32 *pDurationMS =NULL );
   bool writeMBR( char * fileName, AuthenticationParameter & authent, tINT64 startRow, tINT64 endRow, tUINT32 *pDurationMS =NULL );
   bool getMBRControl( IOTableMBRControl & row, AuthenticationParameter & authent );
   bool setMBRControl( IOTableMBRControl & row, AuthenticationParameter & authent );
   bool readDataStore( dta::tBytes & data, AuthenticationParameter & authent, int targetDS =0, tINT64 startRow =-1, tINT64 endRow =-1, tUINT32 *pDurationMS =NULL );
   bool writeDataStore( dta::tBytes & data, AuthenticationParameter & authent, int targetDS, tINT64 startRow, tINT64 endRow, tUINT32 *pDurationMS =NULL );
   bool readDataStore( char * fileName, AuthenticationParameter & authent, int targetDS =0, tINT64 startRow =-1, tINT64 endRow =-1, tUINT32 *pDurationMS =NULL );
   bool writeDataStore( char * fileName, AuthenticationParameter & authent, int targetDS, tINT64 startRow, tINT64 endRow, tUINT32 *pDurationMS =NULL );
   bool showAuthorities( char * securityProvider, AuthenticationParameter & authent );
   bool enableDisableAuthority( bool toEnable, char *targetAuthority, AuthenticationParameter & authent );
   bool setAuthorityAccess( TCG_UID ace, int maxCount, char* targetAuthorities[], AuthenticationParameter & authent );
   bool setAuthorityAccess( char *ace, int sequenceNo, int maxCount, char* targetAuthorities[], AuthenticationParameter & authent );
   bool revertSP( char *target, AuthenticationParameter & authent );
   bool generateRandom( char *target, dta::tBytes & randomData );
   bool protocolStackReset( int comChannel =0, bool syncHostTPerProperties =true );
   bool tperReset( bool syncHostTPerProperties =true );
   bool setTperResetEnable( AuthenticationParameter & authent, bool enable =true );
   bool selectComChannel( int comChannel =0, bool syncHostTPerProperties =true );
   bool setPreferenceToUseDynamicComID( bool useDynamicComID ) { return m_device->setPreferenceToUseDynamicComID( useDynamicComID ); }
   bool readUserLBA( char * fileName, tUINT64 startLBA, tUINT32 lengthLBA );
   bool writeUserLBA( char * fileName, tUINT64 startLBA, tUINT32 lengthLBA );
   bool getUDSPort( IOTable_PortLocking & row, AuthenticationParameter & authent );
   bool setUDSPort( IOTable_PortLocking & row, AuthenticationParameter & authent );
   bool getFWDownload( IOTable_PortLocking & row, AuthenticationParameter & authent );
   bool setFWDownload( IOTable_PortLocking & row, AuthenticationParameter & authent );
   bool firmwareDownload( char * fileName );

   bool isATADevice();
   bool isSeagateDrive();
   bool isRequestedParameterOfDataStoreTablesOK( UINT64VALs *pDataStoreTableSizes );
   void setUseSilo( const bool newUseSilo );
   tUINT8 getSOM() { return m_device->getSOM(); }
   tUINT64 maxLBA() { return m_maxLba; }
   tUINT64 capacityLBA() { return m_maxLba +1; }
   tUINT16 getMaxNumDataStoreTables() { return m_device->getMaxNumberOfDataStoreTables(); }
   bool isDataStoreTableFeatureSupported() { return m_device->isDataStoreTableFeatureSupported(); }
   _tstring getDriveSerialNo() { return m_device->getDriveSerialNo(); }

   // ATA security operations
   bool ataSecuritySetPasswordUser( dta::tBytes &newPassword, bool masterPwdCapabilityHigh =true );
   bool ataSecuritySetPasswordMaster( dta::tBytes &newPassword, tUINT16 masterPwdIdentifier =0x0000 );
   bool ataSecurityUnlock( dta::tBytes &password, bool userPassword =true );
   bool ataSecurityFreezeLock();
   bool ataSecurityDisablePassword( dta::tBytes &password, bool userPassword =true );
   bool ataSecurityEraseDevice( dta::tBytes &password, bool userPassword =true, bool enhancedErase =true );

   // ATA FIPS and TCG FIPS compliance mode
   bool setATAFIPS( dta::tBytes &masterPwd, dta::tBytes &userPwd, bool masterPwdCapabilityHigh =true );
   bool setFIPSPolicy( dta::tBytes &sidPIN, dta::tBytes &admin1PIN );    // jls 20120824
   bool getFIPSPolicy( void );              // jls 20120824
   bool showFIPSCapable( char & Revision, char & OverallLevel, std::string & HardwareVer,   // jls 20120824
                            std::string & , std::string & ModuleName  );
  
protected:
   tUINT64 getNumberRows( TCG_UID targetTable );

   TCG_UID convertToAuthorityUID( char *authority ) { return m_device->mapAuthorityNameToUID( authority ); }
   TCG_UID convertToCredentialUID( char *credential ) { return m_device->mapPinNameToUID( credential ); }


   TCG_UID convertToACEUID( char *ace, int sequenceNo );
#if defined(_WIN32) // nvn20110727
   _tstring tcgErrorMsg( dta::DTA_ERROR status );
#else
   char* tcgErrorMsg( dta::DTA_ERROR status );
#endif
   void printData( dta::tBytes & buffer, int bytesToShow );
   void refreshOS();

   ata::CAta*  m_pATA;
   dta::CScsi* m_pSCSI;
   tUINT32 m_tperSN;
   tUINT64 m_maxLba;
   int m_blockSize;
   int m_numberBands;
   _tstring m_protocolLogFileName;
   _tstring m_driveSerialNumber;

   ITCGInterface * m_device;
   dta::CDriveTrustSession * m_session;

   bool m_bTCGprotocol;
   bool m_bSeaCOSprotocol;
   bool m_bIEEEprotocol;


private:
   CLocalSystem * m_localSystem;

   vector<pair<_tstring, DTIdentifier> > enumerateTrustedDevices( CLocalSystem* localSystem, const _tstring & deviceEnumerationLogFileName );
   DTIdentifier selectDevice( CLocalSystem* localSystem, const _tstring & driveSerialNumber, const _tstring & deviceEnumerationLogFileName );

}; // CTcgDrive

#endif
