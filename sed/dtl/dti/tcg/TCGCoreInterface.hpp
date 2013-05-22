/*! \file TCGCoreInterface.hpp
    \brief Basic API definition for TCG Core Interface.

    This file details the interface classes and functions for writing
    client code that uses the TCG Core security protocol via DTA to access
    DriveTrust devices.  It is a C++ specific interface.  For a 'C' interface,
    include the corresponding .h instead of this file.
    
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

    Copyright © 2009.  Seagate Technology LLC  All Rights Reserved.

    The Software is provided under the Agreement No. 134849 between Seagate
    Technology and Calsoft. All Intellectual Property rights to the Software,
    as between Calsoft and Seagate, will be governed under the terms of the 
    Agreement No. 134849; no other rights to the Software are granted.

*/

#ifndef TCG_CORE_INTERFACE_DOT_HPP
#define TCG_CORE_INTERFACE_DOT_HPP

#if !defined(__cplusplus)
#error C++ compiler required.  Include TCGCoreInterface.h for 'C' compilers.
#endif
// !defined __cplusplus
//=================================
// Include files
//=================================
#include "../dti.hpp"
#include "TCGValues.h"
#include "PacketManager.hpp"
#include "TokenProcessor.hpp"
#include "TCGInterface.hpp"
#ifdef __TCGSILO
#include "../tcgsilo.hpp" // nvn20110719 - case sensitive
#endif
#include <map>

#if defined (_WIN32)
#include <windows.h> // for multimedia timer functions
#pragma warning(disable : 4250)
#elif defined (__DJGPP)
#elif defined (__linux__)
#else
#error "Operating system not defined!"
#endif

namespace dti
{
   //=================================
   // macro definitions
   //=================================
   //#define SWAPWORD( w ) ( ((w) << 8) | (((w) >> 8) & 0x00FF) )
   #define SWAPWORD( w ) (w)

   /// Simple macro to save off current throw or return behavior and enter a try block. Used once within a block/routine.
   #define M_TCGTry()                                                                       \
      TCG_STATUS __result = TS_SUCCESS;                                                     \
      bool __throwOnError = m_session->SetThrowOnError(true);                               \
      try { 


   #define M_TCGThrowError( __bThrow )                                                      \
      if ((__result != TS_SUCCESS) && __throwOnError && (__bThrow))                         \
      {                                                                                     \
         if( TS_DTL_ERROR == __result )                                                     \
            throw getLastError();                                                           \
         else                                                                               \
            throw (TCG_STATUS) __result;                                                    \
      } 


   #define M_TCGCatch( __bThrow, __bReturn )   }                                            \
      catch( const dta::DTA_ERROR & err )                                                   \
      {                                                                                     \
         setLastError(err);                                                                 \
         __result = TS_DTL_ERROR;                                                           \
      }                                                                                     \
      catch( const TCG_STATUS status )                                                      \
      {                                                                                     \
         setLastError(dta::Error(static_cast<dta::eDtaProtocolError>( status )));           \
         __result = status;                                                                 \
      }                                                                                     \
      m_session->SetThrowOnError(__throwOnError);                                           \
      M_TCGThrowError( __bThrow )                                                           \
      if( __bReturn )                                                                       \
         return __result;                                                                   


   #define M_TCGCatchOnly( __bThrow )   }                                                   \
      catch( const dta::DTA_ERROR & err )                                                   \
      {                                                                                     \
         setLastError(err);                                                                 \
         __result = TS_DTL_ERROR;                                                           \
      }                                                                                     \
      catch( const TCG_STATUS status )                                                      \
      {                                                                                     \
         setLastError(dta::Error(static_cast<dta::eDtaProtocolError>( status )));           \
         __result = status;                                                                 \
      }                                                                                     \
      m_session->SetThrowOnError(__throwOnError);                                           \
      M_TCGThrowError( __bThrow )                                                           


   #define M_TCGReturn( __bThrow )                                                          \
      M_TCGThrowError( __bThrow )                                                           \
      return __result; 


   #define M_TCGResult()   ( __result )
   #define M_TCGResultOK() ( TS_SUCCESS == __result )
   #define M_TCGStatusOK( x )   ( TS_SUCCESS == (x) )

   /// Simple macro to save off current throw or return behavior and enter a try block. Multiple parallel use within a block/routine.
   #define M_TCGTryM()   { M_TCGTry() 
   #define M_TCGCatchM( __bThrow, __bReturn )   M_TCGCatch( __bThrow, __bReturn ) } 

   // Immediately stop and return/throw a TCG or DTA error code
   #define M_TCGReturnErr( x )   { M_TCGTry() throw (x); M_TCGCatch( true, true ) }


   //=================================
   // class definitions
   //=================================

   //====================================================================================
   /// \brief Derived class which implementats TCG Core-spec protocol.
   ///
   /// CTcgCoreInterface is a derived class from CDriveTrustInterface which provides the
   /// implementation for the parent class' methods using the TCG Core-spec protocol.
   //====================================================================================
   class CTcgCoreInterface : public ITCGInterface
   {
   public:
      //=================================================================================
      /// \brief Constructor for CTcgCoreInterface.
      ///
      /// The constructor takes a CDriveTrustSession as its class member. Sets up the 
      /// packetManager and tokenProcessor with the session's block size.
      ///
      /// \param newSession   [IN] DriveTrust session object which has been initialized and connected to a DriveTrust device.
      ///
      //=================================================================================
      CTcgCoreInterface( dta::CDriveTrustSession* newSession );

      //=================================================================================
      /// \brief Constructor for CTcgCoreInterface.
      ///
      /// The constructor takes a CDriveTrustSession as its class member. Sets up the 
      /// packetManager and tokenProcessor with the session's block size. Also creates 
      /// a log file.
      ///
      /// \param newSession    [IN] DriveTrust session object which has been initialized and connected to a DriveTrust device.
      /// \param logFileName   [IN] Name of file to log ComPackets.
      ///
      //=================================================================================
      CTcgCoreInterface( dta::CDriveTrustSession* newSession, const _tstring logFileName );

      //=================================================================================
      /// \brief Destructor for CTcgCoreInterface.
      ///
      /// The destructor prepares and closes the XML log file. 
      //=================================================================================
      virtual ~CTcgCoreInterface();


      //=================================================================================
      //
      // TPer/Com methods
      //
      //=================================================================================
      tUINT32 getComID();                              // an SSC specific feature
      etComIDState verifyComID( tUINT32 extComID );    // an SSC specific feature
      TCG_STATUS properties( dta::tBytes & propertyData );  
      TCG_STATUS properties( HostProperties *pHostPropertiesIn, TPerProperties *pTPerProperties, HostProperties *pHostPropertiesOut );

      TCG_STATUS getSupportedProtocolIDs( tUINT16 & numberIDs, dta::tBytes & IDs );
      TCG_STATUS getLevel0DiscoveryData( dta::tBytes & data );
      TCG_STATUS stackReset( tUINT32 extComID );
      TCG_STATUS programmaticTPerReset();
      TCG_STATUS getFipsComplianceInfo( char & Revision, char & OverallLevel, std::string &HardwareVer,
                                         std::string &Version, std::string &ModuleNAme );


      //=================================================================================
      //
      // Session methods (for use around sessions, name begins with '_')
      //
      //=================================================================================
      TCG_STATUS _startSession( 
                       tUINT32 &TPerSN,
                       TCG_UID targetSP,
                       bool writeSession = true,
                       tUINT32 HostSN = 0,
                       tINT64 sessionTimeout = -1,
                       bool syncHostTPerProperties = false );

      TCG_STATUS _startSession( 
                       TCG_UID targetSP,
                       bool writeSession = true,
                       tUINT32 HostSN = 0,
                       tINT64 sessionTimeout = -1,
                       bool syncHostTPerProperties = false );

      TCG_STATUS _startSession( 
                       tUINT32 &TPerSN,
                       TCG_UID targetSP,
                       TCG_UID hostSigningAuthority,
                       tUINT8 *hostChallenge,
                       tUINT16 hostChallengeLength,
                       bool writeSession = true,
                       tUINT32 HostSN = 0,
                       tINT64 sessionTimeout = -1,
                       bool syncHostTPerProperties = false );

      TCG_STATUS _startSession( 
                       TCG_UID targetSP,
                       TCG_UID hostSigningAuthority,
                       tUINT8 *hostChallenge,
                       tUINT16 hostChallengeLength,
                       bool writeSession = true,
                       tUINT32 HostSN = 0,
                       tINT64 sessionTimeout = -1,
                       bool syncHostTPerProperties = false );

      TCG_STATUS _startSession( 
                       tUINT32 &TPerSN,
                       TCG_UID targetSP,
                       AuthenticationParameter & authent,
                       bool writeSession = true,
                       tUINT32 HostSN = 0,
                       tINT64 sessionTimeout = -1,
                       bool syncHostTPerProperties = false );

      TCG_STATUS _startSession( 
                       TCG_UID targetSP,
                       AuthenticationParameter & authent,
                       bool writeSession = true,
                       tUINT32 HostSN = 0,
                       tINT64 sessionTimeout = -1,
                       bool syncHostTPerProperties = false );

      TCG_STATUS _closeSession();

      TCG_STATUS _startTransaction();
      TCG_STATUS _endTransaction( bool commitTransaction = true );


      //=================================================================================
      //
      // SP/Table/Object methods (for use within a session, name begins with '_')
      //
      //=================================================================================
      TCG_STATUS _authenticate( TCG_UID authorityID, dta::tByte* challenge, tUINT16 challengeLength, dta::tBytes & response );
      TCG_STATUS _authenticate( AuthenticationParameter & authent, dta::tBytes & response );
      TCG_STATUS _authenticate( TCG_UID authorityID, dta::tByte* key, tUINT16 keyLength );
      TCG_STATUS _authenticate( AuthenticationParameter & authent );

      TCG_STATUS _get( TCG_UID targetID, dta::tBytes & data ); // Object or Byte/Array Table method, CS1.0 & 2.0
      TCG_STATUS _get( TCG_UID targetID, TCG_UID rowID, dta::tBytes & data ); // for Object-table only, CS1.0 & 2.0
      TCG_STATUS _get( TCG_UID targetID, TCG_UID rowID, int startColumn, int endColumn, dta::tBytes & data ); // for Object-table row only, CS2.0
      TCG_STATUS _get( TCG_UID targetID, dta::tBytes & data, tINT64 startRow, tINT64 endRow ); // for Byte-table only, CS1.0 & 2.0
      TCG_STATUS _get( TCG_UID targetID, int startColumn, int endColumn, dta::tBytes & data ); // for Object, or Object-table, or array-table, CS2.0
      TCG_STATUS _get( TCG_UID targetID, dta::tBytes & data, char* startColumn, char* endColumn, TCG_UID rowID =UID_NULL ); // for Arrary-table or a row in an object-table, CS1.0

      TCG_STATUS _set( TCG_UID targetID, dta::tBytes & data ); // Table or Object method, CS1.0 & 2.0
      TCG_STATUS _set( TCG_UID targetID, dta::tBytes & data, tINT64 startRow, tINT64 endRow ); // for Byte-table only, CS1.0 & 2.0
      TCG_STATUS _set( TCG_UID targetID, TCG_UID rowID, dta::tBytes & data ); // for Arrary-table or a row in an object-table, CS1.0 & 2.0
      TCG_STATUS _set( TCG_UID targetID, dta::tBytes & data, char* startColumn, char* endColumn ); // for Arrary-table or a row in an object-table, CS1.0

      TCG_STATUS _next( TCG_UID *pNextUID, TCG_UID tableID, TCG_UID objectID = UID_NULL, int count =-1 );

      TCG_STATUS _getACL( TCG_UID targetID, TCG_UID methodID, TCG_UIDs & acl );

      TCG_STATUS _erase( TCG_UID bandID );     // Ent-SSC specific implementation
      TCG_STATUS _erase( int bandNo );         // Ent-SSC specific implementation
      TCG_STATUS _genKey( TCG_UID target, tINT64 publicExponent =-1, int pinLength =-1 ); // Opal-SSC specific implementation

      TCG_STATUS _random( dta::tBytes & randomData );
      TCG_STATUS _sign( TCG_UID targetID, dta::tBytes & dataToSign, dta::tBytes & dataSigned );

      TCG_STATUS _activate( TCG_UID target, TCG_UIDs *pSingleUserModeList =NULL, int rangeStartLengthPolicy =-1, UINT64VALs *pDataStoreTableSizes =NULL );    // Opal-SSC specific feature
      TCG_STATUS _activate( TCG_UID target, TCG_BANDNOs *pSingleUserModeList =NULL, int rangeStartLengthPolicy =-1, UINT64VALs *pDataStoreTableSizes =NULL ); // Opal-SSC specific feature
      TCG_STATUS _reactivate( TCG_UIDs *pSingleUserModeList =NULL, int rangeStartLengthPolicy =-1, dta::tBytes *pAdmin1PIN =NULL, UINT64VALs *pDataStoreTableSizes =NULL );      // Opal-SSC specific feature
      TCG_STATUS _reactivate( TCG_BANDNOs *pSingleUserModeList =NULL, int rangeStartLengthPolicy =-1, dta::tBytes *pAdmin1PIN =NULL, UINT64VALs *pDataStoreTableSizes =NULL );   // Opal-SSC specific feature
      TCG_STATUS _revert( TCG_UID target );    // Opal-SSC specific feature
      TCG_STATUS _revertSP();                  // an SSC specific feature


      //=================================================================================
      //
      // Frequently used Table/Object Get / Set utility functions (for use within a session, name begins with '_')
      // 
      // Naming format: _get/_setTableName()
      //
      //=================================================================================
      TCG_STATUS _getSP( TCG_UID targetID, IOTableSP & row );
      TCG_STATUS _setSP( TCG_UID targetID, IOTableSP & row );
      TCG_STATUS _getLockingInfo( IOTableLockingInfo & row );
      TCG_STATUS _getLocking( int rangeNo, IOTableLocking & row );
      TCG_STATUS _setLocking( int rangeNo, IOTableLocking & row );
      TCG_STATUS _getC_Pin( TCG_UID targetID, IOTableC_PIN & row );
      TCG_STATUS _setC_Pin( TCG_UID targetID, IOTableC_PIN & row );
      TCG_STATUS _getAuthority( TCG_UID authority, IOTableAuthority & row );
      TCG_STATUS _setAuthority( TCG_UID authority, IOTableAuthority & row );
      TCG_STATUS _setACE( TCG_UID ace, TCG_UIDs & authorities );
      TCG_STATUS _getK_AES( TCG_UID kaes, tUINT8 & mode );
      TCG_STATUS _getMBRControl( IOTableMBRControl & row );
      TCG_STATUS _setMBRControl( IOTableMBRControl & row );
      TCG_STATUS _getNumberOfRows( TCG_UID targetTable, tUINT64 & numRows );

      TCG_STATUS _get_PortLocking( TCG_UID port, IOTable_PortLocking & row ); // Seagate proprietary
      TCG_STATUS _set_PortLocking( TCG_UID port, IOTable_PortLocking & row ); // Seagate proprietary


      //=================================================================================
      //
      // Helper/Utility functions
      //
      //=================================================================================
      tUINT32 getMethodExecTime() { return m_methodExecTimeMilliSecond; }
      TCG_STATUS refreshLevel0DiscoveryData();
      bool synchronizeHostTPerProperties();
      bool isTCGProtocolSupported();
      bool isComIDMgmtSupported();
      bool isDeviceEnterpriseSSC();
      bool isDeviceOpalSSC();
      bool isDeviceOpalSSCVersion2();
      bool isDeviceMarbleSSC();
      bool isDeviceLocked( bool refresh =true );
      bool isDeviceMBRDone( bool refresh =true );
      bool isDeviceMBREnabled( bool refresh =true );
      tUINT8  getRangeCrossingAllowed();  // jls20120227
      tUINT16 getMaxLockingSPAdmins();    // jls20120227
      tUINT16 getMaxLockingSPUsers();     // jls20120227
      tUINT8  getSIDdefaultValue();       // jls20120227
      tUINT8  getSIDOnRevertValue();      // jls20120227


      bool isSingleUserModeSupported();
      bool isAnyInSingleUserMode( bool refresh =true );
      bool areAllInSingleUserMode( bool refresh =true );
      bool isSingleUserModePolicyOwnedByAdmin( bool refresh =true );
      tUINT32 getSingleUserModeNumLockingObjects();

      bool  isDataStoreTableFeatureSupported();
      tUINT16 getMaxNumberOfDataStoreTables();
      tUINT32 getMaxTotalSizeOfDataStoreTables();
      tUINT32 getDataStoreTableSizeAlignment();

      bool isGeometryAlignmentRequired();
      tUINT32 getGeometryLogicalBlockSize();
      tUINT64 getGeometryAlignmentGranularity();
      tUINT64 getGeometryLowestAlignedLBA();

      bool isDeviceTCGCoreVersion1() { return 1 == m_tcgCoreSpecVersion; }

      bool setPreferenceToUseDynamicComID( bool useDynamicComID ) { m_useDynamicComID = useDynamicComID; return m_useDynamicComID; }
      bool getPreferenceToUseDynamicComID() { return m_useDynamicComID; }

      bool hasSilo() const { return m_hasSilo; };
      bool useSilo() const { return (m_hasSilo && m_useSilo); };
      void setUseSilo(const bool newUseSilo);

      tUINT16  getBaseComID();
      tUINT16  getNumberOfComIDs();

      tUINT32  getMaxUserDataLength();
      dta::tBytes & getResponseBuffer() { dta::tBytes &r = m_responseBuffer; return r; }

      TCG_UID  mapAuthorityNameToUID( char *name ) { return mapAuthorityOrPinNameToUID( name, false ); }
      TCG_UID  mapPinNameToUID( char *name ) { return mapAuthorityOrPinNameToUID( name, true ); }

      _tstring tcgStatusToString( const TCG_STATUS status );
      _tstring dtlErrorToString( const dta::DTA_ERROR status );

      _tstring getDriveSerialNo() { return serialNumber(); }

      tUINT8   getLifeCycleState( bool Refresh );
      tUINT8   getVendorFeatureSupported() { return m_Level0_VendorFeatureSupported; }
      tUINT8   getVendorFeatureEnabled() { return m_Level0_VendorFeatureEnabled; }

      tUINT16  getLogicalPortsAvailable() { return m_Level0_LogicalPortsAvailable; }
      dta::tBytes &getLogicalPortData() { return m_Level0_LogicalPortData; }

      unsigned int getPollSleepTime() const;
      unsigned int setPollSleepTime(const unsigned int t);

   protected:

      TCG_STATUS securityPacketExchange();
      TCG_STATUS securityByteStreamExchange( int returnDataLengthPos =10 );
      TCG_STATUS securityIFExchange( tUINT8 protcolID, tUINT16 spSpecific );
      TCG_STATUS securityIFSend( tUINT8 protcolID, tUINT16 spSpecific, int blocks=1 );
      TCG_STATUS securityIFRecv( tUINT8 protcolID, tUINT16 spSpecific, int blocks=1 );

      TCG_STATUS probeTcgCoreSSC();
      TCG_STATUS selectComID( tUINT32 extComID );

      void checkReturnedCallStatus( dta::tBytes &returnedCallStatus, bool resultPresent =true );

      //=================================================================================
      /// \brief Writes the command ComPacket or IF-Send byte flow to the log file.
      ///
      /// \return None.
      //=================================================================================
      void logSecuritySend( tUINT8 protocolID, tUINT16 spSpecific, bool packetMode = false );

      //=================================================================================
      /// \brief Writes the response ComPacket or IF-Recv byte flow to the log file.
      ///
      /// \return None.
      //=================================================================================
      void logSecurityRecv( tUINT8 protocolID, tUINT16 spSpecific, bool packetMode = false );
      void logTcgPayload( dta::tBytes & buffer, int bytesToShow, bool logASCII=true );
      char *interpretExchangeName( bool packetMode, char *pBuffer, int length );
      char *mapUIDToName( TCG_UID uid, char *pBuffer, int maxLength );
      TCG_UID mapAuthorityOrPinNameToUID( char *name, bool isPin );

      void attemptUsingDmaIF4ATA();
#ifdef __TCGSILO
      void searchForSilo();
#endif

      template <typename T>
      tUINT8 * encodeNamedValue_IntgerList( tUINT8 * pTokenStreamBuffer, T * pData, tUINT32 numDataItems, const char *nameCS1, tUINT64 nameCS2 );
      tUINT8 * encodeNamedValue_Integer( tUINT8 * pTokenStreamBuffer, tUINT64 data, const char *nameCS1, tUINT64 nameCS2 );
      tUINT8 * encodeNamedValue_UID( tUINT8 * pTokenStreamBuffer, TCG_UID data, const char *nameCS1, tUINT64 nameCS2, bool halfUID =false );
      tUINT8 * encodeNamedValue_Bytes( tUINT8 * pTokenStreamBuffer, tUINT8 * pData, tUINT32 length, const char *nameCS1, tUINT64 nameCS2 );
      tUINT8 * encodeNamedValueName( tUINT8 * pTokenStreamBuffer, const char *nameCS1, tUINT64 nameCS2 );

      template <typename T>
      tUINT32 decodeNamedValue_IntgerList( PUINT8 & pTokenStreamBuffer, tUINT32 bufferLength, T * pData, tUINT32 capacityDataItems, const char *nameCS1, tUINT64 nameCS2 );
      tUINT64 decodeNamedValue_Integer( PUINT8 & pTokenStreamBuffer, tUINT32 bufferLength, const char *nameCS1, tUINT64 nameCS2 );
      tUINT32 decodeNamedValue_Bytes( PUINT8 & pTokenStreamBuffer, tUINT32 bufferLength, tUINT8 * pData, tUINT32 dataLength, const char *nameCS1, tUINT64 nameCS2 );
      tUINT8 *decodeNamedValueName( PUINT8 & pTokenStreamBuffer, tUINT32 bufferLength, const char *nameCS1, tUINT64 nameCS2 );


      //=================================================================================
      /// \brief TCG Host-TPer interface runtime variables for this thread/process.
      //=================================================================================
      dta::tBytes  m_commandBuffer;                   /// Byte vector for handling TCG command payload.
      dta::tBytes  m_responseBuffer;                  /// Byte vector for handling TCG response payload.
      CByteOrder   m_swapper;                         /// Used for converting from system to big endian.
      CTcgTokenProcessor m_tokenProcessor;            /// Service class for handling TCG tokens.
      CTcgPacketManager  m_packetManager;             /// Service class for handling TCG ComPackets/Packets/SubPackets.
      tUINT32 m_methodExecTimeMilliSecond;            /// Method call execution duration for the present packet exchange.
      tUINT8  m_tcgCoreSpecVersion;

#ifdef __TCGSILO
      dti::CIEEE1667Interface* m_ACT;                 /// Pointer to an IEEE1667 ACT
      dti::CTCGSilo* m_TCGSilo;                       /// Pointer to an IEEE1667 TCG Silo object.
#endif
      bool m_hasSilo;                                 /// Boolean indicating whether or not the device has a TCG silo
      bool m_useSilo;                                 /// Boolean determining whether or not TCG command are routed through the silo.

      //
      // Level 0 Discovery data
      //
      tUINT16 m_Level0_SSC_Code;          // 0100, 0200, 0203, 0300. 0000=requery Level0 data
      tUINT16 m_Level0_SSC_BaseComID;
      tUINT16 m_Level0_SSC_NumberComID;
      tUINT8  m_Level0_SSC_RangeCrossingAllowed;  // jls20120227 - Opal SSC 2: 0x01 means not allowed
      tUINT16 m_Level0_SSC_MaxLockingAdmins;      // jls20120227 - Opal SSC 2: Max LockingSPAdmins 
      tUINT16 m_Level0_SSC_MaxLockingUsers;       // jls20120227 - Opal SSC 2: Max LockingSPUsers 
      tUINT8  m_Level0_SSC_DefaultSIDisMSID;      // jls20120227 - Opal SSC 2: 0=MSID, 0xff=unknown
      tUINT8  m_Level0_SSC_OnRevertSIDisMSID;     // jls20120227 - Opal SSC 2: 0=MSID, 0xff=unknown

      tUINT8  m_Level0_Tper_Data[1];      // only Byte4 used for the current TCG core spec 1.0 & 2.0
      tUINT8  m_Level0_Locking_Data[1];   // only Byte4 used for the current TCG core spec 1.0 & 2.0

      tUINT8  m_Level0_LifeCycleState;          // Byte 17 of Level 0 header Vendor-specific fields
      tUINT8  m_Level0_VendorFeatureSupported;  // Byte 19 0f Level 0 header Vendor-specific fields
      tUINT8  m_Level0_VendorFeatureEnabled;    // Byte 21 0f Level 0 header Vendor-specific fields

      bool    m_singleUserModeSupported;
      tUINT32 m_Level0_SingleUserFixedACL_NumLockingObjects; // Byte4-7 of the TCG Opal Single-User-Fixed-ACL spec
      tUINT8  m_Level0_SingleUserFixedACL_Mode;              // Byte8 of the TCG Opal Single-User-Fixed-ACL spec, bit0='Any', bit1='All', bit2='Policy'

      bool    m_Level0_DataStoreTableFeatureSet;      // defined in the "Additional DataStore Table" proposal
      tUINT16 m_Level0_MaxNumOfDataStoreTables;       // defined in the "Additional DataStore Table" proposal
      tUINT32 m_Level0_MaxTotalSizeOfDataStoreTables; // defined in the "Additional DataStore Table" proposal
      tUINT32 m_Level0_DataStoreTableSizeAlignment;   // defined in the "Additional DataStore Table" proposal

      bool    m_Level0_AlignmentRequired;    // Defined in Opal SSC V2 "Geometry Reporting Feature Descriptor"
      tUINT32 m_Level0_LogicalBlockSize;     // Defined in Opal SSC V2 "Geometry Reporting Feature Descriptor"
      tUINT64 m_Level0_AlignmentGranularity; // Defined in Opal SSC V2 "Geometry Reporting Feature Descriptor"
      tUINT64 m_Level0_LowestAlignedLBA;     // Defined in Opal SSC V2 "Geometry Reporting Feature Descriptor"

      tUINT16 m_Level0_LogicalPortsAvailable;// Defined in Product Requirements Logical Port Feature Descriptor
      dta::tBytes  m_Level0_LogicalPortData; // Defined in Product Requirements Logical Port Feature Descriptor

      //
      // TPer information stored in this class.
      //
      dta::tBytes  m_MSID;
      bool m_orphanSessionDetected;
      bool m_useDynamicComID;

   private:
      unsigned int m_sleepTime;

   }; // class CTcgCoreInterface

} // namespace dti

#endif // TCG_CORE_INTERFACE_DOT_HPP
