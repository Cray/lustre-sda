/*! \file TCGSessions.hpp
    \brief Basic API definition for common TCG session tasks Interface.

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

#ifndef TCG_SESSIONS_DOT_HPP
#define TCG_SESSIONS_DOT_HPP

#if !defined(__cplusplus)
#error C++ compiler required.  Include TCGCoreInterface.h for 'C' compilers.
#endif
// !defined __cplusplus
//=================================
// Include files
//=================================
#include "TCGCoreInterface.hpp"

namespace dti
{
   //=================================
   // class definitions
   //=================================

   //====================================================================================
   /// \brief Derived class which implementats common TCG session tasks protocol.
   ///
   /// CTcgSessions is a derived class from CTcgCoreInterface which provides the
   /// implementation for the caller class' methods using the TCG protocol.
   //====================================================================================
   class CTcgSessions : virtual public CTcgCoreInterface
   {
   public:
      //=================================================================================
      /// \brief Constructor for CTcgSessions.
      ///
      /// The constructor takes a CDriveTrustSession as its class member. Sets up the 
      /// packetManager and tokenProcessor with the session's block size.
      ///
      /// \param newSession   [IN] DriveTrust session object which has been initialized and connected to a DriveTrust device.
      ///
      //=================================================================================
      CTcgSessions(dta::CDriveTrustSession* newSession);

      //=================================================================================
      /// \brief Constructor for CTcgSessions.
      ///
      /// The constructor takes a CDriveTrustSession as its class member. Sets up the 
      /// packetManager and tokenProcessor with the session's block size. Also creates 
      /// a log file.
      ///
      /// \param newSession    [IN] DriveTrust session object which has been initialized and connected to a DriveTrust device.
      /// \param logFileName   [IN] Name of file to log ComPackets.
      ///
      //=================================================================================
      CTcgSessions(dta::CDriveTrustSession* newSession, const _tstring logFileName);

      //=================================================================================
      /// \brief Destructor for CTcgSessions.
      //=================================================================================
      virtual ~CTcgSessions() {}


      //=================================================================================
      //
      // Common TCG Session-oriented job sequences, helper/utility functions
      //
      //=================================================================================
      int  getMaxBands();

      TCG_STATUS getMSID( dta::tBytes & mSID );

      TCG_STATUS getSPRow( IOTableSP & row, TCG_UID targetSPUID, AuthenticationParameter & authent );
      TCG_STATUS setSPRow( IOTableSP & row, TCG_UID targetSPUID, AuthenticationParameter & authent );
      TCG_STATUS getSPRow( IOTableSP & row, char *targetSPName, AuthenticationParameter & authent );
      TCG_STATUS setSPRow( IOTableSP & row, char *targetSPName, AuthenticationParameter & authent );

      TCG_STATUS getLockingInfoRow( IOTableLockingInfo & row, TCG_UID authorityID = UID_NULL, tUINT8 *authenticatePin =NULL, tUINT16 pinLen =0 );
      TCG_STATUS getLockingInfoRow( IOTableLockingInfo & row, AuthenticationParameter & authent );

      TCG_STATUS getLockingRow( IOTableLocking & row, int rangeNo, bool toStartSession=true, bool toCloseSession=true, TCG_UID authorityID = UID_NULL, tUINT8 *authenticatePin =NULL, tUINT16 pinLen =0 );
      TCG_STATUS setLockingRow( IOTableLocking & row, int rangeNo, bool toStartSession=true, bool toCloseSession=true, TCG_UID authorityID = UID_AUT_ADMIN1, tUINT8 *authenticatePin =NULL, tUINT16 pinLen =0 );
      TCG_STATUS getLockingRow( IOTableLocking & row, int rangeNo, AuthenticationParameter & authent, bool toStartSession=true, bool toCloseSession=true );
      TCG_STATUS setLockingRow( IOTableLocking & row, int rangeNo, AuthenticationParameter & authent, bool toStartSession=true, bool toCloseSession=true );

      TCG_STATUS getC_PINRow( IOTableC_PIN & row, TCG_UID targetID, TCG_UID authorityID = UID_NULL, tUINT8 *authenticatePin =NULL, tUINT16 pinLen =0 );
      TCG_STATUS setC_PINRow( IOTableC_PIN & row, TCG_UID targetID, TCG_UID authorityID = UID_NULL, tUINT8 *authenticatePin =NULL, tUINT16 pinLen =0 );
      TCG_STATUS getC_PINRow( IOTableC_PIN & row, char * targetName, AuthenticationParameter & authent );
      TCG_STATUS setC_PINRow( IOTableC_PIN & row, char * targetName, AuthenticationParameter & authent );

      TCG_STATUS getAuthorityRow( IOTableAuthority & row, TCG_UID targetID, TCG_UID authorityID = UID_NULL, tUINT8 *authenticatePin =NULL, tUINT16 pinLen =0 );
      TCG_STATUS setAuthorityRow( IOTableAuthority & row, TCG_UID targetID, TCG_UID authorityID = UID_NULL, tUINT8 *authenticatePin =NULL, tUINT16 pinLen =0 );
      TCG_STATUS getAuthorityRow( IOTableAuthority & row, char * targetName, AuthenticationParameter & authent );
      TCG_STATUS setAuthorityRow( IOTableAuthority & row, char * targetName, AuthenticationParameter & authent );

      TCG_STATUS eraseBand( int startBandNo, int endBandNo, TCG_UID authorityID = UID_NULL, tUINT8 *authenticatePin =NULL, tUINT16 pinLen =0, bool resetAccess =true );
      TCG_STATUS eraseBand( int startBandNo, int endBandNo, AuthenticationParameter & authent, bool resetAccess =true );

      TCG_STATUS readDataStore( dta::tBytes & data, int targetDS =0, tINT64 startRow =-1, tINT64 endRow =-1, TCG_UID authorityID =UID_NULL, tUINT8 *authenticatePin =NULL, tUINT16 pinLen =0, UserProgressUpdateCallBack progressUpdt =NULL, tUINT32 *pDurationMS =NULL );
      TCG_STATUS writeDataStore( dta::tBytes & data, int targetDS, tINT64 startRow, tINT64 endRow, TCG_UID authorityID, tUINT8 *authenticatePin, tUINT16 pinLen, UserProgressUpdateCallBack progressUpdt =NULL, tUINT32 *pDurationMS =NULL );
      TCG_STATUS readDataStore( dta::tBytes & data, AuthenticationParameter & authent, int targetDS =0, tINT64 startRow =-1, tINT64 endRow =-1, UserProgressUpdateCallBack progressUpdt =NULL, tUINT32 *pDurationMS =NULL );
      TCG_STATUS writeDataStore( dta::tBytes & data, AuthenticationParameter & authent, int targetDS, tINT64 startRow, tINT64 endRow, UserProgressUpdateCallBack progressUpdt =NULL, tUINT32 *pDurationMS =NULL );

      TCG_STATUS readMBR( dta::tBytes & data, tINT64 startRow, tINT64 endRow, TCG_UID authorityID = UID_NULL, tUINT8 *authenticatePin =NULL, tUINT16 pinLen =0, UserProgressUpdateCallBack progressUpdt =NULL, tUINT32 *pDurationMS =NULL );
      TCG_STATUS writeMBR( dta::tBytes & data, tINT64 startRow, tINT64 endRow, TCG_UID authorityID, tUINT8 *authenticatePin, tUINT16 pinLen, UserProgressUpdateCallBack progressUpdt =NULL, tUINT32 *pDurationMS =NULL );
      TCG_STATUS readMBR( dta::tBytes & data, AuthenticationParameter & authent, tINT64 startRow, tINT64 endRow, UserProgressUpdateCallBack progressUpdt =NULL, tUINT32 *pDurationMS =NULL );
      TCG_STATUS writeMBR( dta::tBytes & data, AuthenticationParameter & authent, tINT64 startRow, tINT64 endRow, UserProgressUpdateCallBack progressUpdt =NULL, tUINT32 *pDurationMS =NULL );

      TCG_STATUS readMBRControl( IOTableMBRControl & row, AuthenticationParameter & authent );
      TCG_STATUS writeMBRControl( IOTableMBRControl & row, AuthenticationParameter & authent );

      TCG_STATUS enableAuthority( TCG_UID targetID, AuthenticationParameter & authent );
      TCG_STATUS enableAuthority( char * targetName, AuthenticationParameter & authent );
      TCG_STATUS disableAuthority( TCG_UID targetID, AuthenticationParameter & authent );
      TCG_STATUS disableAuthority( char * targetName, AuthenticationParameter & authent );

      TCG_STATUS setAuthorityACE( TCG_UID ace, TCG_UIDs & authorities, TCG_UID authorityID = UID_AUT_ADMIN1, tUINT8 *authenticatePin =NULL, tUINT16 pinLen =0 );
      TCG_STATUS setAuthorityACE( TCG_UID ace, TCG_UIDs & authorities, AuthenticationParameter & authent );

      TCG_STATUS revertSP( TCG_UID targetSPUID, AuthenticationParameter & authent );
      TCG_STATUS revertSP( char *targetSPName, AuthenticationParameter & authent );

      TCG_STATUS activate( TCG_UID targetSPUID, AuthenticationParameter & authent, TCG_UIDs *pSingleUserModeList =NULL, int rangeStartLengthPolicy =-1, UINT64VALs *pDataStoreTableSizes =NULL );
      TCG_STATUS activate( char *targetSPName, AuthenticationParameter & authent, TCG_BANDNOs *pSingleUserModeList =NULL, int rangeStartLengthPolicy =-1, UINT64VALs *pDataStoreTableSizes =NULL );

      TCG_STATUS reactivate( AuthenticationParameter & authent, TCG_UIDs *pSingleUserModeList =NULL, int rangeStartLengthPolicy =-1, dta::tBytes *pAdmin1PIN =NULL, UINT64VALs *pDataStoreTableSizes =NULL );
      TCG_STATUS reactivate( AuthenticationParameter & authent, TCG_BANDNOs *pSingleUserModeList =NULL, int rangeStartLengthPolicy =-1, dta::tBytes *pAdmin1PIN =NULL, UINT64VALs *pDataStoreTableSizes =NULL );

      TCG_STATUS protocolStackReset( int comChannel =0, bool syncHostTPerProperties =true );
      TCG_STATUS selectComChannel( int comChannel =0, bool syncHostTPerProperties =true );
      TCG_STATUS TPerReset( bool syncHostTPerProperties =true );

      bool isTPerResetSupported() { return false; }
      bool isTPerResetEnabled()  { return false; }    // jls20120404
      TCG_STATUS setTPerResetEnable( AuthenticationParameter & authent, bool enable ) { return TS_DTL_ERROR; } // jls20120404

      tUINT8 getSOM(); // Seagate proprietary
      TCG_STATUS get_PortLockingRow( IOTable_PortLocking & row, TCG_UID targetPort, AuthenticationParameter & authent ); // Seagate proprietary
      TCG_STATUS set_PortLockingRow( IOTable_PortLocking & row, TCG_UID targetPort, AuthenticationParameter & authent ); // Seagate proprietary


   protected:
      TCG_STATUS getFWDownload( IOTable_PortLocking & row, AuthenticationParameter & authent ) { return get_PortLockingRow( row, UID__PORTLOCKING_FWDOWNLOAD, authent ); }
      TCG_STATUS setFWDownload( IOTable_PortLocking & row, AuthenticationParameter & authent ) { return set_PortLockingRow( row, UID__PORTLOCKING_FWDOWNLOAD, authent ); }
      TCG_STATUS getSecureUDS(  IOTable_PortLocking & row, AuthenticationParameter & authent ) { return get_PortLockingRow( row, UID__PORTLOCKING_SECURE_UDS, authent ); }
      TCG_STATUS setSecureUDS(  IOTable_PortLocking & row, AuthenticationParameter & authent ) { return set_PortLockingRow( row, UID__PORTLOCKING_SECURE_UDS, authent ); }
// Currently known logical ports:
// UID__PORTLOCKING_DIAGNOSTIC             0x0001000200010001   //jls20120229 (Seagate Diagnostic Port)
// UID__PORTLOCKING_FWDOWNLOAD             0x0001000200010002
// UID__PORTLOCKING_SECURE_UDS             0x0001000200010003   //jls20120229 (Seagate internal UDS port)
// UID__PORTLOCKING_CHANGEDEF              0x0001000200010005   //jls20120229 (deprecated)
// UID__PORTLOCKING_DCO                    0x000100020001000D   //jls20120229 (deprecated)
// UID__PORTLOCKING_CSFWDOWNLOAD           0x000100020001000E   //jls20121002 (Seagate internal configuration port)

   }; // class CTcgSessions

} // namespace dti

#endif // TCG_SESSIONS_DOT_HPP
