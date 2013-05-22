/*! \file TCGOpalSessions.hpp
    \brief Basic API definition for TCG Opal-SSC session tasks Interface.

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

#ifndef TCG_OPALSESSIONS_DOT_HPP
#define TCG_OPALSESSIONS_DOT_HPP

#if !defined(__cplusplus)
#error C++ compiler required.  Include the corresponding .h for 'C' compilers.
#endif
// !defined __cplusplus
//=================================
// Include files
//=================================
#include "TCGOpalSSC.hpp"
#include "TCGSessions.hpp"

namespace dti
{
   //=================================
   // class definitions
   //=================================

   //====================================================================================
   /// \brief Derived class which implementats TCG Opal SSC spec protocol.
   ///
   /// CTcgOpalSSC is a derived class from CTcgCoreInterface which provides the
   /// implementation for the caller class' methods using the TCG Opal-SSC protocol.
   //====================================================================================
   class CTcgOpalSessions : public CTcgOpalSSC, public CTcgSessions
   {
   public:
      //=================================================================================
      /// \brief Constructor for CTcgOpalSessions.
      ///
      /// The constructor takes a CDriveTrustSession as its class member. Sets up the 
      /// packetManager and tokenProcessor with the session's block size.
      ///
      /// \param newSession   [IN] DriveTrust session object which has been initialized and connected to a DriveTrust device.
      ///
      //=================================================================================
      CTcgOpalSessions(dta::CDriveTrustSession* newSession);

      //=================================================================================
      /// \brief Constructor for CTcgOpalSessions.
      ///
      /// The constructor takes a CDriveTrustSession as its class member. Sets up the 
      /// packetManager and tokenProcessor with the session's block size. Also creates 
      /// a log file.
      ///
      /// \param newSession    [IN] DriveTrust session object which has been initialized and connected to a DriveTrust device.
      /// \param logFileName   [IN] Name of file to log ComPackets.
      ///
      //=================================================================================
      CTcgOpalSessions(dta::CDriveTrustSession* newSession, const _tstring logFileName);

      //=================================================================================
      /// \brief Destructor for CTcgOpalSessions.
      //=================================================================================
      virtual ~CTcgOpalSessions() {}


      //=================================================================================
      //
      // TCG Session-oriented job sequences, helper/utility functions for Opal-SSC
      //
      //=================================================================================
      TCG_STATUS readMBR( dta::tBytes & data, tINT64 startRow, tINT64 endRow, TCG_UID authorityID = UID_NULL, tUINT8 *authenticatePin =NULL, tUINT16 pinLen =0, UserProgressUpdateCallBack progressUpdt =NULL, tUINT32 *pDurationMS =NULL );
      TCG_STATUS writeMBR( dta::tBytes & data, tINT64 startRow, tINT64 endRow, TCG_UID authorityID, tUINT8 *authenticatePin, tUINT16 pinLen, UserProgressUpdateCallBack progressUpdt =NULL, tUINT32 *pDurationMS =NULL );
      TCG_STATUS readMBR( dta::tBytes & data, AuthenticationParameter & authent, tINT64 startRow, tINT64 endRow, UserProgressUpdateCallBack progressUpdt =NULL, tUINT32 *pDurationMS =NULL );
      TCG_STATUS writeMBR( dta::tBytes & data, AuthenticationParameter & authent, tINT64 startRow, tINT64 endRow, UserProgressUpdateCallBack progressUpdt =NULL, tUINT32 *pDurationMS =NULL );

      TCG_STATUS readMBRControl( IOTableMBRControl & row, AuthenticationParameter & authent );
      TCG_STATUS writeMBRControl( IOTableMBRControl & row, AuthenticationParameter & authent );

      TCG_STATUS activate( TCG_UID targetSPUID, AuthenticationParameter & authent, TCG_UIDs *pSingleUserModeList =NULL, int rangeStartLengthPolicy =-1, UINT64VALs *pDataStoreTableSizes =NULL );
      TCG_STATUS activate( char *targetSPName, AuthenticationParameter & authent, TCG_BANDNOs *pSingleUserModeList =NULL, int rangeStartLengthPolicy =-1, UINT64VALs *pDataStoreTableSizes =NULL );

      TCG_STATUS reactivate( AuthenticationParameter & authent, TCG_UIDs *pSingleUserModeList =NULL, int rangeStartLengthPolicy =-1, dta::tBytes *pAdmin1PIN =NULL, UINT64VALs *pDataStoreTableSizes =NULL );
      TCG_STATUS reactivate( AuthenticationParameter & authent, TCG_BANDNOs *pSingleUserModeList =NULL, int rangeStartLengthPolicy =-1, dta::tBytes *pAdmin1PIN =NULL, UINT64VALs *pDataStoreTableSizes =NULL );

      TCG_STATUS TPerReset( bool syncHostTPerProperties =true );
      TCG_STATUS setTPerResetEnable( AuthenticationParameter & authent, bool enable =true );
      bool isTPerResetSupported();
      bool isTPerResetEnabled();

   }; // class CTcgOpalSSC

} // namespace dti

#endif // TCG_OPALSESSIONS_DOC_HPP
