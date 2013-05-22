/*! \file TCGOpalSSC.hpp
    \brief Basic API definition for TCG Opal-SSC Interface.

    This file details the interface classes and functions for writing
    client code that uses the TCG Opal-SSC security protocol via DTA
    to access DriveTrust devices.  It is a C++ specific interface.  For a 
    'C' interface, include the corresponding .h instead of this file.
    
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

#ifndef TCG_OPALSSC_DOT_HPP
#define TCG_OPALSSC_DOT_HPP

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
   /// \brief Derived class which implementats TCG Opal SSC spec protocol.
   ///
   /// CTcgOpalSSC is a derived class from CTcgCoreInterface which provides the
   /// implementation for the caller class' methods using the TCG Opal-SSC protocol.
   //====================================================================================
   class CTcgOpalSSC : virtual public CTcgCoreInterface
   {
   public:
      //=================================================================================
      /// \brief Constructor for CTcgOpalSSC.
      ///
      /// The constructor takes a CDriveTrustSession as its class member. Sets up the 
      /// packetManager and tokenProcessor with the session's block size.
      ///
      /// \param newSession   [IN] DriveTrust session object which has been initialized and connected to a DriveTrust device.
      ///
      //=================================================================================
      CTcgOpalSSC( dta::CDriveTrustSession* newSession );

      //=================================================================================
      /// \brief Constructor for CTcgOpalSSC.
      ///
      /// The constructor takes a CDriveTrustSession as its class member. Sets up the 
      /// packetManager and tokenProcessor with the session's block size. Also creates 
      /// a log file.
      ///
      /// \param newSession    [IN] DriveTrust session object which has been initialized and connected to a DriveTrust device.
      /// \param logFileName   [IN] Name of file to log ComPackets.
      ///
      //=================================================================================
      CTcgOpalSSC( dta::CDriveTrustSession* newSession, const _tstring logFileName );

      //=================================================================================
      /// \brief Destructor for CTcgOpalSSC.
      //=================================================================================
      virtual ~CTcgOpalSSC() {}


      //=================================================================================
      //
      // TPer/Com methods
      //
      //=================================================================================
      tUINT32 getComID();
      etComIDState verifyComID( tUINT32 extComID );
      TCG_STATUS programmaticTPerReset();


      //=================================================================================
      //
      // Session methods (for use around sessions, name begins with '_')
      //
      //=================================================================================


      //=================================================================================
      //
      // SP/Table/Object methods (for use within a session, name begins with '_')
      //
      //=================================================================================
      TCG_STATUS _genKey( TCG_UID target, tINT64 publicExponent =-1, int pinLength =-1 );

      TCG_STATUS _activate( TCG_UID target, TCG_UIDs *pSingleUserModeList =NULL, int rangeStartLengthPolicy =-1, UINT64VALs *pDataStoreTableSizes =NULL );
      TCG_STATUS _activate( TCG_UID target, TCG_BANDNOs *pSingleUserModeList =NULL, int rangeStartLengthPolicy =-1, UINT64VALs *pDataStoreTableSizes =NULL );
      TCG_STATUS _reactivate( TCG_UIDs *pSingleUserModeList =NULL, int rangeStartLengthPolicy =-1, dta::tBytes *pAdmin1PIN =NULL, UINT64VALs *pDataStoreTableSizes =NULL );
      TCG_STATUS _reactivate( TCG_BANDNOs *pSingleUserModeList =NULL, int rangeStartLengthPolicy =-1, dta::tBytes *pAdmin1PIN =NULL, UINT64VALs *pDataStoreTableSizes =NULL );
      TCG_STATUS _revert( TCG_UID target );

      TCG_STATUS _revertSP();
      TCG_STATUS _revertSP( bool bKeepGlobalRangeKey ); // Not supported yet in Seagate SED drives

      TCG_STATUS _erase( TCG_UID lockingObjectUID );    // Added for Opal Single-User-Mode FixedACL spec
      TCG_STATUS _erase( int rangeNo );                 // Added for Opal Single-User-Mode FixedACL spec

   }; // class CTcgOpalSSC

} // namespace dti

#endif // TCG_OPALSSC_DOC_HPP
