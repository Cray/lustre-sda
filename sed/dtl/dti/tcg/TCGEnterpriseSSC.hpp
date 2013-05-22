/*! \file TCGEnterpriseSSC.hpp
    \brief Basic API definition for TCG Enterprise-SSC Interface.

    This file details the interface classes and functions for writing
    client code that uses the TCG Enterprise-SSC security protocol via DTA
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

#ifndef TCG_ENTERPRISESSC_DOT_HPP
#define TCG_ENTERPRISESSC_DOT_HPP

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
   /// \brief Derived class which implementats TCG Enterprise SSC spec protocol.
   ///
   /// CTcgEnterpriseSSC is a derived class from CTcgCoreInterface which provides the
   /// implementation for the caller class' methods using the TCG Enterprise-SSC protocol.
   //====================================================================================
   class CTcgEnterpriseSSC : virtual public CTcgCoreInterface
   {
   public:
      //=================================================================================
      /// \brief Constructor for CTcgEnterpriseSSC.
      ///
      /// The constructor takes a CDriveTrustSession as its class member. Sets up the 
      /// packetManager and tokenProcessor with the session's block size.
      ///
      /// \param newSession  [IN] DriveTrust session object which has been initialized and connected to a DriveTrust device.
      ///
      //=================================================================================
      CTcgEnterpriseSSC(dta::CDriveTrustSession* newSession);

      //=================================================================================
      /// \brief Constructor for CTcgEnterpriseSSC.
      ///
      /// The constructor takes a CDriveTrustSession as its class member. Sets up the 
      /// packetManager and tokenProcessor with the session's block size. Also creates 
      /// a log file.
      ///
      /// \param newSession    [IN] DriveTrust session object which has been initialized and connected to a DriveTrust device.
      /// \param logFileName   [IN] Name of file to log ComPackets.
      ///
      //=================================================================================
      CTcgEnterpriseSSC(dta::CDriveTrustSession* newSession, const _tstring logFileName);

      //=================================================================================
      /// \brief Destructor for CTcgEnterpriseSSC.
      //=================================================================================
      virtual ~CTcgEnterpriseSSC() {}


      //=================================================================================
      //
      // TPer/Com methods
      //
      //=================================================================================
      tUINT32 getComID();
      etComIDState verifyComID( tUINT32 extComID );


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
      TCG_STATUS _erase( TCG_UID bandID );
      TCG_STATUS _erase( int bandNo );

      TCG_STATUS _revertSP();  // Seagate-implementation, out of Ent-SSC

   }; // class CTcgEnterpriseSSC

} // namespace dti

#endif // TCG_ENTERPRISESSC_DOC_HPP
