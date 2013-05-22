/*! \file TCGEntSessions.hpp
    \brief Basic API definition for TCG Enterprise-SSC session tasks Interface.

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

#ifndef TCG_ENTSESSIONS_DOT_HPP
#define TCG_ENTSESSIONS_DOT_HPP

#if !defined(__cplusplus)
#error C++ compiler required.  Include the corresponding .h for 'C' compilers.
#endif
// !defined __cplusplus
//=================================
// Include files
//=================================
#include "TCGEnterpriseSSC.hpp"
#include "TCGSessions.hpp"

namespace dti
{
   //=================================
   // class definitions
   //=================================

   //====================================================================================
   /// \brief Derived class which implementats TCG Enterprise SSC spec protocol.
   ///
   /// CTcgEntSessions is a derived class from CTcgEnterpriseSSC & CTcgSessions which provides
   /// the implementation for the caller class' methods using the TCG Enterprise-SSC protocol.
   //====================================================================================
   class CTcgEntSessions : public CTcgEnterpriseSSC, public CTcgSessions
   {
   public:
      //=================================================================================
      /// \brief Constructor for CTcgEntSessions.
      ///
      /// The constructor takes a CDriveTrustSession as its class member. Sets up the 
      /// packetManager and tokenProcessor with the session's block size.
      ///
      /// \param newSession   [IN] DriveTrust session object which has been initialized and connected to a DriveTrust device.
      ///
      //=================================================================================
      CTcgEntSessions( dta::CDriveTrustSession* newSession );

      //=================================================================================
      /// \brief Constructor for CTcgEntSessions.
      ///
      /// The constructor takes a CDriveTrustSession as its class member. Sets up the 
      /// packetManager and tokenProcessor with the session's block size. Also creates 
      /// a log file.
      ///
      /// \param newSession    [IN] DriveTrust session object which has been initialized and connected to a DriveTrust device.
      /// \param logFileName   [IN] Name of file to log ComPackets.
      ///
      //=================================================================================
      CTcgEntSessions( dta::CDriveTrustSession* newSession, const _tstring logFileName );

      //=================================================================================
      /// \brief Destructor for CTcgEntSessions.
      //=================================================================================
      virtual ~CTcgEntSessions() {}


      //=================================================================================
      //
      // TCG Session-oriented job sequences, helper/utility functions for Enterprise-SSC
      //
      //=================================================================================

   }; // class CTcgEntSessions

} // namespace dti

#endif // TCG_ENTSESSIONS_DOC_HPP
