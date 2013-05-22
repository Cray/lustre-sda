/*! \file osRAID.hpp
    \brief  Implementation of CDriveTrustSession via the CSMI MINIPORT 
            pass-through transport.

    TODO : Detailed description
    
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

#ifndef XPORT_RAID_HPP
#define XPORT_RAID_HPP

// !defined __cplusplus
//=================================
// Include files
//=================================
#include "../osDTSession.hpp"
#include "osTfrRAID.hpp"
#include <dta/Ata.hpp>
#include <dta/platform/win32/OSIncludes.h>
#include <dta/CSMIIOCTL.h>
#include <queue>

namespace dtad {
//=================================
// macro definitions
//=================================

//=================================
// constants
//=================================

//=================================
// typedefs and structures
//=================================

//=================================
// class definitions
//=================================

/// \brief Class representing a communication session between
///        an application and a SAT-based DriveTrust device.
///
/// TODO : Detailed description
///
//
class COSDTSessionRAID : public COSDTSession, public ata::CAta
{
public:
   /// Constructor.
   COSDTSessionRAID();

   //================================================================
   // Implementations of methods defined in CDriveTrustSession
   //================================================================
   virtual dta::DTA_ERROR SecurityDataToDevice( 
      const dta::tBytes &dataToSend 
      );
   virtual dta::DTA_ERROR SecurityDataFromDevice( 
      dta::tBytes &dataToRecv 
      );
   virtual dta::DTA_ERROR SecurityDataToDevice( 
      tUINT8 protocolID,
      tUINT16 spSpecific,
      const dta::tBytes &dataToSend
      );
   virtual dta::DTA_ERROR SecurityDataFromDevice( 
      tUINT8 protocolID,
      tUINT16 spSpecific,
      dta::tBytes &dataToRecv 
      );
   virtual dta::DTA_ERROR GetAttribute(
      const _tstring& attribute,
      _tstring& value
      );
   virtual dta::DTA_ERROR SetAttribute(
      const _tstring& attribute,
      const _tstring& value
      );

protected:
   //================================================================
   // Implementations of methods defined in CAta
   //================================================================
   virtual dta::DTA_ERROR AcquireTFR( 
      ata::CTfr* &pTFR, 
      ata::etAddressMode addressMode 
      );

   virtual dta::DTA_ERROR ReleaseTFR( ata::CTfr* pTFR );

   virtual dta::DTA_ERROR Execute( 
      ata::CTfr* pTFR,
      dta::tBytes& buffer,
      size_t timeout,
      ata::etProtocol protocol,
      ata::etDataDirection direction
      );
   
   

   //================================================================
   //
   /// Get the current block size for the device, interrogating
   /// the device if necessary.  A DTA_ERROR will be thrown in
   /// case of error.
   ///
   /// \return the block size.
   //
   //================================================================
   virtual size_t GetBlockSize();

   //================================================================
protected:
   H2D_RFIS *pstCmdFIS;
   D2H_RFIS *pstRspFIS;

};

//=================================
// function definitions
//=================================

}  // end namespace dtad
#endif // XPORT_ATA_PASS_THROUGH_HPP