/*! \file TCGEnterpriseSSC.cpp
    \brief Basic implementations of base class members from <TCG/TCGEnterpriseSSC.hpp>.

    These implementation shall be cross-platform and relatively generic.
    Some or all of them may be overloaded by derived classes.
    
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

// Disabled Microsoft warnings on C-style functions
#if defined (_WIN32)
#pragma warning(disable : 4996)
#endif

//=================================
// Include files
//=================================
#include "TCGEnterpriseSSC.hpp"
#include "dtlcrypto.h"

using namespace dta;
using namespace dti;

//=======================================================================================
// CTcgEnterpriseSSC
//=======================================================================================
CTcgEnterpriseSSC::CTcgEnterpriseSSC(dta::CDriveTrustSession* newSession)
                 : CDriveTrustInterface(newSession), CTcgCoreInterface(newSession)
{
} // CTcgEnterpriseSSC

//=======================================================================================
// CTcgEnterpriseSSC
//=======================================================================================
CTcgEnterpriseSSC::CTcgEnterpriseSSC(dta::CDriveTrustSession* newSession, const _tstring logFileName)
                 : CDriveTrustInterface(newSession, logFileName), CTcgCoreInterface(newSession, logFileName)
{
} // CTcgEnterpriseSSC


//=================================================================================
/// \brief Return a ComID (extended ID) from TPer's pre-set ComIDs.
///
/// \return tUINT32, an issued extended ComID by the TPer.
//=================================================================================
tUINT32 CTcgEnterpriseSSC::getComID()
{
   static int comid_dispatcher = 0;
   tUINT32 id;

   if( L0_DISCOVERY_FEATURECODE_UNSET == m_Level0_SSC_Code )
      refreshLevel0DiscoveryData();

   if( L0_DISCOVERY_FEATURECODE_SSC_ENTERPRISE == m_Level0_SSC_Code && m_Level0_SSC_NumberComID > 0 )
   {
      id = (((tUINT32) (m_Level0_SSC_BaseComID + comid_dispatcher)) << 16 ) & 0xFFFF0000;

      comid_dispatcher++;
      if( m_Level0_SSC_NumberComID == comid_dispatcher )
         comid_dispatcher = 0;
   }
   else
   {
      switch ( comid_dispatcher )
      {
         case 0:
            id = EXT_COM_ID1;
            break;

         default:
            id = EXT_COM_ID2;
      }

      comid_dispatcher++;
      if( NUMBER_PRESET_COMIDS == comid_dispatcher )
         comid_dispatcher = 0;
   }

   m_packetManager.setExtendedComID( id );
   return id;
} // getComID

//=================================================================================
/// \brief Verify an extended ComID against the TPer's preset ComIDs.
///
/// \param extComID [IN]  Extended ComID.
///
/// \return enum value for the state of the given ComID.
//=================================================================================
etComIDState CTcgEnterpriseSSC::verifyComID( tUINT32 extComID )
{
   if( L0_DISCOVERY_FEATURECODE_UNSET == m_Level0_SSC_Code )
      refreshLevel0DiscoveryData();

   if( ( extComID >= (((tUINT32) m_Level0_SSC_BaseComID) << 16 ) )
    && ( extComID < (((tUINT32) (m_Level0_SSC_BaseComID + m_Level0_SSC_NumberComID)) << 16 ) ) )
   {
      return evISSUED;
   }
   else if( isComIDMgmtSupported() )
   {
      return CTcgCoreInterface::verifyComID( extComID );
   }
   else
   {
      return evINVALID;
   }
} // verifyComID

//=================================================================================
/// \brief Cryptographic erase a band/range of user space, and reset access control of the band on the TPer.
///
/// \param bandID  [IN]  Band/range to be secure erased.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgEnterpriseSSC::_erase( TCG_UID bandID )
{
   M_TCGTry()
   {
      // Set to Session Manager, ComID, TPer/Host SN should have been set
      m_commandBuffer.resize( m_blockSize );
      m_responseBuffer.resize( m_blockSize );

      dta::tByte* p = m_packetManager.setComBuffer( m_commandBuffer );
      p = m_tokenProcessor.buildCallToken( p, bandID, UID_M_ERASE );
      tUINT32 len = m_packetManager.sealComPacket( p );
      m_commandBuffer.resize( len );

      securityPacketExchange();

      dta::tBytes respSubPacketPayload;
      m_packetManager.parseComPacket( m_responseBuffer, respSubPacketPayload );
   }
   M_TCGCatch( true, true );
} // _erase

//=================================================================================
/// \brief Cryptographic erase a band/range of user space, and reset access control of the band on the TPer.
///
/// \param bandNo  [IN]  Band/range number be secure erased.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgEnterpriseSSC::_erase( int bandNo )
{
   return _erase( (TCG_UID) UID_LOCKING_RANGE0 + bandNo );
} // _erase

//=================================================================================
/// \brief Revert the currently authenticated SP (this-SP) to its factory state on the TPer.
/// This is a Seagate proprietary feature, out of Ent-SSC. Revert AdminSP only.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgEnterpriseSSC::_revertSP()
{
   M_TCGTry()
   {
      // Set to Session Manager, ComID, TPer/Host SN should have been set
      m_commandBuffer.resize( m_blockSize );
      m_responseBuffer.resize( m_blockSize );

      dta::tByte* p = m_packetManager.setComBuffer( m_commandBuffer );
      p = m_tokenProcessor.buildCallToken( p, UID_THIS_SP, UID_M_REVERTSP );
      tUINT32 len = m_packetManager.sealComPacket( p );
      m_commandBuffer.resize( len );

      securityPacketExchange();

      dta::tBytes respSubPacketPayload;
      m_packetManager.parseComPacket( m_responseBuffer, respSubPacketPayload );
   }
   M_TCGCatch( true, true );
} // _revertSP
