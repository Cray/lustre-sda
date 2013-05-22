/*! \file tcgOpalSSC.cpp
    \brief Basic implementations of base class members from <TCG/TCGOpalSSC.hpp>.

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
#include "TCGOpalSSC.hpp"
#include "dtlcrypto.h"

using namespace dta;
using namespace dti;

//=======================================================================================
// CTcgOpalSSC
//=======================================================================================
CTcgOpalSSC::CTcgOpalSSC(dta::CDriveTrustSession* newSession)
            : CDriveTrustInterface(newSession), CTcgCoreInterface(newSession)
{
} // CTcgOpalSSC

//=======================================================================================
// CTcgOpalSSC
//=======================================================================================
CTcgOpalSSC::CTcgOpalSSC(dta::CDriveTrustSession* newSession, const _tstring logFileName)
            : CDriveTrustInterface(newSession, logFileName), CTcgCoreInterface(newSession, logFileName)
{
} // CTcgOpalSSC


//=================================================================================
/// \brief Return a ComID (extended ID) from TPer's pre-set ComIDs.
///
/// \return tUINT32, an issued extended ComID by the TPer.
//=================================================================================
tUINT32 CTcgOpalSSC::getComID()
{
   static int comid_dispatcher = 0;
   tUINT32 id;

   if( L0_DISCOVERY_FEATURECODE_UNSET == m_Level0_SSC_Code )
      refreshLevel0DiscoveryData();

   if( m_useDynamicComID && isComIDMgmtSupported() )
   {
      id = CTcgCoreInterface::getComID();
   }
   else
   {
      if( ( L0_DISCOVERY_FEATURECODE_SSC_OPAL == m_Level0_SSC_Code ||
            L0_DISCOVERY_FEATURECODE_SSC_OPAL_V2 == m_Level0_SSC_Code   )&& // nvn20110520
          ( m_Level0_SSC_NumberComID > 0 ) )
      {
         id = (((tUINT32) (m_Level0_SSC_BaseComID + comid_dispatcher)) << 16 ) & 0xFFFF0000;

         comid_dispatcher++;
         if( m_Level0_SSC_NumberComID == comid_dispatcher )
            comid_dispatcher = 0;
      }
      else // Error occures if it falls through here, but try to assign a known ID to allow tentertive comm
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
etComIDState CTcgOpalSSC::verifyComID( tUINT32 extComID )
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
/// \brief TCG programmatic TPer Reset on the TPer.
///
/// \return status byte of the response for this call.
//=================================================================================
TCG_STATUS CTcgOpalSSC::programmaticTPerReset()
{
#ifdef __TCGSILO // Need to get the TCG Silo version of the TPerReset !!!
   // Call the silo reset, if in use
   if( useSilo() )
   {
      M_TCGTry()
      {
         m_TCGSilo->reset();
      }
      M_TCGCatch(false, true)
   } // if
   else
#endif
   {
      m_commandBuffer.resize( m_blockSize );
      memset( &m_commandBuffer[0], 0, m_commandBuffer.size() );
      securityIFSend( SECURITY_PROTOCOLID_COMID_MANAGEMENT, SPSPECIFIC_P02_TPER_RESET, 1 );
      return TS_SUCCESS;
   }
} // programmaticTPerReset

//=================================================================================
/// \brief Generate a Key by the specified credential object.
///
/// \param target          [IN]  UID of target credential object to generate the key.
/// \param publicExponent  [IN]  PublicExponent to be used when invoked on a C_RSA_1024 or C_RSA_2048 object. Optional, -1 indicates omitted.
/// \param pinLength       [IN]  Pin length. Optional, -1 indicates omitted.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgOpalSSC::_genKey( TCG_UID target, tINT64 publicExponent, int pinLength )
{
   M_TCGTry()
   {
      // Set to Session Manager, ComID, TPer/Host SN should have been set
      m_commandBuffer.resize( m_blockSize );
      m_responseBuffer.resize( m_blockSize );

      dta::tByte* p = m_packetManager.setComBuffer( m_commandBuffer );
      p = m_tokenProcessor.buildCallTokenHeader( p, target, UID_M_GEN_KEY );

      if( -1 != publicExponent )
         p = encodeNamedValue_Integer( p, (tUINT64) publicExponent, "PublicExponent", 0 );

      if( -1 != pinLength )
         p = encodeNamedValue_Integer( p, (tUINT64) pinLength, "PinLength", 1 );

      p = m_tokenProcessor.buildCallTokenFooter( p );

      tUINT32 len = m_packetManager.sealComPacket( p );
      m_commandBuffer.resize( len );

      securityPacketExchange();

      dta::tBytes respSubPacketPayload;
      m_packetManager.parseComPacket( m_responseBuffer, respSubPacketPayload );
   }
   M_TCGCatch( true, true );
} // _genKey

//=================================================================================
/// \brief Activate the given SP object from "Manufactured-Inactive" to "Manufactured".
///
/// TCG method depiction
///   SPObjectUID.Activate[ 
///      SingaleUserModeSelectionList = typeOr { EntireLockingTable : LockingTableUID, SelectedLockingObjects : list [ LockingObjectUIDs] },
///      RangeStartRangeLengthPolicy = enum { 0 (User only), 1 (Admins only) },
///      DataStoreTableSizes = list [ integers ] ]
///   => [ ]
///
/// \param target                  [IN]  UID of target SP object to be activated at "Manufactured-Inactive" state.
/// \param pSingleUserModeList     [IN]  Optional, pointer to a caller provided buffer keeping a UID arrary for the Opal SSC's Single User Mode Fixed ACL "SingleUserModeSelectionList". Default NULL means omitted.
/// \param rangeStartLengthPolicy  [IN]  Optional, integer value to represent the Opal SSC's Single User Mode Fixed ACL "RangeStartRangeLengthPolicy". Default -1 means omitted.
/// \param pDataStoreTableSizes    [IN]  Optional, pointer to a caller provided buffer keeping a UINT64 arrary as the "DataStoreTableSizes" parameter for the number and sizes of the DataStore-tables. Default NULL means omitted.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgOpalSSC::_activate( TCG_UID target, TCG_UIDs *pSingleUserModeList, int rangeStartLengthPolicy, UINT64VALs *pDataStoreTableSizes )
{
   M_TCGTry()
   {
      // Set to Session Manager, ComID, TPer/Host SN should have been set
      m_commandBuffer.resize( m_blockSize );
      m_responseBuffer.resize( m_blockSize );

      dta::tByte* p = m_packetManager.setComBuffer( m_commandBuffer );
      p = m_tokenProcessor.buildCallTokenHeader( p, target, UID_M_ACTIVATE );

      if( NULL != pSingleUserModeList )
      {
         p = m_tokenProcessor.buildStartName( p );
         p = m_tokenProcessor.buildNamedValueTokenName( p, 0x060000 );

         if( (*pSingleUserModeList).size() > 0 && UID_TABLE_LOCKING == (*pSingleUserModeList)[0] )
         {
            p = m_tokenProcessor.buildUID( p, UID_TABLE_LOCKING ); // Entire Locking-Table
         }
         else // List of selected Locking Objects
         {
            p = m_tokenProcessor.buildStartList( p );

            for( unsigned int ii=0; ii < (*pSingleUserModeList).size(); ii++ )
               p = m_tokenProcessor.buildUID( p, (*pSingleUserModeList)[ii] );

            p = m_tokenProcessor.buildEndList( p );
         }

         p = m_tokenProcessor.buildEndName( p );
      }

      if( -1 != rangeStartLengthPolicy )
      {
         p = m_tokenProcessor.buildNamedValueToken( p, 0x060001, (tUINT64)rangeStartLengthPolicy );
      }

      if( NULL != pDataStoreTableSizes )
      {
         p = m_tokenProcessor.buildStartName( p );
         p = m_tokenProcessor.buildNamedValueTokenName( p, 0x060002 );

         p = m_tokenProcessor.buildStartList( p );
         for( unsigned int ii=0; ii < (*pDataStoreTableSizes).size(); ii++ )
            p = m_tokenProcessor.buildIntAtom( p, (*pDataStoreTableSizes)[ii] );
         p = m_tokenProcessor.buildEndList( p );

         p = m_tokenProcessor.buildEndName( p );
      }

      p = m_tokenProcessor.buildCallTokenFooter( p );

      tUINT32 len = m_packetManager.sealComPacket( p );
      m_commandBuffer.resize( len );

      securityPacketExchange();

      dta::tBytes respSubPacketPayload;
      m_packetManager.parseComPacket( m_responseBuffer, respSubPacketPayload );
   }
   M_TCGCatch( true, true );
} // _activate

//=================================================================================
/// \brief Activate the given SP object from "Manufactured-Inactive" to "Manufactured".
///
/// TCG method depiction
///   SPObjectUID.Activate[ 
///      SingaleUserModeSelectionList = typeOr { EntireLockingTable : LockingTableUID, SelectedLockingObjects : list [ LockingObjectUIDs] },
///      RangeStartRangeLengthPolicy = enum { 0 (User only), 1 (Admins only) },
///      DataStoreTableSizes = list [ integers ] ]
///   => [ ]
///
/// \param target                  [IN]  UID of target SP object to be activated at "Manufactured-Inactive" state.
/// \param pSingleUserModeList     [IN]  Optional, pointer to a caller provided buffer keeping a range/band number arrary for the Opal SSC's Single User Mode Fixed ACL "SingleUserModeSelectionList". Default NULL means omitted. The first integer value of -1 indicates the entire Locking Table.
/// \param rangeStartLengthPolicy  [IN]  Optional, integer value to represent the Opal SSC's Single User Mode Fixed ACL "RangeStartRangeLengthPolicy". Default -1 means omitted.
/// \param pDataStoreTableSizes    [IN]  Optional, pointer to a caller provided buffer keeping a UINT64 arrary as the "DataStoreTableSizes" parameter for the number and sizes of the DataStore-tables. Default NULL means omitted.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgOpalSSC::_activate( TCG_UID target, TCG_BANDNOs *pSingleUserModeList, int rangeStartLengthPolicy, UINT64VALs *pDataStoreTableSizes )
{
   if( NULL != pSingleUserModeList )
   {
      TCG_UIDs singleUserModeList( (*pSingleUserModeList).size() );

      for( unsigned int ii=0; ii < (*pSingleUserModeList).size(); ii++ )
      {
         if( -1 == (*pSingleUserModeList)[ii] ) // -1 is denoted as the Entire Table
         {
            singleUserModeList[0] = UID_TABLE_LOCKING;
            singleUserModeList.resize( 1 );
            break;
         }

         if( 0 == (*pSingleUserModeList)[ii] )
            singleUserModeList[ii] = UID_LOCKING_RANGE0;
         else
            singleUserModeList[ii] = UID_LOCKING_RANGE1_OM + (*pSingleUserModeList)[ii] -1;
      }

      return _activate( target, &singleUserModeList, rangeStartLengthPolicy, pDataStoreTableSizes );
   }
   else
   {
      return _activate( target, (TCG_UIDs*) NULL, rangeStartLengthPolicy, pDataStoreTableSizes );
   }
} // _activate

//=================================================================================
/// \brief Reactivate the in-session Locking SP.
///
/// TCG method depiction
///   ThisSPUID.Activate[ 
///      SingaleUserModeSelectionList = typeOr { EntireLockingTable : LockingTableUID, SelectedLockingObjects : list [ LockingObjectUIDs] },
///      RangeStartRangeLengthPolicy = enum { 0 (User only), 1 (Admins only) },
///      Admin1PIN = bytes,
///      DataStoreTableSizes = list [ integers ] ]
///   => [ ]
///
/// \param pSingleUserModeList     [IN]  Optional, pointer to a caller provided buffer keeping a UID arrary for the Opal SSC's Single User Mode Fixed ACL "SingleUserModeSelectionList". Default NULL means omitted.
/// \param rangeStartLengthPolicy  [IN]  Optional, integer value to represent the Opal SSC's Single User Mode Fixed ACL "RangeStartRangeLengthPolicy". Default -1 means omitted.
/// \param pAdmin1PIN              [IN]  Optional, pointer to a caller provided byte buffer to represent the Opal SSC's Single User Mode Fixed ACL "Admin1PIN". Default NULL means omitted.
/// \param pDataStoreTableSizes    [IN]  Optional, pointer to a caller provided buffer keeping a UINT64 arrary as the "DataStoreTableSizes" parameter for the number and sizes of the DataStore-tables. Default NULL means omitted.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgOpalSSC::_reactivate( TCG_UIDs *pSingleUserModeList, int rangeStartLengthPolicy, dta::tBytes *pAdmin1PIN, UINT64VALs *pDataStoreTableSizes )
{
   M_TCGTry()
   {
      // Set to Session Manager, ComID, TPer/Host SN should have been set
      m_commandBuffer.resize( m_blockSize );
      m_responseBuffer.resize( m_blockSize );

      dta::tByte* p = m_packetManager.setComBuffer( m_commandBuffer );
      p = m_tokenProcessor.buildCallTokenHeader( p, UID_THIS_SP, UID_M_REACTIVATE );

      if( NULL != pSingleUserModeList )
      {
         p = m_tokenProcessor.buildStartName( p );
         p = m_tokenProcessor.buildNamedValueTokenName( p, 0x060000 );

         if( (*pSingleUserModeList).size() > 0 && UID_TABLE_LOCKING == (*pSingleUserModeList)[0] )
         {
            p = m_tokenProcessor.buildUID( p, UID_TABLE_LOCKING ); // Entire Locking-Table
         }
         else // List of selected Locking Objects
         {
            p = m_tokenProcessor.buildStartList( p );

            for( unsigned int ii=0; ii < (*pSingleUserModeList).size(); ii++ )
               p = m_tokenProcessor.buildUID( p, (*pSingleUserModeList)[ii] );

            p = m_tokenProcessor.buildEndList( p );
         }

         p = m_tokenProcessor.buildEndName( p );
      }

      if( -1 != rangeStartLengthPolicy )
      {
         p = m_tokenProcessor.buildNamedValueToken( p, 0x060001, (tUINT64)rangeStartLengthPolicy );
      }

      if( NULL != pAdmin1PIN )
      {
         if( (*pAdmin1PIN).size() > 0 )
            p = m_tokenProcessor.buildNamedValueToken( p, 0x060002, &(*pAdmin1PIN)[0], (tUINT32)(*pAdmin1PIN).size(), false );
		 else
            p = m_tokenProcessor.buildNamedValueToken( p, 0x060002, (dta::tByte *)"", 0, false );
      }

      if( NULL != pDataStoreTableSizes )
      {
         p = m_tokenProcessor.buildStartName( p );
         p = m_tokenProcessor.buildNamedValueTokenName( p, 0x060003 );

         p = m_tokenProcessor.buildStartList( p );
         for( unsigned int ii=0; ii < (*pDataStoreTableSizes).size(); ii++ )
            p = m_tokenProcessor.buildIntAtom( p, (*pDataStoreTableSizes)[ii] );
         p = m_tokenProcessor.buildEndList( p );

         p = m_tokenProcessor.buildEndName( p );
      }

      p = m_tokenProcessor.buildCallTokenFooter( p );

      tUINT32 len = m_packetManager.sealComPacket( p );
      m_commandBuffer.resize( len );

      securityPacketExchange();

      dta::tBytes respSubPacketPayload;
      m_packetManager.parseComPacket( m_responseBuffer, respSubPacketPayload );
   }
   M_TCGCatch( true, true );
} // _reactivate

//=================================================================================
/// \brief Reactivate the in-session Locking SP.
///
/// TCG method depiction
///   ThisSPUID.Reactivate[ 
///      SingaleUserModeSelectionList = typeOr { EntireLockingTable : LockingTableUID, SelectedLockingObjects : list [ LockingObjectUIDs] },
///      RangeStartRangeLengthPolicy = enum { 0 (User only), 1 (Admins only) },
///      Admin1PIN = bytes,
///      DataStoreTableSizes = list [ integers ] ]
///   => [ ]
///
/// \param pSingleUserModeList     [IN]  Optional, pointer to a caller provided buffer keeping a range/band number arrary for the Opal SSC's Single User Mode Fixed ACL "SingleUserModeSelectionList". Default NULL means omitted. The first integer value of -1 indicates the entire Locking Table.
/// \param rangeStartLengthPolicy  [IN]  Optional, integer value to represent the Opal SSC's Single User Mode Fixed ACL "RangeStartRangeLengthPolicy". Default -1 means omitted.
/// \param pAdmin1PIN              [IN]  Optional, pointer to a caller provided byte buffer to represent the Opal SSC's Single User Mode Fixed ACL "Admin1PIN". Default NULL means omitted.
/// \param pDataStoreTableSizes    [IN]  Optional, pointer to a caller provided buffer keeping a UINT64 arrary as the "DataStoreTableSizes" parameter for the number and sizes of the DataStore-tables. Default NULL means omitted.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgOpalSSC::_reactivate( TCG_BANDNOs *pSingleUserModeList, int rangeStartLengthPolicy, dta::tBytes *pAdmin1PIN, UINT64VALs *pDataStoreTableSizes )
{
   if( NULL != pSingleUserModeList )
   {
      TCG_UIDs singleUserModeList( (*pSingleUserModeList).size() );

      for( unsigned int ii=0; ii < (*pSingleUserModeList).size(); ii++ )
      {
         if( -1 == (*pSingleUserModeList)[ii] ) // -1 is denoted as the Entire Table
         {
            singleUserModeList[0] = UID_TABLE_LOCKING;
            singleUserModeList.resize( 1 );
            break;
         }

         if( 0 == (*pSingleUserModeList)[ii] )
            singleUserModeList[ii] = UID_LOCKING_RANGE0;
         else
            singleUserModeList[ii] = UID_LOCKING_RANGE1_OM + (*pSingleUserModeList)[ii] -1;
      }

      return _reactivate( &singleUserModeList, rangeStartLengthPolicy, pAdmin1PIN, pDataStoreTableSizes );
   }
   else
   {
      return _reactivate( (TCG_UIDs*) NULL, rangeStartLengthPolicy, pAdmin1PIN, pDataStoreTableSizes );
   }
} // _reactivate

//=================================================================================
/// \brief Revert the given object to its factory state on the TPer.
///
/// \param target  [IN]  UID of target object to be reverted.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgOpalSSC::_revert( TCG_UID target )
{
   M_TCGTry()
   {
      // Set to Session Manager, ComID, TPer/Host SN should have been set
      m_commandBuffer.resize( m_blockSize );
      m_responseBuffer.resize( m_blockSize );

      dta::tByte* p = m_packetManager.setComBuffer( m_commandBuffer );
      p = m_tokenProcessor.buildCallToken( p, target, UID_M_REVERT );
      tUINT32 len = m_packetManager.sealComPacket( p );
      m_commandBuffer.resize( len );

      securityPacketExchange();

      dta::tBytes respSubPacketPayload;
      m_packetManager.parseComPacket( m_responseBuffer, respSubPacketPayload );
   }
   M_TCGCatch( true, true );
} // _revert

//=================================================================================
/// \brief Revert the current SP (ThisSP) to its factory state on the TPer.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgOpalSSC::_revertSP()
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

//=================================================================================
/// \brief Revert the current SP (ThisSP) to its factory state on the TPer.
///
/// \param bKeepGlobalRangeKey  [IN]  Whether or not to keep the GlobalRange encryption key after reverting.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgOpalSSC::_revertSP( bool bKeepGlobalRangeKey ) // Not supported yet in Seagate SED drives
{
   M_TCGTry()
   {
      // Set to Session Manager, ComID, TPer/Host SN should have been set
      m_commandBuffer.resize( m_blockSize );
      m_responseBuffer.resize( m_blockSize );

      dta::tByte* p = m_packetManager.setComBuffer( m_commandBuffer );
      p = m_tokenProcessor.buildCallTokenHeader( p, UID_THIS_SP, UID_M_REVERTSP );
      p = m_tokenProcessor.buildNamedValueToken( p, 0x060000, (tUINT64)bKeepGlobalRangeKey );
      p = m_tokenProcessor.buildCallTokenFooter( p );

      tUINT32 len = m_packetManager.sealComPacket( p );
      m_commandBuffer.resize( len );

      securityPacketExchange();

      dta::tBytes respSubPacketPayload;
      m_packetManager.parseComPacket( m_responseBuffer, respSubPacketPayload );
   }
   M_TCGCatch( true, true );
} // _revertSP

//=================================================================================
/// \brief Cryptographic erase a band/range of user space, and reset access control of the band on the TPer. (For Opal SU FixedACL fow now, but may extend to Opal later)
///
/// \param lockingObjectUID  [IN]  Band/range to be secure erased.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgOpalSSC::_erase( TCG_UID lockingObjectUID )
{
   M_TCGTry()
   {
      // Set to Session Manager, ComID, TPer/Host SN should have been set
      m_commandBuffer.resize( m_blockSize );
      m_responseBuffer.resize( m_blockSize );

      dta::tByte* p = m_packetManager.setComBuffer( m_commandBuffer );
      p = m_tokenProcessor.buildCallToken( p, lockingObjectUID, UID_M_ERASE );
      tUINT32 len = m_packetManager.sealComPacket( p );
      m_commandBuffer.resize( len );

      securityPacketExchange();

      dta::tBytes respSubPacketPayload;
      m_packetManager.parseComPacket( m_responseBuffer, respSubPacketPayload );
   }
   M_TCGCatch( true, true );
} // _erase

//=================================================================================
/// \brief Cryptographic erase a band/range of user space, and reset access control of the band on the TPer. (For Opal SU FixedACL fow now, but may extend to Opal later)
///
/// \param rangeNo  [IN]  Band/range number be secure erased.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgOpalSSC::_erase( int rangeNo )
{
   return _erase( (TCG_UID) ( rangeNo ? (UID_LOCKING_RANGE1_OM + rangeNo -1 ) : UID_LOCKING_RANGE0 ) );
} // _erase
