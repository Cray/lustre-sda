/*! \file TCGSessions.cpp
    \brief Basic implementations of base class members from <TCG/TCGSessions.hpp>.

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
#include "TCGSessions.hpp"
#include "dtlcrypto.h"

#if defined(__linux__)
   // nvn20110719
   #define _stricmp(s1, s2) strcasecmp(s1, s2)
   //#define _strnicmp(s1, s2, n) strncasecmp(s1, s2, (n))
#endif

using namespace dta;
using namespace dti;

//=======================================================================================
// CTcgSessions
//=======================================================================================
CTcgSessions::CTcgSessions(dta::CDriveTrustSession* newSession)
             : CDriveTrustInterface(newSession), CTcgCoreInterface(newSession)
{
   if( m_orphanSessionDetected )
      return;

   getMSID( m_MSID );
} // CTcgSessions

//=======================================================================================
// CTcgOpalSessions
//=======================================================================================
CTcgSessions::CTcgSessions(dta::CDriveTrustSession* newSession, const _tstring logFileName)
             : CDriveTrustInterface(newSession, logFileName), CTcgCoreInterface(newSession, logFileName)
{
   if( m_orphanSessionDetected )
      return;

   getMSID( m_MSID );
} // CTcgSessions

//=================================================================================
/// \brief Retrieve the number of user bands from the TPer's Locking-Info table.
///
/// \return the number of user bands.
//=================================================================================
int CTcgSessions::getMaxBands()
{
   IOTableLockingInfo row( false );
   row.MaxRanges_isValid = true;  // Only parsing this item for faster return

   getLockingInfoRow( row );

   if( !row.MaxRanges_isValid )
      throw dta::Error(eGenericInvalidIdentifier);

   return (int) row.MaxRanges;
} // getMaxBands

//=================================================================================
/// \brief Retrieve MSID from the TPer.
///
/// \param mSID       [OUT] MSID data retrieved from TPer.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgSessions::getMSID( dta::tBytes & mSID )
{
   M_TCGTry()
   {
      IOTableC_PIN pin;
	  pin.PIN_length = 0; // only parsing PIN for faster return

      _startSession( UID_SP_ADMIN );
      _getC_Pin( UID_C_PIN_MSID, pin ); //_get( UID_C_PIN_MSID, 3, 3, data ); // just "PIN"
      _closeSession();

      if( pin.PIN_length > 0 )
      {
         mSID.resize( pin.PIN_length );
         memcpy( &mSID[0], pin.PIN, pin.PIN_length );
      }
      else
      {
         mSID.resize( 0 );
         throw dta::Error(eGenericInvalidIdentifier);
      }
   }
   M_TCGCatch( false, false );

   if( !M_TCGResultOK() )
   {
      _closeSession();
   }

   M_TCGReturn( true );
} // getMSID

//=================================================================================
/// \brief Get values of ORG, DataofIssue, Bytes, LifeCycle state, and/or Frozen of a SP object in the SP table.      
///
/// \param row           [IN/OUT] SP table row data structure IOTableSP. Must be initialized properly prior to entry.
/// \param targetSPUID   [IN]     UID of the target SP, e.g., "AdminSP", "LockingSP".
/// \param authent       [IN]     AuthenticationParameter used for authentication, if required.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgSessions::getSPRow( IOTableSP & row, TCG_UID targetSPUID, AuthenticationParameter & authent )
{
   M_TCGTry()
   {
      if( isDeviceEnterpriseSSC() )
      {
         _startSession( UID_SP_ADMIN );
         if( NULL != authent.AuthorityName )
            _authenticate( authent );
      }
      else
      {
         _startSession( UID_SP_ADMIN, authent );
      }

      _getSP( targetSPUID, row );
      _closeSession();
   }
   M_TCGCatch( false, false );

   if( !M_TCGResultOK() )
   {
      _closeSession();
   }

   M_TCGReturn( true );
} // getSPRow

//=================================================================================
/// \brief Set values of ORG, DataofIssue, Bytes, LifeCycle state, and/or Frozen of a SP object in the SP table.      
///
/// \param row           [IN/OUT] SP table row data structure IOTableSP. Must be initialized properly prior to entry.
/// \param targetSPUID   [IN]     UID of the target SP, e.g., "AdminSP", "LockingSP".
/// \param authent       [IN]     AuthenticationParameter used for authentication, if required.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgSessions::setSPRow( IOTableSP & row, TCG_UID targetSPUID, AuthenticationParameter & authent )
{
   if( NULL == authent.AuthorityName )
#if defined(_WIN32) // nvn20110719 - remove gcc warning
      authent.AuthorityName = "SID";
#else
      authent.AuthorityName = (char *)"SID";
#endif

   M_TCGTry()
   {
      if( isDeviceEnterpriseSSC() )
      {
         _startSession( UID_SP_ADMIN );
         if( NULL != authent.AuthorityName )
            _authenticate( authent );
      }
      else
      {
         _startSession( UID_SP_ADMIN, authent );
      }

      _setSP( targetSPUID, row );
      _closeSession();
   }
   M_TCGCatch( false, false );

   if( !M_TCGResultOK() )
   {
      _closeSession();
   }

   M_TCGReturn( true );
} // setSPRow

//=================================================================================
/// \brief Get values of ORG, DataofIssue, Bytes, LifeCycle state, and/or Frozen of a SP object in the SP table.      
///
/// \param row           [IN/OUT] SP table row data structure IOTableSP. Must be initialized properly prior to entry.
/// \param targetSPName  [IN]     Target SP name, e.g., "Admin", or "Locking".
/// \param authent       [IN]     AuthenticationParameter used for authentication, if required.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgSessions::getSPRow( IOTableSP & row, char *targetSPName, AuthenticationParameter & authent )
{
   if( !_stricmp( targetSPName, "Admin" ) )
      return getSPRow( row, UID_SP_ADMIN, authent );
   else
      return getSPRow( row, (isDeviceEnterpriseSSC() ? UID_SP_LOCKING_E : UID_SP_LOCKING_OM), authent );

} // getSPRow

//=================================================================================
/// \brief Set values of ORG, DataofIssue, Bytes, LifeCycle state, and/or Frozen of a SP object in the SP table.      
///
/// \param row           [IN/OUT] SP table row data structure IOTableSP. Must be initialized properly prior to entry.
/// \param targetSPName  [IN]     Target SP name, e.g., "Admin", or "Locking".
/// \param authent       [IN]     AuthenticationParameter used for authentication, if required.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgSessions::setSPRow( IOTableSP & row, char *targetSPName, AuthenticationParameter & authent )
{
   if( !_stricmp( targetSPName, "Admin" ) )
      return setSPRow( row, UID_SP_ADMIN, authent );
   else
      return setSPRow( row, (isDeviceEnterpriseSSC() ? UID_SP_LOCKING_E : UID_SP_LOCKING_OM), authent );

} // setSPRow

//=================================================================================
/// \brief Get values of MaxRanges, MaxReEncryptions, etc, from the LockingInfo table row.
///
/// \param row             [IN/OUT] LockingInfo table row data structure IOTableLockingInfo. Must be initialized properly prior to entry.
/// \param authorityID     [IN]     Authority UID, if required, depending on the columns retrieved by the operation.
/// \param authenticatePin [IN]     Authentication pin to the SP. E.g., BandMaster1, Admin1 or User1, etc.
/// \param pinLen          [IN]     Length of the authentication pin.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgSessions::getLockingInfoRow( IOTableLockingInfo & row, TCG_UID authorityID, tUINT8 *authenticatePin, tUINT16 pinLen )
{
   if( NULL == authenticatePin && m_MSID.size() > 0 ) // caller is indicating to use MSID as the pin
   {
      authenticatePin = &m_MSID[0];
      pinLen = (tUINT8) m_MSID.size();
   }

   M_TCGTry()
   {
      if( isDeviceEnterpriseSSC() )
      {
         _startSession( UID_SP_LOCKING_E );
         if( UID_NULL != authorityID && NULL != authenticatePin && pinLen > 0 )
            _authenticate( authorityID, authenticatePin, pinLen );
      }
      else
      {
         _startSession( UID_SP_LOCKING_OM, authorityID, authenticatePin, pinLen );
      }

      _getLockingInfo( row );
      _closeSession();
   }
   M_TCGCatch( false, false );

   if( !M_TCGResultOK() )
   {
      _closeSession();
   }

   M_TCGReturn( true );
} // getLockingInfoRow

//=================================================================================
/// \brief Get values of MaxRanges, MaxReEncryptions, etc, from the LockingInfo table row.
///
/// \param row      [IN/OUT] LockingInfo table row data structure IOTableLockingInfo. Must be initialized properly prior to entry.
/// \param authent  [IN]     AuthenticationParameter used for authentication.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgSessions::getLockingInfoRow( IOTableLockingInfo & row, AuthenticationParameter & authent )
{
   return getLockingInfoRow( row, mapAuthorityNameToUID(authent.AuthorityName), authent.Pin, authent.PinLength );
} // getLockingInfoRow

//=================================================================================
/// \brief Retrieve and return values of table columns of a range from the Locking table.
///
/// \param row             [IN/OUT] Locking table row data structure IOTableLocking. Must be initialized properly prior to entry.
/// \param rangeNo         [IN ]    The preferred locking range number, starting from 0 (GlobalRange), 1 (Range1), etc.
/// \param toStartSession  [IN]     StartSession needed before the first Get call, otherwise there's already an open session. Convenient with repeated calls to get multi-range data.
/// \param toCloseSession  [IN]     CloseSession needed after the last Get call, otherwise a subsequent CloseSession must be called seperately later.
/// \param authorityID     [IN]     Authority UID, if required by the operation, only if 'toStartSession' is true.
/// \param authenticatePin [IN]     Authentication pin to the SP. E.g., BandMaster1, Admin1 or User1, etc.
/// \param pinLen          [IN]     Length of the authentication pin.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgSessions::getLockingRow( IOTableLocking & row, int rangeNo, bool toStartSession, bool toCloseSession, TCG_UID authorityID, tUINT8 *authenticatePin, tUINT16 pinLen )
{
   if( NULL == authenticatePin && m_MSID.size() > 0 ) // caller is indicating to use MSID as the pin
   {
      authenticatePin = &m_MSID[0];
      pinLen = (tUINT8) m_MSID.size();
   }

   M_TCGTry()
   {
      if( toStartSession )
      {
         if( isDeviceEnterpriseSSC() )
         {
            _startSession( UID_SP_LOCKING_E );
            if( UID_NULL != authorityID && NULL != authenticatePin && pinLen > 0 )
               _authenticate( authorityID, authenticatePin, pinLen );
         }
         else
         {
            _startSession( UID_SP_LOCKING_OM, authorityID, authenticatePin, pinLen );
         }
      }

      _getLocking( rangeNo, row );

      if( toCloseSession )
         _closeSession();
   }
   M_TCGCatch( false, false );

   if( !M_TCGResultOK() )
   {
      _closeSession();
   }

   M_TCGReturn( true );
} // getLockingRow

//=================================================================================
/// \brief Set values of table columns of a range in the Locking table.
///
/// \param row             [IN/OUT] Locking table row data structure IOTableLocking. Must be initialized properly prior to entry.
/// \param rangeNo         [IN ]    The preferred locking range number, starting from 0 (GlobalRange), 1 (Range1), etc.
/// \param toStartSession  [IN]     StartSession needed before the first Get call, otherwise there's already an open session. Convenient with repeated calls to get multi-range data.
/// \param toCloseSession  [IN]     CloseSession needed after the last Get call, otherwise a subsequent CloseSession must be called seperately later.
/// \param authorityID     [IN]     Authority UID, if required by the operation, only if 'toStartSession' is true.
/// \param authenticatePin [IN]     Authentication pin to the SP. E.g., BandMaster1, Admin1 or User1, etc.
/// \param pinLen          [IN]     Length of the authentication pin.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgSessions::setLockingRow( IOTableLocking & row, int rangeNo, bool toStartSession, bool toCloseSession, TCG_UID authorityID, tUINT8 *authenticatePin, tUINT16 pinLen )
{
   if( NULL == authenticatePin && m_MSID.size() > 0 ) // caller is indicating to use MSID as the pin
   {
      authenticatePin = &m_MSID[0];
      pinLen = (tUINT8) m_MSID.size();
   }

   M_TCGTry()
   {
      if( toStartSession )
      {
         if( isDeviceEnterpriseSSC() )
         {
            _startSession( UID_SP_LOCKING_E );
            if( UID_NULL != authorityID && NULL != authenticatePin && pinLen > 0 )
               _authenticate( authorityID, authenticatePin, pinLen );
         }
         else
         {
            _startSession( UID_SP_LOCKING_OM, authorityID, authenticatePin, pinLen );
         }
      }

      _setLocking( rangeNo, row );

      if( toCloseSession )
         _closeSession();
   }
   M_TCGCatch( false, false );

   if( !M_TCGResultOK() )
   {
      _closeSession();
   }

   M_TCGReturn( true );
} // setLockingRow

//=================================================================================
/// \brief Retrieve and return values of table columns of a range from the Locking table.
///
/// \param row             [IN/OUT] Locking table row data structure IOTableLocking. Must be initialized properly prior to entry.
/// \param rangeNo         [IN ]    The preferred locking range number, starting from 0 (GlobalRange), 1 (Range1), etc.
/// \param authent         [IN]     AuthenticationParameter used for authentication.
/// \param toStartSession  [IN]     StartSession needed before the first Get call, otherwise there's already an open session. Convenient with repeated calls to get multi-range data.
/// \param toCloseSession  [IN]     CloseSession needed after the last Get call, otherwise a subsequent CloseSession must be called seperately later.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgSessions::getLockingRow( IOTableLocking & row, int rangeNo, AuthenticationParameter & authent, bool toStartSession, bool toCloseSession )
{
   return getLockingRow( row, rangeNo, toStartSession, toCloseSession, mapAuthorityNameToUID(authent.AuthorityName), authent.Pin, authent.PinLength );
} // getLockingRow

//=================================================================================
/// \brief Set values of table columns of a range in the Locking table.
///
/// \param row             [IN/OUT] Locking table row data structure IOTableLocking. Must be initialized properly prior to entry.
/// \param rangeNo         [IN ]    The preferred locking range number, starting from 0 (GlobalRange), 1 (Range1), etc.
/// \param authent         [IN]     AuthenticationParameter used for authentication.
/// \param toStartSession  [IN]     StartSession needed before the first Get call, otherwise there's already an open session. Convenient with repeated calls to get multi-range data.
/// \param toCloseSession  [IN]     CloseSession needed after the last Get call, otherwise a subsequent CloseSession must be called seperately later.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgSessions::setLockingRow( IOTableLocking & row, int rangeNo, AuthenticationParameter & authent, bool toStartSession, bool toCloseSession )
{
   return setLockingRow( row, rangeNo, toStartSession, toCloseSession, mapAuthorityNameToUID(authent.AuthorityName), authent.Pin, authent.PinLength );
} // setLockingRow

//=================================================================================
/// \brief Retrieve and return column values of a C_PIN object, SID, BandMaster, EraseMaster, Admin, or User, etc, from the C_PIN table.
///
/// \param row             [IN/OUT] C_PIN table row data structure IOTableC_PIN. Must be initialized properly prior to entry.
/// \param targetID        [IN]     Target UID ("SID", "BandMaster", "EraseMaster", "Admin", or "User", etc).
/// \param authorityID     [IN]     Authority UID, if required by the operation.
/// \param authenticatePin [IN]     Authentication pin to the SP. E.g., BandMaster1, Admin1 or User1, etc.
/// \param pinLen          [IN]     Length of the authentication pin.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgSessions::getC_PINRow( IOTableC_PIN & row, TCG_UID targetID, TCG_UID authorityID, tUINT8 *authenticatePin, tUINT16 pinLen )
{
   if( NULL == authenticatePin && m_MSID.size() > 0 ) // caller is indicating to use MSID as the pin
   {
      authenticatePin = &m_MSID[0];
      pinLen = (tUINT8) m_MSID.size();
   }

   M_TCGTry()
   {
      if( UID_C_PIN_SID == targetID || UID_C_PIN_MSID == targetID || UID_C_PIN_PSID == targetID )
      {
         if( isDeviceEnterpriseSSC() )
         {
            _startSession( UID_SP_ADMIN );
            if( UID_NULL != authorityID && NULL != authenticatePin && pinLen > 0 )
               _authenticate( authorityID, authenticatePin, pinLen );
         }
         else
         {
            _startSession( UID_SP_ADMIN, authorityID, authenticatePin, pinLen );
         }

         _getC_Pin( targetID, row );
         _closeSession();
      }

      else if( UID_C_PIN_ERASEMASTER == targetID )
      {
         //if( UID_NULL == authorityID )
         //   authorityID = UID_AUT_ERASEMASTER;

         if( isDeviceEnterpriseSSC() )
         {
            _startSession( UID_SP_LOCKING_E );
            if( UID_NULL != authorityID && NULL != authenticatePin && pinLen > 0 )
               _authenticate( authorityID, authenticatePin, pinLen );
         }
         else // Marble-SSC
         {
            _startSession( UID_SP_LOCKING_OM, authorityID, authenticatePin, pinLen );
         }

         _getC_Pin( targetID, row );
         _closeSession();
      }

      else if( targetID >= UID_C_PIN_BANDMASTER0 && targetID < UID_C_PIN_BANDMASTER0 + 0x00000FFF ) //NNNh
      {
         //if( UID_NULL == authorityID )
         //   authorityID = targetID - UID_C_PIN_BANDMASTER0 + UID_AUT_BANDMASTER0;

         if( isDeviceEnterpriseSSC() )
         {
            _startSession( UID_SP_LOCKING_E );
            if( UID_NULL != authorityID && NULL != authenticatePin && pinLen > 0 )
               _authenticate( authorityID, authenticatePin, pinLen );
         }
         else // Marble-SSC
         {
            _startSession( UID_SP_LOCKING_OM, authorityID, authenticatePin, pinLen );
         }

         _getC_Pin( targetID, row );
         _closeSession();
      }

      else if( targetID >= UID_C_PIN_ADMIN1 && targetID < UID_C_PIN_ADMIN1 + 0x0000FFFF )  //NNNNh
      {
         //if( UID_NULL == authorityID )
         //   authorityID = targetID - UID_C_PIN_ADMIN1 + UID_AUT_ADMIN1;

         _startSession( UID_SP_LOCKING_OM, authorityID, authenticatePin, pinLen );
         _getC_Pin( targetID, row );
         _closeSession();
      }

      else if( targetID >= UID_C_PIN_USER1 && targetID < UID_C_PIN_USER1 + 0x0000FFFF )
      {
         //if( UID_NULL == authorityID )
         //   authorityID = targetID - UID_C_PIN_USER1 + UID_AUT_USER1;

         _startSession( UID_SP_LOCKING_OM, authorityID, authenticatePin, pinLen );
         _getC_Pin( targetID, row );
         _closeSession();
      }

      else
      {
         //std::wcerr << TXT("invalid request") << std::endl;
         throw dta::Error(eGenericInvalidParameter);
      }

   }
   M_TCGCatch( false, false );

   if( !M_TCGResultOK() )
   {
      _closeSession();
   }

   M_TCGReturn( true );
} // getC_PINRow

//=================================================================================
/// \brief Set values of columns of a C_PIN object, SID, BandMaster, EraseMaster, Admin, or User, etc, to the C_PIN table.
///
/// \param row             [IN/OUT] C_PIN table row data structure IOTableC_PIN. Must be initialized properly prior to entry.
/// \param targetID        [IN]     Target UID ("SID", "BandMaster", "EraseMaster", "Admin", or "User", etc).
/// \param authorityID     [IN]     Authority UID, if required by the operation.
/// \param authenticatePin [IN]     Authentication pin to the SP. E.g., BandMaster1, Admin1 or User1, etc.
/// \param pinLen          [IN]     Length of the authentication pin.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgSessions::setC_PINRow( IOTableC_PIN & row, TCG_UID targetID, TCG_UID authorityID, tUINT8 *authenticatePin, tUINT16 pinLen )
{
   if( NULL == authenticatePin && m_MSID.size() > 0 ) // caller is indicating to use MSID as the pin
   {
      authenticatePin = &m_MSID[0];
      pinLen = (tUINT8) m_MSID.size();
   }

   M_TCGTry()
   {
      if( UID_C_PIN_SID == targetID || UID_C_PIN_MSID == targetID || UID_C_PIN_PSID == targetID )
      {
         if( isDeviceEnterpriseSSC() )
         {
            _startSession( UID_SP_ADMIN );
            if( UID_NULL != authorityID && NULL != authenticatePin && pinLen > 0 )
               _authenticate( authorityID, authenticatePin, pinLen );
         }
         else
         {
            _startSession( UID_SP_ADMIN, authorityID, authenticatePin, pinLen );
         }

         _setC_Pin( targetID, row );
         _closeSession();
      }

      else if( UID_C_PIN_ERASEMASTER == targetID )
      {
         if( UID_NULL == authorityID )
            authorityID = UID_AUT_ERASEMASTER;

         if( isDeviceEnterpriseSSC() )
         {
            _startSession( UID_SP_LOCKING_E );
            if( UID_NULL != authorityID && NULL != authenticatePin && pinLen > 0 )
               _authenticate( authorityID, authenticatePin, pinLen );
         }
         else // Marble-SSC
         {
            _startSession( UID_SP_LOCKING_OM, authorityID, authenticatePin, pinLen );
         }

         _setC_Pin( targetID, row );
         _closeSession();
      }

      else if( targetID >= UID_C_PIN_BANDMASTER0 && targetID < UID_C_PIN_BANDMASTER0 + 0x00000FFF ) //NNNh
      {
         if( UID_NULL == authorityID )
            authorityID = targetID - UID_C_PIN_BANDMASTER0 + UID_AUT_BANDMASTER0;

         if( isDeviceEnterpriseSSC() )
         {
            _startSession( UID_SP_LOCKING_E );
            if( UID_NULL != authorityID && NULL != authenticatePin && pinLen > 0 )
               _authenticate( authorityID, authenticatePin, pinLen );
         }
         else // Marble-SSC
         {
            _startSession( UID_SP_LOCKING_OM, authorityID, authenticatePin, pinLen );
         }

         _setC_Pin( targetID, row );
         _closeSession();
      }

      else if( targetID >= UID_C_PIN_ADMIN1 && targetID < UID_C_PIN_ADMIN1 + 0x0000FFFF )  //NNNNh
      {
         if( UID_NULL == authorityID )
            authorityID = targetID - UID_C_PIN_ADMIN1 + UID_AUT_ADMIN1;

         _startSession( UID_SP_LOCKING_OM, authorityID, authenticatePin, pinLen );
         _setC_Pin( targetID, row );
         _closeSession();
      }

      else if( targetID >= UID_C_PIN_USER1 && targetID < UID_C_PIN_USER1 + 0x0000FFFF )
      {
         if( UID_NULL == authorityID )
            authorityID = targetID - UID_C_PIN_USER1 + UID_AUT_USER1;

         _startSession( UID_SP_LOCKING_OM, authorityID, authenticatePin, pinLen );
         _setC_Pin( targetID, row );
         _closeSession();
      }

      else
      {
         //std::wcerr << TXT("invalid request") << std::endl;
         throw dta::Error(eGenericInvalidParameter);
      }
   }
   M_TCGCatch( false, false );

   if( !M_TCGResultOK() )
   {
      _closeSession();
   }

   M_TCGReturn( true );
} // setC_PINRow

//=================================================================================
/// \brief Retrieve and return column values of a C_PIN object, SID, BandMaster, EraseMaster, Admin, or User, etc, from the C_PIN table.
///
/// \param row             [IN/OUT] C_PIN table row data structure IOTableC_PIN. Must be initialized properly prior to entry.
/// \param targetName      [IN]     Target name ("SID", "BandMaster", "EraseMaster", "Admin", or "User", etc).
/// \param authent         [IN]     AuthenticationParameter used for authentication.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgSessions::getC_PINRow( IOTableC_PIN & row, char * targetName, AuthenticationParameter & authent )
{
   return getC_PINRow( row, mapPinNameToUID(targetName), mapAuthorityNameToUID(authent.AuthorityName), authent.Pin, authent.PinLength );
} // getC_PINRow

//=================================================================================
/// \brief Set values of columns of a C_PIN object, SID, BandMaster, EraseMaster, Admin, or User, etc, to the C_PIN table.
///
/// \param row             [IN/OUT] C_PIN table row data structure IOTableC_PIN. Must be initialized properly prior to entry.
/// \param targetName      [IN]     Target name ("SID", "BandMaster", "EraseMaster", "Admin", or "User", etc).
/// \param authent         [IN]     AuthenticationParameter used for authentication.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgSessions::setC_PINRow( IOTableC_PIN & row, char * targetName, AuthenticationParameter & authent )
{
   return setC_PINRow( row, mapPinNameToUID(targetName), mapAuthorityNameToUID(authent.AuthorityName), authent.Pin, authent.PinLength );
} // setC_PINRow

//=================================================================================
/// \brief Retrieve and return column values of an Authority object, SID, BandMaster, EraseMaster, Admin, or User, etc, from the Authority table.
///
/// \param row             [IN/OUT] C_PIN table row data structure IOIOTableAuthority. Must be initialized properly prior to entry.
/// \param targetID        [IN]     Target authority UID ("SID", "BandMaster", "EraseMaster", "Admin", or "User", etc).
/// \param authorityID     [IN]     Authority UID, if required, depending on the operation.
/// \param authenticatePin [IN]     Authentication pin to the SP. E.g., BandMaster1, Admin1 or User1, etc.
/// \param pinLen          [IN]     Length of the authentication pin.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgSessions::getAuthorityRow( IOTableAuthority & row, TCG_UID targetID, TCG_UID authorityID, tUINT8 *authenticatePin, tUINT16 pinLen )
{
   if( NULL == authenticatePin && m_MSID.size() > 0 ) // caller is indicating to use MSID as the pin
   {
      authenticatePin = &m_MSID[0];
      pinLen = (tUINT8) m_MSID.size();
   }

   M_TCGTry()
   {
      if( isDeviceEnterpriseSSC() )
      {
         _startSession( (( UID_AUT_MAKERS == targetID || UID_AUT_SID == targetID || UID_AUT_MSID == targetID || UID_AUT_PSID == targetID ) ? UID_SP_ADMIN : UID_SP_LOCKING_E) );
         if( UID_NULL != authorityID && NULL != authenticatePin && pinLen > 0 )
            _authenticate( authorityID, authenticatePin, pinLen );
      }
      else
      {
         _startSession( (( UID_AUT_MAKERS == targetID || UID_AUT_SID == targetID || UID_AUT_MSID == targetID || UID_AUT_PSID == targetID ) ? UID_SP_ADMIN : UID_SP_LOCKING_OM), authorityID, authenticatePin, pinLen );
      }

      _getAuthority( targetID, row );
      _closeSession();
   }
   M_TCGCatch( false, false );

   if( !M_TCGResultOK() )
   {
      _closeSession();
   }

   M_TCGReturn( true );
} // getAuthorityRow

//=================================================================================
/// \brief Set values of columns of an Authority object, SID, BandMaster, EraseMaster, Admin, or User, etc, to the Authority table.
///
/// \param row             [IN/OUT] C_PIN table row data structure IOTableAuthority. Must be initialized properly prior to entry.
/// \param targetID        [IN]     Target authority UID ("SID", "BandMaster", "EraseMaster", "Admin", or "User", etc).
/// \param authorityID     [IN]     Authority UID, if required, depending on the operation.
/// \param authenticatePin [IN]     Authentication pin to the SP. E.g., BandMaster1, Admin1 or User1, etc.
/// \param pinLen          [IN]     Length of the authentication pin.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgSessions::setAuthorityRow( IOTableAuthority & row, TCG_UID targetID, TCG_UID authorityID, tUINT8 *authenticatePin, tUINT16 pinLen )
{
   if( NULL == authenticatePin && m_MSID.size() > 0 ) // caller is indicating to use MSID as the pin
   {
      authenticatePin = &m_MSID[0];
      pinLen = (tUINT8) m_MSID.size();
   }

   M_TCGTry()
   {
      if( isDeviceEnterpriseSSC() )
      {
         _startSession( (( UID_AUT_MAKERS == targetID || UID_AUT_SID == targetID || UID_AUT_MSID == targetID || UID_AUT_PSID == targetID || UID_AUT_ADMINSP_ADMIN1 == targetID ) ? UID_SP_ADMIN : UID_SP_LOCKING_E) ); // jls20120404 - AdminX in both AdminSP and LockingSP
         if( UID_NULL != authorityID && NULL != authenticatePin && pinLen > 0 )
            _authenticate( authorityID, authenticatePin, pinLen );
      }
      else
      {
         _startSession( (( UID_AUT_MAKERS == targetID || UID_AUT_SID == targetID || UID_AUT_MSID == targetID || UID_AUT_PSID == targetID || UID_AUT_ADMINSP_ADMIN1 == targetID ) ? UID_SP_ADMIN : UID_SP_LOCKING_OM), authorityID, authenticatePin, pinLen ); // jls20120404 - AdminX in both AdminSP and LockingSP
      }

      _setAuthority( targetID, row );
      _closeSession();
   }
   M_TCGCatch( false, false );

   if( !M_TCGResultOK() )
   {
      _closeSession();
   }

   M_TCGReturn( true );
} // setAuthorityRow

//=================================================================================
/// \brief Retrieve and return column values of an Authority object, SID, BandMaster, EraseMaster, Admin, or User, etc, from the Authority table.
///
/// \param row             [IN/OUT] C_PIN table row data structure IOTableAuthority. Must be initialized properly prior to entry.
/// \param targetName      [IN]     Target authority name ("SID", "BandMaster", "EraseMaster", "Admin", or "User", etc).
/// \param authent         [IN]     AuthenticationParameter used for authentication.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgSessions::getAuthorityRow( IOTableAuthority & row, char * targetName, AuthenticationParameter & authent )
{
   return getAuthorityRow( row, mapAuthorityNameToUID(targetName), mapAuthorityNameToUID(authent.AuthorityName), authent.Pin, authent.PinLength );
} // getAuthorityRow

//=================================================================================
/// \brief Set values of columns of an Authority object, SID, BandMaster, EraseMaster, Admin, or User, etc, to the Authority table.
///
/// \param row             [IN/OUT] C_PIN table row data structure IOTableAuthority. Must be initialized properly prior to entry.
/// \param targetName      [IN]     Target authority name ("SID", "BandMaster", "EraseMaster", "Admin", or "User", etc).
/// \param authent         [IN]     AuthenticationParameter used for authentication.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgSessions::setAuthorityRow( IOTableAuthority & row, char * targetName, AuthenticationParameter & authent )
{
   return setAuthorityRow( row, mapAuthorityNameToUID(targetName), mapAuthorityNameToUID(authent.AuthorityName), authent.Pin, authent.PinLength );
} // setAuthorityRow

//=================================================================================
/// \brief Cryptographically erase a band of the TPer.
///
/// \param startBandNo     [IN]  Start band no.
/// \param endBandNo       [IN]  End band no.
/// \param authorityID     [IN]  Authority UID, if required by the operation.
/// \param authenticatePin [IN]  Authentication pin to Admin1.
/// \param pinLen          [IN]  Length of the authentication pin.
/// \param resetAccess     [IN]  Whether to unlock the band and reset the credential value upon method activation. This parameter means only for Opal FixedACL ranges. For normal Opal ranges, it should be set as FALSE. For Ent-SSC, it works as if it were always TRUE, regardless of its actual input.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgSessions::eraseBand( int startBandNo, int endBandNo, TCG_UID authorityID, tUINT8 *authenticatePin, tUINT16 pinLen, bool resetAccess )
{
   if( UID_NULL == authorityID )
      authorityID = isDeviceEnterpriseSSC() ? UID_AUT_ERASEMASTER : UID_AUT_ADMIN1;

   if( NULL == authenticatePin && m_MSID.size() > 0 ) // caller is indicating to use MSID as the pin
   {
      authenticatePin = &m_MSID[0];
      pinLen = (tUINT8) m_MSID.size();
   }

   M_TCGTry()
   {
      if( isDeviceEnterpriseSSC() )
      {
         _startSession( UID_SP_LOCKING_E );
         if( UID_NULL != authorityID && NULL != authenticatePin && pinLen > 0 )
            _authenticate( authorityID, authenticatePin, pinLen );

         for( int ii = startBandNo; ii <= endBandNo; ii++ )
            _erase( ii );
      }
      else
      {
         _startSession( UID_SP_LOCKING_OM, authorityID, authenticatePin, pinLen );

         if( resetAccess )
         {
            for( int ii = startBandNo; ii <= endBandNo; ii++ )
               _erase( ii );
         }
         else
         {
            IOTableLocking row(false);
            for( int ii = startBandNo; ii <= endBandNo; ii++ )
            {
               row.ActiveKey_isValid = true;
               _getLocking( ii, row );
               _genKey( row.ActiveKey );
            }
         }
      }

      _closeSession();
   }
   M_TCGCatch( false, false );

   if( !M_TCGResultOK() )
   {
      _closeSession();
   }

   M_TCGReturn( true );
} // eraseBand

//=================================================================================
/// \brief Cryptographically erase a band of the TPer.
///
/// \param startBandNo     [IN]  Start band no.
/// \param endBandNo       [IN]  End band no.
/// \param authent         [IN]  AuthenticationParameter used for authentication.
/// \param resetAccess     [IN]  Whether to unlock the band and reset the credential value upon method activation. This parameter means only for Opal FixedACL ranges. For normal Opal ranges, it should be set as FALSE. For Ent-SSC, it works as if it were always TRUE, regardless of its actual input.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgSessions::eraseBand( int startBandNo, int endBandNo, AuthenticationParameter & authent, bool resetAccess )
{
   return eraseBand( startBandNo, endBandNo, mapAuthorityNameToUID( authent.AuthorityName ), authent.Pin, authent.PinLength, resetAccess );
} // eraseBand

//=================================================================================
/// \brief Read/Get data from the DataStore table on the TPer.
///
/// \param data            [OUT] Data of raw bytes to be retrieved from the DataStore table.
/// \param targetDS        [IN]  Target Datastore table sequence number, starting at 0. Caller must adjust for 1-based numbering. 
/// \param startRow        [IN]  StartRow number of the data. -1 indicates the first row, as omitted parameter.
/// \param endRow          [IN]  EndRow number of the data. -1 indicates the last row, as omitted parameter.
/// \param authorityID     [IN]  Authority UID, if required by the operation.
/// \param authenticatePin [IN]  Authentication pin to the SP. E.g., BandMaster0 or Admin1.
/// \param pinLen          [IN]  Length of the authentication pin.
/// \param progressUpdt    [IN]  User's progress update routine callback function pointer, if supplied. NULL means no update.
/// \param pDurationMS     [IN]  Pointer to the variable to receive time duration of overall command execution in milli-seconds. NULL indicates not interested.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgSessions::readDataStore( dta::tBytes & data, int targetDS, tINT64 startRow, tINT64 endRow, TCG_UID authorityID, tUINT8 *authenticatePin, tUINT16 pinLen, UserProgressUpdateCallBack progressUpdt, tUINT32 *pDurationMS )
{
   tUINT32  executionTime = 0;
   tINT64   numRows = 0;

   M_TCGTry()
   {
      if( isDeviceEnterpriseSSC() )
      {
         _startSession( UID_SP_LOCKING_E, true, 0, -1, true );
         executionTime += getMethodExecTime();

         if( UID_NULL != authorityID )
         {
            _authenticate( authorityID, authenticatePin, pinLen );
            executionTime += getMethodExecTime();
         }

         // There is no TableTable so we can't get size from there, so
         // just use the default hard-coded value for Enterprise drives.
         numRows = getMaxTotalSizeOfDataStoreTables();
         executionTime += getMethodExecTime();
      }
      else
      {
         _startSession( UID_SP_LOCKING_OM, authorityID, authenticatePin, pinLen, true, 0, -1, true );
         executionTime += getMethodExecTime();

         _getNumberOfRows( UID_TABLETABLE_DATASTORE1_OM + targetDS, (tUINT64 &)numRows );
         executionTime += getMethodExecTime();
      }

      dta::tBytes d;
      tINT64 start = ( -1 == startRow ) ? 0 : startRow;
      tINT64 end = endRow;
      tINT64 chunk = getMaxUserDataLength();

      if( 0 != numRows )
      {
         if( -1 == end )
            end = numRows -1;
      }

      // If request is greater than max size that can be handled by 
      // a ComPacket, break it up into smaller chunks.
      if( -1 != end && end - start +1 > chunk )
      {
         tUINT8 *p;
         tUINT64 size;
         tUINT64 start0 = start;
         data.resize( (unsigned long)(end - start + 1) );
         if( data.size() != end - start + 1 ) // probably too big
            throw dta::Error(eGenericMemoryError);

         while( start <= end )
         {
            tINT64 len = (end - start +1 >= chunk ) ? chunk : (end - start +1);

            if( NULL != progressUpdt )
            {
               if( !progressUpdt( end - start0 +1, start0, start, len ) ) // User pressed Esc to abort
               {
                  data.resize( (unsigned long)(start- start0) );
                  break;
               }
            }

            _get( (isDeviceEnterpriseSSC() ? UID_TABLE_DATASTORE1_EM : UID_TABLE_DATASTORE1_OM) + ((tUINT64)targetDS << 32), d, start, start + len -1 );
            executionTime += getMethodExecTime();

            if( d.size() > 0 )
            {
               m_tokenProcessor.getAtomDataPointer( &d[0], &p, &size );

               if( size != (tUINT64)len )
                  throw dta::Error(eGenericInvalidParameter);

               memcpy( &data[(unsigned long)(start- start0)], p, (unsigned long) len );
            }
            else
            {
               data.resize( (unsigned long)(start- start0) );
               break;
            }

            start += len;

            if( NULL != progressUpdt && start > end ) // 100%
               progressUpdt( end - start0 +1, start0, start-1, len );
         }
      }
      else  // Request is smaller than max data chunk in ComPacket
      {
         _get( (isDeviceEnterpriseSSC() ? UID_TABLE_DATASTORE1_EM : UID_TABLE_DATASTORE1_OM) + ((tUINT64)targetDS << 32), d, start, end );
         executionTime += getMethodExecTime();

         if( d.size() > 0 )
            m_tokenProcessor.getAtomData( &d[0], data );
         else
            data.resize( 0 );
      }

      _closeSession();
      executionTime += getMethodExecTime();

   }
   M_TCGCatch( false, false );

   if( !M_TCGResultOK() )
   {
      _closeSession();
   }

   if( NULL != pDurationMS )
      *pDurationMS = executionTime;

   M_TCGReturn( true );
} // readDataStore

//=================================================================================
/// \brief Write/Set data to the DataStore table on the TPer.
///
/// \param data            [IN]  Data of raw bytes to be written to the DataStore table.
/// \param targetDS        [IN]  Target Datastore table sequence number, starting at 0. Caller must adjust for 1-based numbering. 
/// \param startRow        [IN]  StartRow number of the data. -1 indicates the first row, as omitted parameter.
/// \param endRow          [IN]  EndRow number of the data. -1 indicates the last row, as omitted parameter.
/// \param authorityID     [IN]  Authority UID required by the operation.
/// \param authenticatePin [IN]  Authentication pin to the SP. E.g., BandMaster0 or Admin1.
/// \param pinLen          [IN]  Length of the authentication pin.
/// \param progressUpdt    [IN]  User's progress update routine callback function pointer, if supplied. NULL means no update.
/// \param pDurationMS     [IN]  Pointer to the variable to receive time duration of overall command execution in milli-seconds. NULL indicates not interested.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgSessions::writeDataStore( dta::tBytes & data, int targetDS, tINT64 startRow, tINT64 endRow, TCG_UID authorityID, tUINT8 *authenticatePin, tUINT16 pinLen, UserProgressUpdateCallBack progressUpdt, tUINT32 *pDurationMS )
{
   tUINT32 executionTime = 0;
   tINT64 numRows = 0;

   M_TCGTry()
   {
      if( isDeviceEnterpriseSSC() )
      {
         _startSession( UID_SP_LOCKING_E, true, 0, -1, true );
         executionTime += getMethodExecTime();

         if( UID_NULL != authorityID )
         {
            _authenticate( authorityID, authenticatePin, pinLen );
            executionTime += getMethodExecTime();
         }

         // There is no TableTable so we can't get size from there, so
         // just use the default hard-coded value for Enterprise drives.
         numRows = getMaxTotalSizeOfDataStoreTables();
         executionTime += getMethodExecTime();
      }
      else
      {
         _startSession( UID_SP_LOCKING_OM, authorityID, authenticatePin, pinLen, true, 0, -1, true );
         executionTime += getMethodExecTime();
   
         _getNumberOfRows( UID_TABLETABLE_DATASTORE1_OM + targetDS, (tUINT64 &)numRows );
         executionTime += getMethodExecTime();
      }

      dta::tBytes d;
      tINT64 start = ( -1 == startRow ) ? 0 : startRow;
      tINT64 end = endRow;
      tINT64 chunk = getMaxUserDataLength();
      
      if( 0 != numRows )
      {
         if( -1 == end || end > numRows -1 )
            end = numRows -1;

         if( start + (tINT64)data.size() -1 < end )
            end = start + data.size() -1;
      }

      // If request is greater than max size that can be handled by 
      // a ComPacket, break it up into smaller chunks.
      if( -1 != end && end - start + 1 > chunk )
      {
         tUINT64 start0 = start;
         while( start <= end )
         {
            tINT64 len = (end - start +1 >= chunk ) ? chunk : (end - start +1);
            d.resize( (unsigned long)(len + 4) );
            m_tokenProcessor.buildAtom( &d[0], &data[(unsigned long)(start- start0)], (tUINT32) len );
            d.resize( m_tokenProcessor.sizeofAtom( &d[0]) );

            if( NULL != progressUpdt )
            {
               if( !progressUpdt( end - start0 +1, start0, start, len ) ) // User pressed Esc to abort
                  break;
            }

            _set( (isDeviceEnterpriseSSC() ? UID_TABLE_DATASTORE1_EM : UID_TABLE_DATASTORE1_OM) + ((tUINT64)targetDS << 32), d, start, start + len -1 );
            executionTime += getMethodExecTime();
            start += len;

            if( NULL != progressUpdt && start > end ) // 100%
               progressUpdt( end - start0 +1, start0, start-1, len );
         }
      }
      else // Request is smaller than max ComPacket size limit
      {
         d.resize( data.size() + 4 );
         m_tokenProcessor.buildAtom( &d[0], &data[0], (tUINT32) data.size() );
         d.resize( m_tokenProcessor.sizeofAtom( &d[0]) );
         _set( (isDeviceEnterpriseSSC() ? UID_TABLE_DATASTORE1_EM : UID_TABLE_DATASTORE1_OM) + ((tUINT64)targetDS << 32), d, startRow, endRow );
         executionTime += getMethodExecTime();
      }

      _closeSession();
      executionTime += getMethodExecTime();
   }
   M_TCGCatch( false, false );

   if( !M_TCGResultOK() )
   {
      _closeSession();
   }

   if( NULL != pDurationMS )
      *pDurationMS = executionTime;

   M_TCGReturn( true );
} // writeDataStore

//=================================================================================
/// \brief Read/Get data from the DataStore table on the TPer.
///
/// \param data            [OUT] Data of raw bytes to be retrieved from the DataStore table.
/// \param authent         [IN]  AuthenticationParameter used for authentication, if required/applicable.
/// \param targetDS        [IN]  Target Datastore table sequence number, starting from 0, if multiple datastore tables are supported. The "Additional_DataStore_Tables" spec defines DS table names starting from 1.
/// \param startRow        [IN]  StartRow number of the data. -1 indicates the first row, as omitted parameter.
/// \param endRow          [IN]  EndRow number of the data. -1 indicates the last row, as omitted parameter.
/// \param progressUpdt    [IN]  User's progress update routine callback function pointer, if supplied. NULL means no update.
/// \param pDurationMS     [IN]  Pointer to the variable to receive time duration of overall command execution in milli-seconds. NULL indicates not interested.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgSessions::readDataStore( dta::tBytes & data, AuthenticationParameter & authent, int targetDS, tINT64 startRow, tINT64 endRow, UserProgressUpdateCallBack progressUpdt, tUINT32 *pDurationMS )
{
   return readDataStore( data, targetDS, startRow, endRow, mapAuthorityNameToUID( authent.AuthorityName ), authent.Pin, authent.PinLength, progressUpdt, pDurationMS );
} // readDataStore

//=================================================================================
/// \brief Write/Set data to the DataStore table on the TPer.
///
/// \param data            [IN]  Data of raw bytes to be written to the DataStore table.
/// \param authent         [IN]  AuthenticationParameter used for authentication, if required/applicable.
/// \param targetDS        [IN]  Target Datastore table sequence number, starting from 0, if multiple datastore tables are supported. The "Additional_DataStore_Tables" spec defines DS table names starting from 1.
/// \param startRow        [IN]  StartRow number of the data. -1 indicates the first row, as omitted parameter.
/// \param endRow          [IN]  EndRow number of the data. -1 indicates the last row, as omitted parameter.
/// \param progressUpdt    [IN]  User's progress update routine callback function pointer, if supplied. NULL means no update.
/// \param pDurationMS     [IN]  Pointer to the variable to receive time duration of overall command execution in milli-seconds. NULL indicates not interested.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgSessions::writeDataStore( dta::tBytes & data, AuthenticationParameter & authent, int targetDS, tINT64 startRow, tINT64 endRow, UserProgressUpdateCallBack progressUpdt, tUINT32 *pDurationMS )
{
   return writeDataStore( data, targetDS, startRow, endRow, mapAuthorityNameToUID( authent.AuthorityName ), authent.Pin, authent.PinLength, progressUpdt, pDurationMS );
} // writeDataStore

//=================================================================================
/// \brief Read/Get a section of data from the MBR table on the TPer.
///
/// \param data            [OUT] Data of raw bytes to be retrieved from the MBR table.
/// \param startRow        [IN]  StartRow number of the data. -1 indicates the first row, as omitted parameter.
/// \param endRow          [IN]  EndRow number of the data. -1 indicates the last row, as omitted parameter.
/// \param authorityID     [IN]  Authority UID, if required by the operation.
/// \param authenticatePin [IN]  Authentication pin to the SP. E.g., Admin1 or User1.
/// \param pinLen          [IN]  Length of the authentication pin.
/// \param progressUpdt    [IN]  User's progress update routine callback function pointer, if supplied. NULL means no update.
/// \param pDurationMS     [IN]  Pointer to the variable to receive time duration of overall command execution in milli-seconds. NULL indicates not interested.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgSessions::readMBR( dta::tBytes & data, tINT64 startRow, tINT64 endRow, TCG_UID authorityID, tUINT8 *authenticatePin, tUINT16 pinLen, UserProgressUpdateCallBack progressUpdt, tUINT32 *pDurationMS )
{
   // Opal SSC specific
   //M_TCGReturnErr( (TCG_STATUS) TS_INVALID_PARAMETER );
   M_TCGReturnErr( dta::Error(eGenericNotImplemented) );
} // readMBR

//=================================================================================
/// \brief Write/Set a section of data to the MBR table on the TPer.
///
/// \param data            [IN]  Data of raw bytes to be written to the MBR table.
/// \param startRow        [IN]  StartRow number of the data. -1 indicates the first row, as omitted parameter.
/// \param endRow          [IN]  EndRow number of the data. -1 indicates the last row, as omitted parameter.
/// \param authorityID     [IN]  Authority UID required by the operation.
/// \param authenticatePin [IN]  Authentication pin to the SP. E.g., Admin1 or User1.
/// \param pinLen          [IN]  Length of the authentication pin.
/// \param progressUpdt    [IN]  User's progress update routine callback function pointer, if supplied. NULL means no update.
/// \param pDurationMS     [IN]  Pointer to the variable to receive time duration of overall command execution in milli-seconds. NULL indicates not interested.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgSessions::writeMBR( dta::tBytes & data, tINT64 startRow, tINT64 endRow, TCG_UID authorityID, tUINT8 *authenticatePin, tUINT16 pinLen, UserProgressUpdateCallBack progressUpdt, tUINT32 *pDurationMS )
{
   // Opal SSC specific
   //M_TCGReturnErr( (TCG_STATUS) TS_INVALID_PARAMETER );
   M_TCGReturnErr( dta::Error(eGenericNotImplemented) );
} // writeMBR

//=================================================================================
/// \brief Read/Get a section of data from the MBR table on the TPer.
///
/// \param data            [OUT] Data of raw bytes to be retrieved from the MBR table.
/// \param authent         [IN]  AuthenticationParameter used for authentication, if required/applicable.      
/// \param startRow        [IN]  StartRow number of the data. -1 indicates the first row, as omitted parameter.
/// \param endRow          [IN]  EndRow number of the data. -1 indicates the last row, as omitted parameter.
/// \param progressUpdt    [IN]  User's progress update routine callback function pointer, if supplied. NULL means no update.
/// \param pDurationMS     [IN]  Pointer to the variable to receive time duration of overall command execution in milli-seconds. NULL indicates not interested.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgSessions::readMBR( dta::tBytes & data, AuthenticationParameter & authent, tINT64 startRow, tINT64 endRow, UserProgressUpdateCallBack progressUpdt, tUINT32 *pDurationMS )
{
   // Opal SSC specific
   //M_TCGReturnErr( (TCG_STATUS) TS_INVALID_PARAMETER );
   M_TCGReturnErr( dta::Error(eGenericNotImplemented) );
} // readMBR

//=================================================================================
/// \brief Write/Set a section of data to the MBR table on the TPer.
///
/// \param data            [IN]  Data of raw bytes to be written to the MBR table.
/// \param authent         [IN]  AuthenticationParameter used for authentication, if required/applicable.      
/// \param startRow        [IN]  StartRow number of the data. -1 indicates the first row, as omitted parameter.
/// \param endRow          [IN]  EndRow number of the data. -1 indicates the last row, as omitted parameter.
/// \param progressUpdt    [IN]  User's progress update routine callback function pointer, if supplied. NULL means no update.
/// \param pDurationMS     [IN]  Pointer to the variable to receive time duration of overall command execution in milli-seconds. NULL indicates not interested.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgSessions::writeMBR( dta::tBytes & data, AuthenticationParameter & authent, tINT64 startRow, tINT64 endRow, UserProgressUpdateCallBack progressUpdt, tUINT32 *pDurationMS )
{
   // Opal SSC specific
   //M_TCGReturnErr( (TCG_STATUS) TS_INVALID_PARAMETER );
   M_TCGReturnErr( dta::Error(eGenericNotImplemented) );
} // writeMBR

//=================================================================================
/// \brief Read/Get the states of Enable/Done/MBRDoneOnReset from the MBRControl table on the TPer.
///
/// \param row      [IN/OUT]  MBRControl table row data structure IOTableMBRControl. Must be initialized properly prior to entry.
/// \param authent  [IN]      AuthenticationParameter used for authentication.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgSessions::readMBRControl( IOTableMBRControl & row, AuthenticationParameter & authent )
{
   // Opal SSC specific
   //M_TCGReturnErr( (TCG_STATUS) TS_INVALID_PARAMETER );
   M_TCGReturnErr( dta::Error(eGenericNotImplemented) );
} // readMBRControl

//=================================================================================
/// \brief Write/Set the states of Enable/Done/MBRDoneOnReset to the MBRControl table on the TPer.
///
/// \param row      [IN/OUT]  MBRControl table row data structure IOTableMBRControl. Must be initialized properly prior to entry.
/// \param authent  [IN]      AuthenticationParameter used for authentication.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgSessions::writeMBRControl( IOTableMBRControl & row, AuthenticationParameter & authent )
{
   // Opal SSC specific
   //M_TCGReturnErr( (TCG_STATUS) TS_INVALID_PARAMETER );
   M_TCGReturnErr( dta::Error(eGenericNotImplemented) );
} // writeMBRControl

//=================================================================================
/// \brief Enable an authority (E.g., User1) on the TPer.
///
/// \param targetID    [IN]  Target authority to be enabled. E.g., User1 authority.
/// \param authent     [IN]  AuthenticationParameter, if required by the operation.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgSessions::enableAuthority( TCG_UID targetID, AuthenticationParameter & authent )
{
   IOTableAuthority row;
   row.Enabled_isValid = true;  // Only setting this item
   row.Enabled = true;

   return setAuthorityRow( row, targetID, mapAuthorityNameToUID(authent.AuthorityName), authent.Pin, authent.PinLength );
} // enableAuthority

//=================================================================================
/// \brief Enable an authority (E.g., User1) on the TPer.
///
/// \param targetName  [IN]  Target authority to be enabled. E.g., User1 authority.
/// \param authent     [IN]  AuthenticationParameter, if required by the operation.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgSessions::enableAuthority( char * targetName, AuthenticationParameter & authent )
{
   IOTableAuthority row;
   row.Enabled_isValid = true;  // Only setting this item
   row.Enabled = true;

   return setAuthorityRow( row, targetName, authent );
} // enableAuthority

//=================================================================================
/// \brief Disable an authority (E.g., User1) on the TPer.
///
/// \param targetID    [IN]  Target authority to be disabled. E.g., User1 authority.
/// \param authent     [IN]  AuthenticationParameter, if required by the operation.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgSessions::disableAuthority( TCG_UID targetID, AuthenticationParameter & authent )
{
   IOTableAuthority row;
   row.Enabled_isValid = true;  // Only setting this item
   row.Enabled = false;

   return setAuthorityRow( row, targetID, mapAuthorityNameToUID(authent.AuthorityName), authent.Pin, authent.PinLength );
} // disableAuthority

//=================================================================================
/// \brief Disable an authority (E.g., User1) on the TPer.
///
/// \param targetName  [IN]  Target authority to be disabled. E.g., User1 authority.
/// \param authent     [IN]  AuthenticationParameter, if required by the operation.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgSessions::disableAuthority( char * targetName, AuthenticationParameter & authent )
{
   IOTableAuthority row;
   row.Enabled_isValid = true;  // Only setting this item
   row.Enabled = false;

   return setAuthorityRow( row, targetName, authent );
} // disableAuthority

//=================================================================================
/// \brief Set the "BooleanExpr" column of an ACE object in the ACE table for the specified authorities.
///
/// \param ace             [IN]  Target ACE object UID. E.g., ACE_Locking_Range1_Set_RdLocked.
/// \param authorities     [IN]  Authority UIDs to set to the given ACE object.
/// \param authorityID     [IN]  Authority UID, if required by the operation.
/// \param authenticatePin [IN]  Authentication pin to the SP. E.g., Admin1.
/// \param pinLen          [IN]  Length of the authentication pin.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgSessions::setAuthorityACE( TCG_UID ace, TCG_UIDs & authorities, TCG_UID authorityID, tUINT8 *authenticatePin, tUINT16 pinLen )
{
   M_TCGTry()
   {
      if( isDeviceEnterpriseSSC() )
      {
         _startSession( UID_SP_LOCKING_E );
         if( UID_NULL != authorityID && NULL != authenticatePin && pinLen > 0 )
            _authenticate( authorityID, authenticatePin, pinLen );
      }
      else
      {
         _startSession( UID_SP_LOCKING_OM, authorityID, authenticatePin, pinLen );
      }

      _setACE( ace, authorities );
      _closeSession();
   }
   M_TCGCatch( false, false );

   if( !M_TCGResultOK() )
   {
      _closeSession();
   }

   M_TCGReturn( true );
} // setAuthorityACE

//=================================================================================
/// \brief Set the "BooleanExpr" column of an ACE object in the ACE table for the specified authorities.
///
/// \param ace             [IN]  Target ACE object UID. E.g., ACE_Locking_Range1_Set_RdLocked.
/// \param authorities     [IN]  Authority UIDs to set to the given ACE object.
/// \param authent         [IN]  AuthenticationParameter, if required by the operation.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgSessions::setAuthorityACE( TCG_UID ace, TCG_UIDs & authorities, AuthenticationParameter & authent )
{
   return setAuthorityACE( ace, authorities, mapAuthorityNameToUID( authent.AuthorityName ), authent.Pin, authent.PinLength );
} // setAuthorityACE

//=================================================================================
/// \brief Revert a given SP to its factory state on the TPer.
///
/// \param targetSPUID   [IN]  target SP UID to revert.
/// \param authent       [IN]  AuthenticationParameter required by the operation, e.g., SP Owner PSID for AdminSP.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgSessions::revertSP( TCG_UID targetSPUID, AuthenticationParameter & authent )
{
   if( NULL == authent.Pin && m_MSID.size() > 0 ) // caller is indicating to use MSID as the pin
   {
      authent.Pin = &m_MSID[0];
      authent.PinLength = (tUINT8) m_MSID.size();
   }

   M_TCGTry()
   {
      if( UID_SP_ADMIN == targetSPUID )
      {
         if( NULL == authent.AuthorityName )
#if defined(_WIN32) // nvn20110719 - remove gcc warning
            authent.AuthorityName = "PSID";
#else
            authent.AuthorityName = (char *)"PSID";
#endif

         dta::tBytes PSID;
         if( m_MSID.size() > 0 )
         {
            if( &m_MSID[0] == authent.Pin && !_stricmp( authent.AuthorityName, "PSID" ) ) // using the reversed sequence of MSID as the default PSID
            {
               PSID.resize( m_MSID.size() );
               for( unsigned int ii=0; ii<m_MSID.size(); ii++ )   
                  PSID[m_MSID.size()-1 -ii] = m_MSID[ii];

               authent.Pin = &PSID[0];
            }
         }

         if( isDeviceEnterpriseSSC() )
         {
            _startSession( UID_SP_ADMIN );
            if( UID_NULL != mapAuthorityNameToUID(authent.AuthorityName) && NULL != authent.Pin && authent.PinLength > 0 )
               _authenticate( authent );
         }
         else
         {
            _startSession( UID_SP_ADMIN, authent );
         }

         _revertSP();
         m_packetManager.setTPerSN( 0 ); //closeSession() not required upon success
         if( m_useDynamicComID && isComIDMgmtSupported() )
         {
#ifdef __TCGSILO
            if( !useSilo() )
#endif
            {
               m_packetManager.setExtendedComID( (((tUINT32) m_Level0_SSC_BaseComID) << 16 ) & 0xFFFF0000 );
               //synchronizeHostTPerProperties();
            }
         }
      }

      else if( UID_SP_LOCKING_OM == targetSPUID ) // Opal/Marble
      {
         if( isDeviceEnterpriseSSC() )
            throw dta::Error(eGenericInvalidParameter);

         if( NULL == authent.AuthorityName )
#if defined(_WIN32) // nvn20110719 - remove gcc warning
            authent.AuthorityName = "Admin1";
#else
            authent.AuthorityName = (char *)"Admin1";
#endif

         _startSession( UID_SP_LOCKING_OM, authent );
         _revertSP();
         m_packetManager.setTPerSN( 0 ); //closeSession() not required upon success
         if( m_useDynamicComID && isComIDMgmtSupported() )
         {
#ifdef __TCGSILO
            if( !useSilo() )
#endif
            {
               m_packetManager.setExtendedComID( (((tUINT32) m_Level0_SSC_BaseComID) << 16 ) & 0xFFFF0000 );
               //synchronizeHostTPerProperties();
            }
         }
      }

      else
      {
         //std::wcerr << TXT("invalid request") << std::endl;
         throw dta::Error(eGenericInvalidParameter);
      }
   }
   M_TCGCatch( false, false );

   if( !M_TCGResultOK() )
   {
      _closeSession();
   }

   M_TCGReturn( true );
} // revertSP

//=================================================================================
/// \brief Revert a given SP to its factory state on the TPer.
///
/// \param targetSPName  [IN]  target SP name to revert, e.g., "Admin", "Locking".
/// \param authent       [IN]  AuthenticationParameter required by the operation, e.g., SP Owner PSID for AdminSP.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgSessions::revertSP( char *targetSPName, AuthenticationParameter & authent )
{
   if( NULL == authent.Pin && m_MSID.size() > 0 ) // caller is indicating to use MSID as the pin
   {
      authent.Pin = &m_MSID[0];
      authent.PinLength = (tUINT8) m_MSID.size();
   }

   M_TCGTry()
   {
      if( !_stricmp( targetSPName, "Admin" ) )
      {
         if( NULL == authent.AuthorityName )
#if defined(_WIN32) // nvn20110719 - remove gcc warning
            authent.AuthorityName = "PSID";
#else
            authent.AuthorityName = (char *)"PSID";
#endif

         dta::tBytes PSID;
         if( m_MSID.size() > 0 )
         {
            if( &m_MSID[0] == authent.Pin && !_stricmp( authent.AuthorityName, "PSID" ) ) // using the reversed sequence of MSID as the default PSID
            {
               PSID.resize( m_MSID.size() );
               for( unsigned int ii=0; ii<m_MSID.size(); ii++ )
                  PSID[m_MSID.size()-1 -ii] = m_MSID[ii];

               authent.Pin = &PSID[0];
            }
         }

         if( isDeviceEnterpriseSSC() )
         {
            _startSession( UID_SP_ADMIN );
            if( UID_NULL != mapAuthorityNameToUID(authent.AuthorityName) && NULL != authent.Pin && authent.PinLength > 0 )
               _authenticate( authent );
         }
         else
         {
            _startSession( UID_SP_ADMIN, authent );
         }

         _revertSP();
         m_packetManager.setTPerSN( 0 ); //closeSession() not required upon success
         if( m_useDynamicComID && isComIDMgmtSupported() )
         {
#ifdef __TCGSILO
            if( !useSilo() )
#endif
            {
               m_packetManager.setExtendedComID( (((tUINT32) m_Level0_SSC_BaseComID) << 16 ) & 0xFFFF0000 );
               //synchronizeHostTPerProperties();
            }
         }
      }

      else if( !_stricmp( targetSPName, "Locking" ) ) // Opal/Marble
      {
         if( isDeviceEnterpriseSSC() )
            throw dta::Error(eGenericInvalidParameter);

         if( NULL == authent.AuthorityName )
#if defined(_WIN32) // nvn20110719 - remove gcc warning
            authent.AuthorityName = "Admin1";
#else
            authent.AuthorityName = (char *)"Admin1";
#endif

         _startSession( UID_SP_LOCKING_OM, authent );
         _revertSP();
         m_packetManager.setTPerSN( 0 ); //closeSession() not required upon success
         if( m_useDynamicComID && isComIDMgmtSupported() )
         {
#ifdef __TCGSILO
            if( !useSilo() )
#endif
            {
               m_packetManager.setExtendedComID( (((tUINT32) m_Level0_SSC_BaseComID) << 16 ) & 0xFFFF0000 );
               //synchronizeHostTPerProperties();
            }
         }
      }

      else
      {
         //std::wcerr << TXT("invalid request") << std::endl;
         throw dta::Error(eGenericInvalidParameter);
      }
   }
   M_TCGCatch( false, false );

   if( !M_TCGResultOK() )
   {
      _closeSession();
   }

   M_TCGReturn( true );
} // revertSP

//=================================================================================
/// \brief Activate a given SP in "Manufactured-Inactive" to “Manufactured” state.
///
/// \param targetSPUID             [IN]  target SP UID to activate.
/// \param authent                 [IN]  AuthenticationParameter required by the operation, e.g., SP Owner SID for AdminSP.
/// \param pSingleUserModeList     [IN]  Optional, pointer to a caller provided buffer keeping a UID arrary for the Opal SSC's Single User Mode Fixed ACL "SingleUserModeSelectionList". Default NULL means omitted.
/// \param rangeStartLengthPolicy  [IN]  Optional, integer value to represent the Opal SSC's Single User Mode Fixed ACL "RangeStartRangeLengthPolicy". Default -1 means omitted.
/// \param pDataStoreTableSizes    [IN]  Optional, pointer to a caller provided buffer keeping a UINT64 arrary as the "DataStoreTableSizes" parameter for the number and sizes of the DataStore-tables. Default NULL means omitted.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgSessions::activate( TCG_UID targetSPUID, AuthenticationParameter & authent, TCG_UIDs *pSingleUserModeList, int rangeStartLengthPolicy, UINT64VALs *pDataStoreTableSizes )
{
   // Opal SSC specific
   //M_TCGReturnErr( (TCG_STATUS) TS_INVALID_PARAMETER );
   M_TCGReturnErr( dta::Error(eGenericNotImplemented) );
} // activate

//=================================================================================
/// \brief Activate a given SP in "Manufactured-Inactive" to “Manufactured” state.
///
/// \param targetSPName            [IN]  target SP name to activate, e.g., "Locking".
/// \param authent                 [IN]  AuthenticationParameter required by the operation, e.g., SP Owner SID for AdminSP.
/// \param pSingleUserModeList     [IN]  Optional, pointer to a caller provided buffer keeping a range/band number arrary for the Opal SSC's Single User Mode Fixed ACL "SingleUserModeSelectionList". Default NULL means omitted. The first integer value of -1 indicates the entire Locking Table.
/// \param rangeStartLengthPolicy  [IN]  Optional, integer value to represent the Opal SSC's Single User Mode Fixed ACL "RangeStartRangeLengthPolicy". Default -1 means omitted.
/// \param pDataStoreTableSizes    [IN]  Optional, pointer to a caller provided buffer keeping a UINT64 arrary as the "DataStoreTableSizes" parameter for the number and sizes of the DataStore-tables. Default NULL means omitted.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgSessions::activate( char *targetSPName, AuthenticationParameter & authent, TCG_BANDNOs *pSingleUserModeList, int rangeStartLengthPolicy, UINT64VALs *pDataStoreTableSizes )
{
   // Opal SSC specific
   //M_TCGReturnErr( (TCG_STATUS) TS_INVALID_PARAMETER );
   M_TCGReturnErr( dta::Error(eGenericNotImplemented) );
} // activate

//=================================================================================
/// \brief Reactivate Locking SP.
///
/// \param authent                 [IN]  AuthenticationParameter required by the operation, e.g., SP Owner SID for AdminSP.
/// \param pSingleUserModeList     [IN]  Optional, pointer to a caller provided buffer keeping a UID arrary for the Opal SSC's Single User Mode Fixed ACL "SingleUserModeSelectionList". Default NULL means omitted.
/// \param rangeStartLengthPolicy  [IN]  Optional, integer value to represent the Opal SSC's Single User Mode Fixed ACL "RangeStartRangeLengthPolicy". Default -1 means omitted.
/// \param pAdmin1PIN              [IN]  Optional, pointer to a caller provided byte buffer to represent the Opal SSC's Single User Mode Fixed ACL "Admin1PIN". Default NULL means omitted.
/// \param pDataStoreTableSizes    [IN]  Optional, pointer to a caller provided buffer keeping a UINT64 arrary as the "DataStoreTableSizes" parameter for the number and sizes of the DataStore-tables. Default NULL means omitted.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgSessions::reactivate( AuthenticationParameter & authent, TCG_UIDs *pSingleUserModeList, int rangeStartLengthPolicy, dta::tBytes *pAdmin1PIN, UINT64VALs *pDataStoreTableSizes )
{
   // Opal SSC specific
   //M_TCGReturnErr( (TCG_STATUS) TS_INVALID_PARAMETER );
   M_TCGReturnErr( dta::Error(eGenericNotImplemented) );
} // reactivate

//=================================================================================
/// \brief Reactivate Locking SP.
///
/// \param authent                 [IN]  AuthenticationParameter required by the operation, e.g., SP Owner SID for AdminSP.
/// \param pSingleUserModeList     [IN]  Optional, pointer to a caller provided buffer keeping a range/band number arrary for the Opal SSC's Single User Mode Fixed ACL "SingleUserModeSelectionList". Default NULL means omitted. The first integer value of -1 indicates the entire Locking Table.
/// \param rangeStartLengthPolicy  [IN]  Optional, integer value to represent the Opal SSC's Single User Mode Fixed ACL "RangeStartRangeLengthPolicy". Default -1 means omitted.
/// \param pAdmin1PIN              [IN]  Optional, pointer to a caller provided byte buffer to represent the Opal SSC's Single User Mode Fixed ACL "Admin1PIN". Default NULL means omitted.
/// \param pDataStoreTableSizes    [IN]  Optional, pointer to a caller provided buffer keeping a UINT64 arrary as the "DataStoreTableSizes" parameter for the number and sizes of the DataStore-tables. Default NULL means omitted.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgSessions::reactivate( AuthenticationParameter & authent, TCG_BANDNOs *pSingleUserModeList, int rangeStartLengthPolicy, dta::tBytes *pAdmin1PIN, UINT64VALs *pDataStoreTableSizes )
{
   // Opal SSC specific
   //M_TCGReturnErr( (TCG_STATUS) TS_INVALID_PARAMETER );
   M_TCGReturnErr( dta::Error(eGenericNotImplemented) );
} // reactivate

//=================================================================================
/// \brief Security protocol stack reset.
///
/// \param comChannel             [IN]  ComID channel index, starting from 0 to max.
/// \param syncHostTPerProperties [IN]  Whether or not to synchronize communication Properties between Host and TPer.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgSessions::protocolStackReset( int comChannel, bool syncHostTPerProperties )
{
   TCG_STATUS status;

   if( L0_DISCOVERY_FEATURECODE_UNSET == m_Level0_SSC_Code )
   {
      status = stackReset( EXT_COM_ID1 + ((tUINT32)comChannel << 16) );

      if( syncHostTPerProperties )
         synchronizeHostTPerProperties();

      return status;
   }

   if( comChannel < m_Level0_SSC_NumberComID )
   {
      status = stackReset( (tUINT32)(m_Level0_SSC_BaseComID + comChannel) << 16 );

      if( syncHostTPerProperties )
         synchronizeHostTPerProperties();

      return status;
   }

   M_TCGReturnErr( dta::Error(eGenericInvalidParameter) );
} // protocolStackReset

//=================================================================================
/// \brief Security TPer Reset.
///
/// \param syncHostTPerProperties [IN]  Whether or not to synchronize communication Properties between Host and TPer.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgSessions::TPerReset( bool syncHostTPerProperties )
{
   // Opal SSC specific
   //M_TCGReturnErr( (TCG_STATUS) TS_INVALID_PARAMETER );
   M_TCGReturnErr( dta::Error(eGenericNotImplemented) );
} // TPerReset

//=================================================================================
/// \brief Select the channel for a pre-issued (static) COMID.
///
/// \param comChannel             [IN]  ComID channel index, starting from 0 to max.
/// \param syncHostTPerProperties [IN]  Whether or not to synchronize communication Properties between Host and TPer.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgSessions::selectComChannel( int comChannel, bool syncHostTPerProperties )
{
#ifdef __TCGSILO
   if( !useSilo() )
#endif
   {
      if( comChannel >= 0 )
      {
         if( L0_DISCOVERY_FEATURECODE_UNSET == m_Level0_SSC_Code )
         {
            m_packetManager.setExtendedComID( EXT_COM_ID1 + ((tUINT32)comChannel << 16) );

            if( syncHostTPerProperties )
               synchronizeHostTPerProperties();

            return TS_SUCCESS;
         }
         else if( comChannel < m_Level0_SSC_NumberComID )
         {
            m_packetManager.setExtendedComID( (tUINT32)(m_Level0_SSC_BaseComID + comChannel) << 16 );

            if( syncHostTPerProperties )
               synchronizeHostTPerProperties();

            return TS_SUCCESS;
         }
      }

      M_TCGReturnErr( dta::Error(eGenericInvalidParameter) );
   }

#ifdef __TCGSILO
   return TS_SUCCESS;
#endif
} // selectComChannel

//=================================================================================
/// \brief Get the Security Operating Mode state from the _SecurityOperatingMode table (Seagate Proprietary).
///
/// \return byte value of the SOM state.
//=================================================================================
tUINT8 CTcgSessions::getSOM()
{
   tUINT8 som = 0xFF; // Undefined

   M_TCGTry()
   {
      _startSession( UID_SP_ADMIN );

      dta::tBytes data;
      TCG_STATUS status = _get( UID_TABLE_SECURITY_OPERATING_MODE, data );

      _closeSession();

      if( data.size() > 0 )
         som = (tUINT8) m_tokenProcessor.getAtomData( &data[0] );
      else
         throw dta::Error(eGenericInvalidIdentifier);
   }
   M_TCGCatch( false, false );

   if( !M_TCGResultOK() )
   {
      _closeSession();

   }

   M_TCGThrowError( true );

   return som;
} // getSOM

//=================================================================================
/// \brief Retrieve and return column values of an object from the _PortLocking table. (Seagate proprietary)
///
/// \param row          [IN/OUT] _PortLocking table row data structure IOTable_PortLocking. Must be initialized properly prior to entry.
/// \param targetPort   [IN]     UID of the target port object, e.g., "FWDownload".
/// \param authent      [IN]     AuthenticationParameter used for authentication.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgSessions::get_PortLockingRow( IOTable_PortLocking & row, TCG_UID targetPort, AuthenticationParameter & authent )
{
   if( NULL == authent.AuthorityName )
#if defined(_WIN32) // nvn20110719 - remove gcc warning
      authent.AuthorityName = "SID";
#else
      authent.AuthorityName = (char *)"SID";
#endif

   M_TCGTry()
   {
      if( isDeviceEnterpriseSSC() )
      {
         _startSession( UID_SP_ADMIN );
         if( NULL != authent.AuthorityName )
            _authenticate( authent );
      }
      else
      {
         _startSession( UID_SP_ADMIN, authent );
      }

      _get_PortLocking( targetPort, row );
      _closeSession();
   }
   M_TCGCatch( false, false );

   if( !M_TCGResultOK() )
   {
      _closeSession();
   }

   M_TCGReturn( true );
} // get_PortLockingRow

//=================================================================================
/// \brief Set values of table columns of an object in the _PortLocking table. (Seagate proprietary)
///
/// \param row          [IN/OUT] _PortLocking table row data structure IOTable_PortLocking. Must be initialized properly prior to entry.
/// \param targetPort   [IN]     UID of the target port object, e.g., "FWDownload".
/// \param authent      [IN]     AuthenticationParameter used for authentication.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgSessions::set_PortLockingRow( IOTable_PortLocking & row, TCG_UID targetPort, AuthenticationParameter & authent )
{
   if( NULL == authent.AuthorityName )
#if defined(_WIN32) // nvn20110719 - remove gcc warning
      authent.AuthorityName = "SID";
#else
      authent.AuthorityName = (char *)"SID";
#endif

   M_TCGTry()
   {
      if( isDeviceEnterpriseSSC() )
      {
         _startSession( UID_SP_ADMIN );
         if( NULL != authent.AuthorityName )
            _authenticate( authent );
      }
      else
      {
         _startSession( UID_SP_ADMIN, authent );
      }

      _set_PortLocking( targetPort, row );
      _closeSession();
   }
   M_TCGCatch( false, false );

   if( !M_TCGResultOK() )
   {
      _closeSession();
   }

   M_TCGReturn( true );
} // set_PortLockingRow

