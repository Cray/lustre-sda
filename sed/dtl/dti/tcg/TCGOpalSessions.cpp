/*! \file TCGOpalSessions.cpp
    \brief Basic implementations of base class members from <TCG/TCGOpalSessions.hpp>.

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
#include "TCGOpalSessions.hpp"
#include "dtlcrypto.h"

#if defined(__linux__)
   // nvn20110719
   #define _stricmp(s1, s2) strcasecmp(s1, s2)
   //#define _strnicmp(s1, s2, n) strncasecmp(s1, s2, (n))
#endif

using namespace dta;
using namespace dti;

//=======================================================================================
// CTcgOpalSessions
//=======================================================================================
CTcgOpalSessions::CTcgOpalSessions(dta::CDriveTrustSession* newSession)
                 : CDriveTrustInterface(newSession), CTcgCoreInterface(newSession),
                   CTcgOpalSSC(newSession), CTcgSessions(newSession)
{
} // CTcgOpalSessions

//=======================================================================================
// CTcgOpalSessions
//=======================================================================================
CTcgOpalSessions::CTcgOpalSessions(dta::CDriveTrustSession* newSession, const _tstring logFileName)
                 : CDriveTrustInterface(newSession, logFileName), CTcgCoreInterface(newSession, logFileName),
                   CTcgOpalSSC(newSession, logFileName), CTcgSessions(newSession, logFileName)
{
} // CTcgOpalSessions

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
TCG_STATUS CTcgOpalSessions::readMBR( dta::tBytes & data, tINT64 startRow, tINT64 endRow, TCG_UID authorityID, tUINT8 *authenticatePin, tUINT16 pinLen, UserProgressUpdateCallBack progressUpdt, tUINT32 *pDurationMS )
{
   tUINT32 executionTime = 0;

   M_TCGTry()
   {
      _startSession( UID_SP_LOCKING_OM, authorityID, authenticatePin, pinLen, true, 0, -1, true );
      executionTime += getMethodExecTime();

      dta::tBytes d;
      tINT64 start = ( -1 == startRow ) ? 0 : startRow;
      tINT64 end = endRow;
      tINT64 chunk = getMaxUserDataLength();
      tINT64 numRows = 0;
      _getNumberOfRows( UID_TABLETABLE_MBR, (tUINT64 &)numRows );
      executionTime += getMethodExecTime();

      if( 0 != numRows )
      {
         if( -1 == end )
            end = numRows -1;
      }

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

            _get( UID_TABLE_MBR, d, start, start + len -1 );
            executionTime += getMethodExecTime();

            if( d.size() > 0 )
            {
               m_tokenProcessor.getAtomDataPointer( &d[0], &p, &size );
#if defined(_WIN32) // nvn20110719 - remove gcc warning
               if( size != len )
#else
               if( size != (tUINT64)len )
#endif
               {
                  throw dta::Error(eGenericInvalidParameter);
               }

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
      else
      {
         _get( UID_TABLE_MBR, d, startRow, endRow );
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
TCG_STATUS CTcgOpalSessions::writeMBR( dta::tBytes & data, tINT64 startRow, tINT64 endRow, TCG_UID authorityID, tUINT8 *authenticatePin, tUINT16 pinLen, UserProgressUpdateCallBack progressUpdt, tUINT32 *pDurationMS )
{
   if( UID_NULL == authorityID )
      authorityID = UID_AUT_ADMIN1;

   tUINT32 executionTime = 0;

   M_TCGTry()
   {
      _startSession( UID_SP_LOCKING_OM, authorityID, authenticatePin, pinLen, true, 0, -1, true );
      executionTime += getMethodExecTime();

      dta::tBytes d;
      tINT64 start = ( -1 == startRow ) ? 0 : startRow;
      tINT64 end = endRow;
      tINT64 chunk = getMaxUserDataLength();
      tINT64 numRows = 0;
      _getNumberOfRows( UID_TABLETABLE_MBR, (tUINT64 &)numRows );
      executionTime += getMethodExecTime();

      if( 0 != numRows )
      {
         if( -1 == end || end > numRows -1 )
            end = numRows -1;

         if( start + (tINT64)data.size() -1 < end )
            end = start + data.size() -1;
      }

      _startTransaction(); // Transaction provides roll-back to protect any broken MBR table updte
      executionTime += getMethodExecTime();

      if( -1 != end && end - start +1 > chunk )
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

            _set( UID_TABLE_MBR, d, start, start + len -1 );
            executionTime += getMethodExecTime();
            start += len;

            if( NULL != progressUpdt && start > end ) // 100%
               progressUpdt( end - start0 +1, start0, start-1, len );
         }
      }
      else
      {
         d.resize( data.size() + 4 );
         m_tokenProcessor.buildAtom( &d[0], &data[0], (tUINT32) data.size() );
         d.resize( m_tokenProcessor.sizeofAtom( &d[0]) );
         _set( UID_TABLE_MBR, d, startRow, endRow );
         executionTime += getMethodExecTime();
      }

      _endTransaction();
      executionTime += getMethodExecTime();

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
TCG_STATUS CTcgOpalSessions::readMBR( dta::tBytes & data, AuthenticationParameter & authent, tINT64 startRow, tINT64 endRow, UserProgressUpdateCallBack progressUpdt, tUINT32 *pDurationMS )
{
   return readMBR( data, startRow, endRow, mapAuthorityNameToUID( authent.AuthorityName ), authent.Pin, authent.PinLength, progressUpdt, pDurationMS );
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
TCG_STATUS CTcgOpalSessions::writeMBR( dta::tBytes & data, AuthenticationParameter & authent, tINT64 startRow, tINT64 endRow, UserProgressUpdateCallBack progressUpdt, tUINT32 *pDurationMS )
{
   return writeMBR( data, startRow, endRow, mapAuthorityNameToUID( authent.AuthorityName ), authent.Pin, authent.PinLength, progressUpdt, pDurationMS );
} // writeMBR

//=================================================================================
/// \brief Read/Get the states of Enable/Done/MBRDoneOnReset from the MBRControl table on the TPer.
///
/// \param row      [IN/OUT]  MBRControl table row data structure IOTableMBRControl. Must be initialized properly prior to entry.
/// \param authent  [IN]      AuthenticationParameter used for authentication.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgOpalSessions::readMBRControl( IOTableMBRControl & row, AuthenticationParameter & authent )
{
   M_TCGTry()
   {
      _startSession( UID_SP_LOCKING_OM, authent );
      _getMBRControl( row );
      _closeSession();
   }
   M_TCGCatch( false, false );

   if( !M_TCGResultOK() )
   {
      _closeSession();
   }

   M_TCGReturn( true );
} // readMBRControl

//=================================================================================
/// \brief Write/Set the states of Enable/Done/MBRDoneOnReset to the MBRControl table on the TPer.
///
/// \param row      [IN/OUT]  MBRControl table row data structure IOTableMBRControl. Must be initialized properly prior to entry.
/// \param authent  [IN]      AuthenticationParameter used for authentication.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgOpalSessions::writeMBRControl( IOTableMBRControl & row, AuthenticationParameter & authent )
{
   if( NULL == authent.AuthorityName )
#if defined(_WIN32) // nvn20110719 - remove gcc warning
      authent.AuthorityName = "Admin1";
#else
      authent.AuthorityName = (char *)"Admin1";
#endif

   M_TCGTry()
   {
      _startSession( UID_SP_LOCKING_OM, authent );
      _setMBRControl( row );
      _closeSession();
   }
   M_TCGCatch( false, false );

   if( !M_TCGResultOK() )
   {
      _closeSession();
   }

   M_TCGReturn( true );
} // writeMBRControl

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
TCG_STATUS CTcgOpalSessions::activate( TCG_UID targetSPUID, AuthenticationParameter & authent, TCG_UIDs *pSingleUserModeList, int rangeStartLengthPolicy, UINT64VALs *pDataStoreTableSizes )
{
   if( NULL == authent.AuthorityName )
#if defined(_WIN32) // nvn20110719 - remove gcc warning
      authent.AuthorityName = "SID";
#else
      authent.AuthorityName = (char *) "SID";
#endif

   M_TCGTry()
   {
      _startSession( UID_SP_ADMIN, authent );

      // Optionally, check the target SP's Life Cycle state
      IOTableSP row( false );
      row.LifeCycleState_isValid = true;  // Only parsing this item for faster return
      _getSP( targetSPUID, row );
      if( !row.LifeCycleState_isValid )
         throw dta::Error(eGenericInvalidParameter);

      if( row.LifeCycleState == evManufactured_Inactive )
      {
         // Activate the SP if in "Inactive" state
         _activate( targetSPUID, pSingleUserModeList, rangeStartLengthPolicy, pDataStoreTableSizes );
      }

      _closeSession();
   }
   M_TCGCatch( false, false );

   if( !M_TCGResultOK() )
   {
      _closeSession();
   }

   M_TCGReturn( true );
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
TCG_STATUS CTcgOpalSessions::activate( char *targetSPName, AuthenticationParameter & authent, TCG_BANDNOs *pSingleUserModeList, int rangeStartLengthPolicy, UINT64VALs *pDataStoreTableSizes )
{
   TCG_UID targetSPUID;
   if( !_stricmp( targetSPName, "Locking" ) )
      targetSPUID = UID_SP_LOCKING_OM;
   else
      throw dta::Error(eGenericInvalidParameter);

   if( NULL == authent.AuthorityName )
#if defined(_WIN32) // nvn20110719 - remove gcc warning
      authent.AuthorityName = "SID";
#else
      authent.AuthorityName = (char *)"SID";
#endif

   M_TCGTry()
   {
      _startSession( UID_SP_ADMIN, authent );

      // Optionally, check the target SP's Life Cycle state
      IOTableSP row( false );
      row.LifeCycleState_isValid = true;  // Only parsing this item for faster return
      _getSP( targetSPUID, row );
      if( !row.LifeCycleState_isValid )
         throw dta::Error(eGenericInvalidParameter);

      if( row.LifeCycleState == evManufactured_Inactive )
      {
         // Activate the SP if in "Inactive" state
         _activate( targetSPUID, pSingleUserModeList, rangeStartLengthPolicy, pDataStoreTableSizes );
      }

      _closeSession();
   }
   M_TCGCatch( false, false );

   if( !M_TCGResultOK() )
   {
      _closeSession();
   }

   M_TCGReturn( true );
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
TCG_STATUS CTcgOpalSessions::reactivate( AuthenticationParameter & authent, TCG_UIDs *pSingleUserModeList, int rangeStartLengthPolicy, dta::tBytes *pAdmin1PIN, UINT64VALs *pDataStoreTableSizes )
{
   if( NULL == authent.AuthorityName )
#if defined(_WIN32) // nvn20110719 - remove gcc warning
      authent.AuthorityName = "Admin1";
#else
      authent.AuthorityName = (char *)"Admin1";
#endif

   M_TCGTry()
   {
      _startSession( UID_SP_LOCKING_OM, authent );
      _reactivate( pSingleUserModeList, rangeStartLengthPolicy, pAdmin1PIN, pDataStoreTableSizes );
      // Session is auto closed without needing _closeSession();
   }
   M_TCGCatch( false, false );

   if( !M_TCGResultOK() )
   {
      _closeSession();
   }

   M_TCGReturn( true );
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
TCG_STATUS CTcgOpalSessions::reactivate( AuthenticationParameter & authent, TCG_BANDNOs *pSingleUserModeList, int rangeStartLengthPolicy, dta::tBytes *pAdmin1PIN, UINT64VALs *pDataStoreTableSizes )
{
   if( NULL == authent.AuthorityName )
#if defined(_WIN32) // nvn20110719 - remove gcc warning
      authent.AuthorityName = "Admin1";
#else
      authent.AuthorityName = (char *)"Admin1";
#endif

   M_TCGTry()
   {
      _startSession( UID_SP_LOCKING_OM, authent );
      _reactivate( pSingleUserModeList, rangeStartLengthPolicy, pAdmin1PIN, pDataStoreTableSizes );
      // Session is auto closed without needing _closeSession();
   }
   M_TCGCatch( false, false );

   if( !M_TCGResultOK() )
   {
      _closeSession();
   }

   M_TCGReturn( true );
} // reactivate

//=================================================================================
/// \brief Security TPer Reset.
///
/// \param syncHostTPerProperties [IN]  Whether or not to resynchronize communication Properties between Host and TPer after reset.
///
/// \return status byte of the response ComPacket for this method call.
//=================================================================================
TCG_STATUS CTcgOpalSessions::TPerReset( bool syncHostTPerProperties )
{
   TCG_STATUS status;

   status = programmaticTPerReset();

   if( syncHostTPerProperties )
      synchronizeHostTPerProperties();

   return status;
} // TPerReset

//=================================================================================
/// \brief Check if TPer Reset is supported by the SED.
///
/// \return true if TPerReset is supported, false otherwise.
//=================================================================================
bool CTcgOpalSessions::isTPerResetSupported()
{
   bool result = false;
   tUINT64 value = tINT64(-1);

   M_TCGTry()
   {
      dta::tBytes data;
      _startSession( UID_SP_ADMIN );
      _get( UID_TPERINFO_OM, data );
      _closeSession();

      if( !m_tokenProcessor.isList( data ) ) // At least one list present []
         throw dta::Error(eGenericInvalidIdentifier);

      tUINT8 *p1, *p2;
      p1 = p2 = &data[1];

      // Opal SSC2 supplies Column 8 ("ProgrammaticResetEnable") if TPerReset supported,
      // and row value of column is True or False to indicate if TPerReset is enabled.
      // Here we are just looking to see if the column is present in TPerInfoTable
      decodeNamedValue_Integer( p1, (tUINT32)(&data[0] + data.size() - 1 - p2), "ProgrammaticResetEnable", 8 );

      // If column 8 not found, p1 and p2 are still equal to &data[1].  jls20120404
      if( p1 != p2 )    // if found, p1 points to char after the Column 8 value
         result = true;
   }
   M_TCGCatchOnly( false );

   if( !M_TCGResultOK() )
   {
      _closeSession();
   }

   M_TCGThrowError( true );

   return result;
} // isTPerResetSupported

//=================================================================================
/// \brief Check if TPer Reset is enabled on the SED.    jls20120404
///
/// \return true if TPerReset is enabled, false otherwise.
//=================================================================================
bool CTcgOpalSessions::isTPerResetEnabled()
{
   bool result = false;
   tUINT64 value = 0;

   M_TCGTry()
   {
      dta::tBytes data;
      _startSession( UID_SP_ADMIN );
      _get( UID_TPERINFO_OM, data );
      _closeSession();

      if( !m_tokenProcessor.isList( data ) ) // At least []
         throw dta::Error(eGenericInvalidIdentifier);

      tUINT8 *p1, *p2;
      p1 = p2 = &data[1];

      // Opal SSC2 supplies Column 8 ("ProgrammaticResetEnable") if TPerReset supported,
      // and row value of column is True or False to indicate if TPerReset is enabled.
      // Here we are retrieving the value for column "ProgrammaticResetEnable".
      value = decodeNamedValue_Integer( p1, (tUINT32)(&data[0] + data.size() - 1 - p2), "ProgrammaticResetEnable", 8 );

      if( p1 == p2 )
         throw dta::Error( eGenericNotImplemented );

      if( value != 0 )
         result = true;    // Column exists and value is 1 (TRUE)
   }
   
   M_TCGCatchOnly( false );

   if( !M_TCGResultOK() )
   {
      _closeSession();
   }

   M_TCGThrowError( true );

   return result;
} // isTPerResetEnabled


//=================================================================================
/// \brief Set TPerReset enabled state if supported on the SED.  jls20120404
///
/// \return Success if TPerReset was set (true = enabled, false = disabled).
//=================================================================================
TCG_STATUS CTcgOpalSessions::setTPerResetEnable( AuthenticationParameter & authent, bool enable )
{
   TCG_STATUS status = TS_INVALID_PARAMETER;

   M_TCGTry()
   {
      _startSession( UID_SP_ADMIN );   

      // Must authenticate to SID in order to change the value of the TRE.
      if( NULL == authent.AuthorityName )
         authent.AuthorityName = (char *)"SID";

      _authenticate( authent ); // If no error thrown, then assume authentication succeeded.

      // Opal SSC2 supplies Column 8 ("ProgrammaticResetEnable") if TPerReset supported,
      // and row value of column is set True or False to indicate if TPerReset is enabled.

      dta::tBytes data( m_blockSize );
      tUINT8 *p = &data[0];

      p = m_tokenProcessor.buildStartList( p );
      p = encodeNamedValue_Integer( p, enable, "ProgrammaticResetEnable", 8 );
      p = m_tokenProcessor.buildEndList( p );
      data.resize( p - &data[0] );

      // Update ProgResetEnable colum
      _set( UID_TPERINFO_OM, data );

      _closeSession();

      status = TS_SUCCESS;
   }
   M_TCGCatchOnly( false );

   if( !M_TCGResultOK() )
   {
      _closeSession();
   }

   M_TCGThrowError( true );

   return status;
} // setTPerResetEnable()
