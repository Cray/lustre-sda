/*! \file TCGInterface.cpp
    \brief Basic implementations of base class members from <TCG/TCGInterface.hpp>.

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
#include "TCGEntSessions.hpp"
#include "TCGOpalSessions.hpp"
//#include "TCGMarbleSessions.hpp"

using namespace dta;
using namespace dti;

//=======================================================================================
// ITCGInterface
//=======================================================================================

//=======================================================================================
ITCGInterface* ITCGInterface::CreateTCGInterface( dta::CDriveTrustSession* newSession, const _tstring logFileName, int ssc )
{
   ITCGInterface* pIF;

   if( -1 == ssc )
   {
      //
      // Pull Level0-discovery data to decide which specific TCG-SSC interface to create
      //
      CByteOrder swapper;
      dta::tBytes temp( 512, 0 );

      // TODO: Before executing a TCG Trusted I/O command, we should make sure drive supports TCG  
      
      //newSession->SetAttribute( TXT("Timeout"), TXT("10") );
      newSession->SecurityDataFromDevice( SECURITY_PROTOCOLID_COMPACKET_IO, SPSPECIFIC_P01_LEVEL0_DISCOVERY, temp );

      // parsing the details here
      tUINT32 length = swapper.NetToHost( *((tUINT32*)(&temp[0])) ) + sizeof(tUINT32);
      if( length < L0_DISCOVERY_HEADER_SIZE + L0_DISCOVERY_TPERDESCRIPTOR_SIZE + L0_DISCOVERY_LOCKINGDESCRIPTOR_SIZE + L0_DISCOVERY_SSCDESCRIPTOR_SIZE )
         throw dta::Error(eGenericInvalidIdentifier);

      tUINT8* p = &temp[L0_DISCOVERY_HEADER_SIZE];
      if( L0_DISCOVERY_FEATURECODE_TPER != swapper.NetToHost( *((tUINT16*)p) ) ) // Expecting TPER as the first descriptor
         throw dta::Error(eGenericInvalidIdentifier);

      p += 4 + *(p + 3);
      if( L0_DISCOVERY_FEATURECODE_LOCKING != swapper.NetToHost( *((tUINT16*)p) ) ) // Expecting Locking as the 2nd descriptor
         throw dta::Error(eGenericInvalidIdentifier);

      p += 4 + *(p + 3);
      switch( swapper.NetToHost( *((tUINT16*)p) ) ) // Expecting SSC descriptor
      {
         case L0_DISCOVERY_FEATURECODE_SSC_ENTERPRISE:
            ssc = 1;
            break;

         case L0_DISCOVERY_FEATURECODE_SSC_OPAL:
         case L0_DISCOVERY_FEATURECODE_SSC_OPAL_V2: // nvn20110520
            ssc = 2;
            break;

         case L0_DISCOVERY_FEATURECODE_SSC_MARBLE:
            ssc = 3;
            break;

         default: // unrecognized or invalid descriptor ID
            throw dta::Error(eGenericInvalidIdentifier);
      }
   }

   switch( ssc )
   {
      case 1:
         if( TXT("") == logFileName )
            pIF = new CTcgEntSessions( newSession );
         else
            pIF = new CTcgEntSessions( newSession, logFileName );
         break;

      case 2:
         if( TXT("") == logFileName )
            pIF = new CTcgOpalSessions( newSession );
         else
            pIF = new CTcgOpalSessions( newSession, logFileName );
         break;

      case 3:
         pIF = NULL; // Add them here when they become available in the future
         break;

      default: // unrecognized or invalid SSC type
         throw dta::Error(eGenericInvalidParameter);
   }

   return pIF;
} // CreateTCGInterface

//=======================================================================================
void TPerProperties::setStateAll( bool valid )
{
   MaxComPacketSize_isValid = 
   MaxResponseComPacketSize_isValid = 
   MaxPacketSize_isValid = 
   MaxIndTokenSize_isValid = 
   MaxAggTokenSize_isValid = 
   MaxPackets_isValid = 
   MaxSubpackets_isValid = 
   MaxMethods_isValid = 
   MaxSessions_isValid = 
   MaxReadSessions_isValid = 
   MaxAuthentications_isValid = 
   MaxTransactionLimit_isValid = 
   DefSessionTimeout_isValid = 
   MaxSessionTimeout_isValid = 
   MinSessionTimeout_isValid = 
   DefTransTimeout_isValid = 
   MaxTransTimeout_isValid = 
   MinTransTimeout_isValid = 
   MaxComIDTime_isValid = 
   MaxComIDCMD_isValid = 
   ContinuedTokens_isValid = 
   SequenceNumbers_isValid = 
   AckNak_isValid = 
   Asynchronous_isValid = 
   RealTimeClock_isValid = valid;
} // setStateAll

//=======================================================================================
bool TPerProperties::isEmpty()
{
   return !( MaxComPacketSize_isValid || 
             MaxResponseComPacketSize_isValid ||
             MaxPacketSize_isValid || 
             MaxIndTokenSize_isValid || 
             MaxAggTokenSize_isValid || 
             MaxPackets_isValid || 
             MaxSubpackets_isValid || 
             MaxMethods_isValid || 
             MaxSessions_isValid || 
             MaxReadSessions_isValid || 
             MaxAuthentications_isValid || 
             MaxTransactionLimit_isValid || 
             DefSessionTimeout_isValid || 
             MaxSessionTimeout_isValid || 
             MinSessionTimeout_isValid || 
             DefTransTimeout_isValid || 
             MaxTransTimeout_isValid || 
             MinTransTimeout_isValid || 
             MaxComIDTime_isValid || 
             MaxComIDCMD_isValid || 
             ContinuedTokens_isValid || 
             SequenceNumbers_isValid || 
             AckNak_isValid || 
             Asynchronous_isValid || 
             RealTimeClock_isValid );
} // isEmpty

//=======================================================================================
void HostProperties::setStateAll( bool valid )
{
   MaxComPacketSize_isValid = 
   MaxResponseComPacketSize_isValid = 
   MaxPacketSize_isValid = 
   MaxIndTokenSize_isValid = 
   MaxAggTokenSize_isValid = 
   MaxPackets_isValid = 
   MaxSubpackets_isValid = 
   MaxMethods_isValid = 
   ContinuedTokens_isValid = 
   SequenceNumbers_isValid = 
   AckNak_isValid = 
   Asynchronous_isValid = valid;
} // setStateAll

//=======================================================================================
bool HostProperties::isEmpty()
{
   return !( MaxComPacketSize_isValid || 
             MaxResponseComPacketSize_isValid ||
             MaxPacketSize_isValid || 
             MaxIndTokenSize_isValid || 
             MaxAggTokenSize_isValid || 
             MaxPackets_isValid || 
             MaxSubpackets_isValid || 
             MaxMethods_isValid || 
             ContinuedTokens_isValid || 
             SequenceNumbers_isValid || 
             AckNak_isValid || 
             Asynchronous_isValid );
} // isEmpty

//=======================================================================================
void IOTableSP::setStateAll( bool valid )
{
   UID_isValid = valid;
   Name_length = ( valid ? 0 : -1 );
   ORG_isValid = valid;
   EffectiveAuth_isValid = valid;
   DateofIssue_isValid = valid;
   Bytes_isValid = valid;
   LifeCycleState_isValid = valid;
   Frozen_isValid = valid;
} // setStateAll

//=======================================================================================
bool IOTableSP::isEmpty()
{
   return !( UID_isValid || ( Name_length > 0 ) || ORG_isValid || EffectiveAuth_isValid
          || DateofIssue_isValid || Bytes_isValid || LifeCycleState_isValid || Frozen_isValid );
} // isEmpty

//=======================================================================================
void IOTableLockingInfo::setStateAll( bool valid )
{
   UID_isValid = valid;
   Name_length = ( valid ? 0 : -1 );
   Version_isValid = valid;
   EncryptSupport_isValid = valid;
   MaxRanges_isValid = valid;
   MaxReEncryptions_isValid = valid;
   KeysAvailableCfg_isValid = valid;
   SingleUserModeRanges_isValid = valid;
   RangeStartLengthPolicy_isValid = valid;
   SingleUserModeRanges.resize( 0 );
} // setStateAll

//=======================================================================================
bool IOTableLockingInfo::isEmpty()
{
   return !( UID_isValid || ( Name_length > 0 ) || Version_isValid || EncryptSupport_isValid 
          || MaxRanges_isValid || MaxReEncryptions_isValid || KeysAvailableCfg_isValid 
          || SingleUserModeRanges_isValid || RangeStartLengthPolicy_isValid );
} // isEmpty

//=======================================================================================
void IOTableLocking::setStateAll( bool valid )
{
   UID_isValid = valid;
   Name_length = ( valid ? 0 : -1 );
   CommonName_length = ( valid ? 0 : -1 );
   RangeStart_isValid  = valid;
   RangeLength_isValid = valid;
   ReadLockEnabled_isValid = valid;
   WriteLockEnabled_isValid = valid;
   ReadLocked_isValid = valid;
   WriteLocked_isValid = valid;
   LockOnReset_length = ( valid ? 0 : -1 );  // Adjust with the data upon set
   ActiveKey_isValid = valid;
   NextKey_isValid = valid;
   ReEncryptState_isValid = valid;
   ReEncryptRequest_isValid = valid;
   AdvKeyMode_isValid = valid;
   VerifyMode_isValid = valid;
   ContOnReset_length = ( valid ? 0 : -1 );  // Adjust with the data upon set
   LastReEncryptLBA_isValid = valid;
   LastReEncStat_isValid = valid;
   GeneralStatus_length = ( valid ? 0 : -1 );
   AllowATAUnlock_isValid = valid;
} // setStateAll

//=======================================================================================
bool IOTableLocking::isEmpty()
{
   return !( UID_isValid || ( Name_length > 0 ) || ( CommonName_length > 0 )
          || RangeStart_isValid || RangeLength_isValid || ReadLockEnabled_isValid
          || WriteLockEnabled_isValid || ReadLocked_isValid || WriteLocked_isValid
          || ( LockOnReset_length >= 0 ) || ActiveKey_isValid || NextKey_isValid
          || ReEncryptState_isValid || ReEncryptRequest_isValid
          || AdvKeyMode_isValid || VerifyMode_isValid || ( ContOnReset_length >= 0 )
          || LastReEncryptLBA_isValid || LastReEncStat_isValid || ( GeneralStatus_length > 0 )
          || AllowATAUnlock_isValid );
} // isEmpty

//=======================================================================================
void IOTableC_PIN::setStateAll( bool valid )
{
   UID_isValid = valid;
   Name_length = ( valid ? 0 : -1 );
   CommonName_length = ( valid ? 0 : -1 );
   PIN_length = ( valid ? 0 : -1 );
   CharSet_isValid = valid;
   TryLimit_isValid = valid;
   Tries_isValid = valid;
   Persistence_isValid = valid;
} // setStateAll

//=======================================================================================
bool IOTableC_PIN::isEmpty()
{
   return !( UID_isValid || ( Name_length >= 0 ) || ( CommonName_length >= 0 ) // jls 201203215
          || ( PIN_length >= 0 ) || CharSet_isValid || TryLimit_isValid        // Length == 0 for null string
          || Tries_isValid || Persistence_isValid );
} // isEmpty

//=======================================================================================
void IOTableAuthority::setStateAll( bool valid )
{
   UID_isValid = valid;
   Name_length = ( valid ? 0 : -1 );
   CommonName_length = ( valid ? 0 : -1 );
   IsClass_isValid = valid;
   Class_isValid = valid;
   Enabled_isValid = valid;
   Secure_isValid = valid;
   HashAndSign_isValid = valid;
   PresentCertificate_isValid = valid;
   Operation_isValid = valid;
   Credential_isValid = valid;
   ResponseSign_isValid = valid;
   ResponseExch_isValid = valid;
   ClockStart_isValid = valid;
   ClockEnd_isValid = valid;
   Limit_isValid = valid;
   Uses_isValid = valid;
   Log_isValid = valid;
   LogTo_isValid = valid;
} // setStateAll

//=======================================================================================
bool IOTableAuthority::isEmpty()
{
   return !( UID_isValid || ( Name_length > 0 ) || ( CommonName_length > 0 )
          || IsClass_isValid || Class_isValid || Enabled_isValid || Secure_isValid
          || HashAndSign_isValid || PresentCertificate_isValid || Operation_isValid
          || Credential_isValid || ResponseSign_isValid || ResponseExch_isValid
          || ClockStart_isValid || ClockEnd_isValid || Limit_isValid 
          || Uses_isValid || Log_isValid || LogTo_isValid );
} // isEmpty

//=======================================================================================
void IOTableMBRControl::setStateAll( bool valid )
{
   UID_isValid = valid;
   Enable_isValid = valid;
   Done_isValid = valid;
   MBRDoneOnReset_length = ( valid ? 0 : -1 );  // Adjust with the data upon set
} // setStateAll

//=======================================================================================
bool IOTableMBRControl::isEmpty()
{
   return !( UID_isValid || Enable_isValid || Done_isValid || ( MBRDoneOnReset_length >= 0 ) );
} // isEmpty

//=======================================================================================
void IOTable_PortLocking::setStateAll( bool valid )
{
   UID_isValid = valid;
   Name_length = ( valid ? 0 : -1 );
   LockOnReset_length = ( valid ? 0 : -1 );  // Adjust with the data upon set
   PortLocked_isValid = valid;
} // setStateAll

//=======================================================================================
bool IOTable_PortLocking::isEmpty()
{
   return !( UID_isValid || ( Name_length > 0 ) || ( LockOnReset_length >= 0 ) || PortLocked_isValid );
} // isEmpty

