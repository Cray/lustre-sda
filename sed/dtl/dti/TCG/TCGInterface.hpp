/*! \file TCGInterface.hpp
    \brief TCG API definition for generic TCG Interface functions.

    This file details the interface classes and functions for writing
    client code that uses the TCG security protocol. 
    It is a C++ specific interface, implemented as an abstract class.
    
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

#ifndef TCG_INTERFACE_DOT_HPP
#define TCG_INTERFACE_DOT_HPP

#if !defined(__cplusplus)
#error C++ compiler required.  Include files for 'C' compilers.
#endif
// !defined __cplusplus
//=================================
// Include files
//=================================
#include "../dti.hpp"
#include "TCGValues.h"

#if defined (_WIN32)
#elif defined (__DJGPP)
#elif defined (__linux__)
#else
#error "Operating system not defined!"
#endif

namespace dti
{
   //=================================================================================
   /// \brief User defined/supplied lengthy process progress update callback routine (eg., used with DataStore or MBR table read/write).
   ///
   /// \param total      [IN]  The total amount of data access of workload (in bytes) during the process.
   /// \param start      [IN]  The starting point of addressing (byte index).
   /// \param current    [IN]  The present point of addessing (byte index) to be processed.
   /// \param pace       [IN]  The length of data (interval, in bytes) for the current step.
   ///
   /// \return boolean flag indicating if the user wants to continue the process. True to continue, and false to abort.
   //=================================================================================
   typedef bool (*UserProgressUpdateCallBack)( tUINT64 total, tUINT64 start, tUINT64 current, tUINT64 pace );


   //=================================
   // struct definitions
   //=================================

   //====================================================================================
   /// \brief AuthenticationParameter structure defines pointers to authentication authority name and password.
   ///
   /// Each item of data is coupled with a state flag of validity (or length for an 
   /// array, and using -1 for invalid state), indicating
   /// - For an output (Set), whether the data is valid and will be present or omitted
   /// in the corresponding method-call invocation. Caller sets it prior to calling Set.
   /// - For an iutput (Get), whether the data is intended and will be parsed and returned
   /// from the corresponding Get-method invocation result. Get-method resets it to signal  
   /// to caller the state of availability for this data item.
   //====================================================================================
   struct AuthenticationParameter
   {
      char    * AuthorityName;   // "SID", "MSID", "EraseMaster", "BandMaster#", "Admin#", "User#", etc.
      tUINT8  * Pin;             // Pointer to a buffer of Max 32 bytes.
      tUINT8  PinLength;         // Number of bytes of the Pin.

      AuthenticationParameter( char *name =NULL, tUINT8 *pin =NULL, tUINT8 length =0 ) : AuthorityName(name), Pin(pin), PinLength(length)
      { if( NULL != pin && 0 == length ) PinLength = (tUINT8) strlen((char*)pin); } // assuming an 0-terminated ASCII string
   }; // AuthenticationParameter


   //====================================================================================
   /// \brief The following I/O data structures are for Get/Set on a few selected Object or Table row.
   ///
   /// Each item of data is coupled with a state flag (bool value is used for simplicity, though
   /// a bitmap mechanism is an alternative) of validity (or length for an array, and using -1
   /// for invalid state), indicating
   /// - For an output (Set), whether the data is valid and will be present or omitted
   /// in the corresponding method-call invocation. Caller sets it prior to calling Set.
   /// - For an iutput (Get), whether the data is intended and will be parsed and returned
   /// from the corresponding Get-method invocation result. Get-method resets it to signal  
   /// to caller the state of availability for this data item.
   //====================================================================================

   //====================================================================================
   /// \brief Data structure of selected TPer Properties for Properties() method.
   //====================================================================================
   struct TPerProperties
   {
      tUINT32  MaxComPacketSize;               // "MaxComPacketSize"          (min 1024 for Ent-SSC and 2048 for Opal)
      bool     MaxComPacketSize_isValid;

      tUINT32  MaxResponseComPacketSize;       // "MaxResponseComPacketSize"  (min 1024 for Ent-SSC and 2048 for Opal)
      bool     MaxResponseComPacketSize_isValid;

      tUINT32  MaxPacketSize;                  // "MaxPacketSize"             (min 1004 for Ent-SSC and 2028 for Opal)
      bool     MaxPacketSize_isValid;

      tUINT32  MaxIndTokenSize;                // "MaxIndTokenSize"           (min 256 for Ent-SSC and 1992 for Opal)
      bool     MaxIndTokenSize_isValid;

      tUINT32  MaxAggTokenSize;                // "MaxAggTokenSize"           
      bool     MaxAggTokenSize_isValid;

      tUINT32  MaxPackets;                     // "MaxPackets"                (min 1)
      bool     MaxPackets_isValid;

      tUINT32  MaxSubpackets;                  // "MaxSubpackets"             (min 1)
      bool     MaxSubpackets_isValid;

      tUINT32  MaxMethods;                     // "MaxMethods"                (min 1)
      bool     MaxMethods_isValid;

      tUINT16  MaxSessions;                    // "MaxSessions"               (min 2 for Ent-SSC and 1 for Opal)
      bool     MaxSessions_isValid;

      tUINT16  MaxReadSessions;                // "MaxReadSessions"           
      bool     MaxReadSessions_isValid;

      tUINT16  MaxAuthentications;             // "MaxAuthentications"        (min 1 for Ent-SSC and 2 for Opal)
      bool     MaxAuthentications_isValid;

      tUINT16  MaxTransactionLimit;            // "MaxTransactionLimit"       (min 1)
      bool     MaxTransactionLimit_isValid;

      tUINT64  DefSessionTimeout;              // "DefSessionTimeout"     
      bool     DefSessionTimeout_isValid;

      tUINT64  MaxSessionTimeout;              // "MaxSessionTimeout"     
      bool     MaxSessionTimeout_isValid;

      tUINT64  MinSessionTimeout;              // "MinSessionTimeout"     
      bool     MinSessionTimeout_isValid;

      tUINT32  DefTransTimeout;                // "DefTransTimeout"     
      bool     DefTransTimeout_isValid;

      tUINT32  MaxTransTimeout;                // "MaxTransTimeout"     
      bool     MaxTransTimeout_isValid;

      tUINT32  MinTransTimeout;                // "MinTransTimeout"     
      bool     MinTransTimeout_isValid;

      tUINT64  MaxComIDTime;                   // "MaxComIDTime"     
      bool     MaxComIDTime_isValid;

      tUINT32  MaxComIDCMD;                    // "MaxComIDCMD"     
      bool     MaxComIDCMD_isValid;

      bool     ContinuedTokens;                // "ContinuedTokens"     
      bool     ContinuedTokens_isValid;

      bool     SequenceNumbers;                // "SequenceNumbers"     
      bool     SequenceNumbers_isValid;

      bool     AckNak;                         // "AckNak"     
      bool     AckNak_isValid;

      bool     Asynchronous;                   // "Asynchronous"     
      bool     Asynchronous_isValid;

      bool     RealTimeClock;                  // "RealTimeClock"     
      bool     RealTimeClock_isValid;

      TPerProperties( bool toGet =true ) { setStateAll( toGet ); }
      void setStateAll( bool valid );
      bool isEmpty();
   }; // TPerProperties

   //====================================================================================
   /// \brief Data structure of selected Host Properties for Properties() method.
   //====================================================================================
   struct HostProperties
   {
      tUINT32  MaxComPacketSize;               // "MaxComPacketSize"          (min 1024 for Ent-SSC and 2048 for Opal)
      bool     MaxComPacketSize_isValid;

      tUINT32  MaxResponseComPacketSize;       // "MaxResponseComPacketSize"  (min 1024 for Ent-SSC and 2048 for Opal)
      bool     MaxResponseComPacketSize_isValid;

      tUINT32  MaxPacketSize;                  // "MaxPacketSize"             (min 1004 for Ent-SSC and 2028 for Opal)
      bool     MaxPacketSize_isValid;

      tUINT32  MaxIndTokenSize;                // "MaxIndTokenSize"           (min 256 for Ent-SSC and 1992 for Opal)
      bool     MaxIndTokenSize_isValid;

      tUINT32  MaxAggTokenSize;                // "MaxAggTokenSize"           
      bool     MaxAggTokenSize_isValid;

      tUINT32  MaxPackets;                     // "MaxPackets"                (min 1)
      bool     MaxPackets_isValid;

      tUINT32  MaxSubpackets;                  // "MaxSubpackets"             (min 1)
      bool     MaxSubpackets_isValid;

      tUINT32  MaxMethods;                     // "MaxMethods"                (min 1)
      bool     MaxMethods_isValid;

      bool     ContinuedTokens;                // "ContinuedTokens"     
      bool     ContinuedTokens_isValid;

      bool     SequenceNumbers;                // "SequenceNumbers"     
      bool     SequenceNumbers_isValid;

      bool     AckNak;                         // "AckNak"     
      bool     AckNak_isValid;

      bool     Asynchronous;                   // "Asynchronous"     
      bool     Asynchronous_isValid;

      HostProperties( bool toGet =false ) { setStateAll( toGet ); }
      void setStateAll( bool valid );
      bool isEmpty();
   }; // HostProperties

   //====================================================================================
   /// \brief Data structure of selected columns from table SP row.
   //====================================================================================
   struct IOTableSP
   {
      TCG_UID  UID;                    // 00  - "UID"          (Read Only)
      bool     UID_isValid;

      tUINT8   Name[33];               // 01  - "Name"         (Read Only, max 32 bytes, 0-terminated)
      tINT8    Name_length;

      TCG_UID  ORG;                    // 02  - "ORG"          (Read Only)
      bool     ORG_isValid;

      tUINT8   EffectiveAuth[32];      // 03  - "EffectiveAuth" (Read Only, 32-bytes)
      tINT8    EffectiveAuth_isValid;

      tUINT16  DateofIssue_Year;       // 04  - "DateofIssue"  (Read Only)
      tUINT8   DateofIssue_Month;      // 04  - "DateofIssue"  (Read Only)
      tUINT8   DateofIssue_Day;        // 04  - "DateofIssue"  (Read Only)
      bool     DateofIssue_isValid;

      tUINT64  Bytes;                  // 05  - "Bytes"        (Read Only)
      bool     Bytes_isValid;

      tUINT8   LifeCycleState;         // 06  - "LifeCycleState" (Read Only, 0-15)
      bool     LifeCycleState_isValid;

      bool     Frozen;                 // 07  - "Frozen"
      bool     Frozen_isValid;

      IOTableSP( bool toGet =false ) { setStateAll( toGet ); }
      void setStateAll( bool valid );
      bool isEmpty();
   }; // IOTableSP

   //====================================================================================
   /// \brief Data structure of selected columns from table LockingInfo row.
   //====================================================================================
   struct IOTableLockingInfo
   {
      TCG_UID  UID;                    // 00  - "UID"        (Read Only)
      bool     UID_isValid;

      tUINT8   Name[33];               // 01  - "Name"       (Read Only, max 32 bytes, 0-terminated)
      tINT8    Name_length;

      tUINT32  Version;                // 02  - "Version"    (Read Only)
      bool     Version_isValid;

      tUINT8   EncryptSupport;         // 03  - "EncryptSupport" (Read Only, 0-15)
      bool     EncryptSupport_isValid;

      tUINT32  MaxRanges;              // 04  - "MaxRanges"  (Read Only)
      bool     MaxRanges_isValid;

      tUINT32  MaxReEncryptions;       // 05  - "MaxReEncryptions"  (Read Only)
      bool     MaxReEncryptions_isValid;

      tUINT8   KeysAvailableCfg;       // 06  - "KeysAvailableCfg" (Read Only, 0-7)
      bool     KeysAvailableCfg_isValid;

      TCG_UIDs SingleUserModeRanges;   // 07  - "SingleUserModeRanges" (Read Only, 0-max LockingObject/Table UIDs)
      tINT8    SingleUserModeRanges_isValid;

      tUINT8   RangeStartLengthPolicy; // 08  - "RangeStartLengthPolicy" (Read Only, 0-7, currently only 0 or 1 used)
      bool     RangeStartLengthPolicy_isValid;

      IOTableLockingInfo( bool toGet =true ) { setStateAll( toGet ); }
      void setStateAll( bool valid );
      bool isEmpty();
   }; // IOTableLockingInfo

   //====================================================================================
   /// \brief Data structure of selected columns from table Locking row.
   //====================================================================================
   struct IOTableLocking
   {
      TCG_UID  UID;                    // 00  - "UID"        (Read Only)
      bool     UID_isValid;

      tUINT8   Name[33];               // 01  - "Name"       (Read Only, max 32 bytes, 0-terminated)
      tINT8    Name_length;

      tUINT8   CommonName[33];         // 02  - "CommonName" (max 32 bytes, 0-terminated)
      tINT8    CommonName_length;

      tUINT64  RangeStart;             // 03  - "RangeStart"
      bool     RangeStart_isValid;

      tUINT64  RangeLength;            // 04  - "RangeLength"
      bool     RangeLength_isValid;

      bool     ReadLockEnabled;        // 05  - "ReadLockEnabled"
      bool     ReadLockEnabled_isValid;

      bool     WriteLockEnabled;       // 06  - "WriteLockEnabled"
      bool     WriteLockEnabled_isValid;

      bool     ReadLocked;             // 07  - "ReadLocked"
      bool     ReadLocked_isValid;

      bool     WriteLocked;            // 08  - "WriteLocked"
      bool     WriteLocked_isValid;

      tUINT8   LockOnReset[32];        // 09  - "LockOnReset" (0-31, 0=PowerCycle, 1=Hardware, 2=HotPlug, 3=Programmatic, 4-15 reserved, 16-31 vendor unique)
      tINT8    LockOnReset_length;     // 0=empty (No Locking, or turning locking off), -1=Invalid

      TCG_UID  ActiveKey;              // 0A  - "ActiveKey"
      bool     ActiveKey_isValid;

      TCG_UID  NextKey;                // 0B  - "NextKey"
      bool     NextKey_isValid;

      tUINT8   ReEncryptState;         // 0C  - "ReEncryptState" (Read Only, 1-16)
      bool     ReEncryptState_isValid;

      tUINT8   ReEncryptRequest;       // 0D  - "ReEncryptRequest" (1-16)
      bool     ReEncryptRequest_isValid;

      tUINT8   AdvKeyMode;             // 0E  - "AdvKeyMode" (0-7)
      bool     AdvKeyMode_isValid;

      tUINT8   VerifyMode;             // 0F  - "VerifyMode" (0-7)
      bool     VerifyMode_isValid;

      tUINT8   ContOnReset[32];        // 10h - "ContOnReset" (0-31, 0=PowerCycle, 1=Hardware, 2=HotPlug, 3=Programmatic, 4-15 reserved, 16-31 vendor unique)
      tINT8    ContOnReset_length;     // 0=empty (No Locking, or turning locking off), -1=Invalid

      tUINT64  LastReEncryptLBA;       // 11h - "LastReEncryptLBA" (Read Only)
      bool     LastReEncryptLBA_isValid;

      tUINT8   LastReEncStat;          // 12h  - "LastReEncStat" (Read Only, 0-7)
      bool     LastReEncStat_isValid;

      tUINT8   GeneralStatus[64];      // 13h  - "GeneralStatus" (Read Only, 0-63)
      tINT8    GeneralStatus_length;   // -1=Invalid

      bool     AllowATAUnlock;         // 3Fh  - "AllowATAUnlock" (Seagate proprietary)
      bool     AllowATAUnlock_isValid;

      IOTableLocking( bool toGet =false ) { setStateAll( toGet ); }
      void setStateAll( bool valid );
      bool isEmpty();
   }; // IOTableLocking

   //====================================================================================
   /// \brief Data structure of selected columns from table C_PIN row.
   //====================================================================================
   struct IOTableC_PIN
   {
      TCG_UID  UID;                    // 00  - "UID"        (Read Only)
      bool     UID_isValid;

      tUINT8   Name[33];               // 01  - "Name"       (Read Only, max 32 bytes, 0-terminated)
      tINT8    Name_length;

      tUINT8   CommonName[33];         // 02  - "CommonName" (Read Only, max 32 bytes, 0-terminated)
      tINT8    CommonName_length;

      tUINT8   PIN[33];                // 03  - "PIN"        (max 32 bytes, 0-terminated)
      tINT8    PIN_length;

      TCG_UID  CharSet;                // 04  - "CharSet"    (Read Only in CS1.0)
      bool     CharSet_isValid;

      tUINT32  TryLimit;               // 05  - "TryLimit"
      bool     TryLimit_isValid;

      tUINT32  Tries;                  // 06  - "Tries"
      bool     Tries_isValid;

      bool     Persistence;            // 07  - "Persistence"
      bool     Persistence_isValid;

      IOTableC_PIN( bool toGet =false ) { setStateAll( toGet ); }
      void setStateAll( bool valid );
      bool isEmpty();
   }; // IOTableC_PIN

   //====================================================================================
   /// \brief Data structure of selected columns from table Authority row.
   //====================================================================================
   struct IOTableAuthority
   {
      TCG_UID  UID;                    // 00  - "UID"        (Read Only)
      bool     UID_isValid;

      tUINT8   Name[33];               // 01  - "Name"       (Read Only, max 32 bytes, 0-terminated)
      tINT8    Name_length;

      tUINT8   CommonName[33];         // 02  - "CommonName" (max 32 bytes, 0-terminated)
      tINT8    CommonName_length;

      bool     IsClass;                // 03  - "IsClass"    (Read Only in CS2.0)
      bool     IsClass_isValid;

      TCG_UID  Class;                  // 04  - "Class"
      bool     Class_isValid;

      bool     Enabled;                // 05  - "Enabled"
      bool     Enabled_isValid;

      tUINT8   Secure;                 // 06  - "Secure" (0-255)
      bool     Secure_isValid;

      tUINT8   HashAndSign;            // 07  - "HashAndSign" (0-15)
      bool     HashAndSign_isValid;

      bool     PresentCertificate;     // 08  - "PresentCertificate"
      bool     PresentCertificate_isValid;

      tUINT8   Operation;              // 09  - "Operation" (0-23)
      bool     Operation_isValid;

      TCG_UID  Credential;             // 0A  - "Credential"
      bool     Credential_isValid;

      TCG_UID  ResponseSign;           // 0B  - "ResponseSign"
      bool     ResponseSign_isValid;

      TCG_UID  ResponseExch;           // 0C  - "ResponseExch"
      bool     ResponseExch_isValid;

      tUINT16  ClockStart_Year;        // 0D  - "ClockStart"
      tUINT8   ClockStart_Month;       // 0D  - "ClockStart"
      tUINT8   ClockStart_Day;         // 0D  - "ClockStart"
      bool     ClockStart_isValid;

      tUINT16  ClockEnd_Year;          // 0E  - "ClockEnd"
      tUINT8   ClockEnd_Month;         // 0E  - "ClockEnd"
      tUINT8   ClockEnd_Day;           // 0E  - "ClockEnd"
      bool     ClockEnd_isValid;

      tUINT32  Limit;                  // 0F  - "Limit"
      bool     Limit_isValid;

      tUINT32  Uses;                   // 10h - "Uses"
      bool     Uses_isValid;

      tUINT8   Log;                    // 11h - "Log" (0-3)
      bool     Log_isValid;

      TCG_UID  LogTo;                  // 12h - "LogTo"
      bool     LogTo_isValid;

      IOTableAuthority( bool toGet =false ) { setStateAll( toGet ); }
      void setStateAll( bool valid );
      bool isEmpty();
   }; // IOTableAuthority

   //====================================================================================
   /// \brief Data structure of selected columns from table MBRControl row.
   //====================================================================================
   struct IOTableMBRControl
   {
      TCG_UID  UID;                    // 00  - "UID"        (Read Only)
      bool     UID_isValid;

      bool     Enable;                 // 01  - "Enable"
      bool     Enable_isValid;

      bool     Done;                   // 02  - "Done"
      bool     Done_isValid;

      tUINT8   MBRDoneOnReset[32];     // 03  - "MBRDoneOnReset" (0-31, 0=PowerCycle, 1=Hardware, 2=HotPlug, 3=Programmatic, 4-15 reserved, 16-31 vendor unique)
      tINT8    MBRDoneOnReset_length;  // 0=empty (No change to 'Done' upon any reset), -1=Invalid

      IOTableMBRControl( bool toGet =false ) { setStateAll( toGet ); }
      void setStateAll( bool valid );
      bool isEmpty();
   }; // IOTableMBRControl

   //====================================================================================
   /// \brief Data structure of selected columns from table _PortLocking (Seagate Proprietary) row.
   //====================================================================================
   struct IOTable_PortLocking
   {
      TCG_UID  UID;                    // 00  - "UID"        (Read Only)
      bool     UID_isValid;

      tUINT8   Name[33];               // 01  - "Name"       (Read Only, max 32 bytes, 0-terminated)
      tINT8    Name_length;

      tUINT8   LockOnReset[32];        // 02  - "LockOnReset" (0-31, 0=PowerCycle, 1=Hardware, 2=HotPlug, 3=Programmatic, 4-15 reserved, 16-31 vendor unique)
      tINT8    LockOnReset_length;     // 0=empty (No Locking, or turning locking off), -1=Invalid

      bool     PortLocked;             // 03  - "PortLocked"
      bool     PortLocked_isValid;

      IOTable_PortLocking( bool toGet =false ) { setStateAll( toGet ); }
      void setStateAll( bool valid );
      bool isEmpty();
   }; // IOTable_PortLocking


   //=================================
   // class definitions
   //=================================

   //====================================================================================
   /// \brief An Interface abstract class which defines a set of TCG generic functions.
   ///
   /// ITCGInterface is a derived class from CDriveTrustInterface which provides the
   /// implementation for the parent class' methods.
   //====================================================================================
   class ITCGInterface : virtual public CDriveTrustInterface
   {
   public:
      //=================================================================================
      /// \brief Creates a TCG interface class for applications to use to access a TCG drive.
      ///
      /// \param newSession    [IN]  Pointer to a pre-acquired CDriveTrustSession object.
      /// \param logFileName   [IN]  XML TCG protocol log file name if such log is preferred. An empty string (TXT("")) indicates no log file.
      /// \param ssc           [IN]  TCG SSC type preferred. 1=Entprise, 2=Opal, 3=Marble, and -1=Auto device query and selection.
      ///
      /// \exception throwing dta::DTA_ERROR
      ///
      /// \return ITCGInterface * Pointer to the created TCG corresponding SSC object.
      //=================================================================================
      static ITCGInterface* CreateTCGInterface( dta::CDriveTrustSession* newSession, const _tstring logFileName =TXT(""), int ssc =-1 );

      //=================================================================================
      /// \brief Destructor for ITCGInterface.
      //=================================================================================
      virtual ~ITCGInterface() {}

      //=================================================================================
      //
      // TPer/Com methods
      //
      //=================================================================================

      //=================================================================================
      /// \brief Request a pre-issued or a new ComID (extended ID) from TPer.
      ///
      /// \return tUINT32, an issued extended ComID by the TPer.
      //=================================================================================
      virtual tUINT32 getComID() =0;

      //=================================================================================
      /// \brief Verify an extended ComID with the TPer.
      ///
      /// \param extComID [IN]  Extended ComID.
      ///
      /// \return enum value for the state of the given ComID.
      //=================================================================================
      virtual etComIDState verifyComID( tUINT32 extComID ) =0;

      //=================================================================================
      /// \brief Retrieve TCG Properties information from the TPer.
      ///
      /// TCG method depiction
      ///   SessionManager.Properties[ ]
      ///   => SessionManager.Properties[ Properties : [ name = value ] ]
      ///
      /// \param propertyData [OUT]  Returned TCG Properties data for caller to parse.
      ///
      /// \return Status byte of the response ComPacket for this method call. Saved the protocol info in the internal Response buffer.
      //=================================================================================
      virtual TCG_STATUS properties( dta::tBytes & propertyData ) =0;

      //=================================================================================
      /// \brief Set HostProperties to and/or Retrieve Properties information from the TPer.
      ///
      /// TCG method depiction
      ///   SessionManager.Properties[ HostProperties = [ name = value ... ] ]
      ///   => SessionManager.Properties[ Properties : [ name = value ... ], HostProperties = [ name = value ... ] ]
      ///
      /// \param pHostPropertiesIn  [IN]   Pointer to a caller allocated buffer holding the TCG Host Properties data to set to SED. NULL indicates no setting of HostProperties.
      /// \param pTPerProperties    [OUT]  Pointer to a caller allocated buffer to hold the returned TCG TPer Properties data. NULL indicates not interested.
      /// \param pHostPropertiesOut [OUT]  Pointer to a caller allocated buffer to hold the returned TCG Host Properties data. NULL indicates not interested.
      ///
      /// \return Status byte of the response ComPacket for this method call. Saved the protocol info in the internal Response buffer.
      //=================================================================================
      virtual TCG_STATUS properties( HostProperties *pHostPropertiesIn, TPerProperties *pTPerProperties, HostProperties *pHostPropertiesOut ) =0;

      //=================================================================================
      /// \brief Request supported security protocol ID list from the TPer.
      ///
      /// \param numberIDs    [OUT]  Number of protocol IDs returned.
      /// \param IDs          [OUT]  Returned ID list, one byte each.
      ///
      /// \return status byte of the IF-Recv for this call.
      //=================================================================================
      virtual TCG_STATUS getSupportedProtocolIDs( tUINT16 & numberIDs, dta::tBytes & IDs ) =0;

      //=================================================================================
      /// \brief Request FIPS Compliance Descriptor Info, if available, from the TPer. 
      ///
      /// \param Revision     [OUT]  Char '2' or '3' indicating FIPS 140- level.
      /// \param OverallLevel [OUT]  Char '1' to '4' indicating Overall compliance level.
      /// \param HardwareVer  [OUT]  ATA String (128 chars max)
      /// \param FirmwareVer  [OUT]  ATA String (128 chars max)
      /// \param ModuleName   [OUT]  ATA String (256 chars max)
      ///
      /// \return status byte of the IF-Recv command. If command supported but no info to report, return default "no-FIPS" values.
      //=================================================================================
      virtual TCG_STATUS getFipsComplianceInfo( char & Revision, char & OverallLevel,
                                                     std::string &HardwareVer, std::string &FirmwareVer,
                                                     std::string &ModuleName ) =0;


      //=================================================================================
      /// \brief Request Level 0 device discovery data from the TPer.
      ///
      /// \param data         [OUT]  Returned Level 0 device discovery data.
      ///
      /// \return status byte of the IF-Recv for this call.
      //=================================================================================
      virtual TCG_STATUS getLevel0DiscoveryData( dta::tBytes & data ) =0;

      //=================================================================================
      /// \brief TCG protocol stack reset for the given ComID on the TPer.
      ///
      /// \param extComID [IN]  Extended ComID.
      ///
      /// \return status byte of the response for this call.
      //=================================================================================
      virtual TCG_STATUS stackReset( tUINT32 extComID ) =0;

      //=================================================================================
      /// \brief TCG programmatic TPer Reset on the TPer.
      ///
      /// \return status byte of the response for this call.
      //=================================================================================
      virtual TCG_STATUS programmaticTPerReset() =0;



      //=================================================================================
      //
      // Session/Transaction methods (for use around sessions, name begins with '_')
      //
      //=================================================================================

      //=================================================================================
      /// \brief Start a TCG session against a specific SP with the TPer (for Ent-SSC and Opal-SSC).
      ///
      /// TCG method depiction
      ///   SessionManager.StartSession[   HostSessionID : uinteger,
      ///                                  SP : uid, 
      ///                                  Write : boolean,
      ///                                  SessionTimeOut = uinteger ]
      ///   => SessionManager.SyncSession[ HostSessionID : uinteger, SPSessionID : uinteger ]
      ///
      /// \param TPerSN                 [OUT] TPer session ID returned upon successful.
      /// \param targetSP               [IN]  UID of the target SP to establish the session with.
      /// \param writeSession           [IN]  SessionType as true for Write(1) or false for Read(0, not support yet).
      /// \param HostSN                 [IN]  Host session ID specified, default is zero.
      /// \param sessionTimeout         [IN]  Session timeout value in milli-seconds. -1 indicates omitted parameter.
      /// \param syncHostTPerProperties [IN]  Whether or not to synchronize communication Properties between Host and TPer before session starts.
      ///
      /// \return status byte of the response ComPacket for this method call.
      //=================================================================================
      virtual TCG_STATUS _startSession( 
                            tUINT32 &TPerSN,
                            TCG_UID targetSP,
                            bool writeSession = true,
                            tUINT32 HostSN = 0,
                            tINT64 sessionTimeout = -1,
                            bool syncHostTPerProperties = false ) =0;

      //=================================================================================
      /// \brief Start a TCG session against a specific SP with the TPer (for Ent-SSC and Opal-SSC).
      ///
      /// TCG method depiction
      ///   SessionManager.StartSession[   HostSessionID : uinteger,
      ///                                  SP : uid, 
      ///                                  Write : boolean,
      ///                                  SessionTimeOut = uinteger ]
      ///   => SessionManager.SyncSession[ HostSessionID : uinteger, SPSessionID : uinteger ]
      ///
      /// \param targetSP               [IN]  UID of the target SP to establish the session with.
      /// \param writeSession           [IN]  SessionType as true for Write(1) or false for Read(0, not support yet).
      /// \param HostSN                 [IN]  Host session ID specified, default is zero.
      /// \param sessionTimeout         [IN]  Session timeout value in milli-seconds. -1 indicates omitted parameter.
      /// \param syncHostTPerProperties [IN]  Whether or not to synchronize communication Properties between Host and TPer before session starts.
      ///
      /// \return status byte of the response ComPacket for this method call.
      //=================================================================================
      virtual TCG_STATUS _startSession( 
                            TCG_UID targetSP,
                            bool writeSession = true,
                            tUINT32 HostSN = 0,
                            tINT64 sessionTimeout = -1,
                            bool syncHostTPerProperties = false ) =0;

      //=================================================================================
      /// \brief Start a TCG session against a specific SP with the TPer (for Opal-SSC only).
      ///
      /// TCG method depiction
      ///   SessionManager.StartSession[   HostSessionID : uinteger,
      ///                                  SP : uid, 
      ///                                  Write : boolean,
      ///                                  HostChallenge = bytes,
      ///                                  HostSigningAuthority = uidref {AuthorityObjectUID},
      ///                                  SessionTimeOut = uinteger ]
      ///   => SessionManager.SyncSession[ HostSessionID : uinteger, SPSessionID : uinteger ]
      ///
      /// \param TPerSN                 [OUT] TPer session ID returned upon successful.
      /// \param targetSP               [IN]  UID of the target SP to establish the session with.
      /// \param hostSigningAuthority   [IN]  UID ref value of the host signing authority. 0 indicates omitted parameter.      
      /// \param hostChallenge          [IN]  Host-Challenge/password. NULL indicates omitted parameter.
      /// \param hostChallengeLength    [IN]  Length of the Host-Challenge/password. Zero(0) indicates omitted parameter.
      /// \param writeSession           [IN]  SessionType as true for Write(1) or false for Read(0, not support yet).
      /// \param HostSN                 [IN]  Host session ID specified, default is zero.
      /// \param sessionTimeout         [IN]  Session timeout value in milli-seconds. -1 indicates omitted parameter.
      /// \param syncHostTPerProperties [IN]  Whether or not to synchronize communication Properties between Host and TPer before session starts.
      ///
      /// \return status byte of the response ComPacket for this method call.
      //=================================================================================
      virtual TCG_STATUS _startSession( 
                            tUINT32 & TPerSN,
                            TCG_UID targetSP,
                            TCG_UID hostSigningAuthority,
                            tUINT8 *hostChallenge,
                            tUINT16 hostChallengeLength,
                            bool writeSession = true,
                            tUINT32 HostSN = 0,
                            tINT64 sessionTimeout = -1,
                            bool syncHostTPerProperties = false ) =0;

      //=================================================================================
      /// \brief Start a TCG session against a specific SP with the TPer (for Opal-SSC only).
      ///
      /// TCG method depiction
      ///   SessionManager.StartSession[   HostSessionID : uinteger,
      ///                                  SP : uid, 
      ///                                  Write : boolean,
      ///                                  HostChallenge = bytes,
      ///                                  HostSigningAuthority = uidref {AuthorityObjectUID},
      ///                                  SessionTimeOut = uinteger ]
      ///   => SessionManager.SyncSession[ HostSessionID : uinteger, SPSessionID : uinteger ]
      ///
      /// \param targetSP               [IN]  UID of the target SP to establish the session with.
      /// \param hostSigningAuthority   [IN]  UID ref value of the host signing authority. 0 indicates omitted parameter.      
      /// \param hostChallenge          [IN]  Host-Challenge/password. NULL indicates omitted parameter.
      /// \param hostChallengeLength    [IN]  Length of the Host-Challenge/password. Zero(0) indicates omitted parameter.
      /// \param writeSession           [IN]  SessionType as true for Write(1) or false for Read(0, not support yet).
      /// \param HostSN                 [IN]  Host session ID specified, default is zero.
      /// \param sessionTimeout         [IN]  Session timeout value in milli-seconds. -1 indicates omitted parameter.
      /// \param syncHostTPerProperties [IN]  Whether or not to synchronize communication Properties between Host and TPer before session starts.
      ///
      /// \return status byte of the response ComPacket for this method call.
      //=================================================================================
      virtual TCG_STATUS _startSession( 
                            TCG_UID targetSP,
                            TCG_UID hostSigningAuthority,
                            tUINT8 *hostChallenge,
                            tUINT16 hostChallengeLength,
                            bool writeSession = true,
                            tUINT32 HostSN = 0,
                            tINT64 sessionTimeout = -1,
                            bool syncHostTPerProperties = false ) =0;

      //=================================================================================
      /// \brief Start a TCG session against a specific SP with the TPer (for Opal-SSC only).
      ///
      /// TCG method depiction
      ///   SessionManager.StartSession[   HostSessionID : uinteger,
      ///                                  SP : uid, 
      ///                                  Write : boolean,
      ///                                  HostChallenge = bytes,
      ///                                  HostSigningAuthority = uidref {AuthorityObjectUID},
      ///                                  SessionTimeOut = uinteger ]
      ///   => SessionManager.SyncSession[ HostSessionID : uinteger, SPSessionID : uinteger ]
      ///
      /// \param TPerSN                 [OUT] TPer session ID returned upon successful.
      /// \param targetSP               [IN]  UID of the target SP to establish the session with.
      /// \param authent                [IN]  AuthenticationParameter for authentication.      
      /// \param writeSession           [IN]  SessionType as true for Write(1) or false for Read(0, not support yet).
      /// \param HostSN                 [IN]  Host session ID specified, default is zero.
      /// \param sessionTimeout         [IN]  Session timeout value in milli-seconds. -1 indicates omitted parameter.
      /// \param syncHostTPerProperties [IN]  Whether or not to synchronize communication Properties between Host and TPer before session starts.
      ///
      /// \return status byte of the response ComPacket for this method call.
      //=================================================================================
      virtual TCG_STATUS _startSession( 
                            tUINT32 & TPerSN,
                            TCG_UID targetSP,
                            AuthenticationParameter & authent,
                            bool writeSession = true,
                            tUINT32 HostSN = 0,
                            tINT64 sessionTimeout = -1,
                            bool syncHostTPerProperties = false ) =0;

      //=================================================================================
      /// \brief Start a TCG session against a specific SP with the TPer (for Opal-SSC only).
      ///
      /// TCG method depiction
      ///   SessionManager.StartSession[   HostSessionID : uinteger,
      ///                                  SP : uid, 
      ///                                  Write : boolean,
      ///                                  HostChallenge = bytes,
      ///                                  HostSigningAuthority = uidref {AuthorityObjectUID},
      ///                                  SessionTimeOut = uinteger ]
      ///   => SessionManager.SyncSession[ HostSessionID : uinteger, SPSessionID : uinteger ]
      ///
      /// \param targetSP               [IN]  UID of the target SP to establish the session with.
      /// \param authent                [IN]  AuthenticationParameter for authentication.
      /// \param writeSession           [IN]  SessionType as true for Write(1) or false for Read(0, not support yet).
      /// \param HostSN                 [IN]  Host session ID specified, default is zero.
      /// \param sessionTimeout         [IN]  Session timeout value in milli-seconds. -1 indicates omitted parameter.
      /// \param syncHostTPerProperties [IN]  Whether or not to synchronize communication Properties between Host and TPer before session starts.
      ///
      /// \return status byte of the response ComPacket for this method call.
      //=================================================================================
      virtual TCG_STATUS _startSession( 
                            TCG_UID targetSP,
                            AuthenticationParameter & authent,
                            bool writeSession = true,
                            tUINT32 HostSN = 0,
                            tINT64 sessionTimeout = -1,
                            bool syncHostTPerProperties = false ) =0;

      //=================================================================================
      /// \brief Close the currently open session.
      ///
      /// TCG method depiction
      ///   SessionManager.CloseSession (EOS)
      ///
      /// \return status byte of the response ComPacket for this method call.
      //=================================================================================
      virtual TCG_STATUS _closeSession() =0;

      //=================================================================================
      /// \brief Start a TCG transaction within the current open session.
      ///
      /// \return status byte of the response ComPacket for this method call.
      //=================================================================================
      virtual TCG_STATUS _startTransaction() =0;

      //=================================================================================
      /// \brief End/Close the present TCG transaction within the cureent open session.
      ///
      /// \param commitTransaction [IN]  Whether to commit(true) or abort(false) the present transaction.
      ///
      /// \return status byte of the response ComPacket for this method call.
      //=================================================================================
      virtual TCG_STATUS _endTransaction( bool commitTransaction = true ) =0;



      //=================================================================================
      //
      // Methods of SP, Table and Object (for use within a session, name begins with '_')
      //
      //=================================================================================

      //=================================================================================
      /// \brief Authenticate to a SP table/object with the given credential on the TPer.
      ///
      /// TCG method depiction
      ///   This_SP.Authenticate[ Authority : uid, Challenge = bytes ]
      ///   =>
      ///   [ typeOr {Success : boolean, Response : bytes} ]
      ///
      /// \param authorityID     [IN]  Authority to authenticate with.
      /// \param challenge       [IN]  Credential (key or password) to be used for the authentication. NULL indicates requesting 'nonce' from TPer.
      /// \param challengeLength [IN]  Length of the challenge/credential.
      /// \param response        [OUT] Bytes of the "response" returned by the TPer for a Challenge-Response type of authority (with the first step authentication only), not used otherwise.
      ///
      /// \return status byte of the response ComPacket for this method call.
      //=================================================================================
      virtual TCG_STATUS _authenticate( TCG_UID authorityID, dta::tByte* challenge, tUINT16 challengeLength, dta::tBytes & response ) =0;

      //=================================================================================
      /// \brief Authenticate to a SP table/object with the given credential on the TPer.
      ///
      /// TCG method depiction
      ///   This_SP.Authenticate[ Authority : uid, Challenge = bytes ]
      ///   =>
      ///   [ typeOr {Success : boolean, Response : bytes} ]
      ///
      /// \param authent      [IN]  AuthenticationParameter used with the authentication.
      /// \param response     [OUT] Bytes of the "response" returned by the TPer for a Challenge-Response type of authority (with the first step authentication only), not used otherwise.
      ///
      /// \return status byte of the response ComPacket for this method call.
      //=================================================================================
      virtual TCG_STATUS _authenticate( AuthenticationParameter & authent, dta::tBytes & response ) =0;

      //=================================================================================
      /// \brief Authenticate to a SP table/object with the given credential (regardless of the Challenge-Response return).
      ///
      /// TCG method depiction
      ///   This_SP.Authenticate[ Authority : uid, Challenge = bytes ]
      ///   =>
      ///   [ typeOr {Success : boolean, Response : bytes} ]
      ///
      /// \param authorityID  [IN]  Authority of password/PIN type to authenticate with.
      /// \param key          [IN]  Credential (key or password) to be used for the authentication.
      /// \param keyLength    [IN]  Length of the credential.
      ///
      /// \return status byte of the response ComPacket for this method call.
      //=================================================================================
      virtual TCG_STATUS _authenticate( TCG_UID authorityID, dta::tByte* key, tUINT16 keyLength ) =0;

      //=================================================================================
      /// \brief Authenticate to a SP table/object with the given credential (regardless of the Challenge-Response return).
      ///
      /// TCG method depiction
      ///   This_SP.Authenticate[ Authority : uid, Challenge = bytes ]
      ///   =>
      ///   [ typeOr {Success : boolean, Response : bytes} ]
      ///
      /// \param authent      [IN]  AuthenticationParameter used with the authentication.
      ///
      /// \return status byte of the response ComPacket for this method call.
      //=================================================================================
      virtual TCG_STATUS _authenticate( AuthenticationParameter & authent ) =0;

      //=================================================================================
      /// \brief Table/Object method: Fetch the values of selected table cells(row) from a table/object on the TPer.
      ///
      /// TCG method depiction
      ///   TargetUID.Get [ Cellblock : cell_block ]
      ///   => [ Result : typeOr { Bytes : bytes, RowValues : list [ ColumnNumber = Value ... ] } ]
      ///
      /// \param targetID  [IN]  Table/Object to be read from.
      /// \param data      [OUT] Contents read from the table/object in the form of [ {namedValue pairs} ] or Bytes-Atom.
      ///
      /// \return status byte of the response ComPacket for this method call.
      //=================================================================================
      virtual TCG_STATUS _get( TCG_UID targetID, dta::tBytes & data ) =0; // reading entire table

      //=================================================================================
      /// \brief Object-Table method: Fetch the values from a row of an Object table on the TPer.
      ///
      /// TCG method depiction
      ///   TableUID.Get [ Cellblock : cell_block ]
      ///   => [ Result : typeOr { Bytes : bytes, RowValues : list [ ColumnNumber = Value ... ] } ]
      ///
      /// \param targetID  [IN]  Object-Table to be read from.
      /// \param rowID     [IN]  UID of the row object.
      /// \param data      [OUT] Contents read from the table/object in the form of [ {namedValue pairs} ] or Bytes-Atom.
      ///
      /// \return status byte of the response ComPacket for this method call.
      //=================================================================================
      virtual TCG_STATUS _get( TCG_UID targetID, TCG_UID rowID, dta::tBytes & data ) =0; // for Object-table only

      //=================================================================================
      /// \brief Object-Table method: Fetch the values from a row of an Object table on the TPer.
      ///
      /// TCG method depiction (CS2.0 only)
      ///   TableUID.Get [ Cellblock : cell_block ]
      ///   => [ Result : typeOr { Bytes : bytes, RowValues : list [ ColumnNumber = Value ... ] } ]
      ///
      /// \param targetID     [IN]  Object-Table to be read from.
      /// \param rowID        [IN]  UID of the row object.
      /// \param startColumn  [IN]  start column number, -1 indicates an omitted parameter, meaning "first" column.
      /// \param endColumn    [IN]  end column number, -1 indicates an omitted parameter, meaning "last" column.
      /// \param data         [OUT] Contents read from the table/object in the form of [ {namedValue pairs} ] or Bytes-Atom.
      ///
      /// \return status byte of the response ComPacket for this method call.
      //=================================================================================
      virtual TCG_STATUS _get( TCG_UID targetID, TCG_UID rowID, int startColumn, int endColumn, dta::tBytes & data ) =0; // for Object-table only

      //=================================================================================
      /// \brief Byte-Table method: Fetch the values from a range of a Byte-table on the TPer.
      ///
      /// TCG method depiction
      ///   TargetUID.Get [ Cellblock : cell_block ]
      ///   => [ Result : typeOr { Bytes : bytes, RowValues : list [ ColumnNumber = Value ... ] } ]
      ///
      /// \param targetID  [IN]  Bte-Table to be read from.
      /// \param data      [OUT] Contents read from the table/object in the form of [ {namedValue pairs} ] or Bytes-Atom.
      /// \param startRow  [IN]  start row, -1 indicates an omitted parameter, meaning "first" row.
      /// \param endRow    [IN]  end row, -1 indicates an omitted parameter, meaning "last" row.
      ///
      /// \return status byte of the response ComPacket for this method call.
      //=================================================================================
      virtual TCG_STATUS _get( TCG_UID targetID, dta::tBytes & data, tINT64 startRow, tINT64 endRow ) =0; // for Byte-table only

      //=================================================================================
      /// \brief Array/Object Table method: Fetch the values from a row of a Array table or Object table on the TPer.
      ///
      /// TCG method depiction (CS2.0 only)
      ///   TargetUID.Get [ Cellblock : cell_block ]
      ///   => [ Result : typeOr { Bytes : bytes, RowValues : list [ ColumnNumber = Value ... ] } ]
      ///
      /// \param targetID     [IN]  Array-table or Object-table to be read from.
      /// \param startColumn  [IN]  start column number, -1 indicates an omitted parameter, meaning "first" column.
      /// \param endColumn    [IN]  end column number, -1 indicates an omitted parameter, meaning "last" column.
      /// \param data         [OUT] Contents read from the table/object in the form of [ {namedValue pairs} ] or Bytes-Atom.
      ///
      /// \return status byte of the response ComPacket for this method call.
      //=================================================================================
      virtual TCG_STATUS _get( TCG_UID targetID, int startColumn, int endColumn, dta::tBytes & data ) =0; // for single row Arrary-table or a row in an object-table

      //=================================================================================
      /// \brief Array/Object Table method: Fetch the values from a row of a Array table or Object table on the TPer. (CS1.0)
      ///
      /// TCG method depiction
      ///   TargetUID.Get [ Cellblock : cell_block ]
      ///   => [ Result : typeOr { Bytes : bytes, RowValues : list [ ColumnNumber = Value ... ] } ]
      ///
      /// \param targetID     [IN]  Array-table or Object-table to be read from.
      /// \param data         [OUT] Contents read from the table/object in the form of [ {namedValue pairs} ] or Bytes-Atom.
      /// \param startColumn  [IN]  start column, 0-terminated ASCII string, NULL means "first" column, omitted.
      /// \param endColumn    [IN]  end column, 0-terminated ASCII string, NULL means "last" column, omitted.
      /// \param rowID        [IN]  UID of the row object, optional, UID_NULL indicating omitted.
      ///
      /// \return status byte of the response ComPacket for this method call.
      //=================================================================================
      virtual TCG_STATUS _get( TCG_UID targetID, dta::tBytes & data, char* startColumn, char* endColumn, TCG_UID rowID =UID_NULL ) =0; // for single row Arrary-table or a row in an object-table

      //=================================================================================
      /// \brief Table/Object method: Set the table/object content for a table/object-rows on the TPer.
      ///
      /// \param targetID  [IN]  Table/Object to be written to.
      /// \param data      [IN]  Contents to set/save to the table/object in the form of [ {namedValue pairs} ] or Bytes-Atom.
      ///
      /// \return status byte of the response ComPacket for this method call.
      //=================================================================================
      virtual TCG_STATUS _set( TCG_UID targetID, dta::tBytes & data ) =0;

      //=================================================================================
      /// \brief Byte-Table method: Set the table content for a Byte table rows on the TPer.
      ///
      /// \param targetID  [IN]  Byte Table to be written to.
      /// \param data      [IN]  Contents to set/save to the table/object in the form of [ {namedValue pairs} ] or Bytes-Atom.
      /// \param startRow  [IN]  start row, -1 indicates an omitted parameter, meaning "first" row.
      /// \param endRow    [IN]  end row, -1 indicates an omitted parameter, meaning "last" row.
      ///
      /// \return status byte of the response ComPacket for this method call.
      //=================================================================================
      virtual TCG_STATUS _set( TCG_UID targetID, dta::tBytes & data, tINT64 startRow, tINT64 endRow ) =0; // for Byte-table only

      //=================================================================================
      /// \brief Array/Object Table method: Set the table content for an object table row on the TPer. (CS2.0)
      ///
      /// \param targetID     [IN]  Array or Object Table to be written to.
      /// \param rowID        [IN]  UID of the row object to set value to.
      /// \param data         [IN]  Contents to set/save to the table/object in the form of [ {namedValue pairs} ] or Bytes-Atom.
      ///
      /// \return status byte of the response ComPacket for this method call.
      //=================================================================================
      virtual TCG_STATUS _set( TCG_UID targetID, TCG_UID rowID, dta::tBytes & data ) =0; // for single row Arrary-table or a row in an object-table

      //=================================================================================
      /// \brief Array/Object Table method: Set the table content for an Array or Object table row on the TPer. (CS1.0)
      ///
      /// \param targetID     [IN]  Array or Object Table to be written to.
      /// \param data         [IN]  Contents to set/save to the table/object in the form of [ {namedValue pairs} ] or Bytes-Atom.
      /// \param startColumn  [IN]  start column, 0-terminated ASCII string, NULL means "first" column, omitted.
      /// \param endColumn    [IN]  end column, 0-terminated ASCII string, NULL means "last" column, omitted.
      ///
      /// \return status byte of the response ComPacket for this method call.
      //=================================================================================
      virtual TCG_STATUS _set( TCG_UID targetID, dta::tBytes & data, char* startColumn, char* endColumn ) =0; // for single row Arrary-table or a row in an object-table

      //=================================================================================
      /// \brief Objecy table method: Fetch the next few object UIDs from the UID cloumn of the specified table.
      ///
      /// TCG method depiction
      ///   TableUID.Next [ Where = uidref, Count = uinteger ]
      ///   => [ Result : list [ uidref ... ] ]
      ///
      /// \param pNextUID  [OUT] Pointer to a caller supplied storage of size of count UIDs to keep the returned UIDs. UID_NULL (0) is filled if not enough number of UIDs are returned.
      /// \param tableID   [IN]  Table to be read from.
      /// \param objectID  [IN]  Object to be referenced for its next row in the table.
      /// \param count     [IN]  Number of the next rows to be read from.
      ///
      /// \return status byte of the response ComPacket for this method call.
      //=================================================================================
      virtual TCG_STATUS _next( TCG_UID *pNextUID, TCG_UID tableID, TCG_UID objectID = UID_NULL, int count =-1 ) =0;

      //=================================================================================
      /// \brief Table method: Retrieve the Access Control List (ACL) value for the given target and method.
      ///
      /// TCG method depiction
      ///   MethodTableUID.GetACL [ InvokingID : table_object_ref, MethodID : MethodID_ref ]
      ///   => [ ACL : ACL ]
      ///
      /// \param targetID  [IN]  ThisSP/Table/Object to be read from.
      /// \param methodID  [IN]  Method UID to query ACL for.
      /// \param acl       [OUT] A vector of UIDs as the ACL returned.
      ///
      /// \return status byte of the response ComPacket for this method call.
      //=================================================================================
      virtual TCG_STATUS _getACL( TCG_UID targetID, TCG_UID methodID, TCG_UIDs & acl ) =0;

      //=================================================================================
      /// \brief Cryptographic erase a band/range of user space, and reset access control of the band on the TPer. (For Ent-SSC and Opal Single-User-Mode FixedACL)
      ///
      /// \param bandID  [IN]  Band/range to be secure erased.
      ///
      /// \return status byte of the response ComPacket for this method call.
      //=================================================================================
      virtual TCG_STATUS _erase( TCG_UID bandID ) =0;

      //=================================================================================
      /// \brief Cryptographic erase a band/range of user space, and reset access control of the band on the TPer. (For Ent-SSC and Opal Single-User-Mode FixedACL)
      ///
      /// \param bandNo  [IN]  Band/range number be secure erased.
      ///
      /// \return status byte of the response ComPacket for this method call.
      //=================================================================================
      virtual TCG_STATUS _erase( int bandNo ) =0;

      //=================================================================================
      /// \brief Generate a Key by the specified credential object.
      ///
      /// \param target          [IN]  UID of target credential object to generate the key.
      /// \param publicExponent  [IN]  PublicExponent to be used when invoked on a C_RSA_1024 or C_RSA_2048 object. Optional, -1 indicates omitted.
      /// \param pinLength       [IN]  Pin length. Optional, -1 indicates omitted.
      ///
      /// \return status byte of the response ComPacket for this method call.
      //=================================================================================
      virtual TCG_STATUS _genKey( TCG_UID target, tINT64 publicExponent =-1, int pinLength =-1 ) =0;

      //=================================================================================
      /// \brief Request the "this" SP to generate an array of random bytes.
      ///
      /// \param randomData [IN/OUT]  Random numbers generated with the length set prior to entry.
      ///
      /// \return status byte of the response ComPacket for this method call.
      //=================================================================================
      virtual TCG_STATUS _random( dta::tBytes & randomData ) =0;

      //=================================================================================
      /// \brief Sign a set of data by the specified TPerSign authority object on the TPer.
      ///
      /// TCG method depiction
      ///   TPerSignAuthorityObject.Sign[ DataToSign : bytes ]
      ///   => [ SignedData : bytes ]
      ///
      /// \param targetID    [IN]  TPer signing authority object.
      /// \param dataToSign  [IN]  Bytes of data to be signed.
      /// \param dataSigned  [OUT] Signed data returned.
      ///
      /// \return status byte of the response ComPacket for this method call.
      //=================================================================================
      virtual TCG_STATUS _sign( TCG_UID targetID, dta::tBytes & dataToSign, dta::tBytes & dataSigned ) =0;

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
      virtual TCG_STATUS _activate( TCG_UID target, TCG_UIDs *pSingleUserModeList =NULL, int rangeStartLengthPolicy =-1, UINT64VALs *pDataStoreTableSizes =NULL ) =0;

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
      virtual TCG_STATUS _activate( TCG_UID target, TCG_BANDNOs *pSingleUserModeList =NULL, int rangeStartLengthPolicy =-1, UINT64VALs *pDataStoreTableSizes =NULL ) =0;

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
      /// \param pSingleUserModeList     [IN]  Optional, pointer to a caller provided buffer keeping a UID arrary for the Opal SSC's Single User Mode Fixed ACL "SingleUserModeSelectionList". Default NULL means omitted.
      /// \param rangeStartLengthPolicy  [IN]  Optional, integer value to represent the Opal SSC's Single User Mode Fixed ACL "RangeStartRangeLengthPolicy". Default -1 means omitted.
      /// \param pAdmin1PIN              [IN]  Optional, pointer to a caller provided byte buffer to represent the Opal SSC's Single User Mode Fixed ACL "Admin1PIN". Default NULL means omitted.
      /// \param pDataStoreTableSizes    [IN]  Optional, pointer to a caller provided buffer keeping a UINT64 arrary as the "DataStoreTableSizes" parameter for the number and sizes of the DataStore-tables. Default NULL means omitted.
      ///
      /// \return status byte of the response ComPacket for this method call.
      //=================================================================================
      virtual TCG_STATUS _reactivate( TCG_UIDs *pSingleUserModeList =NULL, int rangeStartLengthPolicy =-1, dta::tBytes *pAdmin1PIN =NULL, UINT64VALs *pDataStoreTableSizes =NULL ) =0;

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
      virtual TCG_STATUS _reactivate( TCG_BANDNOs *pSingleUserModeList =NULL, int rangeStartLengthPolicy =-1, dta::tBytes *pAdmin1PIN =NULL, UINT64VALs *pDataStoreTableSizes =NULL ) =0;

      //=================================================================================
      /// \brief Revert the given object to its factory state on the TPer.
      ///
      /// \param target  [IN]  UID of target object to be reverted.
      ///
      /// \return status byte of the response ComPacket for this method call.
      //=================================================================================
      virtual TCG_STATUS _revert( TCG_UID target ) =0;

      //=================================================================================
      /// \brief Revert the currently authenticated SP (this-SP) to its factory state on the TPer.
      ///
      /// \return status byte of the response ComPacket for this method call.
      //=================================================================================
      virtual TCG_STATUS _revertSP() =0;



      //=================================================================================
      //
      // Frequently used Table/Object Get / Set utility functions (for use within a session, name begins with '_')
      //
      //=================================================================================

      //=================================================================================
      /// \brief Get values of ORG, DataofIssue, Bytes, LifeCycle state, and/or Frozen of a SP object in the SP table.      
      ///
      /// \param targetID  [IN]     Target UID, a SP object UID in the SP table.
      /// \param row       [IN/OUT] SP table row data structure IOTableSP. Must be initialized properly prior to entry.
      ///
      /// \return status byte of the response ComPacket for this method call.
      //=================================================================================
      virtual TCG_STATUS _getSP( TCG_UID targetID, IOTableSP & row ) =0;

      //=================================================================================
      /// \brief Set values of PIN, TryLimit, Tries, and/or Persistence of a C_PIN object in the C_PIN table.
      ///
      /// \param targetID  [IN]     Target UID, a SP object UID in the SP table.
      /// \param row       [IN/OUT] SP table row data structure IOTableSP. Must be initialized properly prior to entry.
      ///
      /// \return status byte of the response ComPacket for this method call.
      //=================================================================================
      virtual TCG_STATUS _setSP( TCG_UID targetID, IOTableSP & row ) =0;

      //=================================================================================
      /// \brief Get values of MaxRanges, MaxReEncryptions, etc, from the LockingInfo table row.
      ///
      /// \param row      [IN/OUT] LockingInfo table row data structure IOTableLockingInfo. Must be initialized properly prior to entry.
      ///
      /// \return status byte of the response ComPacket for this method call.
      //=================================================================================
      virtual TCG_STATUS _getLockingInfo( IOTableLockingInfo & row ) =0;

      //=================================================================================
      /// \brief Get values of table columns of a range from the Locking table.
      ///
      /// \param rangeNo  [IN ]    The preferred locking range number, starting from 0 (GlobalRange), 1 (Range1), etc.
      /// \param row      [IN/OUT] Locking table row data structure IOTableLocking. Must be initialized properly prior to entry.
      ///
      /// \return status byte of the response ComPacket for this method call.
      //=================================================================================
      virtual TCG_STATUS _getLocking( int rangeNo, IOTableLocking & row ) =0;

      //=================================================================================
      /// \brief Set values of table columns of a range to the Locking table.
      ///
      /// \param rangeNo  [IN ]    The preferred locking range number, starting from 0 (GlobalRange), 1 (Range1), etc.
      /// \param row      [IN/OUT] Locking table row data structure IOTableLocking. Must be initialized properly prior to entry.
      ///
      /// \return status byte of the response ComPacket for this method call.
      //=================================================================================
      virtual TCG_STATUS _setLocking( int rangeNo, IOTableLocking & row ) =0;

      //=================================================================================
      /// \brief Get values of PIN, TryLimit, Tries, and/or Persistence of a C_PIN object in the C_PIN table.      
      ///
      /// \param targetID  [IN]     Target UID, a C_PIN object UID in the C_PIN table.
      /// \param row       [IN/OUT] C_PIN table row data structure IOTableC_PIN. Must be initialized properly prior to entry.
      ///
      /// \return status byte of the response ComPacket for this method call.
      //=================================================================================
      virtual TCG_STATUS _getC_Pin( TCG_UID targetID, IOTableC_PIN & row ) =0;

      //=================================================================================
      /// \brief Set values of PIN, TryLimit, Tries, and/or Persistence of a C_PIN object in the C_PIN table.
      ///
      /// \param targetID  [IN]     Target UID, a C_PIN object UID in the C_PIN table.
      /// \param row       [IN/OUT] C_PIN table row data structure IOTableC_PIN. Must be initialized properly prior to entry.
      ///
      /// \return status byte of the response ComPacket for this method call.
      //=================================================================================
      virtual TCG_STATUS _setC_Pin( TCG_UID targetID, IOTableC_PIN & row ) =0;

      //=================================================================================
      /// \brief Get the value of the columns("Enabled", etc) of an authority (E.g., User1) in Authority table.
      ///
      /// \param authority   [IN]     Target authority to get from. E.g., User1 authority.
      /// \param row         [IN/OUT] Authority table row data structure IOTableAuthority. Must be initialized properly prior to entry.
      ///
      /// \return status byte of the response ComPacket for this method call.
      //=================================================================================
      virtual TCG_STATUS _getAuthority( TCG_UID authority, IOTableAuthority & row ) =0;

      //=================================================================================
      /// \brief Set the value of the columns("Enabled", etc) of an authority (E.g., User1) in Authority table.
      ///
      /// \param authority   [IN]     Target authority to set to. E.g., User1 authority.
      /// \param row         [IN/OUT] Authority table row data structure IOTableAuthority. Must be initialized properly prior to entry.
      ///
      /// \return status byte of the response ComPacket for this method call.
      //=================================================================================
      virtual TCG_STATUS _setAuthority( TCG_UID authority, IOTableAuthority & row ) =0;

      //=================================================================================
      /// \brief Set the "BooleanExpr" column of an ACE object in the ACE table for the specified authorities.
      ///
      /// \param ace             [IN]  Target ACE object UID. E.g., ACE_Locking_Range1_Set_RdLocked.
      /// \param authorities     [IN]  Authority UIDs to set to the given ACE object.
      ///
      /// \return status byte of the response ComPacket for this method call.
      //=================================================================================
      virtual TCG_STATUS _setACE( TCG_UID ace, TCG_UIDs & authorities ) =0;

      //=================================================================================
      /// \brief Get value of 'Mode' from the K_AES_128/256 table row.
      ///
      /// \param kaes    [IN]   UID of the K_AES_128 or 256 table row to get columns from.
      /// \param mode    [OUT]  The 'Mode' value to be returned (an enum, 0-23).
      ///
      /// \return status byte of the response ComPacket for this method call.
      //=================================================================================
      virtual TCG_STATUS _getK_AES( TCG_UID kaes, tUINT8 & mode ) =0;

      //=================================================================================
      /// \brief Read/Get the states of Enable/Done/MBRDoneOnReset from the MBRControl table on the TPer.
      ///
      /// \param row      [IN/OUT]  MBRControl table row data structure IOTableMBRControl. Must be initialized properly prior to entry.
      ///
      /// \return status byte of the response ComPacket for this method call.
      //=================================================================================
      virtual TCG_STATUS _getMBRControl( IOTableMBRControl & row ) = 0;

      //=================================================================================
      /// \brief Write/Set the states of Enable/Done/MBRDoneOnReset to the MBRControl table on the TPer.
      ///
      /// \param row      [IN/OUT]  MBRControl table row data structure IOTableMBRControl. Must be initialized properly prior to entry.
      ///
      /// \return status byte of the response ComPacket for this method call.
      //=================================================================================
      virtual TCG_STATUS _setMBRControl( IOTableMBRControl & row ) = 0;

      //=================================================================================
      /// \brief Get the 'Rows' column value of a given table on the TPer's Table-Table.
      ///
      /// \param targetTable  [IN]   Target table UID.
      /// \param numRows      [OUT]  Number of rows read for the 'Rows' column.
      ///
      /// \return status byte of the response ComPacket for this method call.
      //=================================================================================
      virtual TCG_STATUS _getNumberOfRows( TCG_UID targetTable, tUINT64 & numRows ) =0;



      //=================================================================================
      //
      // TCG Session-oriented job sequences, helper/utility functions
      //
      //=================================================================================

      //=================================================================================
      /// \brief Retrieve the number of user bands from the TPer's Locking-Info table.
      ///
      /// \return the number of user bands.
      //=================================================================================
      virtual int  getMaxBands() =0;

      //=================================================================================
      /// \brief Retrieve MSID from the TPer.
      ///
      /// \param mSID       [OUT] MSID data retrieved from TPer.
      ///
      /// \return status byte of the response ComPacket for this method call.
      //=================================================================================
      virtual TCG_STATUS getMSID( dta::tBytes & mSID ) =0;

      //=================================================================================
      /// \brief Get values of ORG, DataofIssue, Bytes, LifeCycle state, and/or Frozen of a SP object in the SP table.      
      ///
      /// \param row           [IN/OUT] SP table row data structure IOTableSP. Must be initialized properly prior to entry.
      /// \param targetSPUID   [IN]     UID of the target SP, e.g., "AdminSP", "LockingSP".
      /// \param authent       [IN]     AuthenticationParameter used for authentication, if required.
      ///
      /// \return status byte of the response ComPacket for this method call.
      //=================================================================================
      virtual TCG_STATUS getSPRow( IOTableSP & row, TCG_UID targetSPUID, AuthenticationParameter & authent ) =0;

      //=================================================================================
      /// \brief Get values of ORG, DataofIssue, Bytes, LifeCycle state, and/or Frozen of a SP object in the SP table.      
      ///
      /// \param row           [IN/OUT] SP table row data structure IOTableSP. Must be initialized properly prior to entry.
      /// \param targetSPName  [IN]     Target SP name, e.g., "Admin", or "Locking".
      /// \param authent       [IN]     AuthenticationParameter used for authentication, if required.
      ///
      /// \return status byte of the response ComPacket for this method call.
      //=================================================================================
      virtual TCG_STATUS getSPRow( IOTableSP & row, char *targetSPName, AuthenticationParameter & authent ) =0;

      //=================================================================================
      /// \brief Set values of ORG, DataofIssue, Bytes, LifeCycle state, and/or Frozen of a SP object in the SP table.      
      ///
      /// \param row           [IN/OUT] SP table row data structure IOTableSP. Must be initialized properly prior to entry.
      /// \param targetSPUID   [IN]     UID of the target SP, e.g., "AdminSP", "LockingSP".
      /// \param authent       [IN]     AuthenticationParameter used for authentication, if required.
      ///
      /// \return status byte of the response ComPacket for this method call.
      //=================================================================================
      virtual TCG_STATUS setSPRow( IOTableSP & row, TCG_UID targetSPUID, AuthenticationParameter & authent ) =0;

      //=================================================================================
      /// \brief Set values of ORG, DataofIssue, Bytes, LifeCycle state, and/or Frozen of a SP object in the SP table.      
      ///
      /// \param row           [IN/OUT] SP table row data structure IOTableSP. Must be initialized properly prior to entry.
      /// \param targetSPName  [IN]     Target SP name, e.g., "Admin", or "Locking".
      /// \param authent       [IN]     AuthenticationParameter used for authentication, if required.
      ///
      /// \return status byte of the response ComPacket for this method call.
      //=================================================================================
      virtual TCG_STATUS setSPRow( IOTableSP & row, char *targetSPName, AuthenticationParameter & authent ) =0;

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
      virtual TCG_STATUS getLockingInfoRow( IOTableLockingInfo & row, TCG_UID authorityID = UID_NULL, tUINT8 *authenticatePin =NULL, tUINT16 pinLen =0 ) =0;

      //=================================================================================
      /// \brief Get values of MaxRanges, MaxReEncryptions, etc, from the LockingInfo table row.
      ///
      /// \param row      [IN/OUT] LockingInfo table row data structure IOTableLockingInfo. Must be initialized properly prior to entry.
      /// \param authent  [IN]     AuthenticationParameter used for authentication.
      ///
      /// \return status byte of the response ComPacket for this method call.
      //=================================================================================
      virtual TCG_STATUS getLockingInfoRow( IOTableLockingInfo & row, AuthenticationParameter & authent ) =0;

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
      virtual TCG_STATUS getLockingRow( IOTableLocking & row, int rangeNo, bool toStartSession=true, bool toCloseSession=true, TCG_UID authorityID = UID_NULL, tUINT8 *authenticatePin =NULL, tUINT16 pinLen =0 ) =0;

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
      virtual TCG_STATUS getLockingRow( IOTableLocking & row, int rangeNo, AuthenticationParameter & authent, bool toStartSession=true, bool toCloseSession=true ) =0;

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
      virtual TCG_STATUS setLockingRow( IOTableLocking & row, int rangeNo, bool toStartSession=true, bool toCloseSession=true, TCG_UID authorityID = UID_AUT_ADMIN1, tUINT8 *authenticatePin =NULL, tUINT16 pinLen =0 ) =0;

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
      virtual TCG_STATUS setLockingRow( IOTableLocking & row, int rangeNo, AuthenticationParameter & authent, bool toStartSession=true, bool toCloseSession=true ) =0;

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
      virtual TCG_STATUS getC_PINRow( IOTableC_PIN & row, TCG_UID targetID, TCG_UID authorityID = UID_NULL, tUINT8 *authenticatePin =NULL, tUINT16 pinLen =0 ) =0;

      //=================================================================================
      /// \brief Retrieve and return column values of a C_PIN object, SID, BandMaster, EraseMaster, Admin, or User, etc, from the C_PIN table.
      ///
      /// \param row             [IN/OUT] C_PIN table row data structure IOTableC_PIN. Must be initialized properly prior to entry.
      /// \param targetName      [IN]     Target name ("SID", "BandMaster", "EraseMaster", "Admin", or "User", etc).
      /// \param authent         [IN]     AuthenticationParameter used for authentication.
      ///
      /// \return status byte of the response ComPacket for this method call.
      //=================================================================================
      virtual TCG_STATUS getC_PINRow( IOTableC_PIN & row, char * targetName, AuthenticationParameter & authent ) =0;

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
      virtual TCG_STATUS setC_PINRow( IOTableC_PIN & row, TCG_UID targetID, TCG_UID authorityID = UID_NULL, tUINT8 *authenticatePin =NULL, tUINT16 pinLen =0 ) =0;

      //=================================================================================
      /// \brief Set values of columns of a C_PIN object, SID, BandMaster, EraseMaster, Admin, or User, etc, to the C_PIN table.
      ///
      /// \param row             [IN/OUT] C_PIN table row data structure IOTableC_PIN. Must be initialized properly prior to entry.
      /// \param targetName      [IN]     Target name ("SID", "BandMaster", "EraseMaster", "Admin", or "User", etc).
      /// \param authent         [IN]     AuthenticationParameter used for authentication.
      ///
      /// \return status byte of the response ComPacket for this method call.
      //=================================================================================
      virtual TCG_STATUS setC_PINRow( IOTableC_PIN & row, char * targetName, AuthenticationParameter & authent ) =0;

      //=================================================================================
      /// \brief Retrieve and return column values of an Authority object, SID, BandMaster, EraseMaster, Admin, or User, etc, from the Authority table.
      ///
      /// \param row             [IN/OUT] Authority table row data structure IOTableAuthority. Must be initialized properly prior to entry.
      /// \param targetID        [IN]     Target authority UID ("SID", "BandMaster", "EraseMaster", "Admin", or "User", etc).
      /// \param authorityID     [IN]     Authority UID, if required, depending on the operation.
      /// \param authenticatePin [IN]     Authentication pin to the SP. E.g., BandMaster1, Admin1 or User1, etc.
      /// \param pinLen          [IN]     Length of the authentication pin.
      ///
      /// \return status byte of the response ComPacket for this method call.
      //=================================================================================
      virtual TCG_STATUS getAuthorityRow( IOTableAuthority & row, TCG_UID targetID, TCG_UID authorityID = UID_NULL, tUINT8 *authenticatePin =NULL, tUINT16 pinLen =0 ) =0;

      //=================================================================================
      /// \brief Retrieve and return column values of an Authority object, SID, BandMaster, EraseMaster, Admin, or User, etc, from the Authority table.
      ///
      /// \param row             [IN/OUT] Authority table row data structure IOTableAuthority. Must be initialized properly prior to entry.
      /// \param targetName      [IN]     Target authority name ("SID", "BandMaster", "EraseMaster", "Admin", or "User", etc).
      /// \param authent         [IN]     AuthenticationParameter used for authentication.
      ///
      /// \return status byte of the response ComPacket for this method call.
      //=================================================================================
      virtual TCG_STATUS getAuthorityRow( IOTableAuthority & row, char * targetName, AuthenticationParameter & authent ) =0;

      //=================================================================================
      /// \brief Set values of columns of an Authority object, SID, BandMaster, EraseMaster, Admin, or User, etc, to the Authority table.
      ///
      /// \param row             [IN/OUT] Authority table row data structure IOTableAuthority. Must be initialized properly prior to entry.
      /// \param targetID        [IN]     Target authority UID ("SID", "BandMaster", "EraseMaster", "Admin", or "User", etc).
      /// \param authorityID     [IN]     Authority UID, if required, depending on the operation.
      /// \param authenticatePin [IN]     Authentication pin to the SP. E.g., BandMaster1, Admin1 or User1, etc.
      /// \param pinLen          [IN]     Length of the authentication pin.
      ///
      /// \return status byte of the response ComPacket for this method call.
      //=================================================================================
      virtual TCG_STATUS setAuthorityRow( IOTableAuthority & row, TCG_UID targetID, TCG_UID authorityID = UID_NULL, tUINT8 *authenticatePin =NULL, tUINT16 pinLen =0 ) =0;

      //=================================================================================
      /// \brief Set values of columns of an Authority object, SID, BandMaster, EraseMaster, Admin, or User, etc, to the Authority table.
      ///
      /// \param row             [IN/OUT] Authority table row data structure IOTableAuthority. Must be initialized properly prior to entry.
      /// \param targetName      [IN]     Target authority name ("SID", "BandMaster", "EraseMaster", "Admin", or "User", etc).
      /// \param authent         [IN]     AuthenticationParameter used for authentication.
      ///
      /// \return status byte of the response ComPacket for this method call.
      //=================================================================================
      virtual TCG_STATUS setAuthorityRow( IOTableAuthority & row, char * targetName, AuthenticationParameter & authent ) =0;

      //=================================================================================
      /// \brief Cryptographically erase a band of the TPer.
      ///
      /// \param startBandNo     [IN]  Start band no.
      /// \param endBandNo       [IN]  End band no.
      /// \param authorityID     [IN]  Authority UID, if required by the operation.
      /// \param authenticatePin [IN]  Authentication pin to EraseMaster.
      /// \param pinLen          [IN]  Length of the authentication pin.
      /// \param resetAccess     [IN]  Whether to unlock the band and reset the credential value upon method activation. This parameter means only for Opal FixedACL ranges. For normal Opal ranges, it should be set as FALSE. For Ent-SSC, it works as if it were always TRUE, regardless of its actual input.
      ///
      /// \return status byte of the response ComPacket for this method call.
      //=================================================================================
      virtual TCG_STATUS eraseBand( int startBandNo, int endBandNo, TCG_UID authorityID =UID_NULL, tUINT8 *authenticatePin =NULL, tUINT16 pinLen =0, bool resetAccess =true ) =0;

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
      virtual TCG_STATUS eraseBand( int startBandNo, int endBandNo, AuthenticationParameter & authent, bool resetAccess =true ) =0;

      //=================================================================================
      /// \brief Read/Get data from the DataStore table on the TPer.
      ///
      /// \param data            [OUT] Data of raw bytes to be retrieved from the DataStore table.
      /// \param targetDS        [IN]  Target Datastore table sequence number, starting from 0, if multiple datastore tables are supported. The "Additional_DataStore_Tables" spec defines DS table names starting from 1.
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
      virtual TCG_STATUS readDataStore( dta::tBytes & data, int targetDS =0, tINT64 startRow =-1, tINT64 endRow =-1, TCG_UID authorityID = UID_NULL, tUINT8 *authenticatePin =NULL, tUINT16 pinLen =0, UserProgressUpdateCallBack progressUpdt =NULL, tUINT32 *pDurationMS =NULL ) =0;

      //=================================================================================
      /// \brief Write/Set data to the DataStore table on the TPer.
      ///
      /// \param data            [IN]  Data of raw bytes to be written to the DataStore table.
      /// \param targetDS        [IN]  Target Datastore table sequence number, starting from 0, if multiple datastore tables are supported. The "Additional_DataStore_Tables" spec defines DS table names starting from 1.
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
      virtual TCG_STATUS writeDataStore( dta::tBytes & data, int targetDS, tINT64 startRow, tINT64 endRow, TCG_UID authorityID, tUINT8 *authenticatePin, tUINT16 pinLen, UserProgressUpdateCallBack progressUpdt =NULL, tUINT32 *pDurationMS =NULL ) =0;

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
      virtual TCG_STATUS readDataStore( dta::tBytes & data, AuthenticationParameter & authent, int targetDS =0, tINT64 startRow =-1, tINT64 endRow =-1, UserProgressUpdateCallBack progressUpdt =NULL, tUINT32 *pDurationMS =NULL ) =0;

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
      virtual TCG_STATUS writeDataStore( dta::tBytes & data, AuthenticationParameter & authent, int targetDS, tINT64 startRow, tINT64 endRow, UserProgressUpdateCallBack progressUpdt =NULL, tUINT32 *pDurationMS =NULL ) =0;

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
      virtual TCG_STATUS readMBR( dta::tBytes & data, tINT64 startRow, tINT64 endRow, TCG_UID authorityID = UID_NULL, tUINT8 *authenticatePin =NULL, tUINT16 pinLen =0, UserProgressUpdateCallBack progressUpdt =NULL, tUINT32 *pDurationMS =NULL ) =0;

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
      virtual TCG_STATUS writeMBR( dta::tBytes & data, tINT64 startRow, tINT64 endRow, TCG_UID authorityID, tUINT8 *authenticatePin, tUINT16 pinLen, UserProgressUpdateCallBack progressUpdt =NULL, tUINT32 *pDurationMS =NULL ) =0;

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
      virtual TCG_STATUS readMBR( dta::tBytes & data, AuthenticationParameter & authent, tINT64 startRow, tINT64 endRow, UserProgressUpdateCallBack progressUpdt =NULL, tUINT32 *pDurationMS =NULL ) =0;

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
      virtual TCG_STATUS writeMBR( dta::tBytes & data, AuthenticationParameter & authent, tINT64 startRow, tINT64 endRow, UserProgressUpdateCallBack progressUpdt =NULL, tUINT32 *pDurationMS =NULL ) =0;

      //=================================================================================
      /// \brief Read/Get the states of Enable/Done/MBRDoneOnReset from the MBRControl table on the TPer.
      ///
      /// \param row      [IN/OUT]  MBRControl table row data structure IOTableMBRControl. Must be initialized properly prior to entry.
      /// \param authent  [IN]      AuthenticationParameter used for authentication.
      ///
      /// \return status byte of the response ComPacket for this method call.
      //=================================================================================
      virtual TCG_STATUS readMBRControl( IOTableMBRControl & row, AuthenticationParameter & authent ) =0;

      //=================================================================================
      /// \brief Write/Set the states of Enable/Done/MBRDoneOnReset to the MBRControl table on the TPer.
      ///
      /// \param row      [IN/OUT]  MBRControl table row data structure IOTableMBRControl. Must be initialized properly prior to entry.
      /// \param authent  [IN]      AuthenticationParameter used for authentication.
      ///
      /// \return status byte of the response ComPacket for this method call.
      //=================================================================================
      virtual TCG_STATUS writeMBRControl( IOTableMBRControl & row, AuthenticationParameter & authent ) =0;

      //=================================================================================
      /// \brief Enable an authority (E.g., User1) on the TPer.
      ///
      /// \param targetID    [IN]  Target authority to be enabled. E.g., User1 authority.
      /// \param authent     [IN]  AuthenticationParameter, if required by the operation.
      ///
      /// \return status byte of the response ComPacket for this method call.
      //=================================================================================
      virtual TCG_STATUS enableAuthority( TCG_UID targetID, AuthenticationParameter & authent ) =0;

      //=================================================================================
      /// \brief Enable an authority (E.g., User1) on the TPer.
      ///
      /// \param targetName  [IN]  Target authority to be enabled. E.g., User1 authority.
      /// \param authent     [IN]  AuthenticationParameter, if required by the operation.
      ///
      /// \return status byte of the response ComPacket for this method call.
      //=================================================================================
      virtual TCG_STATUS enableAuthority( char * targetName, AuthenticationParameter & authent ) =0;

      //=================================================================================
      /// \brief Disable an authority (E.g., User1) on the TPer.
      ///
      /// \param targetID    [IN]  Target authority to be disabled. E.g., User1 authority.
      /// \param authent     [IN]  AuthenticationParameter, if required by the operation.
      ///
      /// \return status byte of the response ComPacket for this method call.
      //=================================================================================
      virtual TCG_STATUS disableAuthority( TCG_UID targetID, AuthenticationParameter & authent ) =0;

      //=================================================================================
      /// \brief Disable an authority (E.g., User1) on the TPer.
      ///
      /// \param targetName  [IN]  Target authority to be disabled. E.g., User1 authority.
      /// \param authent     [IN]  AuthenticationParameter, if required by the operation.
      ///
      /// \return status byte of the response ComPacket for this method call.
      //=================================================================================
      virtual TCG_STATUS disableAuthority( char * targetName, AuthenticationParameter & authent ) =0;

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
      virtual TCG_STATUS setAuthorityACE( TCG_UID ace, TCG_UIDs & authorities, TCG_UID authorityID = UID_AUT_ADMIN1, tUINT8 *authenticatePin =NULL, tUINT16 pinLen =0 ) =0;

      //=================================================================================
      /// \brief Set the "BooleanExpr" column of an ACE object in the ACE table for the specified authorities.
      ///
      /// \param ace             [IN]  Target ACE object UID. E.g., ACE_Locking_Range1_Set_RdLocked.
      /// \param authorities     [IN]  Authority UIDs to set to the given ACE object.
      /// \param authent         [IN]  AuthenticationParameter, if required by the operation.
      ///
      /// \return status byte of the response ComPacket for this method call.
      //=================================================================================
      virtual TCG_STATUS setAuthorityACE( TCG_UID ace, TCG_UIDs & authorities, AuthenticationParameter & authent ) =0;

      //=================================================================================
      /// \brief Revert a given SP to its factory state on the TPer.
      ///
      /// \param targetSPUID   [IN]  target SP UID to revert.
      /// \param authent       [IN]  AuthenticationParameter required by the operation, e.g., SP Owner PSID for AdminSP.
      ///
      /// \return status byte of the response ComPacket for this method call.
      //=================================================================================
      virtual TCG_STATUS revertSP( TCG_UID targetSPUID, AuthenticationParameter & authent ) =0;

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
      virtual TCG_STATUS activate( TCG_UID targetSPUID, AuthenticationParameter & authent, TCG_UIDs *pSingleUserModeList =NULL, int rangeStartLengthPolicy =-1, UINT64VALs *pDataStoreTableSizes =NULL ) =0;

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
      virtual TCG_STATUS activate( char *targetSPName, AuthenticationParameter & authent, TCG_BANDNOs *pSingleUserModeList =NULL, int rangeStartLengthPolicy =-1, UINT64VALs *pDataStoreTableSizes =NULL ) =0;

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
      virtual TCG_STATUS reactivate( AuthenticationParameter & authent, TCG_UIDs *pSingleUserModeList =NULL, int rangeStartLengthPolicy =-1, dta::tBytes *pAdmin1PIN =NULL, UINT64VALs *pDataStoreTableSizes =NULL ) =0;

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
      virtual TCG_STATUS reactivate( AuthenticationParameter & authent, TCG_BANDNOs *pSingleUserModeList =NULL, int rangeStartLengthPolicy =-1, dta::tBytes *pAdmin1PIN =NULL, UINT64VALs *pDataStoreTableSizes =NULL ) =0;

      //=================================================================================
      /// \brief Revert a given SP to its factory state on the TPer.
      ///
      /// \param targetSPName  [IN]  target SP name to revert, e.g., "Admin", "Locking".
      /// \param authent       [IN]  AuthenticationParameter required by the operation, e.g., SP Owner PSID for AdminSP.
      ///
      /// \return status byte of the response ComPacket for this method call.
      //=================================================================================
      virtual TCG_STATUS revertSP( char *targetSPName, AuthenticationParameter & authent ) =0;

      //=================================================================================
      /// \brief Security protocol stack reset.
      ///
      /// \param comChannel             [IN]  ComID channel index, starting from 0 to max.
      /// \param syncHostTPerProperties [IN]  Whether or not to synchronize communication Properties between Host and TPer.
      ///
      /// \return status byte of the response ComPacket for this method call.
      //=================================================================================
      virtual TCG_STATUS protocolStackReset( int comChannel =0, bool syncHostTPerProperties =true ) =0;

      //=================================================================================
      /// \brief Security TPer Reset.
      ///
      /// \param syncHostTPerProperties [IN]  Whether or not to synchronize communication Properties between Host and TPer.
      ///
      /// \return status byte of the response ComPacket for this method call.
      //=================================================================================
      virtual TCG_STATUS TPerReset( bool syncHostTPerProperties =true ) =0;

      //=================================================================================
      /// \brief Select the channel for a pre-issued (static) COMID.
      ///
      /// \param comChannel             [IN]  ComID channel index, starting from 0 to max.
      /// \param syncHostTPerProperties [IN]  Whether or not to synchronize communication Properties between Host and TPer.
      ///
      /// \return status byte of the response ComPacket for this method call.
      //=================================================================================
      virtual TCG_STATUS selectComChannel( int comChannel =0, bool syncHostTPerProperties =true ) =0;

      //=================================================================================
      /// \brief Get the Security Operating Mode state from the _SecurityOperatingMode table (Seagate Proprietary).
      ///
      /// \return byte value of the SOM state.
      //=================================================================================
      virtual tUINT8 getSOM() =0;

      //=================================================================================
      /// \brief Retrieve and return column values of the FWDownload port object from the _PortLocking table. (Seagate proprietary)
      ///
      /// \param row          [IN/OUT] _PortLocking table row data structure IOTable_PortLocking. Must be initialized properly prior to entry.
      /// \param authent      [IN]     AuthenticationParameter used for authentication. Default is SID.
      ///
      /// \return status byte of the response ComPacket for this method call.
      //=================================================================================
      virtual TCG_STATUS getFWDownload( IOTable_PortLocking & row, AuthenticationParameter & authent ) =0;

      //=================================================================================
      /// \brief Set values of table columns of the FWDownload port object in the _PortLocking table. (Seagate proprietary)
      ///
      /// \param row          [IN/OUT] _PortLocking table row data structure IOTable_PortLocking. Must be initialized properly prior to entry.
      /// \param authent      [IN]     AuthenticationParameter used for authentication. Default is SID.
      ///
      /// \return status byte of the response ComPacket for this method call.
      //=================================================================================
      virtual TCG_STATUS setFWDownload( IOTable_PortLocking & row, AuthenticationParameter & authent ) =0;

      //=================================================================================
      /// \brief Retrieve and return column values of the UDS port object from the _PortLocking table. (Seagate proprietary)
      ///
      /// \param row          [IN/OUT] _PortLocking table row data structure IOTable_PortLocking. Must be initialized properly prior to entry.
      /// \param authent      [IN]     AuthenticationParameter used for authentication. Default is SID.
      ///
      /// \return status byte of the response ComPacket for this method call.
      //=================================================================================
      virtual TCG_STATUS getSecureUDS( IOTable_PortLocking & row, AuthenticationParameter & authent ) =0;

      //=================================================================================
      /// \brief Set values of table columns of the UDS port object in the _PortLocking table. (Seagate proprietary)
      ///
      /// \param row          [IN/OUT] _PortLocking table row data structure IOTable_PortLocking. Must be initialized properly prior to entry.
      /// \param authent      [IN]     AuthenticationParameter used for authentication. Default is SID.
      ///
      /// \return status byte of the response ComPacket for this method call.
      //=================================================================================
      virtual TCG_STATUS setSecureUDS( IOTable_PortLocking & row, AuthenticationParameter & authent ) =0;

      //=================================================================================
      //
      // Helper/Utility functions
      //
      //=================================================================================
      virtual tUINT32 getMethodExecTime() =0;
      virtual bool synchronizeHostTPerProperties() =0;
      virtual bool isTCGProtocolSupported() =0;
      virtual bool isDeviceEnterpriseSSC() =0;
      virtual bool isDeviceOpalSSC() =0;
      virtual bool isDeviceOpalSSCVersion2() =0;   // jls20120103
      virtual tUINT8  getRangeCrossingAllowed() =0;// jls20120227
      virtual tUINT16 getMaxLockingSPAdmins() =0;  // jls20120227
      virtual tUINT16 getMaxLockingSPUsers() =0;   // jls20120227
      virtual tUINT8  getSIDdefaultValue() =0;     // jls20120227
      virtual tUINT8  getSIDOnRevertValue() =0;    // jls20120227

      virtual bool isDeviceMarbleSSC() =0;
      virtual bool isDeviceTCGCoreVersion1() =0;
      virtual bool isDeviceLocked( bool refresh =true ) =0;
      virtual bool isDeviceMBRDone( bool refresh =true ) =0;
      virtual bool isDeviceMBREnabled( bool refresh =true ) =0;
      virtual bool isTPerResetSupported() =0;
      virtual bool isTPerResetEnabled() =0;        //  jls20120404
      virtual TCG_STATUS setTPerResetEnable( AuthenticationParameter & authent, bool enable =true ) =0; // jls20120404

      virtual bool isSingleUserModeSupported() =0;
      virtual bool isAnyInSingleUserMode( bool refresh =true ) =0;
      virtual bool areAllInSingleUserMode( bool refresh =true ) =0;
      virtual bool isSingleUserModePolicyOwnedByAdmin( bool refresh =true ) =0;
      virtual tUINT32 getSingleUserModeNumLockingObjects() =0;

      virtual bool  isDataStoreTableFeatureSupported() =0;
      virtual tUINT16 getMaxNumberOfDataStoreTables() =0;
      virtual tUINT32 getMaxTotalSizeOfDataStoreTables() =0;
      virtual tUINT32 getDataStoreTableSizeAlignment() =0;

      virtual bool isGeometryAlignmentRequired() =0;
      virtual tUINT32 getGeometryLogicalBlockSize() =0;
      virtual tUINT64 getGeometryAlignmentGranularity() =0;
      virtual tUINT64 getGeometryLowestAlignedLBA() =0;

      virtual bool setPreferenceToUseDynamicComID( bool useDynamicComID ) =0;
      virtual bool getPreferenceToUseDynamicComID() =0;

      virtual tUINT16 getBaseComID() =0;
      virtual tUINT16 getNumberOfComIDs() =0;

      virtual tUINT32 getMaxUserDataLength() =0;
      virtual dta::tBytes & getResponseBuffer() =0;

      virtual TCG_UID mapAuthorityNameToUID( char *name ) =0;
      virtual TCG_UID mapPinNameToUID( char *name ) =0;
      virtual char *  mapUIDToName( TCG_UID uid, char *pBuffer, int maxLength ) =0; // jls20120316

      virtual _tstring tcgStatusToString( const TCG_STATUS status ) =0;
      virtual _tstring dtlErrorToString( const dta::DTA_ERROR status ) =0;

      virtual _tstring getDriveSerialNo() =0;

      virtual tUINT8 getLifeCycleState( bool Refresh ) =0;
      virtual tUINT8 getVendorFeatureSupported() =0;
      virtual tUINT8 getVendorFeatureEnabled() =0;

      virtual tUINT16 getLogicalPortsAvailable() =0;
      virtual dta::tBytes &getLogicalPortData() =0;

      virtual bool hasSilo() const =0;
      virtual void setUseSilo(const bool newUseSilo) =0;

      //=================================================================================
      //
      // Poll sleep time getter/setter methods
      //
      //=================================================================================
      //=================================================================================
      /// \brief Get current poll sleep time for securityPacketExchange.
      ///
      /// \return Current poll time (ms).
      //=================================================================================
      virtual unsigned int getPollSleepTime() const = 0;

      //=================================================================================
      /// \brief Set current poll sleep time for securityPacketExchange.
      ///
      /// \param t      [IN]  Poll sleep time.
      ///
      /// \return Poll sleep time before setting to the new value.
      //=================================================================================
      virtual unsigned int setPollSleepTime(const unsigned int t) = 0;


   protected:
      //=================================================================================
      /// \brief Constructor for ITCGInterface.
      ///
      /// The constructor takes a CDriveTrustSession as its class member. Not called directly by apps.
      ///
      /// \param newSession [in] DriveTrust session object which has been initialized
      ///                        and connected to a DriveTrust device.
      ///
      //=================================================================================
      ITCGInterface(dta::CDriveTrustSession* newSession) : CDriveTrustInterface(newSession) {}

      //=================================================================================
      /// \brief Constructor for ITCGInterface.
      ///
      /// The constructor takes a CDriveTrustSession as its class member. Not called directly by apps.
      /// It creates a log file.
      ///
      /// \param newSession [in] DriveTrust session object which has been initialized
      ///                        and connected to a DriveTrust device.
      /// \param logFileName [in] Name of file to log ComPackets.
      ///
      //=================================================================================
      ITCGInterface(dta::CDriveTrustSession* newSession, const _tstring logFileName) : CDriveTrustInterface(newSession, logFileName) {}


   }; // class ITCGInterface

} // namespace dti

#endif // TCG_INTERFACE_DOT_HPP
