/*! \file dta.hpp
    \brief Basic API definition for Drive Trust Access (DTA).

    This file details the interface classes and functions for writing
    client code that uses DTA to access DriveTrust devices.  It is a
    C++ specific interface.  For a 'C' interface, include dta.h instead
    of this file.
    
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
#ifndef DTA_DOT_HPP
#define DTA_DOT_HPP

#if !defined(__cplusplus)
#error C++ compiler required.  Include dta.h for 'C' compilers.
#endif
// !defined __cplusplus
//=================================
// Include files
//=================================
#include <string>
#include <list>
#include <vector>
#include <dta/errors.h>

namespace dta {
//=================================
// macro definitions
//=================================
#ifdef  min
#undef  min
#endif
#define min(a,b)  ((a < b) ? a : b)

#ifdef CLEARBIT
#undef CLEARBIT
#endif
#define CLEARBIT(a, b)  (a &= ~(1UL << b))

#ifdef SETBIT
#undef SETBIT
#endif
#define SETBIT(a, b) (a |= (1UL << b))

#ifdef TOGGLEBIT
#undef TOGGLEBIT
#endif
#define TOBBLEBIT(a, b) (a ^= (1UL << b))

#ifdef READBIT
#undef READBIT
#endif
#define READBIT(a, b) ((a >> b) & 1)

/// Simple macro to save off current throw or return
/// behavior and enter a try block.
#define M_DriveTrustBaseTry()                            \
   dta::DTA_ERROR __result = dta::Success;               \
   bool __throwOnError = SetThrowOnError(true);          \
   try

/// Simple macro to catch a DTA_ERROR.  This will
/// restore ThrowOnError to previous setting and also
/// assign __result with the provided error code.
#define M_DriveTrustBaseCatch()                          \
   catch( const dta::DTA_ERROR& err )                    \
   {                                                     \
      __result = err;                                    \
   }                                                     \
   SetThrowOnError( __throwOnError );

/// Simple macro to catch DTA_ERRORs in a CDriveTrustBase
/// object and return or rethrow the error as necessary.
#define M_DriveTrustBaseSimpleEndTry()                   \
   M_DriveTrustBaseCatch()                               \
   if ( (!M_DtaSuccess(__result)) && GetThrowOnError() ) \
   {                                                     \
      throw __result;                                    \
   }                                                     \
   return __result;

//=================================
// constants
//=================================

/// Security Protocol Bits
const tUINT16 SECURITY_PROTOCOL_BIT_TCG      = 0x0001;
const tUINT16 SECURITY_PROTOCOL_BIT_IEEE1667 = 0x0002;
const tUINT16 SECURITY_PROTOCOL_BIT_SEACOS   = 0x0004;

/// Transport Protocol Bits
const tUINT16 TRANSPORT_PROTOCOL_BIT_ATA     = 0x0001;
const tUINT16 TRANSPORT_PROTOCOL_BIT_SCSI    = 0x0002;
const tUINT16 TRANSPORT_PROTOCOL_BIT_USB     = 0x0004;
const tUINT16 TRANSPORT_PROTOCOL_BIT_1394    = 0x0008;
const tUINT16 TRANSPORT_PROTOCOL_BIT_RAID    = 0x0010;
const tUINT16 TRANSPORT_PROTOCOL_BIT_ES      = 0x0020;

/// Bus Type Strings
const _tstring BUS_TYPE_ATA                  = TXT("ATA:");
const _tstring BUS_TYPE_SCSI                 = TXT("SCSI:");
const _tstring BUS_TYPE_USB                  = TXT("USB:");
const _tstring BUS_TYPE_1394                 = TXT("1394:");
const _tstring BUS_TYPE_RAID                 = TXT("RAID:");
const _tstring BUS_TYPE_ES                   = TXT("ES:");
const _tstring BUS_TYPE_UNDETERMINED         = TXT("UNDETERMINED:");

extern const DTA_ERROR Success;

/// A list of possible lock types for a session.
typedef enum
{
   eLockTypeAll=0,   //!< Lock or unlock all other enumerations
   eLockTypeTxRx,    //!< (Un)Lock a Trusted Send/Trusted Receive pair
   eLockTypeSession, //!< (Un)Lock all similar sessions
   eLockTypeMaxValue //!< Enumeration terminator
} eSessionLockTypes;

/// A list of security protocol IDs.
typedef enum
{
   eSPDiscovery = 0x00, //!< Protocol 0 is for discovery.
   eSPTCG       = 0x01, //!< TCG Protocol
   eSPIEEE1667  = 0xEE, //!< IEEE-1667 is Enhanced Storage under Windows.
   eSPSeaCOS    = 0xF0, //!< F0 is vendor unique, SeaCOS for Seagate.
} eSecurityProtocols;

//=================================
// typedefs and structures
//=================================
/// Abstracted type for a DriveTrust Identifier
typedef _tstring DTIdentifier;

/// A grouping of DriveTrust Identifiers
typedef std::list<DTIdentifier> DTIdentifierCollection;

/// A grouping of DriveTrust Attributes
typedef std::list<_tstring> DTAttributeCollection;

/// A mapping of byte types
typedef tUINT8 tByte;

/// A flat memory grouping of bytes for data payloads.
typedef std::vector< tByte > tBytes;

//=================================
// class definitions
//=================================
class CDriveTrustSession;

//====================================================================================
/// \brief Base class for most DriveTrust access classes.
///
/// CDriveTrustBase is a base class providing some comm
/// functionality for DriveTrust access classes.  It
/// provides default implementations as well that can be
/// overridden as necessary.
//====================================================================================
class CDriveTrustBase
{
protected:
   /// Default constructor.
   CDriveTrustBase();
   /// Default destructor.
   virtual ~CDriveTrustBase() {}
public:
   //================================================================
   //
   /// Release currently held system resources and invalidate object.
   ///
   /// This method should be called when use of the CDriveTrustBase 
   /// interface is complete.  After Destroy() is called, the caller
   /// should not call any other methods on the interface or 
   /// attempt to dispose of the object in any way.
   ///
   /// \return DTA_ERROR - Return success (0) or error code.
   ///
   /// @pre None.
   ///
   /// @post Object is destroyed, and should not be used again.
   //
   //================================================================
   virtual DTA_ERROR Destroy();

   //================================================================
   //
   /// Returns whether the object will return or throw a 
   /// a DTA_ERROR when an error is encountered.
   ///
   /// \return Boolean value noting if an error is thrown (true)
   ///         or just returned (false) when an error occurs.
   ///
   /// @pre  None
   ///
   /// @post None
   //
   //================================================================
   virtual bool GetThrowOnError() const;

   //================================================================
   //
   /// Determines whether methods in the DriveTrust object should
   /// signal an error through a return code or by throwing.
   ///
   /// All methods on the DriveTrust interface by default will
   /// return a DTA_ERROR structure on completion.  If 
   /// SetThrowOnError( true ) is called, then any error generated
   /// will be thrown (via the C++ mechanism) to the caller, 
   /// allowing the caller easy use of the try/catch mechanism.
   ///
   /// \param newVal - (IN)
   ///      Boolean value determining whether the behavior of
   ///      the object on error is to return the DTA_ERROR
   ///      or to throw it for the caller to catch.
   ///
   /// \return Previous value of ThrowOnError.
   ///
   /// @pre  None
   ///
   /// @post None
   //
   //================================================================
   virtual bool SetThrowOnError( bool newVal );

   //================================================================
   //
   /// Add an entry to the log file, if available.
   ///
   /// DriveTrust objects frequently have the ability to log
   /// significant events (errors) or entries to a log file, if
   /// requested by the user.  By default, logging is disabled 
   /// unless a log file name is specifically provided.
   ///
   /// \param error - (IN)
   ///      A DTA_ERROR enumeration, or success if no error is
   ///      to be reported to the log.
   ///
   /// \param text - (IN)
   ///      The text to be placed in the log file, or an empty
   ///      string if no extra text is requested.
   ///
   /// \return The DTA_ERROR provided in error.
   ///
   /// @pre  None
   ///
   /// @post None
   //
   //================================================================
   virtual dta::DTA_ERROR AddLogEntry( 
      const dta::DTA_ERROR &error,
      const _tstring& text 
      );

protected:
   /// Determines if errors are throw when encountered.
   bool m_throwOnError;

}; // end CDriveTrustBase

//====================================================================================
/// \brief Class representing a communication session between
///        an application and the DriveTrust device.
///
/// CDriveTrustSession is an interface defining the minimal command
/// support required for DriveTrust devices.  The actual object
/// is created via CLocalSystem::CreateSession().  When use of
/// the object (session) is complete, it should be concluded with
/// Destroy() to release system resources.
///
//
//====================================================================================
class CDriveTrustSession : public CDriveTrustBase
{
protected:
   /// Default destructor.
   virtual ~CDriveTrustSession() {}
public:
   //================================================================
   //
   /// Transmit a security command via a data payload to a DriveTrust
   /// device.
   ///
   /// This method can be called to transmit a security payload to
   /// a DriveTrust device.  Implementation of the transfer over the
   /// interface will vary according to the hardware and interfaces
   /// used.  For example, for ATA-8 devices, this command may be 
   /// mapped to the ATA-8 operation TRUSTED SEND (5Eh) or
   /// TRUSTED SEND DMA (5Fh).
   ///
   /// In most cases, the user is going to want to couple together
   /// a SecurityDataToDevice() and SecurityDataFromDevice() to 
   /// deliver a payload to the device and then pick up the 
   /// appropriate response data.  For these cases, it is recommended
   /// to use the SecurityDataExchange() method for convenience.
   ///
   /// \param dataToSend - (IN)
   ///      A data payload to be delivered to the device.  This
   ///      payload shall be formatted according to the protocol
   ///      ID established when the session was created.
   ///
   /// \return DTA_ERROR - Return success (0) or error code.
   ///
   /// @pre None
   ///
   /// @post None
   //
   //================================================================
   virtual DTA_ERROR SecurityDataToDevice( const dta::tBytes &dataToSend ) = 0;

   //================================================================
   //
   /// Receives a security response via a data payload from a DriveTrust
   /// device.
   ///
   /// This method can be called to receive a security payload from 
   /// a DriveTrust device.  Implementation of the transfer over the
   /// interface will vary according to the hardware and interfaces
   /// used.  For example, for ATA-8 devices, this command may be 
   /// mapped to the ATA-8 operation TRUSTED RECEIVE (5Ch) or
   /// TRUSTED RECEIVE DMA (5Dh).
   ///
   /// In most cases, the user is going to want to couple together
   /// a SecurityDataToDevice() and SecurityDataFromDevice() to 
   /// deliver a payload to the device and then pick up the 
   /// appropriate response data.  For these cases, it is recommended
   /// to use the SecurityDataExchange() method for convenience.
   ///
   /// \param dataToRecv - (IN, OUT)
   ///      A data payload delivered from the device to the host.  
   ///      The buffer will be populated with data received from
   ///      the device.  The size of the buffer determines the
   ///      number of bytes expected and placed in the buffer.
   ///
   /// \return DTA_ERROR - Return success (0) or error code.
   ///
   /// @pre None
   ///
   /// @post None
   //
   //================================================================
   virtual DTA_ERROR SecurityDataFromDevice( 
      dta::tBytes &dataToRecv 
      ) = 0;

   //================================================================
   //
   /// Exchange security data buffers with a DriveTrust Device.
   ///
   /// In most cases, the user is going to want to couple together
   /// a SecurityDataToDevice() and SecurityDataFromDevice() to 
   /// deliver a payload to the device and then pick up the 
   /// appropriate response data.  This method is a convenient way
   /// do so and may provide hints to the DTA objects on how to
   /// optimize data traffic or locking behaviors.
   ///
   /// \param dataToSend - (IN)
   ///      A data payload to be delivered to the device.  This
   ///      payload shall be formatted according to the protocol
   ///      ID established when the session was created.
   ///
   /// \param dataToRecv - (OUT)
   ///      A data payload delivered from the device to the host.  
   ///      This payload shall be formatted according to the 
   ///      protocol ID established when the session was created.
   ///
   /// \return DTA_ERROR - Return success (0) or error code.
   ///
   /// @pre None
   ///
   /// @post None
   //
   //================================================================
   virtual DTA_ERROR SecurityDataExchange( 
      const dta::tBytes &dataToSend,
      dta::tBytes &dataToRecv 
      );

   //================================================================
   //
   /// Transmit a security command via a protocol ID, SP specific value,
   /// and a data payload to a DriveTrust device.
   ///
   /// This method is a more generic version of delivering a security 
   /// command, especially pertinent to the TCG-compliant devices (IF-Send).
   /// It can be called to transmit a security payload with a given 
   /// protocol ID and a SP specific value to a DriveTrust device.
   /// Implementation of the transfer over the interface will vary 
   /// according to the hardware and interfaces used.  For example, 
   /// this command may be mapped to the SCSI operation Security 
   /// Protocol-Out (B5h) for SCSI/SAS/FC devices, or ATA-8 operation
   /// TRUSTED SEND (5Eh) or TRUSTED SEND DMA (5Fh) for ATA/SATA devices.
   ///
   /// In most cases, the user is going to want to couple together
   /// a SecurityDataToDevice() and SecurityDataFromDevice() to deliver
   /// a payload to the device and then pick up the appropriate response data.
   /// For these cases, it is recommended to use the SecurityDataExchange()
   /// method for convenience.
   ///
   /// \param protocolID - (IN)
   ///      A security protocol ID value to be used with this command.
   ///      For a TCG device, it can be 0, or 1 to 6.
   ///      For a SeaCOS device, it's a fixed value, F0h ("vendor-specific").
   ///
   /// \param spSpecific - (IN)
   ///      SP specific value.
   ///      For a TCG device, it's the ComID.
   ///      For a SeaCOS device, it's usually 0.
   ///
   /// \param dataToSend - (IN)
   ///      A data payload to be delivered to the device.  This
   ///      payload shall be formatted according to the protocol
   ///      ID and the SP specific parameter.
   ///
   /// \return DTA_ERROR - Return success (0) or error code.
   ///
   /// @pre None
   ///
   /// @post None
   //
   //================================================================
   virtual DTA_ERROR SecurityDataToDevice( 
      tUINT8 protocolID,
      tUINT16 spSpecific,
      const dta::tBytes &dataToSend
      ) = 0;

   //================================================================
   //
   /// Receives a security response via a protocol ID, SP specific value,
   /// and a data payload from a DriveTrust device.
   ///
   /// This method is a more generic version of getting a security 
   /// response, especially pertinent to the TCG-compliant devices (IF-Recv).
   /// It can be called to receive a security payload with a given 
   /// protocol ID and a SP specific value from a DriveTrust device.
   /// Implementation of the transfer over the interface will vary 
   /// according to the hardware and interfaces used.  For example,
   /// this command may be mapped to the SCSI operation Security 
   /// Protocol-In (A2h) for SCSI/SAS/FC devices, or ATA-8 operation
   /// TRUSTED RECEIVE (5Ch) or TRUSTED RECEIVE DMA (5Dh) for ATA/SATA
   /// devices.
   ///
   /// In most cases, the user is going to want to couple together
   /// a SecurityDataToDevice() and SecurityDataFromDevice() to deliver
   /// a payload to the device and then pick up the appropriate response data.
   /// For these cases, it is recommended to use the SecurityDataExchange()
   /// method for convenience.
   ///
   /// \param protocolID - (IN)
   ///      A security protocol ID value to be used with this command.
   ///      For a TCG device, it can be 0, or 1 to 6.
   ///      For a SeaCOS device, it's a fixed value, F0h ("vendor-specific").
   ///
   /// \param spSpecific - (IN)
   ///      SP specific value.
   ///      For a TCG device, it's the ComID.
   ///      For a SeaCOS device, it's usually 0.
   ///
   /// \param dataToRecv - (IN, OUT)
   ///      A data payload delivered from the device to the host.  
   ///      The buffer will be populated with data received from
   ///      the device.  The size of the buffer determines the
   ///      number of bytes expected and placed in the buffer.
   ///
   /// \return DTA_ERROR - Return success (0) or error code.
   ///
   /// @pre None
   ///
   /// @post None
   //
   //================================================================
   virtual DTA_ERROR SecurityDataFromDevice( 
      tUINT8 protocolID,
      tUINT16 spSpecific,
      dta::tBytes &dataToRecv 
      ) = 0;

   //================================================================
   //
   /// Exchange security command/response with a DriveTrust Device.
   ///
   /// In most cases, the user is going to want to couple together
   /// a SecurityDataToDevice() and SecurityDataFromDevice() to deliver
   /// a payload to the device and then pick up the appropriate response
   /// data. This method is a convenient way to do so and may provide 
   /// hints to the DTA objects on how to optimize data traffic or locking 
   /// behaviors.
   ///
   /// \param protocolID - (IN)
   ///      A security protocol ID value to be used with this command.
   ///      For a TCG device, it can be 0, or 1 to 6.
   ///      For a SeaCOS device, it's a fixed value, F0h ("vendor-specific").
   ///
   /// \param spSpecific - (IN)
   ///      SP specific value.
   ///      For a TCG device, it's the ComID.
   ///      For a SeaCOS device, it's usually 0.
   ///
   /// \param dataToSend - (IN)
   ///      A data payload to be delivered to the device.  This
   ///      payload shall be formatted according to the protocol
   ///      ID established when the session was created.
   ///
   /// \param dataToRecv - (OUT)
   ///      A data payload delivered from the device to the host.  
   ///      This payload shall be formatted according to the 
   ///      protocol ID established when the session was created.
   ///
   /// \return DTA_ERROR - Return success (0) or error code.
   ///
   /// @pre None
   ///
   /// @post None
   //
   //================================================================
   virtual DTA_ERROR SecurityDataExchange( 
      tUINT8 protocolID,
      tUINT16 spSpecific,
      const dta::tBytes &dataToSend,
      dta::tBytes &dataToRecv 
      );

   //================================================================
   //
   /// Places the device in a lower power mode (i.e. standby)
   ///
   /// \param dataToRecv - (OUT)
   ///      A data payload delivered from the device to the host.  
   ///      This payload shall be formatted according to the 
   ///      protocol ID established when the session was created.
   ///
   /// \return DTA_ERROR - Return success (0) or error code.
   ///
   //
   //================================================================
   virtual DTA_ERROR StopUnit(dta::tBytes &dataToRecv);

   //================================================================
   //
   /// "Wakes" the device from a lower power mode (i.e. standby)
   ///
   /// \param dataToRecv - (OUT)
   ///      A data payload delivered from the device to the host.  
   ///      This payload shall be formatted according to the 
   ///      protocol ID established when the session was created.
   ///
   /// \return DTA_ERROR - Return success (0) or error code.
   //
   //================================================================
   virtual DTA_ERROR StartUnit(dta::tBytes &dataToRecv);

   //================================================================
   //
   /// Return a list of supported attribute for the session.
   ///
   /// \param attributes - (OUT)
   ///      A list of strings.  Each string is the name of a
   ///      requestable attribute on the device.
   ///
   /// \return DTA_ERROR - Return success (0) or error code.
   ///
   /// @pre None
   ///
   /// @post None
   //
   //================================================================
   virtual DTA_ERROR GetSupportedAttributes(
      DTAttributeCollection &attributes
      ) = 0;

   //================================================================
   //
   /// Find and return an attribute for the session.
   ///
   /// This method will return information about the session or device
   /// based on a requested attribute value.  For example, a user may
   /// want to inquire about the timeout value for the current session
   /// in case a larger timeout is needed for subsequent commands.
   ///
   /// \param attribute - (IN)
   ///      The name of the attribute requested from the 
   ///      session.  An empty name is currently invalid.
   ///
   /// \param value - (OUT)
   ///      The value of the specified attribute on the current
   ///      device or session.  An empty result can be valid.
   ///
   /// \return DTA_ERROR - Return success (0) or error code.  An
   ///      error code of {eDtaCategoryGeneric,eGenericInvalidParameter}
   ///      will be returned if the attribute name is unknown for
   ///      the device specified.
   ///
   /// @pre None
   ///
   /// @post None
   //
   //================================================================
   virtual DTA_ERROR GetAttribute(
      const _tstring& attribute,
      _tstring& value
      ) = 0;

   //================================================================
   //
   /// Find and attempt to set an attribute for the session.
   ///
   /// This method will try to set information about the session
   /// based on a requested attribute value.  For example, a user may
   /// want to change the timeout value for the current session
   /// if subsequent commands require a long timeout value.
   ///
   /// \param attribute - (IN)
   ///      The name of the attribute requested from the particular
   ///      device.  An empty name is currently invalid.
   ///
   /// \param value - (IN)
   ///      The value of the specified attribute on the specified
   ///      session.  An empty result can be valid.
   ///
   /// \return DTA_ERROR - Return success (0) or error code.  An
   ///      error code of {eDtaCategoryGeneric,eGenericInvalidParameter}
   ///      will be returned if the attribute name is unknown for
   ///      the device specified.
   ///
   /// @pre None
   ///
   /// @post None
   //
   //================================================================
   virtual DTA_ERROR SetAttribute(
      const _tstring& attribute,
      const _tstring& value
      ) = 0;

   //================================================================
   //
   /// Release currently held system resources and invalidate object.
   ///
   /// This method should be called when use of the CDriveTrustSession 
   /// object is complete.  After Destroy() is called, the caller
   /// should not call any other methods on the interface or 
   /// attempt to dispose of the object in any way.
   ///
   /// In addition to freeing any resources used by the object, the
   /// object will attempt to reset the security state of the
   /// resources on the DriveTrust device.  This should effectively
   /// remove any authentications previously done against the device.
   ///
   /// \return DTA_ERROR - Return success (0) or error code.
   ///
   /// @pre None.
   ///
   /// @post Object is destroyed, and should not be used again.
   //
   //================================================================
   virtual DTA_ERROR Destroy();

   //================================================================
   //
   /// Lock the session object, to avoid access to the session
   /// device by other threads or processes.  This method must
   /// be implemented by a derived OS-dependent class.
   ///
   /// \param  lockType (IN) Which lock the caller wishes to use
   ///
   /// \param  timeout (IN) A timeout value in seconds for
   ///         acquiring the lock.
   ///
   /// \return DTA_ERROR - Return success (0) or error code.
   //
   //================================================================
   virtual dta::DTA_ERROR LockSession( 
      eSessionLockTypes lockType,
      size_t timeout 
      ) = 0;

   //================================================================
   //
   /// Unlock the session object, to allow access to the session
   /// device by other threads or processes.  This method must
   /// be implemented by a derived OS-dependent class.
   ///
   /// \param  lockType (IN) Which lock the caller wishes to use
   ///
   /// \return DTA_ERROR - Return success (0) or error code.
   //
   //================================================================
   virtual dta::DTA_ERROR UnlockSession(
      eSessionLockTypes lockType
      ) = 0;

};  // end CDriveTrustSession


//====================================================================================
/// \brief DriveTrust device discovery and interrogation interface.
///
/// CLocalSystem is an interface that abstracts interactions with
/// the O/S to discover DriveTrust devices and interrogate them
/// for basic information (properties) and capabilities.
///
/// An object supporting the CLocalSystem interface is created with
/// the method CreateLocalSystemObject().  When use of the object
/// is complete, Destroy() should be called on the object to
/// release any held resources.
//====================================================================================
class CLocalSystem : public CDriveTrustBase
{
public:
   //================================================================
   //
   /// Find and return identifiers for currently known DriveTrust devices.
   ///
   /// This method will return a collection of identifiers for potential
   /// DriveTrust devices on the local system.  These identifiers
   /// can be used to gather additional information (attributes) or
   /// to ask the CLocalSystem object to start a communication session
   /// with the devices.
   ///
   /// \param identifiers - (OUT)
   ///      List of DTIdentifiers, one for each drive.  The
   ///      list will be empty and repopulated in the method.
   ///      An empty list is not necessarily an error.
   ///
   /// \param options - (IN)
   ///      A string containing any optional parameters used
   ///      while generating the indentifier list.  Format and
   ///      usage of this string is TBD.  This will be able to
   ///      filter the identifier list to devices that report
   ///      support of a specific protocol ID.
   ///
   /// \param logFile - (IN)
   ///      If not empty, the name of a log file where information
   ///      will be written about what devices were discovered, and
   ///      which ones were selected and omitted into the
   ///      identifiers list.  If the parameter is empty, no log
   ///      will be written.
   ///
   /// \return DTA_ERROR - Return success (0) or error code.
   ///
   /// @pre None
   ///
   /// @post None
   //
   //================================================================
   virtual DTA_ERROR GetDriveTrustIdentifiers(
      DTIdentifierCollection &identifiers,
      const _tstring& options = TXT(""),
      const _tstring& logFile = TXT("")
      ) = 0;

   //================================================================
   //
   /// Find and return an attribute for a specified DriveTrust Identifier
   ///
   /// This method will return information about a DriveTrust device
   /// based on a requested attribute value.  For example, a user may
   /// want to inquire about the serial number for a specific device
   /// to determine if this device is one they wish to use.
   ///
   /// \param identifier - (IN)
   ///      The identifier for the drive in question.  This
   ///      identifier can be found through the 
   ///      GetDriveTrustIdentifers() method.
   ///
   /// \param attribute - (IN)
   ///      The name of the attribute requested from the particular
   ///      device.  An empty name is currently invalid.
   ///
   /// \param value - (OUT)
   ///      The value of the specified attribute on the specified
   ///      DriveTrust device.  An empty result can be valid.
   ///
   /// \return DTA_ERROR - Return success (0) or error code.  An
   ///      error code of {eDtaCategoryGeneric,eGenericInvalidParameter}
   ///      will be returned if the attribute name is unknown for
   ///      the device specified.
   ///
   /// @pre None
   ///
   /// @post None
   //
   //================================================================
   virtual DTA_ERROR GetDeviceAttribute(
      const DTIdentifier& identifier,
      const _tstring& attribute,
      _tstring& value
      ) = 0;

   //================================================================
   //
   /// Create a session object to use with a specific DriveTrust device.
   ///
   /// This method will allocate and return a pointer to a 
   /// CDriveTrustSession object.  A session is used to communicate
   /// to a DriveTrust device via Trusted Commands.
   ///
   /// \param identifier - (IN)
   ///      The identifier for the drive in question.  This
   ///      identifier can be found through the 
   ///      GetDriveTrustIdentifers() method.
   ///
   /// \param protocol - (IN)
   ///      The protocol ID to be used for the entirety of the
   ///      session.  As an example, the TCG specification
   ///      might specify a protocol of 0x01.
   ///
   /// \param options - (IN)
   ///      A string containing any optional parameters used
   ///      while creating the session. Valid keywords and
   ///      parameters are as follows:
   ///
   ///      -log logfilename : Append any generated error
   ///         information for this session to the provided
   ///         logfilename ( e.g. "C:\\session.log" ).
   ///
   ///      Additional format and contents of this string 
   ///      are to be determined.
   ///
   /// \param session - (OUT)
   ///
   /// \return DTA_ERROR - Return success (0) or error code.  
   ///
   /// @pre None
   ///
   /// @post None
   //
   //================================================================
   virtual DTA_ERROR CreateSession(
      const dta::DTIdentifier  &identifier,
      const tUINT8             protocol,
      const _tstring           &options,
      dta::CDriveTrustSession* &session
      ) = 0;

}; // end CLocalSystem

//====================================================================================
/// \brief Inline class to automate locking/unlocking 
///      of a session object.
///
/// This class will lock and unlock a COSDTSession object
///   at object construction and destruction respectively.
/// 
//
//====================================================================================
template < eSessionLockTypes lockType >
class CSessionAutoLock
{
public:
   CSessionAutoLock( 
      CDriveTrustSession* session, 
      size_t timeout = 1000 
      )
      : m_session( session )
   {
      dta::DTA_ERROR status = m_session->LockSession( lockType, timeout );
      if ( !M_DtaSuccess( status ) )
      {
         throw status;
      }
   }
   ~CSessionAutoLock()
   {
      // Ignore errors, if any.
      m_session->UnlockSession( lockType );
   }
private:
   CDriveTrustSession *m_session;
};

//====================================================================================
/// \brief A device with a session.
///
//====================================================================================
class CDevice
{
public:
   //================================================================
   /// CDevice Constructor creates a session to the device.
   ///
   /// \param deviceIdentifier [in] Name of device used to create handle.
   /// \param protocol [in] Security protocol for the session.
   //================================================================
   CDevice(const dta::DTIdentifier deviceIdentifier=TXT(""), tUINT8 protocol=0x00);

   ~CDevice();

   //================================================================
   /// Returns the identifier used to create the handle of the device.
   ///
   /// \return Identifier string for the device.
   //================================================================
   inline dta::DTIdentifier identifier() const {return m_identifier;};

   //================================================================
   /// Returns the transport protocol tag.
   ///
   /// \return Transport protocol tag.
   //================================================================
   _tstring protocolTag();

   //================================================================
   /// Returns the serial number of the device. Creates a session and
   /// retreives the information, if not done so already.
   ///
   /// \return Device serial number.
   //================================================================
   _tstring serialNumber();

   //================================================================
   /// Returns the session used to the device.
   ///
   /// \return Session to the device.
   //================================================================
   dta::CDriveTrustSession* session();

   //================================================================
   /// Returns a list of supported security protocols.
   ///
   /// \return List of supported security protocols by the device.
   //================================================================
   std::vector<tUINT8> supportedSecurityProtcols();

protected:
   dta::DTIdentifier          m_identifier;
   _tstring                   m_protocolTag;
   tUINT8                     m_protocol;
   _tstring                   m_serialNumber;
   dta::CDriveTrustSession*   m_session;
   std::vector<tUINT8>        m_supportedSecurityProtocols;
}; // CDevice

//=================================
// function definitions
//=================================
// Create an object supporting the CLocalSystem interface.
DTA_ERROR CreateLocalSystemObject( CLocalSystem* &localSystemObject );

/// Trim spaces from a string, right and left.
_tstring Trim( const _tstring& str, bool trimLeft, bool trimRight );

//====================================================================================
/// \brief Function for determining if a device (by identifier) matches a transport protocol filter.
///
/// \param[in] transportProtocol Bit field for filtering which transports to select (0 = no filter)
/// \param[in] identifier        String identifier for the device being tested for the transport filter.
///
/// \return True, if device matches the transport protocol filter, false otherwise.
//====================================================================================
bool isTransportSupported(const tUINT16 transportProtocol, const _tstring identifier);

//====================================================================================
/// \brief Function for determing if a protocol filter matches a list of supported security protocols (by identifer).
///
/// \param[in] securityProtocol  Bit field for filtering which security protocols to select (0 = no filter)
/// \param[in] supportedSecurityProtocols List of security protocols, which will be matched with a security protocol bit field.
///
/// \return True, if matching supported security protocol is found, false otherwise.
//====================================================================================
bool isSecuritySupported(const tUINT16 securityProtocol, const std::vector<tUINT8> supportedSecurityProtocols);

//====================================================================================
/// \brief Function for retreiving a list of devices on a system based on transport and security protocol.
///
/// \param[in] transportProtocol Bit field for filtering which transports to select (0 = no filter)
/// \param[in] securityProtocol  Bit field for filtering which security protocols to select (0 = no filter)
///
/// \return Vector of CDevice objects which match the requested transport and security requirements.
//====================================================================================
std::vector<CDevice> GetDevices(const tUINT16 transportProtocol=0, const tUINT16 securityProtocol=0, const _tstring logFile=TXT(""));

}  // end namespace dta
#endif // DTA_DOT_H