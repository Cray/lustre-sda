/*! \file osDTSession.hpp
    \brief Implementation of COSDTSession base class for transports.

    TODO : Detailed description
    
    \legal 
    All software, source code, and any additional materials contained
    herein (the "Software") are owned by Seagate Technology LLC and are 
    protected by law and international treaties.� No rights to the 
    Software, including any rights to distribute, reproduce, sell, or 
    use the Software, are granted unless a license agreement has been 
    mutually agreed to and executed between Seagate Technology LLC and 
    an authorized licensee.�

    The Software contains SEAGATE CONFIDENTIAL INFORMATION AND SEAGATE 
    TRADE SECRET INFORMATION that must be protected as such.

    Copyright � 2008.� Seagate Technology LLC �All Rights Reserved.

    The Software is provided under the Agreement No. 134849 between Seagate
    Technology and Calsoft. All Intellectual Property rights to the Software,
    as between Calsoft and Seagate, will be governed under the terms of the 
    Agreement No. 134849; no other rights to the Software are granted.
*/

#ifndef OS_DRIVETRUST_SESSION_HPP
#define OS_DRIVETRUST_SESSION_HPP

//=================================
// Include files
//=================================
#include "dta/platform/linux32/osLogObject.hpp" // nvn20110622
#include <dta/dta.hpp>
#include <pthread.h> // nvn20110627
#include "LinuxIncludes.h" // nvn20110624
//#include <windows.h>  // nvn20110622

namespace dtad {
//=================================
// macro definitions
//=================================

//=================================
// constants
//=================================
#define chSeparator        ';'
#define txtATA             TXT("ATA")
#define txtBlockSize       TXT("BlockSize" )
#define txtCapacity        TXT("CapacityInBytes")
#define txtDeviceName      TXT("DeviceName")
#define txtEnhancedStorage TXT("EnhancedStorage")
#define txtProduct         TXT("ProductIdentification")
#define txtProdRev         TXT("ProductRevisionLevel")
#define txtProtocolID      TXT("ProtocolID")
#define txtSCSI            TXT("SCSI")
#define txtSerialNum       TXT("SerialNumber")
#define txtSpSpecific      TXT("SPSpecific")
#define txtTimeout         TXT("Timeout"   )
#define txtTransport       TXT("Transport" )
#define txtVendor          TXT("VendorIdentification")
#define txtTrustedDMA      TXT("TrustedDMA")

/// Overload the eLockTypeAll array position to mean the
/// currently selected device.  That's where the device
/// handle is stored.
#define M_OsDevice (m_hand[dta::eLockTypeAll])

//=================================
// typedefs and structures
//=================================

//=================================
// class definitions
//=================================

/// \brief Base class representing a communication session.
///
/// This class provides common functionality between various
/// transport mechanisms for shuttling DriveTrust commands
/// and responses between the host application and the device.
/// 
/// Most notably on Windows, this class contains the HANDLE
/// for the device and a few bare required attributes (timeout
/// and device name ).
//
class COSDTSession : public dta::CDriveTrustSession
{
   friend class COSDTSessionAutoLock;
protected:
   /// Default destructor.
   virtual ~COSDTSession() {}
public:
   /// Default constructor.  Open() should be called on
   /// the object after it is constructed to open the session,
   /// if possible.
   COSDTSession();

   //================================================================
   //
   /// Open a session based on provided parameters.
   ///
   /// This method should be called after object constructor and
   /// prior to any other methods except Destroy().  It will attempt
   /// to begin a session on the requested device with the provided
   /// parameters.
   ///
   /// After Open() completes, the owner should call Destroy() to
   /// release resources acquired by Open() and remove the object.
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
   ///      while creating the session.  The format and contents
   ///      of this string are to be determined.
   ///
   /// \return DTA_ERROR - Return success (0) or error code.  
   ///
   /// @pre None
   ///
   /// @post None
   //
   //================================================================
   virtual dta::DTA_ERROR Open(
      const dta::DTIdentifier  &identifier,
      const tUINT8             protocol,
      const _tstring           &options
      );
   //================================================================
   // Implementations of methods defined in CDriveTrustSession
   //================================================================
   virtual dta::DTA_ERROR GetAttribute(
      const _tstring& attribute,
      _tstring& value
      );
   virtual dta::DTA_ERROR SetAttribute(
      const _tstring& attribute,
      const _tstring& value
      );
   virtual dta::DTA_ERROR Destroy();

   virtual dta::DTA_ERROR GetSupportedAttributes(
      dta::DTAttributeCollection &attributes
      );

   virtual dta::DTA_ERROR AddLogEntry( 
      const dta::DTA_ERROR &error,
      const _tstring& text 
      );
protected:
   //================================================================
   //
   /// Release currently held system resources.
   ///
   /// This method is called whenever all resources used by the
   /// object should be freed, but the object itself is not
   /// scheduled for removal (deletion).
   ///
   /// \return DTA_ERROR - Return success (0) or error code.
   ///
   /// @pre None.
   ///
   /// @post Object has released all resources.  Open() should be
   ///       called to acquire a new session as appropriate.
   //
   //================================================================
   virtual dta::DTA_ERROR FreeResources();

   //================================================================
   //
   /// Get the current block size for the device, interrogating
   /// the device if necessary.  A DTA_ERROR will be thrown in
   /// case of error.
   ///
   /// \return the block size.
   //
   //================================================================
   virtual size_t GetBlockSize() = 0;

   //================================================================
   //
   /// Lock the session object, to avoid access to the session
   /// device by other threads or processes.
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
      dta::eSessionLockTypes lockType,
      size_t timeout 
      );

   //================================================================
   //
   /// Unlock the session object, to allow access to the session
   /// device by other threads or processes.
   ///
   /// \param  lockType (IN) Which lock the caller wishes to use
   ///
   /// \return DTA_ERROR - Return success (0) or error code.
   //
   //================================================================
   virtual dta::DTA_ERROR UnlockSession(
      dta::eSessionLockTypes lockType
      );

   //================================================================
   //
   /// Creates the mutex for the current device.
   ///
   /// \param  identifier [in] Identifier to used to create the mutex.
   ///
   /// \return DTA_ERROR - Return success (0) or error code.
   //
   //================================================================
   dta::DTA_ERROR CreateSessionMutex(const dta::DTIdentifier &identifier);

   //================================================================
   HANDLE   m_hand[dta::eLockTypeMaxValue]; //!< Array of Windows handles
   //pthread_mutex_t   m_hand[dta::eLockTypeMaxValue]; //!< Array of Linux mutex TODO: // nvn20110627
   _tstring m_deviceName;  //!< Name used to open the device handle
   tUINT8   m_protocolID;  //!< Protocol ID requested at Open()
   tUINT16  m_spSpecific;  //!< SP_Specific value for T10/T13 command.
   tUINT32    m_timeout;     //!< Timeout value used by the O/S for commands.
   dta::DTAttributeCollection 
    m_supportedAttributes; //!< List of supported attribute names.
   unsigned 
      m_lockCount[dta::eLockTypeMaxValue]; //!< Number of locks held on mutex
   dta::COSLogObject m_log;//!< output log file object.
};

//=================================
// function definitions
//=================================

}  // end namespace dtad
#endif // OS_DRIVETRUST_SESSION_HPP
