/*! \file dti.hpp
    \brief Basic API definition for Drive Trust Interface (DTI).

    This file details the interface classes and functions for writing
    client code that uses a specific security protocol via DTA to access
    DriveTrust devices.  It is a C++ specific interface.  For a 'C' interface,
    include dti.h instead of this file.
    
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

#ifndef DTI_DOT_HPP
#define DTI_DOT_HPP

#if !defined(__cplusplus)
#error C++ compiler required.  Include dti.h for 'C' compilers.
#endif
// !defined __cplusplus

//=================================
// Include files
//=================================
#include <dta/dta.hpp>
#include <dta/errors.h>
#include <time.h>
#include <sys/timeb.h>

namespace dti
{
   //=================================
   // class definitions
   //=================================

   //====================================================================================
   /// \brief Base class for most DriveTrust Interface classes.
   ///
   /// CDriveTrustInterface is a base class providing some common functionality for
   /// DriveTrust security related functions.  These are fully defined in derived
   /// classes which actually implement the virtual functions depending on the underlying
   /// protocol supported by the trusted drive.
   //====================================================================================
   class CDriveTrustInterface
   {
   public:
      //=================================================================================
      /// \brief Constructor for CDriveTrustInterface.
      ///
      /// The constructor takes a CDriveTrustSession as it class member.
      ///
      /// \param newSession [in]DriveTrust session object which has been initialized and
      ///                        connected to a DriveTrust device.
      //=================================================================================
      CDriveTrustInterface(dta::CDriveTrustSession* newSession);

      //=================================================================================
      /// \brief Constructor for CDriveTrustInterface.
      ///
      /// The constructor takes a CDriveTrustSession as it class member.
      ///
      /// \param newSession [in] DriveTrust session object which has been initialized and
      ///                        connected to a DriveTrust device.
      /// \param logFileName [in]Name of file to log APDUs.
      ///
      //=================================================================================
      CDriveTrustInterface(dta::CDriveTrustSession* newSession, const _tstring logFileName);

      //=================================================================================
      /// \brief Destructor for CDriveTrustInterface.
      ///
      /// Closes out the log file, if necessary.
      //=================================================================================
      ~CDriveTrustInterface();

      //=================================================================================
      /// \brief Returns the last thrown DTA_ERROR.
      ///
      /// \return Last DTA_ERROR error thrown.
      //=================================================================================
      inline dta::DTA_ERROR getLastError() const
      {
         return m_lastError;
      };

      //=================================================================================
      /// \brief Returns the session currently being used.
      ///
      /// \return Session currently being used.
      //=================================================================================
      inline dta::CDriveTrustSession* session()
      {
         return m_session;
      };
      
      //=================================================================================
      /// \brief Returns the session currently being used.
      ///
      /// \return Session currently being used.
      //=================================================================================
      inline dta::CDriveTrustSession* getSession()
      {
         return m_session;
      };

      //=================================================================================
      /// \brief Sets whether logging is enabled or not.
      ///
      /// \param newValue  New logging value.
      //=================================================================================
      inline void setLogging(const bool newValue)
      {
         m_logging = newValue;
      };

      //=================================================================================
      /// \brief Returns the current logging setting.
      ///
      /// \return True if logging enabled, false otherwise.
      //=================================================================================
      inline bool logging() const
      {
         return m_logging;
      };

      //=================================================================================
      /// \brief Returns the current device's serial number.
      ///
      /// \return Serial number of device.
      //=================================================================================
      inline _tstring serialNumber()
      {
         if (!m_serialNumber.size())
         {
            m_session->GetAttribute(TXT("SerialNumber"), m_serialNumber);
         }
         return m_serialNumber;
      };

      //=================================================================================
      /// \brief Sets the last thrown DTA_ERROR.
      ///
      /// \param error [in] Last DTA_ERROR error thrown.
      //=================================================================================
      inline void setLastError(dta::DTA_ERROR error)
      {
         m_lastError = error;
      };

   protected:
      //=================================================================================
      /// \brief Returns the current time with milliseconds.
      ///
      /// \return String output of current time.
      //=================================================================================
      static const char* currentTime();

      dta::CDriveTrustSession* m_session; /// Session used for communicating with device.
      tUINT16 m_blockSize;                /// Transport block size.
      dta::DTA_ERROR m_lastError;         /// Last DTA error.
      FILE* m_logFile;                    /// File for logging APDU events.
      bool m_logging;                     /// Variable set to enable/disable logging.
      _tstring m_serialNumber;            /// Drive serial number.
   }; // class CDriveTrustInterface

} // namespace dti

#endif // DTI_DOT_H