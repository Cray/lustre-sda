/*! \file ieee1667i.hpp
    \brief Basic API definition for IEEE-1667.

    This file details the interface classes and functions for writing
    client code that uses the SeaCOS security protocol via DTA to access
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

#ifndef IEEE1667_DOT_HPP
#define IEEE1667_DOT_HPP

#if !defined(__cplusplus)
#error C++ compiler required.  Include IEEE1667.h for 'C' compilers.
#endif
// !defined __cplusplus
//=================================
// Include files
//=================================
#include "dti.hpp"
#include "ieee1667values.h"
#include "byteorder.hpp"

namespace dti
{
   //=================================
   // macro definitions
   //=================================
   /// Simple macro to save off current throw or return behavior and enter a try block
   /// for 1667 devices.
   #define M_IEEE1667Try()                                     \
      IEEE1667_STATUS __result = SC_SUCCESS;                   \
      bool __throwOnError = m_session->SetThrowOnError(true);  \
      try

   #define M_IEEE1667Catch()                          \
      catch( const dta::DTA_ERROR& err )              \
      {                                               \
         setLastError(err);                           \
         __result = (IEEE1667_STATUS)err.Info.Detail; \
      }                                               \
      m_session->SetThrowOnError(__throwOnError);     \
      if ((__result != SC_SUCCESS) && __throwOnError) \
      {                                               \
         throw getLastError();                        \
      }                                               \
      return __result;

   /// Simple macro to save off current throw or return behavior and enter a try block
   /// for Silos
   #define M_SiloTry()                                                  \
      IEEE1667_STATUS __result = SC_SUCCESS;                            \
      bool __throwOnError = m_device->session()->SetThrowOnError(true); \
      try

   #define M_SiloCatch()                              \
      catch( const dta::DTA_ERROR& err )              \
      {                                               \
         m_device->setLastError(err);                           \
         __result = (IEEE1667_STATUS)err.Info.Detail; \
      }                                               \
      m_device->session()->SetThrowOnError(__throwOnError);     \
      if ((__result != SC_SUCCESS) && __throwOnError) \
      {                                               \
         throw m_device->getLastError();                        \
      }                                               \
      return __result;


   //=================================
   // enumeration
   //=================================
   /// Host OS values defined for Probe Silo
   typedef enum
   {
      eOSWindows        = 0x01,  /// Microsoft Windows
      eOSMacOS          = 0x02,  /// Mac OS
      eOSSymbianOS      = 0x03,  /// SymbianOS
      eOSPalmOS         = 0x04,  /// Palm OS
      eOSRIMOS          = 0x05,  /// RIMOS
      eOSStringDefined  = 0x06,  /// String Defined
      eOSWindowsCE      = 0x07,  /// Microsoft Windows CE
   } e1667OSs;

   /// Probe Silo Commands
   typedef enum
   {
      // Probe Silo Commands
      eProbeFunction = 0x01,  /// Probe Command
   } eCommands;

   //=================================
   // structs
   //=================================
#pragma pack(push, 2)   
   //
   // PROBE SILO
   //

   /// Windows OS Specification for probe silo command
   typedef struct tWindowsOSSpecification
   {
      tUINT32 windowsMajorVersion;  /// Bytes 0-3
      tUINT32 windowsMinorVersion;  /// Bytes 4-7
      tUINT32 windowsBuildNumber;   /// Bytes 8-11
      tUINT32 windowsPlatformID;    /// Bytes 12-15
   }  WindowsOSSpecification;

   /// Probe Command payload structure
   typedef struct tProbeCommandPayload
   {
      CommonPayloadHeader header;            /// Byte 0-7
      tUINT8 hostIEEE1667MajorVersion;       /// Byte 8
      tUINT8 hostIEEE1667MinorVersion;       /// Byte 9
      tUINT8 reserved[2];                    /// Byte 10-11
      tUINT8 hostOS;                         /// Byte 12
      tUINT8 hostOSSpecificationLength;      /// Byte 13
      tUINT8 hostImplementationMajorVersion; /// Byte 14
      tUINT8 hostImplementationMinorVersion; /// Byte 15
   }  ProbeCommandPayload;

   /// Probe Command Response payload structure
   typedef struct tProbeResponse
   {
      ResponsePayloadHeader header;    /// Byte 0-7
      tUINT32 availablePayloadLength;  /// Byte 8-11
      tUINT16 siloListLength;          /// Byte 12-13
      tUINT8* siloList;                /// Byte 14+
   }  ProbeResponse;

   /// Probe Command Silo Element
   typedef struct tSiloElement
   {
      tUINT32 siloTypeID;                 // Byte 0-3
      tUINT8  specificationMajorVersion;  // Byte 4
      tUINT8  specificationMinorVersion;  // Byte 5
      tUINT8  implementationMajorVersion; // Byte 6
      tUINT8  implementationMinorVersion; // Byte 7
   } SiloElement;

   /// Probe Command Silo List Element
   typedef struct tSiloListElement
   {
      tUINT8 reserved[28];       /// Bytes 0-27
      SiloElement siloElement;   /// Bytes 28-35
   }  SiloListElement;
#pragma pack(pop)

   //=================================
   // class definitions
   //=================================

   //====================================================================================
   /// \brief Derived class which implements IEEE-1667 protocol.
   ///
   /// CIEEE1667Interface is a derived class from CDriveTrustInterface which provides the
   /// implementation for the parent class' methods using the IEEE-1667 protocol.
   //====================================================================================
   class CIEEE1667Interface : public CDriveTrustInterface
   {
   public:
      //=================================================================================
      /// \brief Constructor for CIEEE1667Interface.
      ///
      /// The constructor takes a CDriveTrustSession as it class member.
      ///
      /// \param newSession [in] DriveTrust session object which has been initialized
      ///                        and connected to a DriveTrust device.
      ///
      //=================================================================================
      CIEEE1667Interface(dta::CDriveTrustSession* newSession);

      //=================================================================================
      /// \brief Constructor for CIEEE1667Interface.
      ///
      /// The constructor takes a CDriveTrustSession as it class member. Also creates a
	   /// log file.
      ///
      /// \param newSession [in] DriveTrust session object which has been initialized
      ///                        and connected to a DriveTrust device.
      /// \param logFileName [in] Name of file to log commands.
      ///
      //=================================================================================
      CIEEE1667Interface(dta::CDriveTrustSession* newSession, const _tstring logFileName);

      //=================================================================================
      /// \brief Method for sending a command pair to/from the device.
      ///
      /// Provides a general function for sending a command to a silo on the device.
      ///
      /// \param siloIndex  [in]  DriveTrust session object which has been initialized
      ///                         and connected to a DriveTrust device.
      /// \param functionID [in]  Name of file to log commands.
      /// \param dataToSend [in]  Block of data to send to the device.
      /// \param dataToRecv [out] Block of data to receive from the device.
      ///
      /// \return Status code from the response.
      //=================================================================================
      IEEE1667_STATUS sendCommand(const tUINT8 siloIndex, const tUINT8 functionID,
                                  dta::tBytes &dataToSend, dta::tBytes &dataToRecv);

      //=================================================================================
      /// \brief Method for sending data to the device.
      ///
      /// Provides a general function for sending a data to a silo on the device.
      ///
      /// \param siloIndex  [in]  DriveTrust session object which has been initialized
      ///                         and connected to a DriveTrust device.
      /// \param functionID [in]  Name of file to log commands.
      /// \param dataToSend [in]  Block of data to send to the device.
      ///
      /// \return Status code from the response.
      //=================================================================================
      IEEE1667_STATUS protocolOut(const tUINT8 siloIndex, const tUINT8 functionID,
                                  dta::tBytes &dataToSend);

      //=================================================================================
      /// \brief Method for receiving data from the device.
      ///
      /// Provides a general function for receiving data from a silo on the device.
      ///
      /// \param siloIndex  [in]  DriveTrust session object which has been initialized
      ///                         and connected to a DriveTrust device.
      /// \param functionID [in]  Name of file to log commands.
      /// \param dataToRecv [out] Block of data to receive from the device.
      ///
      /// \return Status code from the response.
      //=================================================================================
      IEEE1667_STATUS protocolIn(const tUINT8 siloIndex, const tUINT8 functionID,
                                 dta::tBytes &dataToRecv);

      //=================================================================================
      /// \brief Method for parsing response payloads.
      ///
      /// Returns the status code and trims the payload header from the given data block.
      ///
      /// \param payload [in|out] Block of data to receive from the device.
      ///
      /// \return Status code from the payload.
      //=================================================================================
      IEEE1667_STATUS parseResponse(dta::tBytes &payload) const;

      //=================================================================================
      /// \brief Method for sending a probe command to/from the device.
      ///
      /// This executes a 1667 probe command and populates a list of silos.
      ///
      /// \return Status code from the response.
      //=================================================================================
      IEEE1667_STATUS probeCommand();

      //=================================================================================
      /// \brief Method for giving access to the list of silos.
      ///
      /// Returns a copy of the classes silo.
      ///
      /// \return List of silos.
      //=================================================================================
      inline std::vector<SiloElement> getSilos() const
      {
         return m_silos;
      };

      //=================================================================================
      /// \brief Returns the index of a given silo type id.
      ///
      /// \param stid   Silo Type ID for query.
      ///
      /// \return Index of given silo type id if found, 0xFF if not found.
      //=================================================================================
      tUINT8 getSiloIndex(tUINT32 stid);

      //=================================================================================
      /// \brief This functions adds a 1667 command header to a given payload.
      ///
      /// \param payload [in|out] Payload to add command header to.
      ///
      /// \return Payload parameter has command payload header.
      //=================================================================================
      static void add1667CommandHeader(dta::tBytes& payload);

   //=================================================================================
   /// \brief Returns a string description of a status word.
   ///
   /// \param status [in] Status word to be translated.
   ///
   /// \return String description of given status word.
   //=================================================================================
   static _tstring statusToString(const IEEE1667_STATUS status);

   private:
      CByteOrder m_swapper;               /// Used for converting from system to big endian.
      std::vector<SiloElement> m_silos;   /// List of silos on this device.
   }; // class CIEEE1667Interface


   //====================================================================================
   /// \brief Base class which structures IEEE-1667 protocol silos.
   ///
   /// CSiloBase is a base class which provides common functionality for IEEE-1667
   /// protocol silos which include keeping track of the silos type id and index.
   //====================================================================================
   class CSiloBase
   {
   public:
      //=================================================================================
      /// \brief Constructor for CSiloBase.
      ///
      /// The constructor takes a CIEEE1667Interface as it class member.
      ///
      /// \param siloTypeID [in] The IEEE-1667 Silo Type ID for this silo.
      /// \param device [in]     CIEEE1667Interface object which has been initialized
      ///                        and connected to a DriveTrust device.
      ///
      //=================================================================================
      CSiloBase(tUINT32 siloTypeID, dti::CIEEE1667Interface* device)
         : m_siloTypeID(siloTypeID), m_device(device)
      {
         m_siloIndex = device->getSiloIndex(m_siloTypeID);
      };

      //=================================================================================
      /// \brief Returns the silo's index.
      ///
      /// \return Silo's index.
      //=================================================================================
      inline tUINT8 siloIndex() const
      {
         return m_siloIndex;
      };

      //=================================================================================
      /// \brief Returns the Silo Type ID.
      ///
      /// \return Silo type ID.
      //=================================================================================
      inline tUINT32 siloTypeID() const
      {
         return m_siloTypeID;
      };

   protected:
      tUINT8  m_siloIndex;
      tUINT32 m_siloTypeID;
      CIEEE1667Interface* m_device;
   }; // class CSiloBase
} // namespace dti

#endif // IEEE1667_DOT_HPP