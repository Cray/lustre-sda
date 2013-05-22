/*! \file osLocalSystemObject.cpp
    \brief Windows-specific implementation of COSLocalSystemObject.

    This implementation is specific to the Windows O/S.  It may include
    Windows-specific headers and definitions as necessary.
    
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

//=================================
// Include files
//=================================
#include <sstream>
#include <queue> // nvn20110629
#include "osLocalSystemObject.hpp"
#include <assert.h>
#ifdef BUILD_SEAGATE_INTERNAL_SDK
#include "transports/osES.hpp" // This must be included before Guid definitions.
#endif // BUILD_SEAGATE_INTERNAL_SDK
#if 0 // nvn20110629
#include <windows.h>
#include <initguid.h>   // Guid definition
#include <devguid.h>    // GUID_DEVCLASS_DISKDRIVE
#include <WinIoCtl.h>
#include <cfgmgr32.h>   // CM_* definitions
#endif
//#include "setupdi/GetClassDevs.hpp"  // nvn20110629 // <class> CDeviceInfoList
#include <dta/tptr.hpp>
#include <dta/parseoptions.hpp>
#include "transports/osATAPT.hpp"
#include "transports/osSAT.hpp"
#include "transports/osRAID.hpp"
#include "scsiCore.h" // nvn20110705

using namespace dtad;

//=================================
// macro/constant definitions
//=================================

#define BUILD_FOR_OLD_NVIDIA_STORPORT    // 12-10-2009 jls for testing


//=================================
// typedefs and structures
//=================================

/// Bus type of the device.  This enumeration denotes
/// common bus types used to access the device.  Note that
/// the O/S typically reports the bus type of the driver,
/// which may ( or may not ) reflect the actual bus type
/// used to communicate to the device.
enum etBusType 
{ 
   /// Select devices that LocalSystem can determine a particular 
   /// bus type.  evDefault is a container for the combined 
   /// evUSB, evSCSI, and evATA enumerations.
   evDefault,  
   /// Select devices regardless of bus type.
   evAll, 
   /// Select devices reported as having a USB bus type.
   evUSB, 
   /// Select devices reported as having a SCSI bus type.
   evSCSI, 
   /// Select devices reported as having a RAID bus type.
   evRAID, 
   /// Select devices reported as having a ATA bus type.
   evATA, 
   /// Select devices reported as having a 1394 bus type.
   ev1394,
   /// Select devices found via Enhanced Storage.
   evES,
   /// A default bus type for things that aren't a known discrete
   /// bus type.
   evErr 
};

//=================================
// function implementations
//=================================

//=================================
// class implementations
//=================================

//================================================================
COSLocalSystem::COSLocalSystem()
{
}

//================================================================
COSLocalSystem::~COSLocalSystem()
{
}

//================================================================
dta::DTA_ERROR COSLocalSystem::GetDriveTrustIdentifiers(
      dta::DTIdentifierCollection &identifiers,
      const _tstring& optionString,
      const _tstring& logFileName
      )
{
   M_DriveTrustBaseTry()
   {
      _tstring logFile = logFileName;
      identifiers.clear();

      dta::tstringMap options;
      dta::tstringMap::iterator option;
      _tstring wildcard = dta::ParseOptions( options, optionString );
      // If a log file wasn't specified as a parameter, look
      // at the options string to see if it is specified there.
      if ( 0 == logFile.size() )
      {
         option = options.find( TXT("-log") );
         if ( options.end() != option )
         {
            logFile = option->second;
         }
      }

      if ( logFile.size() )
      {
         m_log.Open( logFile, TXT("Find DriveTrust Identifiers") );
      }
      else
      {
         m_log.Close();
      }

      // Check the options string for a bus type.
      etBusType busType = evDefault;
      _tstring strBusType;
      option = options.find( TXT("-bustype") );
      if ( options.end() != option )
      {
         strBusType = option->second;
      }
      
      if ( TXT("all") == strBusType )
      {
         busType = evAll;
      }
      else if ( TXT("USB") == strBusType )
      {
         busType = evUSB;
      }
      else if ( TXT("1394") == strBusType )
      {
         busType = ev1394;
      }
      else if ( TXT("SCSI") == strBusType )
      {
         busType = evSCSI;
      }
      else if ( TXT("ATA") == strBusType )
      {
         busType = evATA;
      }
      else if ( TXT("RAID") == strBusType )
      {
         busType = evRAID;
      } 
      else if ( TXT("ES") == strBusType )
      {
         busType = evES;
      } 
      else if ( TXT("") != strBusType )
      {
         throw AddLogEntry( 
            dta::Error( dta::eGenericInvalidParameter ),
            TXT("Invalid bus type '") + strBusType + TXT("'") 
            );
      }

      // nvn20110705
      scan_devices();
      if (!sg_map.empty())
      {
         std::map < string, string >::iterator i = sg_map.begin();

         for (i = sg_map.begin(); i != sg_map.end(); i++)
         {
            _tostringstream sstr;
            sstr << TXT("Found device: ") << i->first;
            AddLogEntry( dta::Success, sstr.str() );

              if( scan_sg(i->first))
              {
                 _tostringstream sstr;
                 sstr << TXT("Device bus type: ");
                 etBusType currentBusType = evErr;

                // string::size_type pos = myDev.businfo.find( '@' );
                // myDev.businfo.substr( 0, pos )
                 switch( myDev.busType )
                 {
                 case 0:
                    sstr << TXT("BusTypeSas (ATA)");
                    currentBusType = evATA;
                    break;
                 case 1:
                    sstr << TXT("BusTypeSas (SCSI)");
                    currentBusType = evSCSI;
                    break;
                 case 2:
                    sstr << TXT("BusTypeUsb (USB)");
                    currentBusType = evUSB;
                    break;
                 case 3:
                    sstr << TXT("BusTypeRAID (RAID)");
                    currentBusType = evRAID;
                    break;
                 //case BusTypeUnknown:
                 //   sstr << TXT("BusTypeUnknown");
                 //   break;
                 //case BusTypeSsa:
                 //   sstr << TXT("BusTypeSsa");
                 //   break;
                 default:
                    sstr << TXT("BusTypeInvalid");
                    break;
                 }

                 // Using the bus type, create the prefix for the
                 // current identifier.  It will be ultimately passed
                 // back to the user.
                 dta::DTIdentifier currentIdentifier;
                 switch ( currentBusType )
                 {
                 case evUSB:
                    currentIdentifier = dta::BUS_TYPE_USB;
                    break;
                 case evSCSI:
                    currentIdentifier = dta::BUS_TYPE_SCSI;
                    break;
                 case evATA:
                    currentIdentifier = dta::BUS_TYPE_ATA;
                    break;
                 case ev1394:
                    currentIdentifier = dta::BUS_TYPE_1394;
                    break;
                 case evRAID:
                    currentIdentifier = dta::BUS_TYPE_RAID;
                    break;
                 default:
                    currentIdentifier = dta::BUS_TYPE_UNDETERMINED;
                    break;
                 }

                 // Now, filter this device based on its bus type
                 // and the bus type we're looking for.
                 bool recognized = false;
                 switch ( busType )
                 {
                 case evDefault:
                    recognized = (currentBusType != evErr );
                    break;
                 case evAll:
                    recognized = true;
                    break;
                 case evUSB:
                    recognized = (currentBusType == evUSB );
                    break;
                 case ev1394:
                    recognized = (currentBusType == ev1394 );
                    break;
                 case evSCSI:
                    recognized = (currentBusType == evSCSI );
                    break;
                 case evATA:
                    recognized = (currentBusType == evATA );
                    break;
                 case evRAID:
                    recognized = (currentBusType == evRAID );
                    break;
                 case evErr:
                 default:
                    break;
                 }
                 if ( !recognized )
                 {
                    sstr << TXT(", device omitted.");
                    AddLogEntry( dta::Success, sstr.str() );
                    continue;
                 }

                 // Bus type recognized, add a log entry.
                 AddLogEntry( dta::Success, sstr.str() );

                 // An identifier consists of a prefixed interface
                 // type and a postfix name to use for CreateFile()
                 // (under Windows).  We've validated that this
                 // 'thing' is a disk device, so add it to the
                 // list of identifiers!
                 //
                 // SPECIAL NOTE: Note that the identifier list is
                 // not exclusively DriveTrust devices : we have no
                 // way at the moment to guarantee (or disprove)
                 // their support for DriveTrust commands without
                 // opening the device for access.
                 //
                // if ( currentIdentifier != _T("RAID:") )
                 //{
                    currentIdentifier += (myDev.description + "@" + i->first);
                    identifiers.push_back( currentIdentifier );
                 //}

                 AddLogEntry( dta::Success,
                    TXT("Added '") + currentIdentifier + TXT("' to list.")
                    );

              }
         }
      }
      else
      {
         // Don't know how this is possible (to have a NULL)
         // but check out of pure paranoia.
         AddLogEntry( dta::Error( dta::eGenericMemoryError ),
            TXT("NULL found on device path string check, omitted")
            );

         throw 1;
      }

#if 0 // TODO: // nvn20110704 - make linux device discovery
      LPGUID diskGuid = (LPGUID)&GUID_DEVINTERFACE_DISK;

      SetupDi::CClassDevs devs;
      if ( NO_ERROR != devs.GetInterfaceClass( diskGuid ))
      {
         tOSError error = devs.LastError();
         throw AddLogEntry(
            dta::Error( error ),
            TXT("Error in GetInterfaceClass()")
            );
      }

      DWORD i;
      SP_DEVICE_INTERFACE_DATA spdid;
      tVarLenStruct<SP_DEVICE_INTERFACE_DETAIL_DATA> spdidd;
      spdidd.p->cbSize = sizeof( SP_DEVICE_INTERFACE_DETAIL_DATA );

      /** I want to use DevInst out of this to remove the device later,
       ** so I need to define and initialize it here.
       **/
      SP_DEVINFO_DATA DevInfoData;

      // Iterate thru the enum'ed devices

      for( i = 0
         ; NO_ERROR == devs.EnumDeviceInterfaces( spdid, i, diskGuid, NULL )
         ; i++ 
         )
      {
         DWORD reqSize;
         tOSError error = NO_ERROR;
         DevInfoData.cbSize = sizeof(DevInfoData);

         // Attempt to pull, and then reallocate for spdidd as necessary.
         if (!(SetupDiGetDeviceInterfaceDetail(devs, &spdid,
            spdidd.p, (DWORD)spdidd.alloc, &reqSize, &DevInfoData )))
         {
            error = ::GetLastError();
            if ( ERROR_INSUFFICIENT_BUFFER != error )
            {
               AddLogEntry( dta::Error( error ),
                  TXT("Error in first SetupDiGetDeviceInterfaceDetail()")
                  );
               continue;
            }
            // Yes, this allocates extra space.  But it's not a lot.
            spdidd.realloc( reqSize );
            spdidd.p->cbSize = sizeof( SP_DEVICE_INTERFACE_DETAIL_DATA );
            if (!(SetupDiGetDeviceInterfaceDetail(devs, &spdid,
               spdidd.p, (DWORD)spdidd.alloc, &reqSize, NULL )))
            {
               AddLogEntry( dta::Error( error ),
                  TXT("Error in second SetupDiGetDeviceInterfaceDetail()")
                  );
               continue;
            }
         }
         // At this point, spdidd has been successfully populated
         // with valid data.  Set the len member to reflect how much
         // of it actually *is* valid data.
         spdidd.len = reqSize;
         TCHAR *DevicePath = spdidd.p->DevicePath;
         if ( DevicePath )
         {
            _tostringstream sstr;
            sstr << TXT("Found device: ") << DevicePath;
            AddLogEntry( dta::Success, sstr.str() );
         }
         else
         {
            // Don't know how this is possible (to have a NULL)
            // but check out of pure paranoia.
            AddLogEntry( dta::Error( dta::eGenericMemoryError ),
               TXT("NULL found on device path string check, omitted")
               );
         }

         _tostringstream sstr;
         sstr << TXT("Device bus type: ");
         etBusType currentBusType = evErr;

         // With our CreateFile name safely in hand, now we need to
         // open the device and do some IOCTLs to discover more about
         // the disk device.
         HANDLE hand = CreateFile(
                   DevicePath,                         // device interface name
                   GENERIC_READ | GENERIC_WRITE,       // dwDesiredAccess
                   FILE_SHARE_READ | FILE_SHARE_WRITE, // dwShareMode
                   NULL,                               // lpSecurityAttributes
                   OPEN_EXISTING,                      // dwCreationDistribution
                   0,                                  // dwFlagsAndAttributes
                   NULL                                // hTemplateFile
                   );

         if ( INVALID_HANDLE_VALUE == hand )
         {
            tOSError error = ::GetLastError();
            if ( evAll == busType )
            {
               AddLogEntry( dta::Error( error ),
                  TXT("CreateFile() failed, bus type unavailable.")
                  );
               sstr << TXT("BusTypeUnavailable");
            }
            else
            {
               AddLogEntry( dta::Error( error ),
                  TXT("CreateFile() failed, device omitted.")
                  );
               continue;
            }
         }

         /////////////////////////////////////////////////////
         // Find out information about this device.  Most notably,
         // we need to know the bus type ( USB, SCSI, ATA ).
         if ( INVALID_HANDLE_VALUE != hand )
         {
            DWORD bytesReturned = 0;
            UCHAR outbuf[512];
            STORAGE_PROPERTY_QUERY propQuery =
               { StorageAdapterProperty, PropertyStandardQuery, 0 };

            if( !DeviceIoControl( hand, IOCTL_STORAGE_QUERY_PROPERTY,
               &propQuery, sizeof(propQuery), &outbuf, sizeof(outbuf),
               &bytesReturned, NULL ) )
            {
               tOSError error = ::GetLastError();
               // If I can't issue the IOCTL to determine a 
               // bus type, I omit the drive.  Unless, of course,
               // the user has specifically requested that ALL devices
               // be returned.
               if ( evAll == busType )
               {
                  AddLogEntry( dta::Error( error ),
                     TXT("IOCTL_STORAGE_QUERY_PROPERTY failed, bus type unavailable.")
                     );
                  sstr << TXT("BusTypeUnavailable");
               }
               else
               {
                  AddLogEntry( dta::Error( error ),
                     TXT("IOCTL_STORAGE_QUERY_PROPERTY failed, device omitted.")
                     );
                  continue;
               }
            }
            else  // IOCTL_STORAGE_QUERY_PROPERTY succeeded!
            {
               PSTORAGE_ADAPTER_DESCRIPTOR pSAD=(PSTORAGE_ADAPTER_DESCRIPTOR)outbuf;

               switch( pSAD->BusType )
               {
               case BusTypeAtapi:
                  sstr << TXT("BusTypeAtapi (ATA)");
                  currentBusType = evATA;
                  break;
               case BusTypeAta:
                  sstr << TXT("BusTypeAta (ATA)");
                  currentBusType = evATA;
                  break;
               case BusTypeSata:
                  sstr << TXT("BusTypeSata (ATA)");
                  currentBusType = evATA;
                  break;
               case BusTypeiScsi:
                  sstr << TXT("BusTypeiScsi (SCSI)");
                  currentBusType = evSCSI;
                  break;
               case BusTypeScsi:
                  sstr << TXT("BusTypeScsi (SCSI)");
                  currentBusType = evSCSI;
                  break;
               case BusTypeFibre:
                  sstr << TXT("BusTypeFibre (SCSI)");
                  currentBusType = evSCSI;
                  break;
               case BusTypeSas:
                  sstr << TXT("BusTypeSas (SCSI)");
                  currentBusType = evSCSI;
                  break;
               case BusTypeUsb:
                  sstr << TXT("BusTypeUsb (USB)");
                  currentBusType = evUSB;
                  break;
               case BusType1394:
                  sstr << TXT("BusType1394 (SCSI)");
                  currentBusType = ev1394;
                  break;
               case BusTypeUnknown:
                  sstr << TXT("BusTypeUnknown");
                  break;
               case BusTypeSsa:
                  sstr << TXT("BusTypeSsa");
                  break;
               case BusTypeRAID:
                  sstr << TXT("BusTypeRAID (RAID)");
                  currentBusType = evRAID;   
                  break;
               default:
                  sstr << TXT("BusTypeInvalid");
                  break;
               }
            }  // else IOCTL_STORAGE_QUERY_PROPERTY succeeded!

            ::CloseHandle(hand);
            hand = INVALID_HANDLE_VALUE;
         }

         // Using the bus type, create the prefix for the
         // current identifier.  It will be ultimately passed
         // back to the user.
         dta::DTIdentifier currentIdentifier;
         switch ( currentBusType )
         {
         case evUSB:
            currentIdentifier = dta::BUS_TYPE_USB;
            break;
         case evSCSI:
            currentIdentifier = dta::BUS_TYPE_SCSI;
            break;
         case evATA:
            currentIdentifier = dta::BUS_TYPE_ATA;
            break;
         case ev1394:
            currentIdentifier = dta::BUS_TYPE_1394;
            break;
         case evRAID:
            currentIdentifier = dta::BUS_TYPE_RAID;
            break;
         default:
            currentIdentifier = dta::BUS_TYPE_UNDETERMINED;
            break;
         }

         // Now, filter this device based on its bus type
         // and the bus type we're looking for.
         bool recognized = false;
         switch ( busType )
         {
         case evDefault:
            recognized = (currentBusType != evErr );
            break;
         case evAll:
            recognized = true;
            break;
         case evUSB:
            recognized = (currentBusType == evUSB );
            break;
         case ev1394:
            recognized = (currentBusType == ev1394 );
            break;
         case evSCSI:
            recognized = (currentBusType == evSCSI );
            break;
         case evATA:
            recognized = (currentBusType == evATA );
            break;
         case evRAID:
            recognized = (currentBusType == evRAID );
            break;
         case evErr:
         default:
            break;
         }
         if ( !recognized )
         {//scan_scsi();
            sstr << TXT(", device omitted.");
            AddLogEntry( dta::Success, sstr.str() );
            continue;
         }

         // Bus type recognized, add a log entry.
         AddLogEntry( dta::Success, sstr.str() );

         // An identifier consists of a prefixed interface
         // type and a postfix name to use for CreateFile()
         // (under Windows).  We've validated that this
         // 'thing' is a disk device, so add it to the 
         // list of identifiers!
         //
         // SPECIAL NOTE: Note that the identifier list is
         // not exclusively DriveTrust devices : we have no
         // way at the moment to guarantee (or disprove)
         // their support for DriveTrust commands without
         // opening the device for access.
         //
         if ( currentIdentifier != _T("RAID:") )
         {
            currentIdentifier += DevicePath;
            identifiers.push_back( currentIdentifier );
         }
#if 0
         if (currentIdentifier == _T("RAID:") )
		   {
            char szDrive[16];
            for (i = 0; i < 8; i++)
            {
               currentIdentifier = _T("RAID:");

               //sprintf_s(szDrive, 11, "\\\\.\\SCSI%d:", i);
               sprintf( szDrive, "\\\\.\\SCSI%d:", i );
               wchar_t file[11];
               file[10] = '\0';
               mbstowcs(file, szDrive, strlen(szDrive));
#else
         else  // if (currentIdentifier == _T("RAID:") )
         {
            // Look for up to 8 devices on the raid bus
            for (i = 0; i < 8; i++)
            {
               currentIdentifier = _T("RAID:");

               _TCHAR file[11];
               _stprintf_s( file, sizeof(file)/sizeof(file[0]), __T("\\\\.\\SCSI%d:"), i );
               file[10] = __T('\0');
#endif
               HANDLE hand = CreateFile( file, GENERIC_READ | GENERIC_WRITE,
                                               FILE_SHARE_READ | FILE_SHARE_WRITE,
                                               NULL, OPEN_EXISTING, 0, NULL );
               if( hand != INVALID_HANDLE_VALUE )
               {   
                  currentIdentifier += file;
                  identifiers.push_back( currentIdentifier ); 
               }  
            }
         }      
         AddLogEntry( dta::Success, 
            TXT("Added '") + currentIdentifier + TXT("' to list.")
            ); 
      }

      if ( ERROR_NO_MORE_ITEMS != devs.LastError() )
      {
         throw AddLogEntry(
            dta::Error( static_cast<tOSError>(devs.LastError()) ),
            TXT("Error in EnumDeviceInterfaces()")
            );
      }

#ifdef BUILD_SEAGATE_INTERNAL_SDK
      // Get a list of 1667 devices, if requested
      if ((busType == evES) || (busType == evAll)|| (busType == evDefault))
      {
         HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
         if (!FAILED(hr))
         {
            CComPtr<IEnumEnhancedStorageACT> pEnum;
            IEnhancedStorageACT** rgACTs = NULL;
            hr = CoCreateInstance(CLSID_EnumEnhancedStorageACT,
                                          NULL,
                                          CLSCTX_INPROC_SERVER,
                                          IID_IEnumEnhancedStorageACT,
                                          (VOID**) &pEnum);
            if (!FAILED(hr))
            {
               ULONG cACTs = 0;
               hr = pEnum->GetACTs(&rgACTs, &cACTs);
               if (!FAILED(hr))
               {
                  // Loop through all ACTs and collect the volume names
                  for (ULONG idxACT = 0; idxACT < cACTs; idxACT++)
                  {
                     LPWSTR uniqueID;
                     hr = rgACTs[idxACT]->GetUniqueIdentity(&uniqueID);
                     rgACTs[idxACT]->Release();
                     if (!FAILED(hr))
                     {
                        dta::DTIdentifier identifierUniqueID(uniqueID);
                        identifierUniqueID.insert(0, TXT("ES:"));
                        identifiers.push_back(identifierUniqueID);
                     }
                     CoTaskMemFree(uniqueID);
                  } // for
               } // if
               else
               {
                  // Need to add logging here
               }
            } 
            else // if failed cocreateinstance
            {
               // Need to add logging here
            }
            CoTaskMemFree(rgACTs);
         } // if CoInitialize failed
      } // if 1667 bus type
#endif // BUILD_SEAGATE_INTERNAL_SDK
#endif
   }
   M_DriveTrustBaseSimpleEndTry()
}



//================================================================
dta::DTA_ERROR COSLocalSystem::CreateSession(
      const dta::DTIdentifier  &identifier,
      const tUINT8             protocol,
      const      _tstring      &options,
      dta::CDriveTrustSession* &session
      )
{
   dtad::COSDTSession *newSession = NULL;
   M_DriveTrustBaseTry()
   {
      dta::DTIdentifier::size_type pos = identifier.find( ':' );
      if ( dta::DTIdentifier::npos == pos )
      {
         // Invalid identifier : could not find the separator
         // between the bus type and the CreateFile() name.
         throw AddLogEntry(
            dta::Error( dta::eGenericInvalidIdentifier ),
            TXT("Identifier separator not found")
            );
      }

      pos++; // include the ':' in the offset.
      const _tstring busType = identifier.substr( 0, pos );
      const _tstring devName = identifier.substr( pos );

      if ( busType == dta::BUS_TYPE_ATA )
      {
         // Create a session object for ATA PASS-THROUGH!
#ifdef BUILD_FOR_OLD_NVIDIA_STORPORT
         /// Added for support of NVIDIA SAT driver; 
         /// QueryDeviceParams returns bus type ATA, but since
         /// NVidia driver only supports scsi IOCTLs, must create
         /// a SAT session so drive responds like a SAT device.
         /// NVidia should return Bus Type SCSI since they only
         /// support that mode, and then use SCSIOP_ATA_PASSTHRU12/16.

         const _tstring devType = identifier.substr( pos+2, 3 );//( pos+4, 3 ); // nvn20110707

         if ( devType == TXT("ATA") )//if ( devType == _T("ide") ) // nvn20110629
         {	  
            // TODO: // nvn20110707 - linux only have scsi ?
            /*newSession = new COSDTSessionATAPT();
            AddLogEntry( dta::Success,
               TXT("Created new ATA Session object")
               );*/
            newSession = new COSDTSessionSAT();
            AddLogEntry( dta::Success,
               TXT("Created new SAT Session object")
               );
         } 
         else if ( _tstring(devType) == TXT("SCS") ) //else if ( _tstring(devType) == _T("scs") ) // nvn20110629
         {
            newSession = new COSDTSessionSAT();
            AddLogEntry( dta::Success,
               TXT("Created new SAT Session object")
               );
         }
#else
         newSession = new COSDTSessionATAPT();
         AddLogEntry( dta::Success,
            TXT("Created new ATA Session object")
            );

#endif // BUILD_FOR_OLD_NVIDIA_STORPORT

      }
      else if ( busType == dta::BUS_TYPE_SCSI )
      {
         // Create a session object for SCSI PASS-THROUGH
         //newSession = new COSDTSessionSAT( false );
         newSession = new COSDTSessionSAT(); //move it to scsi // nvn20110715
         newSession->SetAttribute( TXT("Transport"), TXT("SCSI") );
         AddLogEntry( dta::Success,
            TXT("Created new SCSI Session object")
            );
      }
      else if ( busType == dta::BUS_TYPE_1394 )
      {
         // Create a session object for SCSI PASS-THROUGH
         newSession = new COSDTSessionSAT( true );
         AddLogEntry( dta::Success,
            TXT("Created new SCSI Session object")
            );
      }
      else if ( busType == dta::BUS_TYPE_USB )
      {
         newSession = new COSDTSessionSAT();
         AddLogEntry( dta::Success,
            TXT("Created new USB Session object")
            );
      }
      else if ( busType == dta::BUS_TYPE_RAID )
      {
         newSession = new COSDTSessionRAID();
         AddLogEntry( dta::Success,
            TXT("Created new RAID Session object")
            );
      }
#ifdef BUILD_SEAGATE_INTERNAL_SDK
      else if ( busType == dta::BUS_TYPE_ES )
      {
         // Complete when constructor is finished
         newSession = new COSDTSessionES();
         AddLogEntry( dta::Success,
            TXT("Created new Enhanced Storage Session object")
            );
      }
#endif // BUILD_SEAGATE_INTERNAL_SDK
      else
      {
         // Whatever this is, it's not something we
         // recognize as a DriveTrust identifier.
         throw AddLogEntry(
            dta::Error( dta::eGenericInvalidIdentifier ),
            TXT("Unknown bus type in identifier string")
            );
      }
      newSession->Open( devName, protocol, options );

      // Success, move the session pointer to output.
      session = newSession;
      newSession = NULL;
   }
   M_DriveTrustBaseCatch()

   if ( !M_DtaSuccess( __result ) )
   {
      // If we failed, destroy any session that is
      // already been created.  It's unuseable.
      if ( newSession ) try
      {
         newSession->Destroy();
      }
      catch(...)
      {
      }
      if ( GetThrowOnError() )
      {
         throw __result;
      }
   }
   return __result;
}

//================================================================
dta::DTA_ERROR COSLocalSystem::GetDeviceAttribute(
      const dta::DTIdentifier& identifier,
      const _tstring& attribute,
      _tstring& value
      )
{
   M_DriveTrustBaseTry()
   {
      // TODO : Find device from identifier!
      // TODO : Pull attribute from device!
      throw AddLogEntry(
         dta::Error( dta::eGenericNotImplemented ),
         TXT("GetDeviceAttribute() not implemented")
         );
   }
   M_DriveTrustBaseSimpleEndTry()
}

//================================================================
dta::DTA_ERROR COSLocalSystem::AddLogEntry( 
   const dta::DTA_ERROR& error,
   const _tstring& text
   )
{
   return m_log.AddLogEntry( error, text );
}
