/*! \file osDTSession.cpp
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
#include <dta/numstr.hpp>
#include "osDTSession.hpp"
#include <dta/parseoptions.hpp>
using namespace dtad;

//=================================
// macro/constant definitions
//=================================
pthread_mutex_t recmutex0 = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;
pthread_mutex_t recmutex1 = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;
pthread_mutex_t recmutex2 = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;
//=================================
// typedefs and structures
//=================================

//=================================
// function implementations
//=================================

//=================================
// class implementations
//=================================

COSDTSession::COSDTSession()
: m_deviceName( TXT("") )
, m_protocolID( 0 )
, m_spSpecific( 0 )
, m_timeout ( -1 )
{
   for ( unsigned i = 0; i < dta::eLockTypeMaxValue; i++ )
   {
      m_hand[i] = INVALID_HANDLE_VALUE; // TODO: nvn20110627
      m_lockCount[i] = 0;
   }
   m_supportedAttributes.push_back( txtBlockSize );
   m_supportedAttributes.push_back( txtCapacity );
   m_supportedAttributes.push_back( txtDeviceName );
   m_supportedAttributes.push_back( txtProtocolID );
   m_supportedAttributes.push_back( txtSpSpecific );
   m_supportedAttributes.push_back( txtTimeout );
}

dta::DTA_ERROR COSDTSession::Open(
      const dta::DTIdentifier  &identifier,
      const tUINT8             protocol,
      const _tstring           &optionString
      )
{
   M_DriveTrustBaseTry()
   {
      FreeResources();

      dta::tstringMap options;
      dta::tstringMap::iterator option;
      _tstring wildcard = dta::ParseOptions( options, optionString );
      option = options.find( TXT("-log") );
      if ( options.end() != option )
      {
         // Log file specified!
         m_log.Open( option->second, 
            TXT("Open Session " + identifier) 
            );
      }

      //
      // Open the device handle as appropriate.
      //
      /*M_OsDevice = CreateFile( identifier.c_str(),
         GENERIC_READ | GENERIC_WRITE,
         FILE_SHARE_READ | FILE_SHARE_WRITE,
         NULL,
         OPEN_EXISTING,
         FILE_FLAG_NO_BUFFERING | FILE_FLAG_OVERLAPPED,
         NULL);*/
      dta::DTIdentifier::size_type pos = identifier.find('@/');
      string tmpstr = (identifier.substr(pos)).c_str();
      M_OsDevice = open(tmpstr.c_str(), O_RDWR|O_NONBLOCK); //!< Array of Linux mutex // nvn20110627
      if ( INVALID_HANDLE_VALUE == M_OsDevice )
      {
         throw AddLogEntry(
            //dta::Error( static_cast<tOSError>(::GetLastError()) ),
            dta::Error( static_cast<tOSError>(errno) ), // nvn20110627
            //TXT("Error in CreateFile()").c_str
            TXT("Error in CreateFile()")
            );
      }

      // Create the session's mutex
      CreateSessionMutex(identifier);

      //
      // TODO : Parse the options string for additional settings as necessary.
      //
      m_protocolID = protocol;
      m_timeout    = 15;         // [jls: changed to accomodate FDE terminate 8 second time]
      m_spSpecific = 0;
      m_deviceName = identifier;
   }
   M_DriveTrustBaseSimpleEndTry()
} // Open

dta::DTA_ERROR COSDTSession::FreeResources()
{
   M_DriveTrustBaseTry()
   {
      //tOSError error = ERROR_SUCCESS;
	  tOSError error = 0; // nvn20110627
      _tstring strError;
      m_protocolID = 0;
      m_timeout    = -1;
      m_spSpecific = 0;
      m_deviceName.clear();

      // Close all device handles
      for ( unsigned i = 0; i < dta::eLockTypeMaxValue; i++ )
      {
         // Free any mutex locks.
         while ( 0 < m_lockCount[ i ] )
         {
            m_lockCount[i]--;
            //if ( !ReleaseMutex( m_hand[i] ) )
            switch (i)
            {
            case 0:
               if ( pthread_mutex_unlock( &recmutex0 ) ) // nvn20110627
               {
                  error = errno; // nvn20110627
                  //error = ::GetLastError();
                  strError = TXT("Error() in ReleaseMutex()");
               }
               if ( pthread_mutex_destroy( &recmutex0 ) ) // nvn20110627
               {
                  strError = TXT("Error() in CloseHandle()");
                  error = errno; // nvn20110627
               }
               break;

            case 1:
               if ( pthread_mutex_unlock( &recmutex1 ) ) // nvn20110627
			   {
				  error = errno;
				  strError = TXT("Error() in ReleaseMutex()");
			   }
               if ( pthread_mutex_destroy( &recmutex1 ) ) // nvn20110627
               {
                  strError = TXT("Error() in CloseHandle()");
                  error = errno; // nvn20110627
               }
               break;

            case 2:
               if ( pthread_mutex_unlock( &recmutex2 ) ) // nvn20110627
               {
                  error = errno;
                  strError = TXT("Error() in ReleaseMutex()");
               }
               if ( pthread_mutex_destroy( &recmutex2 ) ) // nvn20110627
               {
                  strError = TXT("Error() in CloseHandle()");
                  error = errno; // nvn20110627
               }
               break;

            default:
               break;
            }
         }


         // Close mutex (or device) handle.
         if ( INVALID_HANDLE_VALUE != m_hand[i] )
         {
            if (dta::eLockTypeAll == i)
            {
               //if ( !CloseHandle( m_hand[i] ) )
               if ( close(m_hand[i]) ) // M_OsDevice // nvn20111007
               {
                  strError = TXT("Error() in CloseHandle()");
                  error = errno; //error = ::GetLastError(); // nvn20110627
               }
            }
            m_hand[i] = INVALID_HANDLE_VALUE;
         }
      }

      //if ( ERROR_SUCCESS != error )
      if ( 0 != error ) // nvn20110627
      {
         dta::DTA_ERROR dtaError( dta::Error(error) );
         AddLogEntry( dtaError, strError );
         m_log.Close();
         throw dtaError;
      }
      m_log.Close();

   }
   M_DriveTrustBaseSimpleEndTry()
}

dta::DTA_ERROR COSDTSession::Destroy()
{
   dta::_DTA_ERROR result = dta::Success;

   M_DriveTrustBaseTry()
   {
      FreeResources();
   }
   M_DriveTrustBaseCatch()

   try
   {
      result = dta::CDriveTrustSession::Destroy();
   }
   // Destroy can delete the 'this' operator.  The
   // normal macros wrapping catch aren't safe to
   // use because they may attempt to access 'this'.
   catch( const dta::DTA_ERROR& err )
   {
      result = err;
   }

   // Now, assign result to the FreeResources() error code 
   // (if a failure), or leave it assigned to the Destroy()
   // error code (if FreeResources() succeeded).
   if ( M_DtaFail( __result ) )
   {
      result = __result;
   }

   // And now, re-throw or return the result as appropriate.
   if ( M_DtaFail( result ) && __throwOnError )
   {
      throw result;
   }
   return result;
}

dta::DTA_ERROR COSDTSession::GetSupportedAttributes(
   dta::DTAttributeCollection &attributes
   )
{
   attributes = m_supportedAttributes;
   return dta::Success;
}

dta::DTA_ERROR COSDTSession::GetAttribute(
   const _tstring& attribute,
   _tstring& value
   )
{
   M_DriveTrustBaseTry()
   {
      value = TXT("");
      if ( 0 == attribute.size() )
      {
         // User has requested a list of known attributes.
         bool first = true;
         dta::DTAttributeCollection::iterator iter;
         for (iter = m_supportedAttributes.begin();
            iter != m_supportedAttributes.end();
            iter++)
         {
            if (first)
            {
               value = *iter;
               first = false;
            }
            else
            {
               value += chSeparator;
               value += *iter;
            }
         }
      }
      else if ( txtDeviceName == attribute )
      {
         value = m_deviceName;
      }
      else if ( txtProtocolID == attribute )
      {
         _tostringstream sstr;
         sstr<< tUINT32(m_protocolID);
         value = sstr.str();
      }
      else if ( txtSpSpecific == attribute )
      {
         _tostringstream sstr;
         sstr << m_spSpecific;
         value = sstr.str();
      }
      else if ( txtTimeout == attribute )
      {
         _tostringstream sstr;
         sstr << m_timeout;
         value = sstr.str();
      }
      else
      {
         throw AddLogEntry(
            dta::Error( dta::eGenericInvalidParameter ),
            TXT("Unknown attribute: ") + attribute
            );
      }
   }
   M_DriveTrustBaseSimpleEndTry()
}

dta::DTA_ERROR COSDTSession::LockSession( 
      dta::eSessionLockTypes lockType,
      size_t timeout 
      )
{
   M_DriveTrustBaseTry()
   {
#if 0 // nvn20110627
      DWORD waitResult;
      if ( lockType >= dta::eLockTypeMaxValue )
      {
         // Invalid lock type.
         throw AddLogEntry(
            dta::Error( dta::eGenericInvalidParameter ),
            TXT("Invalid lock type")
            );
      }
      else if ( lockType == dta::eLockTypeAll )
      {
         const unsigned waitSize = dta::eLockTypeMaxValue - 1;
         waitResult = WaitForMultipleObjects(
            waitSize,
            &m_hand[1],
            TRUE,    // Wait for all locks
            (DWORD)timeout
            );

         // Force range results to a single value.
         if ( waitResult > WAIT_OBJECT_0 &&
            waitResult < WAIT_OBJECT_0 + waitSize - 1 )
         {
            waitResult = WAIT_OBJECT_0;
         }

         if ( waitResult >= WAIT_ABANDONED_0 &&
            waitResult < WAIT_ABANDONED_0 + waitSize - 1 )
         {
            waitResult = WAIT_ABANDONED;
         }

      }
      else  // single lock
      {
         waitResult = WaitForSingleObject(
            m_hand[lockType], (DWORD) timeout );
      }

      switch ( waitResult )
      {
      case WAIT_ABANDONED:
         // The owner gave up on the object and went away.
         // Lock it for ourself, and continue.
         __result = LockSession ( lockType, timeout );
         break;
      case WAIT_OBJECT_0:
         // Success!
         m_lockCount[ lockType ]++;
         break;
      case WAIT_TIMEOUT:
         throw AddLogEntry(
            dta::Error( dta::eGenericTimeoutError ),
            TXT("Timeout waiting for session lock")
            );
         break;
      case WAIT_FAILED:
         throw AddLogEntry(
            dta::Error( static_cast<tOSError>(::GetLastError()) ),
            TXT("Wait for session lock FAILED!")
            );
         break;
      default:
         throw AddLogEntry(
            dta::Error( dta::eGenericFatalError ),
            TXT("Error: Wait for session lock returned INVALID result")
            );
         break;
      }
#else
      // nvn20110718
      tUINT8 waitResult;
      if ( lockType >= dta::eLockTypeMaxValue )
      {
         // Invalid lock type.
         throw AddLogEntry(
            dta::Error( dta::eGenericInvalidParameter ),
            TXT("Invalid lock type")
            );
      }
      else if ( lockType == dta::eLockTypeAll )
      {
         // linux doesn't have multiple lock , sooo... just skip it
         /*
         const unsigned waitSize = dta::eLockTypeMaxValue - 1;
         waitResult = WaitForMultipleObjects(
            waitSize,
            &m_hand[1],
            TRUE,    // Wait for all locks
            (DWORD)timeout
            );*/

      }
      else  // single lock
      {
         //waitResult = WaitForSingleObject(
         //   m_hand[lockType], (DWORD) timeout );
         //for ( unsigned i = dta::eLockTypeAll;
         //   ++i < dta::eLockTypeMaxValue;
         //   )
         {
            switch(lockType)
            {
            //case 0:
            //   // Create the mutex with the attributes set
            //   waitResult = pthread_mutex_lock(&recmutex0);
            //   break;

            case dta::eLockTypeTxRx:
               // Create the mutex with the attributes set
               waitResult = pthread_mutex_lock(&recmutex1);
               break;

            case dta::eLockTypeSession:
               // Create the mutex with the attributes set
               waitResult = pthread_mutex_lock(&recmutex2);
               break;

            default:
               break;
            }

            if ( waitResult == 0 )
            {
               m_lockCount[ lockType ]++;
            }
            else
            {
               waitResult = errno;
               throw 1;
            }
         } // for
      }
#endif
   }
   M_DriveTrustBaseSimpleEndTry()
}

dta::DTA_ERROR COSDTSession::UnlockSession(
      dta::eSessionLockTypes lockType
      )
{
   M_DriveTrustBaseTry()
   {
      if ( lockType >= dta::eLockTypeMaxValue )
      {
         throw AddLogEntry(
            dta::Error( dta::eGenericInvalidParameter ),
            TXT("Invalid lock type")
            );
      }
      else if ( lockType > dta::eLockTypeAll )
      {
         // Single lock!
         -- m_lockCount[lockType];
         /*if ( !ReleaseMutex( m_hand[lockType] ) )
         {
            tOSError error = ::GetLastError();
            throw AddLogEntry(
               dta::Error( error ),
               TXT("ReleaseMutex() failed")
               );
         }*/
         switch(lockType)
         {
         // TODO: // nvn20110718 - temporary comment throwable mutex unlock
         // nvntry
         //case dta::eLockTypeAll:
         //    if ( !pthread_mutex_unlock( &recmutex0 ) )
         //    {
         //       tOSError error = errno;
         //       throw AddLogEntry(
         //          dta::Error( error ),
         //          TXT("ReleaseMutex() failed")
         //       );
         //    }
         //    break;

         // nvn20110826
         case dta::eLockTypeTxRx:
            if ( pthread_mutex_unlock( &recmutex1 ) )
            {
               tOSError error = errno;
               throw AddLogEntry(
                  dta::Error( error ),
                  TXT("ReleaseMutex() failed")
               );
            }
            break;

         case dta::eLockTypeSession:
            if ( pthread_mutex_unlock( &recmutex2 ) )
            {
               tOSError error = errno;
               throw AddLogEntry(
                  dta::Error( error ),
                  TXT("ReleaseMutex() failed")
               );
            }
            break;

         default:
            break;
         }
      }
      else // all locks.
      {
         for ( unsigned i = lockType + 1;
            i < dta::eLockTypeMaxValue;
            i++
            )
         {
            UnlockSession( static_cast<dta::eSessionLockTypes>(i) );
         }
      }
   }
   M_DriveTrustBaseSimpleEndTry()
}

dta::DTA_ERROR COSDTSession::SetAttribute(
   const _tstring& attribute,
   const _tstring& value
   )
{
   M_DriveTrustBaseTry()
   {
      if ( txtDeviceName == attribute )
      {
         // Can't change the device name in an open session.
         throw AddLogEntry(
            dta::Error( dta::eGenericAttributeReadOnly ),
            TXT("Error: Device Name attribute may not be changed")
            );
      }
      else if ( txtProtocolID == attribute )
      {
         // Can't change the protocol ID in an open session.
         throw AddLogEntry(
            dta::Error( dta::eGenericAttributeReadOnly ),
            TXT("Error: Protocol ID attribute may not be changed")
            );
      }
      else if ( txtSpSpecific == attribute )
      {
         tUINT16 spSpecific = 0;
         const tCHAR* p;
         for (p = value.c_str(); *p; p++ )
         {
            if ( '0' <= *p && '9' >= *p )
            {
               spSpecific *= 10;
               spSpecific += ( *p - '0' );
            }
            else
            {
               // Whatever it is, it's not numeric.
               throw AddLogEntry(
                  dta::Error( dta::eGenericInvalidParameter ),
                  TXT("Error: Specified Protocol ID not numeric")
                  );
            }
         }
         m_spSpecific = spSpecific;
      }
      else if ( txtTimeout == attribute )
      {
    	 tUINT32 timeout = 0;
         const tCHAR* p;
         for (p = value.c_str(); *p; p++ )
         {
            if ( '0' <= *p && '9' >= *p )
            {
               timeout *= 10;
               timeout += ( *p - '0' );
            }
            else
            {
               // Whatever it is, it's not numeric.
               throw AddLogEntry(
                  dta::Error( dta::eGenericInvalidParameter ),
                  TXT("Error: Specified Timeout not numeric")
                  );
            }
         }
         m_timeout = timeout;
      }
      else
      {
         throw AddLogEntry(
            dta::Error( dta::eGenericInvalidParameter ),
            TXT("Error: Unknown attribute ") + attribute
            );
      }
   }
   M_DriveTrustBaseSimpleEndTry()
}

dta::DTA_ERROR COSDTSession::CreateSessionMutex(const dta::DTIdentifier &identifier)
{
   M_DriveTrustBaseTry()
   {
      //
      // Open/create the protection mutex for the device.
      // First, we have to "munch" the device name to create
      // a valid mutex name.
      //
      _tstring lockBaseName;
      _tstring::const_iterator iter;
      for( iter = identifier.begin(); iter != identifier.end(); iter++ )
      {
         if ( isalnum( *iter ) )
         {
            lockBaseName += *iter;
         }
      } // for

      pthread_mutexattr_t mutexattr;  // Mutex Attribute
      // Set the mutex as a recursive mutex
      pthread_mutexattr_settype(&mutexattr, PTHREAD_MUTEX_RECURSIVE_NP);


      // Now, create the necessary mutexes for our locks.
      //tOSError error = ERROR_SUCCESS;
      tOSError error = 0L; // nvn20110627
      for ( unsigned i = dta::eLockTypeAll;
         ++i < dta::eLockTypeMaxValue;
         )
      {
         //TCHAR ch = 'A' + (TCHAR)(i-1); // TODO: // nvn20110627 - named mutex

         // Populate the NamedMutex handle table for each lock type
         /*m_hand[i] = ::CreateMutex( NULL, // no security attributes
            FALSE,                        // not the initial owner
            (TCHAR("Global\\") + lockBaseName + ch).c_str()   // named mutex
            );*/
         switch(i)
         {
         case 0:
            // Create the mutex with the attributes set
            m_hand[i] = pthread_mutex_init(&recmutex0, &mutexattr);
            break;

         case 1:
            // Create the mutex with the attributes set
            m_hand[i] = pthread_mutex_init(&recmutex1, &mutexattr);
            break;

         case 2:
            // Create the mutex with the attributes set
            m_hand[i] = pthread_mutex_init(&recmutex2, &mutexattr);
            break;

         default:
        	 break;
         }

         //if ( NULL == m_hand[i] )
         if ( NULL != m_hand[i] )
         {
            error = errno;
            m_hand[i] = INVALID_HANDLE_VALUE;
         }
      } // for

      if ( 0L != error )
      {
         dta::DTA_ERROR dtaError( dta::Error( error ) );
         AddLogEntry( dtaError,
            TXT("Error: CreateMutex() failed")
            );
         FreeResources();
         throw dtaError;
      } // if
   }
   M_DriveTrustBaseSimpleEndTry()
} // CreateSessionMutex

//================================================================
dta::DTA_ERROR COSDTSession::AddLogEntry( 
   const dta::DTA_ERROR &error,
   const _tstring& text 
   )
{
   return m_log.AddLogEntry( error, text );
}
