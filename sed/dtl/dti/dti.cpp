/*! \file dti.cpp
    \brief Basic implementations of base class members from <dti/dti.hpp>.

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

    Copyright © 2008.  Seagate Technology LLC  All Rights Reserved.

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
#include "dti.hpp"
using namespace dti;

//=======================================================================================
// CDriveTrustInterface
//=======================================================================================
CDriveTrustInterface::CDriveTrustInterface(dta::CDriveTrustSession* newSession) : m_session(newSession)
{
   // No log file
   m_logFile = NULL;
   m_logging = false;

   // Set the block size
   _tstring strBlockSize;
   m_session->GetAttribute(TXT("BlockSize"), strBlockSize);
   m_blockSize = _tatoi(strBlockSize.c_str());
} // CDriveTrustInterface

//=======================================================================================
// CDriveTrustInterface
//=======================================================================================
CDriveTrustInterface::CDriveTrustInterface(dta::CDriveTrustSession* newSession,
                                            const _tstring logFileName) : m_session(newSession)
{
   // Initialize the time
   #if defined(_WIN32) // nvn20110616
   _tzset();
   #else
   tzset();
   #endif

   // Create the log file
   m_logFile = _tfopen(logFileName.c_str(), TXT("w"));
   m_logging = true;
   fprintf(m_logFile, "<?xml version=\"1.0\" encoding=\"iso-8859-1\"?>\n");
   
   _tstring strSerialNumber;
   m_session->GetAttribute(TXT("SerialNumber"), strSerialNumber);
   fprintf(m_logFile, "<Session device=\"%s\" time=\"%s\">\n", strSerialNumber.c_str(), currentTime());

   // Save the Block Size
   _tstring strBlockSize;
   m_session->GetAttribute(TXT("BlockSize"), strBlockSize);
   m_blockSize = _tatoi(strBlockSize.c_str());
} // CDriveTrustInterface

//=======================================================================================
// CDriveTrustInterface
//=======================================================================================
CDriveTrustInterface::~CDriveTrustInterface()
{
   if (m_logFile)
   {
      fprintf(m_logFile, "</Session time=\"%s\">\n", currentTime());
      fclose(m_logFile);
   }
} // ~CDriveTrustInterface

//=======================================================================================
// currentTime
//=======================================================================================
const char* CDriveTrustInterface::currentTime()
{
   static time_t ltime;
   static char timebuf[26];
   static char output[29];
   static struct _timeb tstruct;
   time(&ltime);
   #if defined(_WIN32) // nvn20110616
      _ftime(&tstruct);
      ctime_s(timebuf, 26, &ltime);
   #else
      ftime(&tstruct);      
      ctime_r(&ltime, timebuf);
   #endif   
   sprintf(&output[0], "%.19s.%03u %s", timebuf, tstruct.millitm, &timebuf[20]);
   output[28] = '\0';
   return &output[0];
} // currentTime