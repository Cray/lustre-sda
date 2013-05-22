/*! \file TCGEntSessions.cpp
    \brief Basic implementations of base class members from <TCG/TCGEntSessions.hpp>.

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
#include "dtlcrypto.h"

using namespace dta;
using namespace dti;

//=======================================================================================
// CTcgEntSessions
//=======================================================================================
CTcgEntSessions::CTcgEntSessions(dta::CDriveTrustSession* newSession)
                : CDriveTrustInterface(newSession), CTcgCoreInterface(newSession),
                  CTcgEnterpriseSSC(newSession), CTcgSessions(newSession)
                  
{
} // CTcgEntSessions

//=======================================================================================
// CTcgEntSessions
//=======================================================================================
CTcgEntSessions::CTcgEntSessions(dta::CDriveTrustSession* newSession, const _tstring logFileName)
                : CDriveTrustInterface(newSession, logFileName), CTcgCoreInterface(newSession, logFileName),
                  CTcgEnterpriseSSC(newSession, logFileName), CTcgSessions(newSession, logFileName)
                  
{
} // CTcgEntSessions
