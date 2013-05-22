/*! \file atatasks.cpp
    \brief Implementations of atatasks.hpp.

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

//=================================
// Include files
//=================================
#include <iostream> // nvn20110615
#include "atatasks.hpp"
#include "common.h"

using namespace ata;

// Disabled Microsoft warnings on C-style functions
#if defined (_WIN32)
#pragma warning(disable : 4996)
#endif

//=======================================================================================
// CAtaTasks
//=======================================================================================
CAtaTasks::CAtaTasks() : CAta()
{
} // CAtaTasks


//=======================================================================================
// DownloadMicrocode
//=======================================================================================
void CAtaTasks::DownloadMicrocode()
{
   _tstring filename;
   _tcout << TXT("Enter microcode file name (with full path): ");
   _tcin >> filename;
   _tcin.clear();
   fflush(stdin);

   try
   {
      CAta::DownloadMicrocode(filename);
   }
   catch (dta::DTA_ERROR & err)
   {
      _tcout << TXT("Error Firmware Download:") << (tUINT16)err.Info.Detail << std::endl;
   } // catch
} // DownloadMicrocode
