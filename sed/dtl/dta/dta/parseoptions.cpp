/*! \file parseoptions.cpp
    \brief Windows-specific implementation of COSLocalSystemObject.

    This implementation is specific to the Windows O/S.  It may include
    Windows-specific headers and definitions as necessary.
    
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

//=================================
// Include files
//=================================
#include "parseoptions.hpp"

//=================================
// macro/constant definitions
//=================================

//=================================
// typedefs and structures
//=================================

//=================================
// function implementations
//=================================

void dta::AddOrModifyMap( tstringMap& output, 
                    const _tstring &key, 
                    const _tstring &value 
                    )
{
   tstringMap::iterator iter;
   iter = output.find( key );
   if ( output.end() == iter )
   {
      output.insert( tstringMap::value_type( key, value ) );
   }
   else
   {
      iter->second = value;
   }
}

_tstring::size_type dta::FindNextNonSpace( 
                              const _tstring &input, 
                              _tstring::size_type pos 
                             )
{
   _tstring::size_type max = input.size();

   while ( pos != _tstring::npos 
      && pos < max 
      && isspace( input[pos] ) 
      )
   {
      pos++;
   }
   return ( pos < max ? pos : _tstring::npos );
}

_tstring::size_type dta::FindSpace( 
                              const _tstring &input, 
                              _tstring::size_type pos 
                             )
{
   _tstring::size_type max;

   bool previousCharBackslash = false;
   bool insideQuotes = false;
   for ( max = input.size(); pos < max; pos++ )
   {
      const tCHAR ch = input[pos];
      if ( '\\' == ch )
      {
         previousCharBackslash = !previousCharBackslash;
      }
      else if ( '"' == ch )
      {
         if ( !previousCharBackslash )
         {
            // Not a backslashed quote, so quotes are
            // either starting or ending.
            insideQuotes = !insideQuotes;
         }
         previousCharBackslash = false;
      }
      else if ( isspace( ch ) )
      {
         if (!( previousCharBackslash || insideQuotes ) )
         {
            // Found a "real" space!
            break;
         }
         previousCharBackslash = false;
      }
      else
      {
         previousCharBackslash = false;
      }
   }
   return ( pos < max ? pos : _tstring::npos );
}

_tstring dta::ParseOptions( tstringMap& output, const _tstring &input )
{
   _tstring wildcard;
   output.erase( output.begin(), output.end() );

   if ( 0 == input.size() )
   {
      // Nothing to do!
      return wildcard;
   }

   _tstring option;

   _tstring::size_type start, end;
   for( start  = FindNextNonSpace( input, 0); 
        start != _tstring::npos; 
        start  = FindNextNonSpace( input, end )
        )
   {
      // 'start' is the start of the substring.  Search
      // for the next space to find the end of the
      // substring.
      end = FindSpace( input, start );

      _tstring subString = input.substr( start, end-start );

      if ( subString.size() )
      {
         if ( option.size() )
         {
            if ( '-' == subString[0] )
            {
               // This is another option : the previous one needs to be mapped.
               AddOrModifyMap( output, option, TXT("") );
               option = subString;
            }
            else
            {
               // This is the value : the pair needs to be mapped.
               AddOrModifyMap( output, option, subString );
               option = TXT("");
            }
         }
         else // option currently empty.
         {
            if ( '-' == subString[0] )
            {
               option = subString;
            }
            else
            {
               // TODO : handle wildcard already being found.
               wildcard = subString;
            }
         }
      } // if subString.size()
   }

   if ( option.size() )
   {
      // We have one option left to process.
      AddOrModifyMap( output, option, TXT("") );
   }

   return wildcard;
}

