/*! \file parseoptions.hpp
    \brief Definition of ParseOptions() method.

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

#ifndef DTA_PARSEOPTIONS_HPP
#define DTA_PARSEOPTIONS_HPP

// !defined __cplusplus
//=================================
// Include files
//=================================
#include "dta.hpp"
#include <map>

//=================================
// macro definitions
//=================================
namespace dta {

//=================================
// constants
//=================================

//=================================
// typedefs and structures
//=================================

/// A map of string to strings.  This is used to search
/// and find option names and values in the option string.
typedef std::map< _tstring, _tstring > tstringMap;

//=================================
// function definitions
//=================================

///
/// Add a new entry or edit an existing entry in the
/// provided map.  If the provided key exists, the
/// entry will be changed to the new value.  Otherwise,
/// both the key and value will be added to the map.
///
/// \param output (OUT) A tstringMap to be added or edited.
///
/// \param key (IN) The key value for the new or edited entry.
///
/// \param value (IN) The key value for the new or edited entry.
///
/// \return None
///
void AddOrModifyMap( tstringMap& output, 
                    const _tstring &key, 
                    const _tstring &value 
                    );

///
/// Search for next non-space character in a string.
///
/// Scan forward in a string from a given position, looking
/// for the next item that fails isspace().
///
/// \param input (IN) A string to be searched
///
/// \param pos (IN) The starting position.
///
/// \return The index to the next valid space, or npos if none.
///
_tstring::size_type FindNextNonSpace( 
                              const _tstring &input, 
                              _tstring::size_type pos 
                             );

///
/// Search for next valid space in a string.
///
/// Scan forward in a string from a given position, looking
/// for the next item that passes isspace().  Will look at 
/// quotes (") and escaped chars (\) to determine if 
/// items should be skipped.
///
/// \param input (IN) A string to be searched
///
/// \param pos (IN) The starting position.
///
/// \return The index to the next valid space, or npos if none.
///
_tstring::size_type FindSpace( 
                              const _tstring &input, 
                              _tstring::size_type pos 
                             );

///
/// Parse a provided option string.  This method will parse
/// an option string, breaking it into a map of option names
/// and (optional) option values.
///
/// This method will throw a DTA_ERROR if an error occurs
/// during parsing.
/// 
/// \param output (OUT) A tstringMap of parsed option names
///      and values.
///
/// \param input (IN) A string to be parsed into the output map.
///
/// \return The wilcard option ( no leading - ) if found.
///
_tstring ParseOptions( tstringMap& output, const _tstring &input );

}  // end namespace dta
#endif // DTA_PARSEOPTIONS_HPP
