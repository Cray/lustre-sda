/*****************************************************************************
 * Author:   Valient Gough <vgough@pobox.com>
 *
 *****************************************************************************
 * Copyright (c) 2004, Valient Gough
 *
 * This library is free software; you can tidistribute it and/or modify it under
 * the terms of the GNU General Public License (GPL), as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GPL in the file COPYING for more
 * details.
 */

#ifndef _FileIO_incl_
#define _FileIO_incl_

#include "encfs.h"

#include <inttypes.h>
#include <string>

#include "Interface.h"

#include "CipherKey.h"
// File ID now mapps to ino_t but on lustre it would map to the 128 bit File ID
// TBD 
typedef ino_t FileID_t;


struct IORequest
{
    off_t offset;

    // amount of bytes to read/write.
    int dataLen;
    unsigned char *data;

    IORequest();
};

inline IORequest::IORequest()
    : offset(0)
    , dataLen(0)
    , data(0)
{
}

class FileIO
{
public:
    FileIO();
    virtual ~FileIO();

    virtual rel::Interface interface() const =0;

    // default implementation returns 1, meaning this is not block oriented.
    virtual int blockSize() const; 

    virtual void setFileName(const char *fileName) =0;
    virtual const char *getFileName() const =0;

    // Not sure about this -- it is specific to CipherFileIO, but the
    // alternative methods of exposing this interface aren't much nicer..
    virtual bool setIV( uint64_t iv );

    // open file for specified mode.  There is no corresponding close, so a
    // file is open until the FileIO interface is destroyed.
    virtual int open( int flags ) =0;
   
    // get filesystem attributes for a file
    virtual int getAttr( struct stat *stbuf ) const =0;
    virtual off_t getSize( ) const =0;

    virtual ssize_t read( const IORequest &req ) const =0;
    virtual bool write( const IORequest &req ) =0;

    virtual int truncate( off_t size ) =0;

    virtual bool isWritable() const =0;

#ifdef HAVE_XATTR
    virtual CipherKey getFileKey() =0;
    virtual FileID_t getFileID( std::string &fileIdentifier ) =0;

#  ifdef XATTR_ADD_OPT
    virtual int setxattr(const char *name, const char *value,
              size_t size, int flags, uint32_t position, int options) =0;
    virtual ssize_t getxattr(const char *name, char *value,
              size_t size, uint32_t position, int options ) const =0;
    virtual ssize_t listxattr(char *list, size_t size, int options ) const =0;
    virtual int removexattr(const char *name, int options ) =0;
#  else
    virtual int setxattr(const char *name, const char *value,
              size_t size, int flags) =0;
    virtual ssize_t getxattr(const char *name, char *value,
              size_t size ) const =0;
    virtual ssize_t listxattr(char *list, size_t size ) const =0;
    virtual int removexattr(const char *name ) =0;
#  endif  //XATTR_ADD_OPT

#endif // HAVE_XATTR


private:
    // not implemented..
    FileIO( const FileIO & );
    FileIO &operator = ( const FileIO & );
};

#endif

