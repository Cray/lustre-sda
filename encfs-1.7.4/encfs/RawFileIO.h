/*****************************************************************************
 * Author:   Valient Gough <vgough@pobox.com>
 *
 *****************************************************************************
 * Copyright (c) 2004, Valient Gough
 *
 * This library is free software; you can distribute it and/or modify it under
 * the terms of the GNU General Public License (GPL), as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GPL in the file COPYING for more
 * details.
 */

#ifndef _RawFileIO_incl_
#define _RawFileIO_incl_

#include "FileIO.h"

#include <string>

class RawFileIO : public FileIO
{
public:
    RawFileIO();
    RawFileIO( const std::string &fileName );
    virtual ~RawFileIO();

    virtual rel::Interface interface() const;

    virtual void setFileName( const char *fileName );
    virtual const char *getFileName() const;

    virtual int open( int flags );
    
    virtual int getAttr( struct stat *stbuf ) const;
    virtual off_t getSize() const;

    virtual ssize_t read( const IORequest & req ) const;
    virtual bool write( const IORequest &req );

    virtual int truncate( off_t size );

    virtual bool isWritable() const;
#ifdef HAVE_XATTR
    virtual CipherKey getFileKey();
    virtual FileID_t getFileID( std::string &fileIdentifier );

#  ifdef XATTR_ADD_OPT
    virtual int setxattr(const char *name, const char *value,
              size_t size, int flags, uint32_t position, int options);
    virtual ssize_t getxattr(const char *name, char *value,
              size_t size, uint32_t position, int options ) const;
    virtual ssize_t listxattr(char *list, size_t size, int options ) const;
    virtual int removexattr(const char *name, int options );
#  else
    virtual int setxattr(const char *name, const char *value,
              size_t size, int flags);
    virtual ssize_t getxattr(const char *name, char *value,
              size_t size ) const;
    virtual ssize_t listxattr(char *list, size_t size ) const;
    virtual int removexattr(const char *name );
#  endif  //XATTR_ADD_OPT

#endif // HAVE_XATTR


protected:

    std::string name;

    bool knownSize;
    off_t fileSize;

    int fd;
    int oldfd;
    bool canWrite;

    FileID_t m_fileId;
};

#endif

