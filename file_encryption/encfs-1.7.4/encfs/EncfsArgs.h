#ifndef ENCFSARGS_H
#define ENCFSARGS_H


const int MaxFuseArgs = 32;
#include "FileUtils.h"
#include <sstream>
#include <string>
#include <boost/scoped_ptr.hpp>
#include <boost/shared_ptr.hpp>

using namespace std;
using boost::shared_ptr;
using boost::scoped_ptr;

struct EncFS_Args
{
    string mountPoint; // where to make filesystem visible
    bool isDaemon; // true == spawn in background, log to syslog
    bool isThreaded; // true == threaded
    bool isVerbose; // false == only enable warning/error messages
    int idleTimeout; // 0 == idle time in minutes to trigger unmount
    const char *fuseArgv[MaxFuseArgs];
    int fuseArgc;

    shared_ptr<EncFS_Opts> opts;

    // for debugging
    // In case someone sends me a log dump, I want to know how what options are
    // in effect.  Not internationalized, since it is something that is mostly
    // useful for me!
    string toString()
    {
        ostringstream ss;
        ss << (isDaemon ? "(daemon) " : "(fg) ");
        ss << (isThreaded ? "(threaded) " : "(UP) ");
        if(idleTimeout > 0)
            ss << "(timeout " << idleTimeout << ") ";
        if(opts->checkKey) ss << "(keyCheck) ";
        if(opts->forceDecode) ss << "(forceDecode) ";
        if(opts->ownerCreate) ss << "(ownerCreate) ";
        if(opts->useStdin) ss << "(useStdin) ";
        if(opts->reverseEncryption) ss << "(reverseEncryption) ";
        if(opts->mountOnDemand) ss << "(mountOnDemand) ";
        for(int i=0; i<fuseArgc; ++i)
            ss << fuseArgv[i] << ' ';

        return ss.str();
    }

    EncFS_Args()
        : opts( new EncFS_Opts() )
    {
    }
};

#endif
