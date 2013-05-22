#include "ConfFileReader.h"
#include <cstdlib>

#include <rlog/rlog.h>
#include <rlog/Error.h>
#include <rlog/RLogChannel.h>
#include <rlog/SyslogNode.h>
#include <rlog/StdioNode.h>
using namespace libconfig;
using namespace rlog;
bool ConfFileReader::instanceFlag = false;
ConfFileReader* ConfFileReader::single = NULL;
ConfFileReader* ConfFileReader::getInstance()
{
    if(! instanceFlag)
    {
        single = new ConfFileReader();
        instanceFlag = true;
        return single;
    }
    else
    {
        return single;
    }
}
Setting& ConfFileReader::GetAttrValue(const char* attr) const 
{
    try
    {
	return cfg.lookup(attr);
    }
    catch(...)
    {
        std::cout<<"Attribute not defined in Config file"<<std::endl;
	exit(101);
    } 
}
bool ConfFileReader::IsAttr(const char* attr) const
{
  return cfg.exists(attr);
}

int ConfFileReader::ReadConfigFile()
{
  try
  {
    /* Load the configuration.. */
    std::cout << "loading [encfs.conf].." << std::endl;
    cfg.readFile("/etc/encfs.conf");
  }
  catch (ParseException &e)
  {
    std::cout << "Parse error at line " << std::endl;
    exit(1);
  }
  catch (FileIOException &e) 
  {
    std::cout <<"Configuration file not found." << std::endl;
    exit(1);
  }
  return 0;
}

ConfFileReader::ConfFileReader ()
{
   ReadConfigFile();
}
   
ConfFileReader::ConfFileReader(const ConfFileReader&)
{
   // Prevent copy-construction
}

ConfFileReader& ConfFileReader::operator=(const ConfFileReader&)
{
   // Prevent assignment
}

Setting& get_attr_value(const char* attr)
{
    ConfFileReader* RdConf = ConfFileReader::getInstance();
    return RdConf->GetAttrValue(attr);
}

#if 0
int main()
{
	const char* ServerUrl=get_attr_value("SERVER_URL");
	std::cout << "ok (ServerUrl =" << ServerUrl << ")" << std::endl;
        return 0;
}
#endif
