#ifndef __HTTPREQUEST_HPP__
#define __HTTPREQUEST_HPP__

#include <functional>

void HttpRequest( const char* server, const char* resource, int port, const std::function<void(int, char*)>& cb );

#endif
