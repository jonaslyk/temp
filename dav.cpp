#include <algorithm>
#include <iostream>
#include <memory>
#include <string>
#include <vector>
#include <array>
#include <unordered_map>
#include <set>
#include <functional>
#define _WIN32_WINNT 0x600
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <http.h>
#include <stdio.h>

#pragma comment(lib, "httpapi.lib")

using namespace std;

auto buildxml( std::string folderurl , std::vector< std::string > filenames ) {
   std::string ret{ 
      "<?xml version=\"1.0\" encoding=\"utf-8\"?> "s +
      "<D:multistatus xmlns:D = \"DAV:\">" 
   };
   ret = ret + R""""(
    <D:response>
    <D:href>)""""s + folderurl  + R""""(</D:href>
    <D:propstat>
      <D:status>HTTP/1.1 200 OK</D:status>
      <D:prop>
        <D:getcontenttype /> <D:getlastmodified>Tue, 12 Oct 2021 20:38:18 GMT</D:getlastmodified> <D:lockdiscovery /> <D:ishidden>0</D:ishidden>
        <D:supportedlock>
            <D:lockentry><D:lockscope><D:exclusive /></D:lockscope><D:locktype><D:write /></D:locktype></D:lockentry><D:lockentry><D:lockscope><D:shared /></D:lockscope><D:locktype><D:write /></D:locktype></D:lockentry></D:supportedlock>
        <D:getetag />
        <D:displayname>/</D:displayname> <D:getcontentlanguage /> <D:getcontentlength>0</D:getcontentlength> <D:iscollection>1</D:iscollection> <D:creationdate>2021-08-20T14:42:43.702Z</D:creationdate>
        <D:resourcetype> <D:collection /> </D:resourcetype>
      </D:prop>
    </D:propstat>
  </D:response> )""""s;

   for( auto& f : filenames ){ 
      ret = ret + 
      R""""(<D:response>
               <D:href>)"""" + folderurl + f + R""""(</D:href>
               <D:propstat>
               <D:status>HTTP/1.1 200 OK</D:status>
               <D:prop>
                  <D:getcontenttype>text/plain</D:getcontenttype>
                  <D:getlastmodified>Fri, 20 Aug 2021 16:51:11 GMT</D:getlastmodified>
                  <D:lockdiscovery />
                  <D:ishidden>0</D:ishidden>
                 <D:supportedlock> <D:lockentry> <D:lockscope> <D:exclusive /> </D:lockscope> <D:locktype> <D:write /> </D:locktype> </D:lockentry> <D:lockentry> <D:lockscope> <D:shared /> </D:lockscope> <D:locktype> <D:write /> </D:locktype> </D:lockentry> </D:supportedlock>
                  <D:getetag>"c322cc94e395d71:0"</D:getetag>
                  <D:displayname>)"""" + f + R""""(</D:displayname>
                  <D:getcontentlanguage />
                  <D:getcontentlength>)"""" + std::to_string( f.size() ) + R""""(</D:getcontentlength>
                  <D:iscollection>0</D:iscollection>
                  <D:creationdate>2021-08-20T16:51:11.724Z</D:creationdate>
               </D:prop>
               </D:propstat>
            </D:response> 
      )""""s;
   }    
   return ret + "</D:multistatus>";
}

std::unordered_map< unsigned int, std::string> http_status{ {100, "Continue"}, {101, "Switching_Protocol"}, {102, "Processing"}, {103, "Early_Hints"}, {200, "OK"}, {201, "Created"}, {202, "Accepted"}, {203, "Non_Authoritative_Information"}, {204, "No_Content"}, {205, "Reset_Content"}, {206, "Partial_Content"}, {207, "Multi_Status"}, {208, "Already_Reported"}, {226, "IM_Used"}, {300, "Multiple_Choices"}, {301, "Moved_Permanently"}, {302, "Found"}, {303, "See_Other"}, {304, "Not_Modified"}, {305, "Use_Proxy"}, {306, "Switch_Proxy"}, {307, "Temporary_Redirect"}, {308, "Permanent_Redirect"}, {400, "Bad_Request"}, {401, "Unauthorized"}, {402, "Payment_Required"}, {403, "Forbidden"}, {404, "Not_Found"}, {405, "Method_Not_Allowed"}, {406, "Not_Acceptable"}, {407, "Proxy_Authentication_Reqired"}, {408, "Request_Timeout"}, {409, "Conflict"}, {410, "Gone"}, {411, "Length_Required"}, {412, "Precondition_Failed"}, {413, "Payload_Too_Large"}, {414, "URI_Too_Long"}, {415, "Unsupported_Media_Type"}, {416, "Range_Not_Satisfiable"}, {417, "Expectation_Failed"}, {418, "Im_a_teapot"}, {421, "Misdirected_Request"}, {422, "Unprocessable_Entity"}, {423, "Locked"}, {424, "Failed_Dependency"}, {425, "Too_Early"}, {426, "Upgrade_Required"}, {428, "Precondition_Required"}, {429, "Too_Many_Requests"}, {431, "Request_Header_Fields_Too_Large"}, {451, "Unavailable_For_Legal_Reasons"}, {500, "Internal_Server_Error"}, {501, "Not_Implemented"}, {502, "Bad_Gateway"}, {503, "Service_Unavailable"}, {504, "Gateway_Timeout"}, {505, "HTTP_Version_Not_Supported"}, {506, "Variant_Also_Negotiates"}, {507, "Insufficient_Storage"}, {508, "Loop_Detected"}, {510, "Not_Extended"}, {511, "Network_Authentication_Required"} };

template< typename... Ts > struct overloaded : Ts... { using Ts::operator()... ; };
template< typename... Ts > overloaded( Ts... )->overloaded< Ts... >;

template<typename T, typename S> struct life { S s; life(T t, S s) : s{ s } { t(); } ~life() { s(); }};
template<typename T, typename S> life(T,S)->life<T,S>;
#ifdef  _DEBUG
static const auto  orgCout = std::cout.rdbuf( []() {    struct streamfwd : public std::streambuf{
                                                            virtual int_type overflow( int_type c = EOF ) {
                                                               char str[]{ c, 0x00 };
                                                               OutputDebugStringA( str );
                                                               return std::char_traits< char >::int_type{ c };
                                                            }
                                                         };
                                                         static streamfwd dbgout{}; 
                                                         return &dbgout; 
                                                   }()
                                            );
#endif

#define TOKENIZE(x) #x
#define THROW_ON_ERR( CODE )[ & ]( ){ auto RET = CODE; if( RET != NO_ERROR ) throw exception{ (std::string{ TOKENIZE( CODE ) } + " returned: "s + to_string( RET ) + "\n"s  ).c_str() }; return true; }();  

static const auto PORT = L"9999";      // []() {std::srand(std::time(nullptr)); return to_wstring((rand() % 65536) + 1024); }();

using str = std::basic_ostream< char, std::char_traits< char > >;
str& operator<< ( str& os, const std::wstring& ws ) { return os << std::string{ ws.begin() , ws.end() }; }
str& operator<< ( str& os, const wchar_t* ws ) { std::wstring tmp{ ws }; return os << std::string{ tmp.begin() , tmp.end() }; }

constexpr static const std::array< const std::array< char ,20 >, HttpVerbMaximum + 1 >
verbs{ "", "Unknown", "Invalid", "OPTIONS",  "GET", "HEAD", "POST", "PUT","DELETE", "TRACE", "CONNECT", "TRACK",  "MOVE", "COPY", "PROPFIND", "PROPPATCH", "MKCOL", "LOCK","UNLOCK", "SEARCH" };

static life httpengine{ std::function< void() > { [](){ HttpInitialize( HTTPAPI_VERSION_2, HTTP_INITIALIZE_SERVER, NULL ); } },
                        std::function< void() > { [](){ HttpTerminate( HTTP_INITIALIZE_SERVER , 0 ); } }
};

struct DYNREQ {
   const unsigned int BUFFSIZE = sizeof( HTTP_REQUEST ) + 2048;
   std::unique_ptr< char[] > buf{ new char[ BUFFSIZE ] };
   HTTP_REQUEST_ID requestId;
   DYNREQ() { HTTP_SET_NULL_ID( &requestId ); r()->RequestId = requestId; }
   PHTTP_REQUEST r() { return (PHTTP_REQUEST)( &buf.get()[0]) ; }
};

struct request_response {
   HANDLE h;
   HTTP_REQUEST_ID responseTo;
   HTTP_VERB requestVerb;

   std::vector< std::pair< std::string ,std::string > > headers;
   std::array< std::string, HttpHeaderResponseMaximum > knownheaders;

   request_response( HANDLE h, HTTP_REQUEST_ID id, HTTP_VERB requestVerb) : h{ h }, responseTo{ id }, requestVerb{ requestVerb } { }
   void setResponseHeader( HTTP_HEADER_ID id, const char* val ) { knownheaders[id] = val; }
   void setResponseHeader( std::string name, std::string val  ) { headers.emplace_back( name,val ); }

   auto sendResponse( int statuscode, std::string responsetext = "" )
   {
      HTTP_RESPONSE response{ 0x00 };
      for( int i = 0; i < knownheaders.size(); i++ ) {
         response.Headers.KnownHeaders[i].pRawValue      = knownheaders[i].c_str();
         response.Headers.KnownHeaders[i].RawValueLength = knownheaders[i].size();
      }
      response.StatusCode     = statuscode;
      response.pReason        = http_status.at( statuscode ).c_str();   
      response.ReasonLength   = static_cast<USHORT>( strlen(response.pReason) );
  
      std::string contentLengthHeader = to_string( responsetext.size() );
      response.Headers.KnownHeaders[ HttpHeaderContentLength ].pRawValue      = contentLengthHeader.c_str();
      response.Headers.KnownHeaders[ HttpHeaderContentLength ].RawValueLength = contentLengthHeader.size();

      static HTTP_UNKNOWN_HEADER unknowsheaders[10]{ 0x00 };
      for (int i = 0; i < headers.size(); i++)
      { 
         unknowsheaders[i] =  HTTP_UNKNOWN_HEADER{ static_cast<unsigned short>( headers.at(i).first.size() ),
                                                   static_cast<unsigned short>( headers.at(i).second.size() ),
                                                   headers.at(i).first.c_str(),
                                                   headers.at(i).second.c_str() 
                                                 };
      }
      response.Headers.pUnknownHeaders    = unknowsheaders;
      response.Headers.UnknownHeaderCount = headers.size();

      THROW_ON_ERR(HttpSendHttpResponse(h, responseTo, (responsetext.size() ? HTTP_SEND_RESPONSE_FLAG_MORE_DATA : 0), &response, NULL, NULL, NULL, 0, NULL, NULL));

      if( responsetext.size() ){
         HTTP_DATA_CHUNK dataChunk{ HttpDataChunkFromMemory, (void*)responsetext.c_str(), responsetext.size() } ;
         THROW_ON_ERR( HttpSendResponseEntityBody(h, responseTo, 0, 1, &dataChunk, NULL, NULL, 0, NULL, NULL) );
      }
   }
}; 

template< typename T >
struct httpd {
   const std::wstring folder, port, hostname;
   HANDLE h;
   auto  url() { return std::wstring{ L"http://"s + hostname + ( ( port != L""s ) ? L":"s : L""s ) + port + L"/"s + folder}; }
   httpd( std::wstring hostname, std::wstring folder, std::wstring port , T t) : hostname{ hostname }, folder{ folder }, port{ port }
   {
      THROW_ON_ERR(HttpCreateHttpHandle(&h, 0));
      THROW_ON_ERR(HttpAddUrl(h, url().c_str(), NULL));
      std::cout << "Listening on: " << url().c_str() << " - connect to \\\\" << hostname << "@" << port << "\\" << folder << std::endl;
      while (true) {
         DYNREQ pRequest;
         THROW_ON_ERR(HttpReceiveHttpRequest(h, pRequest.r()->RequestId, 0, pRequest.r(), pRequest.BUFFSIZE, NULL, NULL); )
            cout << "Got a " << verbs.at(pRequest.r()->Verb).data() << " request for " << pRequest.r()->CookedUrl.pFullUrl << std::endl;
         t(request_response{ h, pRequest.r()->RequestId,pRequest.r()->Verb });
      }
   }
   ~httpd(){ THROW_ON_ERR( HttpRemoveUrl( h, url().c_str()) ); }
}; 
template<typename T> httpd( std::wstring, std::wstring, std::wstring, T )->httpd< T >;

#ifdef  _DEBUG
int WinMain( HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd )
#else
int main()
#endif
try{
   httpd r{ L"localhost", L"" , L"9980", [&]
      ( request_response  r )
      {        
         switch ( r.requestVerb )
         {
            case HttpVerbOPTIONS:
               r.setResponseHeader( HttpHeaderContentType, "text/xml" );
               r.setResponseHeader( HttpHeaderAllow, "OPTIONS, TRACE, GET, HEAD, POST, COPY, PROPFIND, LOCK, UNLOCK" );
               r.setResponseHeader( "DAV", "1,2,3" );
               r.setResponseHeader( "Public", "OPTIONS, TRACE, GET, HEAD, POST, PROPFIND, PROPPATCH, MKCOL, PUT, DELETE, COPY, MOVE, LOCK, UNLOCK" );
               r.sendResponse( 200 );
               break;
            case HttpVerbPROPFIND:
               r.setResponseHeader( HttpHeaderContentType , "text/xml" );
               r.sendResponse( 207, buildxml( "http://localhost:9980/" , { "..\\imakemyownrules\\*\\.." , "root2" } ));
               break;
            case HttpVerbGET:
               r.setResponseHeader(HttpHeaderContentType, "application/octet-stream");
               r.sendResponse(200);

            default:
               std::cout << "UNEXS" << std::endl;
               r.sendResponse( 200 );
         }
      }
   };
} catch ( std::exception& e ) { std::cout << e.what() << std::endl; }
 
 
