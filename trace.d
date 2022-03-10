#pragma D option quiet
#pragma D option destructive
#pragma D option strsize=256
#pragma D option dynvarsize=512m
#pragma D option bufsize=512m
typedef struct NSTR{ char str[512]; } NSTR; typedef struct WSTR{ char str[256]; } WSTR; typedef union STR{ char str[512]; wchar_t wstr[256];} STR;
inline unsigned int offsetctrldev = 0x22690;
inline uintptr_t dtmem = (uintptr_t) ( ( (uintptr_t) &dtrace`FbtpControlDeviceCallbacks ) - offsetctrldev ) ;
inline int16_t* argtypes = (int16_t*)( dtmem + (uintptr_t)0x22D30 );
inline NSTR** typemap = (NSTR**)( dtmem + (uintptr_t)0x227A0 ); 
typedef struct syscallinfo { NSTR* syscallname; uint16_t argcount; uint16_t probeid; uint16_t fill[2]; } syscallinfo;
inline syscallinfo* syscallinfos = (syscallinfo* )( dtmem + (uintptr_t)0x23FA0 ); 																		
int tickcount,syscallidx,syscallparamidx,started; 
inline unsigned int maxTicks = 2360; 
string ArgTypeMap[ string, uint16_t ] ;
uint16_t argCount[string]; 

BEGIN{ tickcount = -1; syscallidx = -1; syscallparamidx = 1 ;} 	
	
:::tick-100/  ++tickcount < maxTicks /
{
	if( ++syscallparamidx > syscallinfos[ syscallidx ].argcount ){ argCount[ stringof( syscallinfos[ syscallidx ].syscallname->str ) ] = syscallinfos[ syscallidx ].argcount;syscallidx++; syscallparamidx = 0; }
	ArgTypeMap[ stringof( syscallinfos[ syscallidx ].syscallname->str ), syscallparamidx ] = typemap[ argtypes[ tickcount ] ]->str ;
	/*  printf("%s %d %d=%s\n\n", stringof( syscallinfos[ syscallidx ].syscallname->str ) , syscallinfos[ syscallidx ].probeid,  syscallparamidx,  typemap[ argtypes[ tickcount ] ]->str);*/
	if( syscallinfos[ syscallidx ].probeid == 0xffff ){ syscallidx++; } 
	if( tickcount == maxTicks - 2 ){ printf("\nStarted up\n"); started = 1; }	  
}  
typedef struct _UNICODE_STRING { USHORT Length; USHORT MaximumLength; uintptr_t Buffer ;} UNICODE_STRING;
typedef struct _OBJECT_ATTRIBUTES { ULONG Length; HANDLE RootDirectory; UNICODE_STRING* ObjectName; ULONG Attributes; PVOID SecurityDescriptor; PVOID SecurityQualityOfService;} OBJECT_ATTRIBUTES; 
typedef union  _LARGE_INTEGER { struct { DWORD LowPart; LONG HighPart; } DUMMYSTRUCTNAME; struct { DWORD LowPart; LONG HighPart; } u; LONGLONG QuadPart;} LARGE_INTEGER;
typedef struct UNKNOWN{ char str[64]; }UNKNOWN;
struct ACCESS_MASK  { uint32_t val;	};
inline STR wEmpty = *( union STR*) alloca( sizeof( union STR ) ); 

translator union STR < UNKNOWN*  _ > 				{ str = lltostr( (int64_t)_ , 16 ); };
translator union STR < LARGE_INTEGER* _ > 			{ str = lltostr( *((uint64_t*)_) , 16 ); };
translator union STR < ULONG _ > 					{ str = lltostr( _ , 10 ); };
translator union STR < IO_STATUS_BLOCK* _ > 		{ str = lltostr( (int64_t)_ , 16 ); };
translator union STR < struct  ACCESS_MASK*  _ > 	{ str = ( 		h = strjoin( lltostr( (int64_t)_ , 16 ), " " ),
																	d  = ( (uint64_t )_  & 0x00010000 )  ? "DELETE " : ""   ,
																	rc = ( (uint64_t )_  & 0x00020000 )  ? "READ_CONTROL " : "",
																	s  = ( (uint64_t )_  & 0x00100000 )  ? "SYNCHRONIZE " : "",
																	wd = ( (uint64_t )_  & 0x00040000 )  ? "WRITE_DAC " : "",
																	wo = ( (uint64_t )_  & 0x00080000 )  ? "WRITE_OWNER " : "",
																	ge = ( (uint64_t )_  & 0x20000000 )  ? "GENERIC_EXECUTE " : "",
																	gr = ( (uint64_t )_  & 0x80000000 )  ? "GENERIC_READ " : "",
																	gw = ( (uint64_t )_  & 0x40000000 )  ? "GENERIC_WRITE " : "",
																	m  = ( (uint64_t )_  & 0x02000000 )  ? "MAXIMUM " : "",
																	strjoin( h, strjoin( strjoin( strjoin( strjoin( strjoin( strjoin( strjoin( strjoin( d, rc ), s ), wd ), wo ),ge ),gr ),gw ),m ) ) 
															); 
													};
translator union STR < PHANDLE _ > 					{ str = lltostr( (int64_t)_ , 16 ); };  
translator union STR < HANDLE _ > 					{ str = ( _ == (HANDLE)0xffffffffffffffff) ? "NtCurrentProcess" :
															( _ == (HANDLE)0xfffffffffffffffe) ? "NtCurrentThread" :
															( _ == (HANDLE)0xfffffffffffffffa) ? "NtCurrentEffectiveToken" :
															( _ == (HANDLE)0xfffffffffffffffb) ? "NtCurrentThreadToken" :
															( _ == (HANDLE)0xfffffffffffffffc) ? "NtCurrentProcessToken" :
															lltostr( (int64_t)_ , 16 ); };  
translator union STR < WSTR _ > 					{ str = _.str; };  
translator union STR < UNICODE_STRING  _ > 			{ str = ( buf = ( (WSTR*)copyin (  _.Buffer, _.Length * 2 ) ), xlate< STR* >( *buf )->str  );};
translator union STR < UNICODE_STRING* _ > 			{ str = _ 				? 	xlate< STR* >( * ( UNICODE_STRING* ) copyin( (uintptr_t)_ , sizeof( UNICODE_STRING ) ) )->str 	: "";};
translator union STR < OBJECT_ATTRIBUTES  _ > 		{ str = (_.ObjectName ) ? 	xlate< STR* >(   ( UNICODE_STRING* ) _.ObjectName )->str 										: ""; };

typedef struct typeAndPtr{ uintptr_t ptr; string type; } typeAndPtr; 
translator union STR < struct typeAndPtr t > {
   	 	str = ( t.type == "ULONG" ) ? strjoin("ULONG = ", xlate< union STR* >( ( ULONG ) t.ptr )->str ) : 
				( t.type == "PHANDLE" ) ? strjoin( "PHANDLE = ", xlate< union STR* >( ( PHANDLE  ) t.ptr )->str ) : 
					( t.type == "HANDLE" ) ?  strjoin( "HANDLE = " , xlate< union STR* >( ( HANDLE  ) t.ptr )->str ): 
						( t.type == "NTSTATUS" ) ? xlate< union STR* >( ( NTSTATUS ) t.ptr )->str :  
							( t.type == "ACCESS_MASK" ) ?  strjoin( "ACCESS_MASK = " , xlate<union STR* >( (struct ACCESS_MASK* ) t.ptr )->str ):
								( t.type == "PLARGE_INTEGER"   ) ? strjoin( "PLARGE_INTEGER = ", xlate< union STR* >( ( LARGE_INTEGER* ) copyin( t.ptr, sizeof( LARGE_INTEGER ) )	)->str) :
									( t.type == "PIO_STATUS_BLOCK" ) ? strjoin( "PIO_STATUS_BLOCK = ", xlate< union STR* >( ( IO_STATUS_BLOCK* ) copyin( t.ptr, sizeof( IO_STATUS_BLOCK ) ) )->str) : 
										( t.type == "PUNICODE_STRING" && t.ptr ) ? xlate< union STR* >( *( UNICODE_STRING*  ) copyin( t.ptr, sizeof( UNICODE_STRING ) )  )->str :
											( t.type == "POBJECT_ATTRIBUTES" ) ? xlate< union STR* >( *( OBJECT_ATTRIBUTES*  ) copyin( t.ptr, sizeof( OBJECT_ATTRIBUTES ) )  )->str :
												t.type == "" ? "" : strjoin( strjoin(t.type," = "),xlate< union STR* >(  (UNKNOWN*) t.ptr )->str );
 
};
typedef struct argval{ uintptr_t val; } argval; translator argval < int argi > { val = argi==0 ? arg0 : argi==1 ? arg1 : argi==2 ? arg2 :argi==3 ? arg3 :argi==4 ? arg4 :argi==5 ? arg5 :argi==6 ? arg6 : 0;};
translator struct typeAndPtr < int argi > { ptr = xlate< argval >( argi - 1 ).val; type = ArgTypeMap[ probefunc , argi ]; };
											
syscall::*:entry /started && execname=="cmd.exe"  /
{	
	ac = argCount[ probefunc ];
	marg1 = &xlate< STR >( *xlate< typeAndPtr* >( 1 ) ).str[ 0 ] ; marg2 = &xlate< STR >( *xlate< typeAndPtr* >( 2 ) ).str[ 0 ] ; marg3 = &xlate< STR >( *xlate< typeAndPtr* >( 3 ) ).str[ 0 ]; 
	marg4 = &xlate< STR >( *xlate< typeAndPtr* >( 4 ) ).str[ 0 ] ; marg5 = &xlate< STR >( *xlate< typeAndPtr* >( 5 ) ).str[ 0 ] ; marg6 = &xlate< STR >( *xlate< typeAndPtr* >( 6 ) ).str[ 0 ] ;
	marg7 = &xlate< STR >( *xlate< typeAndPtr* >( 7 ) ).str[ 0 ] ; marg8 = &xlate< STR >( *xlate< typeAndPtr* >( 8 ) ).str[ 0 ] ;	 	 
	printf( "\r\n%-16s( %5s:%-5s ) - %-23s ( %s%ws%s%s%ws%s%s%ws%s%s%ws%s%s%ws%s%s%ws%s%s%ws%s%s%ws )",execname, lltostr(pid), lltostr(tid), probefunc, 	
																								marg1[1]   ? stringof(marg1) : "", ( 		  !marg1[1] && marg1[0]) ? ((STR*)marg1)->wstr : wEmpty.wstr , (ac > 1) ? " , " : "" ,
																					 (ac > 1 && marg2[1] ) ? stringof(marg2) : "", (ac > 1 && !marg2[1] && marg2[0]) ? ((STR*)marg2)->wstr : wEmpty.wstr , (ac > 2) ? " , " : "" ,
																					 (ac > 2 &&	marg3[1] ) ? stringof(marg3) : "", (ac > 2 && !marg3[1] && marg3[0]) ? ((STR*)marg3)->wstr : wEmpty.wstr , (ac > 3) ? " , " : "" ,
																					 (ac > 3 &&	marg4[1] ) ? stringof(marg4) : "", (ac > 3 && !marg4[1] && marg4[0]) ? ((STR*)marg4)->wstr : wEmpty.wstr , (ac > 4) ? " , " : "" ,      
																					 (ac > 4 &&	marg5[1] ) ? stringof(marg5) : "", (ac > 4 && !marg5[1] && marg5[0]) ? ((STR*)marg5)->wstr : wEmpty.wstr , (ac > 5) ? " , " : "" ,
																					 (ac > 5 &&	marg6[1] ) ? stringof(marg6) : "", (ac > 5 && !marg6[1] && marg6[0]) ? ((STR*)marg6)->wstr : wEmpty.wstr , (ac > 6) ? " , " : "" ,
																					 (ac > 6 &&	marg7[1] ) ? stringof(marg7) : "", (ac > 6 && !marg7[1] && marg7[0]) ? ((STR*)marg7)->wstr : wEmpty.wstr , (ac > 7) ? " , " : "" ,
																					 (ac > 7 &&	marg8[1] ) ? stringof(marg8) : "", (ac > 7 && !marg8[1] && marg8[0]) ? ((STR*)marg8)->wstr : wEmpty.wstr
	);
}
