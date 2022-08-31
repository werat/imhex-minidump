// Lots of things are taken from
// https://github.com/rust-minidump/rust-minidump/blob/main/minidump-common/src/format.rs

#include <std/io.pat>
#include <std/time.pat>

fn timestamp(u128 ts) {
	std::time::Time time = std::time::to_utc(ts);
	return std::time::format(time);
};

struct MINIDUMP_HEADER {
	char signature[4];  // Must be MDMP
	u16 magic;  // Implementation specific magic, typically [0x93, 0xa7]
	u16 version;
	u32 stream_count;
	u32 stream_directory_rva;
	u32 checksum;
	// Disable the formatter, it crashes ImHex 1.21.2
	u32 time_date_stamp; // [[format("timestamp")]];
	u64 flags;
};

enum MINIDUMP_STREAM_TYPE : u32 {
	UnusedStream = 0,
	ReservedStream0 = 1,
	ReservedStream1 = 2,
	ThreadListStream = 3,
	ModuleListStream = 4,
	MemoryListStream = 5,
	ExceptionStream = 6,
	SystemInfoStream = 7,
	ThreadExListStream = 8,
	Memory64ListStream = 9,
	CommentStreamA = 10,
	CommentStreamW = 11,
	HandleDataStream = 12,
	FunctionTable = 13,
	UnloadedModuleListStream = 14,
	MiscInfoStream = 15,
	MemoryInfoListStream = 16,
	ThreadInfoListStream = 17,
	HandleOperationListStream = 18,
	TokenStream = 19,
	JavaScriptDataStream = 20,
	SystemMemoryInfoStream = 21,
	ProcessVmCountersStream = 22,
	IptTraceStream = 23,
	ThreadNamesStream = 24,
	ceStreamNull = 0x00008000,
	ceStreamSystemInfo = 0x00008001,
	ceStreamException = 0x00008002,
	ceStreamModuleList = 0x00008003,
	ceStreamProcessList = 0x00008004,
	ceStreamThreadList = 0x00008005,
	ceStreamThreadContextList = 0x00008006,
	ceStreamThreadCallStackList = 0x00008007,
	ceStreamMemoryVirtualList = 0x00008008,
	ceStreamMemoryPhysicalList = 0x00008009,
	ceStreamBucketParameters = 0x0000800a,
	ceStreamProcessModuleMap = 0x0000800b,
	ceStreamDiagnosisList = 0x0000800c,
	LastReservedStream = 0x0000ffff,
	BreakpadInfoStream = 0x47670001,
	AssertionInfoStream = 0x47670002,
	LinuxCpuInfo = 0x47670003,
	LinuxProcStatus = 0x47670004,
	LinuxLsbRelease = 0x47670005,
	LinuxCmdLine = 0x47670006,
	LinuxEnviron = 0x47670007,
	LinuxAuxv = 0x47670008,
	LinuxMaps = 0x47670009,
	LinuxDsoDebug = 0x4767000A,
	CrashpadInfoStream = 0x43500001,
	MozMacosCrashInfoStream = 0x4d7a0001,
};

enum ProcessorArchitecture : u16 {
	INTEL = 0,
	MIPS = 1,
	ALPHA = 2,
	PPC = 3,
	SHX = 4,
	ARM = 5,
	IA64 = 6,
	ALPHA64 = 7,
	MSIL = 8,
	AMD64 = 9,
	IA32_ON_WIN64 = 10,
	ARM64 = 12,
	SPARC = 0x8001,
	PPC64 = 0x8002,
	ARM64_OLD = 0x8003,
	MIPS64 = 0x8004,
	UNKNOWN = 0xffff,
};

enum PlatformId : u32 {
	VER_PLATFORM_WIN32s = 1,
	VER_PLATFORM_WIN32_WINDOWS = 2,
	VER_PLATFORM_WIN32_NT = 3,
	VER_PLATFORM_WIN32_CE = 4,
	Unix = 0x8000,
	MacOs = 0x8101,
	Ios = 0x8102,
	Linux = 0x8201,
	Solaris = 0x8202,
	Android = 0x8203,
	Ps3 = 0x8204,
	NaCl = 0x8205,
};

using RVA = u32;

struct MINIDUMP_LOCATION_DESCRIPTOR {
	u32 data_size;
	RVA rva;
};

struct MINIDUMP_MEMORY_DESCRIPTOR {
	u64 start_of_memory_range;
	MINIDUMP_LOCATION_DESCRIPTOR memory;

	u8 memory_bytes[memory.data_size] @ memory.rva;
};

struct MINIDUMP_STRING {
	u32 len_str [[name("Length")]];
	char16 buffer[len_str / 2] [[name("Buffer")]];  // UTF-16 string.
};

struct CPU_INFORMATION {
	u8 data[24];
};

struct MINIDUMP_SYSTEM_INFO {
	ProcessorArchitecture processor_architecture;
	u16 processor_level;
	u16 processor_revision;
	u8 number_of_processors;
	u8 product_type;
	u32 major_version;
	u32 minor_version;
	u32 build_number;
	PlatformId platform_id;
	RVA csd_version_rva;
	u16 suite_mask;
	u16 reserved2;
	CPU_INFORMATION cpu;

	MINIDUMP_STRING service_pack @ csd_version_rva;
};

struct VS_FIXEDFILEINFO {
	u32 signature;
	u32 struct_version;
	u32 file_version_hi;
	u32 file_version_lo;
	u32 product_version_hi;
	u32 product_version_lo;
	u32 file_flags_mask;
	u32 file_flags;
	u32 file_os;
	u32 file_type;
	u32 file_subtype;
	u32 file_date_hi;
	u32 file_date_lo;
};

enum CvSignature : u32 {
	Pdb20 = 0x3031424e,
	Pdb70 = 0x53445352,
	Elf = 0x4270454c,
	Cv41 = 0x3930424e,
	Cv50 = 0x3131424e,
};

// CV_INFO_PDB70
struct CodeView {
	CvSignature signature;
	// TODO: switch based on the signature.
	u128 pdb_guid;
	u32 age;
	char pdb_path[];
};

struct MINIDUMP_MODULE {
	u64 base_of_image;
	u32 size_of_image;
	u32 checksum;
	u32 time_date_stamp;
	RVA module_name_rva;
	VS_FIXEDFILEINFO version_info;
	MINIDUMP_LOCATION_DESCRIPTOR cv_record;
	MINIDUMP_LOCATION_DESCRIPTOR misc_record;
	u64 reserved0;
	u64 reserved1;

	MINIDUMP_STRING module_name @ module_name_rva;

	if (cv_record.data_size > 0) {
		CodeView code_view @ cv_record.rva;
	}
};

struct MINIDUMP_MODULE_LIST {
	u32 num_modules;
	MINIDUMP_MODULE modules[num_modules];
};

struct CONTEXT_AMD64 {
	u64 p1_home;
	u64 p2_home;
	u64 p3_home;
	u64 p4_home;
	u64 p5_home;
	u64 p6_home;
	u32 context_flags;
	u32 mx_csr;
	u16 cs;
	u16 ds;
	u16 es;
	u16 fs;
	u16 gs;
	u16 ss;
	u32 eflags;
	u64 dr0;
	u64 dr1;
	u64 dr2;
	u64 dr3;
	u64 dr6;
	u64 dr7;
	u64 rax;
	u64 rcx;
	u64 rdx;
	u64 rbx;
	u64 rsp;
	u64 rbp;
	u64 rsi;
	u64 rdi;
	u64 r8;
	u64 r9;
	u64 r10;
	u64 r11;
	u64 r12;
	u64 r13;
	u64 r14;
	u64 r15;
	u64 rip;
	u8 float_save[512];
	u128 vector_register[26];
	u64 vector_control;
	u64 debug_control;
	u64 last_branch_to_rip;
	u64 last_branch_from_rip;
	u64 last_exception_to_rip;
	u64 last_exception_from_rip;
};

struct MINIDUMP_THREAD {
	u32 thread_id;
	u32 suspend_count;
	u32 priority_class;
	u32 priority;
	u64 teb;
	MINIDUMP_MEMORY_DESCRIPTOR stack;
	MINIDUMP_LOCATION_DESCRIPTOR thread_context;

	// Thread context data, architecture-specific.
	// TODO: find a better way to switch here.
	if (thread_context.data_size == 1232) {  // sizeof(CONTEXT_AMD64)
		CONTEXT_AMD64 context_amd64 @ thread_context.rva;
	}
};

struct MINIDUMP_THREAD_LIST {
	u32 num_threads;
	MINIDUMP_THREAD threads[num_threads];
};

struct MINIDUMP_MEMORY_LIST {
	u32 num_memory_ranges;
	MINIDUMP_MEMORY_DESCRIPTOR memory_ranges[num_memory_ranges];
};

struct MINIDUMP_DIRECTORY {
	MINIDUMP_STREAM_TYPE stream_type;
	u32 data_size;
	u32 rva;
};

MINIDUMP_HEADER minidump_header @ 0x00;
MINIDUMP_DIRECTORY minidump_directory[minidump_header.stream_count] @ minidump_header.stream_directory_rva;

// Index of the current stream in the stream list.
u16 streamIndex;

struct Stream {

	if (minidump_directory[streamIndex].stream_type == MINIDUMP_STREAM_TYPE::SystemInfoStream) {
		MINIDUMP_SYSTEM_INFO system_info;
	} else if (minidump_directory[streamIndex].stream_type == MINIDUMP_STREAM_TYPE::ModuleListStream) {
		MINIDUMP_MODULE_LIST module_list;
	} else if (minidump_directory[streamIndex].stream_type == MINIDUMP_STREAM_TYPE::ThreadListStream) {
		MINIDUMP_THREAD_LIST thread_list;
	} else if (minidump_directory[streamIndex].stream_type == MINIDUMP_STREAM_TYPE::MemoryListStream) {
		MINIDUMP_MEMORY_LIST memory_list;
	}

	// Move the current offset to the start of the next stream.
	if (streamIndex < minidump_header.stream_count-1) {
		streamIndex = streamIndex + 1;
		if (minidump_directory[streamIndex].data_size > 0) {
			$ = minidump_directory[streamIndex].rva;
		}
	}

} [[inline]];

Stream streams[minidump_header.stream_count] @ minidump_directory[0].rva;
