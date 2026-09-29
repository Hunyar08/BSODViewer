#include <windows.h>
#include <commctrl.h>
#include "resource.h"
#include <dbghelp.h>
#include <winevt.h>
#include <shlobj.h>
#include <shellapi.h>
#include <filesystem>
#include <string>
#include <vector>
#include <algorithm>
#include <cstdint>
#include <cwctype>
#include <cwchar>
#include <thread>
#include <cstddef>

namespace fs = std::filesystem;

namespace {

constexpr wchar_t kClassName[] = L"BSODViewerWindow";
constexpr int kTreeId = 100, kListId = 101, kDetailsId = 102, kFilterId = 103, kStatusId = 104;
constexpr int kRefreshId = 105, kFolderId = 106, kOpenId = 107;
constexpr int kMenuRefresh = 201, kMenuScanFolder = 202, kMenuExit = 203, kMenuAbout = 204;
constexpr UINT kScanDoneMessage = WM_APP + 1;

enum class ReportKind { Bugcheck, Dump };

struct Report {
    ReportKind kind = ReportKind::Dump;
    std::wstring time, code, subject, filePath, dumpPath, details, prevention, dumpInfo;
    std::uint64_t ticks = 0;
};

struct ScanResult {
    std::vector<Report> reports;
    std::wstring note;
    bool usedEverything = false;
};

#pragma pack(push, 1)
struct EverythingQueryW {
    DWORD replyWindow;
    DWORD replyMessage;
    DWORD searchFlags;
    DWORD offset;
    DWORD maxResults;
    wchar_t search[1];
};

struct EverythingItemW {
    DWORD flags;
    DWORD filenameOffset;
    DWORD pathOffset;
};

struct EverythingListW {
    DWORD totalFolders;
    DWORD totalFiles;
    DWORD totalItems;
    DWORD numFolders;
    DWORD numFiles;
    DWORD numItems;
    DWORD offset;
    EverythingItemW items[1];
};
#pragma pack(pop)

constexpr DWORD kEverythingQueryMessage = 2;
constexpr DWORD kEverythingReplyLimit = 5000;
constexpr ULONGLONG kEverythingWaitMs = 5000;

HWND g_window, g_tree, g_list, g_details, g_filter, g_status;
HFONT g_font;
HANDLE g_everythingReplyEvent = nullptr;
std::vector<Report> g_reports;
std::vector<size_t> g_visible;
std::vector<std::wstring> g_everythingPaths;
std::wstring g_scanFolder, g_selectedPath;
std::wstring g_scanSource;
HTREEITEM g_treeItems[4]{};
bool g_scanInProgress = false;
DWORD g_everythingReplyCode = 0x42530000;

std::wstring Lower(std::wstring value) {
    std::transform(value.begin(), value.end(), value.begin(), [](wchar_t ch) { return static_cast<wchar_t>(towlower(ch)); });
    return value;
}

std::wstring BaseName(const std::wstring& path) {
    const size_t slash = path.find_last_of(L"\\/");
    return slash == std::wstring::npos ? path : path.substr(slash + 1);
}

std::wstring FormatTime(const FILETIME& utc) {
    FILETIME local{};
    SYSTEMTIME st{};
    if (!FileTimeToLocalFileTime(&utc, &local) || !FileTimeToSystemTime(&local, &st)) return L"Unknown time";
    wchar_t buffer[64]{};
    swprintf_s(buffer, L"%04u-%02u-%02u  %02u:%02u:%02u", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return buffer;
}

std::uint64_t FileTicks(const FILETIME& time) {
    ULARGE_INTEGER value{};
    value.LowPart = time.dwLowDateTime;
    value.HighPart = time.dwHighDateTime;
    return value.QuadPart;
}

std::wstring HexCode(unsigned long code) {
    wchar_t buffer[24]{};
    swprintf_s(buffer, L"0x%08lX", code);
    return buffer;
}

struct Advice { const wchar_t* title; const wchar_t* details; const wchar_t* prevention; };

Advice ExplainBugcheck(unsigned long code) {
    switch (code) {
    case 0xA: return { L"IRQL_NOT_LESS_OR_EQUAL", L"Kernel-mode code accessed invalid or pageable memory at an interrupt level where it could not be accessed. A driver is common, but the code alone does not identify one.", L"Install Windows and device-driver updates. If this began after a driver or device change, roll it back or disconnect it. Check memory stability if it persists." };
    case 0x1A: return { L"MEMORY_MANAGEMENT", L"Windows found a serious memory-management inconsistency. RAM, unstable memory settings, storage corruption, or a driver may contribute.", L"Return memory settings to defaults, run Windows Memory Diagnostic, check the system drive, and review recent driver changes." };
    case 0x3B: return { L"SYSTEM_SERVICE_EXCEPTION", L"An exception occurred during a Windows system-service routine. The exception details or a named dump module may narrow it down.", L"Update Windows and graphics/device drivers. Undo recent driver, security-software, or hardware changes; check system files if it continues." };
    case 0x50: return { L"PAGE_FAULT_IN_NONPAGED_AREA", L"Kernel code referenced invalid memory. Drivers and failing memory are frequent possibilities, not certainties.", L"Review recent drivers and hardware, run a memory test, and check system-drive health. Keep Windows and firmware current." };
    case 0x7E: return { L"SYSTEM_THREAD_EXCEPTION_NOT_HANDLED", L"A system thread raised an unhandled exception. The exception code and faulting module, when available, are useful clues.", L"Update or roll back the driver named in the report, apply Windows updates, and review recently added low-level utilities." };
    case 0x9F: return { L"DRIVER_POWER_STATE_FAILURE", L"A driver did not complete a power transition in time, often around sleep, resume, or shutdown.", L"Update chipset, storage, network, and graphics drivers. Check connected devices and firmware; isolate sleep/resume issues one device at a time." };
    case 0xD1: return { L"DRIVER_IRQL_NOT_LESS_OR_EQUAL", L"A kernel driver accessed invalid or pageable memory at an elevated interrupt level. A driver is a frequent suspect, not a certainty.", L"Update or roll back recently changed drivers. Disconnect new devices and avoid third-party driver-updater utilities." };
    case 0x124: return { L"WHEA_UNCORRECTABLE_ERROR", L"Windows Hardware Error Architecture reported an uncorrectable hardware error. The WHEA record is needed to distinguish CPU, memory, bus, or device faults.", L"Return overclock/undervolt settings to defaults, check cooling and power, update firmware, and use vendor diagnostics before replacing hardware." };
    case 0x139: return { L"KERNEL_SECURITY_CHECK_FAILURE", L"The kernel detected corruption of a critical data structure. A driver, memory instability, or damaged system files may be involved.", L"Undo recent driver or hardware changes, test memory stability, and check system files. Identify a module from the dump before changing drivers." };
    case 0x133: return { L"DPC_WATCHDOG_VIOLATION", L"A deferred procedure call or interrupt ran too long. Storage and device drivers are common areas to investigate.", L"Update storage-controller and device drivers, check drive health, and disconnect recently added devices to isolate the source." };
    default: return { L"Windows stop error", L"Windows recorded this bugcheck code. It describes a class of failure, but does not by itself prove which component caused it.", L"Use the dump and matching Event Viewer record to identify a driver or hardware error. Apply manufacturer updates, then undo recent changes one at a time." };
    }
}

std::wstring XmlDecode(std::wstring value) {
    const std::pair<const wchar_t*, const wchar_t*> entities[] = {
        { L"&lt;", L"<" }, { L"&gt;", L">" }, { L"&quot;", L"\"" }, { L"&apos;", L"'" }, { L"&amp;", L"&" }
    };
    for (const auto& [entity, replacement] : entities) {
        size_t pos = 0;
        while ((pos = value.find(entity, pos)) != std::wstring::npos) {
            value.replace(pos, wcslen(entity), replacement);
            pos += wcslen(replacement);
        }
    }
    return value;
}

std::wstring Attribute(const std::wstring& tag, const wchar_t* name) {
    std::wstring key = name;
    key += L"=\"";
    const size_t start = tag.find(key);
    if (start == std::wstring::npos) return {};
    const size_t valueStart = start + key.size(), end = tag.find(L'"', valueStart);
    return end == std::wstring::npos ? std::wstring{} : tag.substr(valueStart, end - valueStart);
}

std::vector<std::pair<std::wstring, std::wstring>> EventData(const std::wstring& xml) {
    std::vector<std::pair<std::wstring, std::wstring>> values;
    size_t pos = 0;
    while ((pos = xml.find(L"<Data", pos)) != std::wstring::npos) {
        const size_t tagEnd = xml.find(L'>', pos);
        const size_t valueEnd = tagEnd == std::wstring::npos ? tagEnd : xml.find(L"</Data>", tagEnd);
        if (tagEnd == std::wstring::npos || valueEnd == std::wstring::npos) break;
        const std::wstring tag = xml.substr(pos, tagEnd - pos + 1);
        values.emplace_back(Attribute(tag, L"Name"), XmlDecode(xml.substr(tagEnd + 1, valueEnd - tagEnd - 1)));
        pos = valueEnd + 7;
    }
    return values;
}

bool ParseHexAfter(const std::wstring& text, size_t start, unsigned long& value) {
    const size_t found = text.find(L"0x", start);
    if (found == std::wstring::npos) return false;
    size_t end = found + 2;
    while (end < text.size() && iswxdigit(text[end])) ++end;
    if (end == found + 2) return false;
    try { value = std::stoul(text.substr(found + 2, end - found - 2), nullptr, 16); return true; }
    catch (...) { return false; }
}

std::vector<Report> ScanBugchecks(std::wstring& note) {
    std::vector<Report> reports;
    const wchar_t* xpath = L"*[System[Provider[@Name='Microsoft-Windows-WER-SystemErrorReporting'] and EventID=1001]]";
    EVT_HANDLE query = EvtQuery(nullptr, L"System", xpath, EvtQueryChannelPath | EvtQueryReverseDirection);
    if (!query) {
        note = L"Could not read the System event log; some records may require elevated access.";
        return reports;
    }
    EVT_HANDLE events[64]{};
    DWORD count = 0;
    while (reports.size() < 200 && EvtNext(query, 64, events, 0, 0, &count)) {
        for (DWORD i = 0; i < count && reports.size() < 200; ++i) {
            DWORD needed = 0;
            EvtRender(nullptr, events[i], EvtRenderEventXml, 0, nullptr, &needed, nullptr);
            if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || needed < sizeof(wchar_t)) { EvtClose(events[i]); continue; }
            std::vector<wchar_t> buffer(needed / sizeof(wchar_t) + 1, L'\0');
            if (EvtRender(nullptr, events[i], EvtRenderEventXml, needed, buffer.data(), &needed, nullptr)) {
                const std::wstring xml(buffer.data());
                const auto fields = EventData(xml);
                std::wstring message;
                for (const auto& field : fields) { message += field.second; message += L" "; }
                unsigned long code = 0;
                if (ParseHexAfter(message, 0, code)) {
                    const Advice advice = ExplainBugcheck(code);
                    Report report;
                    report.kind = ReportKind::Bugcheck;
                    report.code = HexCode(code);
                    report.subject = advice.title;
                    report.details = advice.details;
                    report.prevention = advice.prevention;

                    const size_t timeAt = xml.find(L"<TimeCreated");
                    if (timeAt != std::wstring::npos) {
                        const size_t tagEnd = xml.find(L'>', timeAt);
                        const std::wstring timeText = tagEnd == std::wstring::npos ? L"" : Attribute(xml.substr(timeAt, tagEnd - timeAt + 1), L"SystemTime");
                        SYSTEMTIME st{};
                        if (swscanf_s(timeText.c_str(), L"%hu-%hu-%huT%hu:%hu:%hu", &st.wYear, &st.wMonth, &st.wDay, &st.wHour, &st.wMinute, &st.wSecond) == 6) {
                            FILETIME ft{};
                            if (SystemTimeToFileTime(&st, &ft)) { report.ticks = FileTicks(ft); report.time = FormatTime(ft); }
                        }
                    }
                    if (report.time.empty()) report.time = L"Unknown time";
                    for (const auto& field : fields) {
                        if (Lower(field.first).find(L"dump") != std::wstring::npos && Lower(field.second).find(L".dmp") != std::wstring::npos) {
                            report.dumpPath = field.second;
                            break;
                        }
                    }
                    reports.push_back(std::move(report));
                }
            }
            EvtClose(events[i]);
        }
    }
    EvtClose(query);
    return reports;
}

std::wstring FaultingModule(const MINIDUMP_MODULE_LIST* modules, ULONG streamSize, ULONGLONG fileSize, ULONG64 address) {
    if (!modules || streamSize < sizeof(ULONG)) return {};
    const size_t maxCount = (streamSize - sizeof(ULONG)) / sizeof(MINIDUMP_MODULE);
    const ULONG count = static_cast<ULONG>(std::min<size_t>(modules->NumberOfModules, maxCount));
    for (ULONG i = 0; i < count; ++i) {
        const auto& module = modules->Modules[i];
        if (address < module.BaseOfImage || address - module.BaseOfImage >= module.SizeOfImage) continue;
        const ULONGLONG nameOffset = module.ModuleNameRva;
        if (nameOffset > fileSize || fileSize - nameOffset < sizeof(ULONG)) continue;
        const auto* name = reinterpret_cast<const MINIDUMP_STRING*>(reinterpret_cast<const BYTE*>(modules) + module.ModuleNameRva);
        if (name->Length < 32768 && name->Length % sizeof(wchar_t) == 0 && name->Length <= fileSize - nameOffset - sizeof(ULONG))
            return BaseName(std::wstring(name->Buffer, name->Length / sizeof(wchar_t)));
    }
    return {};
}

Report InspectDump(const fs::path& path) {
    Report report;
    report.kind = ReportKind::Dump;
    report.filePath = path.wstring();
    report.subject = L"Crash dump file";
    report.details = L"Windows crash dump found. Its contents and size depend on the system's crash-dump settings.";
    report.prevention = L"Select a matching bugcheck event for stop-code guidance. A dump file alone does not prove the cause.";
    WIN32_FILE_ATTRIBUTE_DATA attributes{};
    if (GetFileAttributesExW(report.filePath.c_str(), GetFileExInfoStandard, &attributes)) {
        report.time = FormatTime(attributes.ftLastWriteTime);
        report.ticks = FileTicks(attributes.ftLastWriteTime);
    } else report.time = L"Unknown time";

    HANDLE file = CreateFileW(report.filePath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) { report.dumpInfo = L"Dump contents could not be opened; access may be restricted."; return report; }
    LARGE_INTEGER fileLength{};
    GetFileSizeEx(file, &fileLength);
    const ULONGLONG fileSize = fileLength.QuadPart > 0 ? static_cast<ULONGLONG>(fileLength.QuadPart) : 0;
    HANDLE mapping = CreateFileMappingW(file, nullptr, PAGE_READONLY, 0, 0, nullptr);
    const void* view = mapping ? MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0) : nullptr;
    if (!view) report.dumpInfo = L"Could not map this file. It may be a full memory dump rather than a minidump.";
    else {
        PMINIDUMP_DIRECTORY directory = nullptr;
        void* stream = nullptr;
        ULONG streamSize = 0;
        if (MiniDumpReadDumpStream(const_cast<void*>(view), SystemInfoStream, &directory, &stream, &streamSize) && streamSize >= sizeof(MINIDUMP_SYSTEM_INFO)) {
            const auto* info = static_cast<const MINIDUMP_SYSTEM_INFO*>(stream);
            const wchar_t* arch = info->ProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ? L"x64" :
                info->ProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL ? L"x86" : L"unknown architecture";
            report.dumpInfo = std::wstring(L"Minidump detected (Windows ") + std::to_wstring(info->MajorVersion) + L"." + std::to_wstring(info->MinorVersion) + L", " + arch + L").";
        } else report.dumpInfo = L"File found, but DbgHelp could not read it as a minidump. Full kernel dumps need specialized analysis.";

        if (MiniDumpReadDumpStream(const_cast<void*>(view), ExceptionStream, &directory, &stream, &streamSize) && streamSize >= sizeof(MINIDUMP_EXCEPTION_STREAM)) {
            const auto* exception = static_cast<const MINIDUMP_EXCEPTION_STREAM*>(stream);
            report.code = HexCode(exception->ExceptionRecord.ExceptionCode);
            report.subject = L"Process exception";
            report.details = L"The dump contains exception code " + report.code + L". This is not a Windows bugcheck/stop code.";
            if (MiniDumpReadDumpStream(const_cast<void*>(view), ModuleListStream, &directory, &stream, &streamSize)) {
                const std::wstring module = FaultingModule(static_cast<const MINIDUMP_MODULE_LIST*>(stream), streamSize, fileSize, exception->ExceptionRecord.ExceptionAddress);
                if (!module.empty()) { report.subject = module; report.dumpInfo += L"\r\nException address is within module: " + module; }
            }
        }
        UnmapViewOfFile(view);
    }
    if (mapping) CloseHandle(mapping);
    CloseHandle(file);
    return report;
}

bool IsDumpFile(const fs::path& path) {
    const std::wstring extension = Lower(path.extension().wstring());
    return extension == L".dmp" || extension == L".mdmp" || extension == L".hdmp";
}

bool ReadIpcString(const BYTE* data, DWORD dataSize, DWORD offset, DWORD stringsOffset, std::wstring& value) {
    if (offset < stringsOffset || offset >= dataSize || offset % alignof(wchar_t) != 0) return false;
    const wchar_t* text = reinterpret_cast<const wchar_t*>(data + offset);
    const size_t capacity = (dataSize - offset) / sizeof(wchar_t);
    size_t length = 0;
    while (length < capacity && text[length] != L'\0') ++length;
    if (length == capacity) return false;
    value.assign(text, length);
    return true;
}

bool HandleEverythingResults(const COPYDATASTRUCT& copyData) {
    if (copyData.dwData != g_everythingReplyCode) return false;
    g_everythingPaths.clear();
    const auto* bytes = static_cast<const BYTE*>(copyData.lpData);
    const size_t headerSize = offsetof(EverythingListW, items);
    if (bytes && copyData.cbData >= headerSize) {
        const auto* list = reinterpret_cast<const EverythingListW*>(bytes);
        const size_t maxItems = (copyData.cbData - headerSize) / sizeof(EverythingItemW);
        if (list->numItems <= maxItems) {
            const DWORD stringsOffset = static_cast<DWORD>(headerSize + static_cast<size_t>(list->numItems) * sizeof(EverythingItemW));
            for (DWORD i = 0; i < list->numItems; ++i) {
                const EverythingItemW& item = list->items[i];
                if (item.flags & 0x1) continue;
                std::wstring filename, path;
                if (!ReadIpcString(bytes, copyData.cbData, item.filenameOffset, stringsOffset, filename) ||
                    !ReadIpcString(bytes, copyData.cbData, item.pathOffset, stringsOffset, path)) continue;
                const fs::path fullPath = path.empty() ? fs::path(filename) : fs::path(path) / filename;
                if (IsDumpFile(fullPath)) g_everythingPaths.push_back(fullPath.wstring());
            }
        }
    }
    if (g_everythingReplyEvent) SetEvent(g_everythingReplyEvent);
    return true;
}

bool QueryEverythingIndex(HWND replyWindow, DWORD replyCode) {
    if (!g_everythingReplyEvent) return false;
    const HWND everythingWindow = FindWindowW(L"EVERYTHING_TASKBAR_NOTIFICATION", nullptr);
    if (!everythingWindow) return false;

    const std::wstring search = L"ext:dmp;mdmp;hdmp";
    const size_t querySize = offsetof(EverythingQueryW, search) + (search.size() + 1) * sizeof(wchar_t);
    if (querySize > MAXDWORD) return false;
    std::vector<BYTE> payload(querySize);
    auto* query = reinterpret_cast<EverythingQueryW*>(payload.data());
    query->replyWindow = static_cast<DWORD>(reinterpret_cast<UINT_PTR>(replyWindow));
    query->replyMessage = replyCode;
    query->searchFlags = 0;
    query->offset = 0;
    query->maxResults = kEverythingReplyLimit;
    std::copy(search.begin(), search.end(), query->search);
    query->search[search.size()] = L'\0';

    ResetEvent(g_everythingReplyEvent);
    COPYDATASTRUCT copyData{};
    copyData.dwData = kEverythingQueryMessage;
    copyData.cbData = static_cast<DWORD>(querySize);
    copyData.lpData = payload.data();
    DWORD_PTR response = 0;
    if (!SendMessageTimeoutW(everythingWindow, WM_COPYDATA, reinterpret_cast<WPARAM>(replyWindow),
        reinterpret_cast<LPARAM>(&copyData), SMTO_ABORTIFHUNG, 2000, &response) || response != TRUE) return false;
    return WaitForSingleObject(g_everythingReplyEvent, static_cast<DWORD>(kEverythingWaitMs)) == WAIT_OBJECT_0;
}

void AddDumpReport(const fs::path& path, std::vector<Report>& reports) {
    if (!IsDumpFile(path) || reports.size() >= kEverythingReplyLimit ||
        GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES) return;
    const std::wstring normalized = Lower(path.lexically_normal().wstring());
    for (const auto& existing : reports) {
        if (existing.kind == ReportKind::Dump && Lower(fs::path(existing.filePath).lexically_normal().wstring()) == normalized) return;
    }
    reports.push_back(InspectDump(path));
}

void CollectDumpFiles(const fs::path& root, bool recursive, std::vector<Report>& reports) {
    std::error_code error;
    if (!fs::exists(root, error)) return;
    if (fs::is_regular_file(root, error)) { AddDumpReport(root, reports); return; }
    const auto options = fs::directory_options::skip_permission_denied;
    if (recursive) {
        for (fs::recursive_directory_iterator it(root, options, error), end; it != end; it.increment(error)) {
            if (error) { error.clear(); continue; }
            if (it->is_regular_file(error) && IsDumpFile(it->path())) AddDumpReport(it->path(), reports);
            if (reports.size() >= kEverythingReplyLimit) break;
        }
    } else {
        for (fs::directory_iterator it(root, options, error), end; it != end; it.increment(error)) {
            if (error) { error.clear(); continue; }
            if (it->is_regular_file(error) && IsDumpFile(it->path())) AddDumpReport(it->path(), reports);
        }
    }
}

std::wstring EnvironmentPath(const wchar_t* variable) {
    const DWORD length = GetEnvironmentVariableW(variable, nullptr, 0);
    if (!length) return {};
    std::wstring value(length, L'\0');
    const DWORD written = GetEnvironmentVariableW(variable, value.data(), length);
    if (!written || written >= length) return {};
    value.resize(written);
    return value;
}

ScanResult ScanSystem(const std::wstring& extraFolder, HWND replyWindow, DWORD replyCode) {
    ScanResult result;
    result.reports = ScanBugchecks(result.note);
    result.usedEverything = QueryEverythingIndex(replyWindow, replyCode);
    if (result.usedEverything) {
        for (const auto& path : g_everythingPaths) AddDumpReport(fs::path(path), result.reports);
    }
    const std::wstring windows = EnvironmentPath(L"WINDIR"), local = EnvironmentPath(L"LOCALAPPDATA");
    if (!windows.empty()) {
        CollectDumpFiles(fs::path(windows) / L"Minidump", false, result.reports);
        CollectDumpFiles(fs::path(windows) / L"MEMORY.DMP", false, result.reports);
        CollectDumpFiles(fs::path(windows) / L"LiveKernelReports", true, result.reports);
    }
    if (!local.empty()) CollectDumpFiles(fs::path(local) / L"CrashDumps", false, result.reports);
    if (!extraFolder.empty()) CollectDumpFiles(fs::path(extraFolder), true, result.reports);
    for (auto& event : result.reports) {
        if (event.kind != ReportKind::Bugcheck) continue;
        if (!event.dumpPath.empty() && GetFileAttributesW(event.dumpPath.c_str()) != INVALID_FILE_ATTRIBUTES) continue;
        std::uint64_t best = 10ULL * 60 * 10000000;
        for (const auto& dump : result.reports) {
            if (dump.kind != ReportKind::Dump || dump.ticks == 0 || event.ticks == 0) continue;
            const std::uint64_t distance = dump.ticks > event.ticks ? dump.ticks - event.ticks : event.ticks - dump.ticks;
            if (distance <= best) { best = distance; event.dumpPath = dump.filePath; }
        }
    }
    std::stable_sort(result.reports.begin(), result.reports.end(), [](const Report& a, const Report& b) { return a.ticks > b.ticks; });
    return result;
}

void SetStatus(const std::wstring& text) { SendMessageW(g_status, SB_SETTEXTW, 0, reinterpret_cast<LPARAM>(text.c_str())); }
void SetDetails(const std::wstring& text) { SetWindowTextW(g_details, text.c_str()); }

void AddColumn(const wchar_t* text, int width, int index) {
    LVCOLUMNW column{};
    column.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    column.pszText = const_cast<LPWSTR>(text);
    column.cx = width;
    column.iSubItem = index;
    ListView_InsertColumn(g_list, index, &column);
}

void ShowReports(int category) {
    ListView_DeleteAllItems(g_list);
    g_visible.clear();
    g_selectedPath.clear();
    wchar_t filterText[512]{};
    GetWindowTextW(g_filter, filterText, static_cast<int>(std::size(filterText)));
    const std::wstring filter = Lower(filterText);
    for (size_t index = 0; index < g_reports.size(); ++index) {
        const Report& report = g_reports[index];
        if (category == 2 && report.kind != ReportKind::Bugcheck) continue;
        if (category == 3 && report.kind != ReportKind::Dump) continue;
        const std::wstring dumpName = BaseName(report.dumpPath.empty() ? report.filePath : report.dumpPath);
        const std::wstring search = Lower(report.time + L" " + report.code + L" " + report.subject + L" " + report.filePath + L" " + report.dumpPath);
        if (!filter.empty() && search.find(filter) == std::wstring::npos) continue;
        const int row = ListView_GetItemCount(g_list);
        LVITEMW item{};
        item.mask = LVIF_TEXT;
        item.iItem = row;
        item.pszText = const_cast<LPWSTR>(report.time.c_str());
        ListView_InsertItem(g_list, &item);
        ListView_SetItemText(g_list, row, 1, const_cast<LPWSTR>(report.kind == ReportKind::Bugcheck ? L"Bugcheck event" : L"Dump file"));
        ListView_SetItemText(g_list, row, 2, const_cast<LPWSTR>(report.code.c_str()));
        ListView_SetItemText(g_list, row, 3, const_cast<LPWSTR>(report.subject.c_str()));
        ListView_SetItemText(g_list, row, 4, const_cast<LPWSTR>(dumpName.c_str()));
        g_visible.push_back(index);
    }
    SetStatus(std::to_wstring(g_visible.size()) + L" item(s)  |  " + std::to_wstring(g_reports.size()) + L" total discovered" +
        (g_scanSource.empty() ? L"" : L"  |  " + g_scanSource));
}

void SelectCategory(int category) {
    ShowReports(category);
    SetDetails(L"Select a crash report or dump file to see its analysis and suggested next steps.\r\n\r\nA stop code describes a failure class; it does not necessarily identify the root cause.");
}

void DisplaySelected(int row) {
    if (row < 0 || row >= static_cast<int>(g_visible.size())) return;
    const Report& report = g_reports[g_visible[static_cast<size_t>(row)]];
    g_selectedPath = report.dumpPath.empty() ? report.filePath : report.dumpPath;
    std::wstring text = report.subject + L"\r\n" + report.time;
    if (!report.code.empty()) text += L"\r\nStop / exception code: " + report.code;
    text += L"\r\n\r\nWhat it may mean\r\n" + report.details;
    if (!report.dumpInfo.empty()) text += L"\r\n\r\nDump inspection\r\n" + report.dumpInfo;
    text += L"\r\n\r\nWhat to try\r\n" + report.prevention;
    if (!report.dumpPath.empty()) text += L"\r\n\r\nRelated dump: " + report.dumpPath;
    else if (!report.filePath.empty()) text += L"\r\n\r\nFile: " + report.filePath;
    else text += L"\r\n\r\nNo matching dump file was found.";
    SetDetails(text);
}

void UpdateReports(ScanResult* result) {
    if (!result) return;
    g_reports = std::move(result->reports);
    const std::wstring note = result->note;
    g_scanSource = result->usedEverything ? L"Everything index" : L"Windows folder fallback";
    delete result;
    g_scanInProgress = false;
    HTREEITEM selected = TreeView_GetSelection(g_tree);
    int category = 1;
    for (int i = 0; i < 4; ++i) if (selected == g_treeItems[i]) category = i;
    ShowReports(category);
    if (!note.empty()) SetStatus(note + L"  |  " + std::to_wstring(g_visible.size()) + L" item(s)  |  " + g_scanSource);
    SetDetails(L"Scan complete. Choose a row to inspect its stop-code explanation, dump metadata, and suggested next steps.\r\n\r\nDump/event matches use a recorded file path or a close timestamp; ambiguous matches are not guessed.");
}

void StartScan() {
    if (g_scanInProgress) return;
    g_scanInProgress = true;
    SetStatus(L"Scanning Windows dump locations and recent bugcheck events...");
    EnableWindow(GetDlgItem(g_window, kRefreshId), FALSE);
    EnableWindow(GetDlgItem(g_window, kFolderId), FALSE);
    g_everythingPaths.clear();
    if (++g_everythingReplyCode == 0) ++g_everythingReplyCode;
    const DWORD replyCode = g_everythingReplyCode;
    const std::wstring folder = g_scanFolder;
    const HWND window = g_window;
    std::thread([folder, window, replyCode]() {
        auto* result = new ScanResult(ScanSystem(folder, window, replyCode));
        if (!PostMessageW(window, kScanDoneMessage, 0, reinterpret_cast<LPARAM>(result))) delete result;
    }).detach();
}

void ChooseFolder() {
    BROWSEINFOW browse{};
    browse.hwndOwner = g_window;
    browse.lpszTitle = L"Choose a folder to scan for .dmp and .mdmp files";
    browse.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
    PIDLIST_ABSOLUTE selected = SHBrowseForFolderW(&browse);
    if (!selected) return;
    wchar_t path[MAX_PATH]{};
    if (SHGetPathFromIDListW(selected, path)) { g_scanFolder = path; StartScan(); }
    CoTaskMemFree(selected);
}

std::wstring EnvironmentPath(const wchar_t* variable);

void OpenSelected() {
    if (!g_selectedPath.empty() && GetFileAttributesW(g_selectedPath.c_str()) != INVALID_FILE_ATTRIBUTES) {
        const std::wstring args = L"/select,\"" + g_selectedPath + L"\"";
        ShellExecuteW(g_window, L"open", L"explorer.exe", args.c_str(), nullptr, SW_SHOWNORMAL);
    } else {
        const std::wstring windows = EnvironmentPath(L"WINDIR");
        if (!windows.empty()) ShellExecuteW(g_window, L"open", (windows + L"\\Minidump").c_str(), nullptr, nullptr, SW_SHOWNORMAL);
    }
}

void AddTreeItem(int index, const wchar_t* label) {
    TVINSERTSTRUCTW insert{};
    insert.hParent = TVI_ROOT;
    insert.hInsertAfter = TVI_LAST;
    insert.item.mask = TVIF_TEXT;
    insert.item.pszText = const_cast<LPWSTR>(label);
    g_treeItems[index] = TreeView_InsertItem(g_tree, &insert);
}

void CreateControls(HWND window) {
    g_font = static_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT));
    CreateWindowW(L"STATIC", L"Blue Screen Dump Viewer", WS_CHILD | WS_VISIBLE, 12, 8, 420, 28, window, nullptr, nullptr, nullptr);
    CreateWindowW(L"STATIC", L"Crash reports, dump files, and practical troubleshooting", WS_CHILD | WS_VISIBLE, 13, 34, 520, 20, window, nullptr, nullptr, nullptr);
    CreateWindowW(L"BUTTON", L"Scan again", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 12, 62, 94, 27, window, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kRefreshId)), nullptr, nullptr);
    CreateWindowW(L"BUTTON", L"Scan folder...", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 111, 62, 106, 27, window, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kFolderId)), nullptr, nullptr);
    CreateWindowW(L"BUTTON", L"Open dump", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 222, 62, 92, 27, window, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kOpenId)), nullptr, nullptr);
    CreateWindowW(L"STATIC", L"Filter:", WS_CHILD | WS_VISIBLE, 330, 67, 42, 20, window, nullptr, nullptr, nullptr);
    g_filter = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 373, 64, 250, 24, window, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kFilterId)), nullptr, nullptr);
    g_tree = CreateWindowExW(WS_EX_CLIENTEDGE, WC_TREEVIEWW, L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | TVS_HASBUTTONS | TVS_LINESATROOT | TVS_SHOWSELALWAYS, 10, 100, 205, 500, window, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kTreeId)), nullptr, nullptr);
    g_list = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | LVS_REPORT | LVS_SHOWSELALWAYS | LVS_SINGLESEL, 222, 100, 650, 320, window, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kListId)), nullptr, nullptr);
    g_details = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | WS_VSCROLL, 222, 428, 650, 170, window, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kDetailsId)), nullptr, nullptr);
    g_status = CreateWindowExW(0, STATUSCLASSNAMEW, L"Ready", WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP, 0, 0, 0, 0, window, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kStatusId)), nullptr, nullptr);
    for (HWND child = GetWindow(window, GW_CHILD); child; child = GetWindow(child, GW_HWNDNEXT)) SendMessageW(child, WM_SETFONT, reinterpret_cast<WPARAM>(g_font), TRUE);
    ListView_SetExtendedListViewStyle(g_list, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);
    AddColumn(L"Date and time", 145, 0); AddColumn(L"Type", 105, 1); AddColumn(L"Code", 105, 2);
    AddColumn(L"Stop code / image", 245, 3); AddColumn(L"Dump file", 190, 4);
    AddTreeItem(0, L"Overview"); AddTreeItem(1, L"All crash reports"); AddTreeItem(2, L"Bugcheck events"); AddTreeItem(3, L"Dump files");
    TreeView_SelectItem(g_tree, g_treeItems[1]);

    HMENU menu = CreateMenu(), file = CreatePopupMenu(), help = CreatePopupMenu();
    AppendMenuW(file, MF_STRING, kMenuRefresh, L"Scan again");
    AppendMenuW(file, MF_STRING, kMenuScanFolder, L"Scan folder...");
    AppendMenuW(file, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(file, MF_STRING, kMenuExit, L"Exit");
    AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(file), L"File");
    AppendMenuW(help, MF_STRING, kMenuAbout, L"About");
    AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(help), L"Help");
    SetMenu(window, menu);
}

void Layout(HWND window) {
    RECT client{};
    GetClientRect(window, &client);
    const int width = client.right, height = client.bottom;
    SendMessageW(g_status, WM_SIZE, 0, 0);
    RECT status{};
    GetWindowRect(g_status, &status);
    const int available = height - (status.bottom - status.top);
    const int left = 222, rightWidth = width - left - 12;
    const int listHeight = std::max(160, (available - 118) * 58 / 100);
    MoveWindow(g_tree, 10, 100, 202, available - 110, TRUE);
    MoveWindow(g_list, left, 100, rightWidth, listHeight, TRUE);
    MoveWindow(g_details, left, 108 + listHeight, rightWidth, std::max(90, available - listHeight - 118), TRUE);
    MoveWindow(g_filter, std::max(373, width - 280), 64, std::min(250, std::max(120, width - 390)), 24, TRUE);
    ListView_SetColumnWidth(g_list, 0, 145); ListView_SetColumnWidth(g_list, 1, 105); ListView_SetColumnWidth(g_list, 2, 105);
    ListView_SetColumnWidth(g_list, 3, std::max(170, rightWidth - 545)); ListView_SetColumnWidth(g_list, 4, 190);
}

LRESULT CALLBACK WindowProc(HWND window, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
    case WM_CREATE:
        g_window = window;
        CreateControls(window);
        Layout(window);
        StartScan();
        return 0;
    case WM_SIZE:
        if (g_tree) Layout(window);
        return 0;
    case WM_GETMINMAXINFO: {
        auto* limits = reinterpret_cast<MINMAXINFO*>(lParam);
        limits->ptMinTrackSize.x = 950;
        limits->ptMinTrackSize.y = 560;
        return 0;
    }
    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case kRefreshId: case kMenuRefresh: StartScan(); return 0;
        case kFolderId: case kMenuScanFolder: ChooseFolder(); return 0;
        case kOpenId: OpenSelected(); return 0;
        case kFilterId:
            if (HIWORD(wParam) == EN_CHANGE) {
                HTREEITEM selected = TreeView_GetSelection(g_tree);
                int category = 1;
                for (int i = 0; i < 4; ++i) if (selected == g_treeItems[i]) category = i;
                ShowReports(category);
            }
            return 0;
        case kMenuExit: DestroyWindow(window); return 0;
        case kMenuAbout:
            MessageBoxW(window, L"Blue Screen Dump Viewer\n\nReads recent Windows bugcheck records and searches known dump locations. It does not repair Windows or guarantee a root-cause diagnosis.", L"About BSOD Viewer", MB_OK | MB_ICONINFORMATION);
            return 0;
        }
        break;
    case WM_NOTIFY:
        if (reinterpret_cast<LPNMHDR>(lParam)->hwndFrom == g_tree && reinterpret_cast<LPNMHDR>(lParam)->code == TVN_SELCHANGEDW) {
            const auto* change = reinterpret_cast<const NMTREEVIEWW*>(lParam);
            for (int i = 0; i < 4; ++i) if (change->itemNew.hItem == g_treeItems[i]) SelectCategory(i);
            return 0;
        }
        if (reinterpret_cast<LPNMHDR>(lParam)->hwndFrom == g_list) {
            const auto* notification = reinterpret_cast<const NMLISTVIEW*>(lParam);
            if (notification->hdr.code == LVN_ITEMCHANGED && (notification->uNewState & LVIS_SELECTED)) DisplaySelected(notification->iItem);
            if (notification->hdr.code == NM_DBLCLK) OpenSelected();
        }
        break;
    case WM_COPYDATA:
        if (lParam) {
            const auto* copyData = reinterpret_cast<const COPYDATASTRUCT*>(lParam);
            if (HandleEverythingResults(*copyData)) return TRUE;
        }
        break;
    case kScanDoneMessage:
        UpdateReports(reinterpret_cast<ScanResult*>(lParam));
        EnableWindow(GetDlgItem(window, kRefreshId), TRUE);
        EnableWindow(GetDlgItem(window, kFolderId), TRUE);
        return 0;
    case WM_DESTROY:
        g_window = nullptr;
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(window, message, wParam, lParam);
}

} // namespace

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int showCommand) {
    INITCOMMONCONTROLSEX controls{ sizeof(controls), ICC_TREEVIEW_CLASSES | ICC_LISTVIEW_CLASSES | ICC_BAR_CLASSES };
    InitCommonControlsEx(&controls);
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    g_everythingReplyEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    WNDCLASSEXW windowClass{ sizeof(windowClass) };
    windowClass.lpfnWndProc = WindowProc;
    windowClass.hInstance = instance;
    windowClass.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    windowClass.hIcon = LoadIconW(instance, MAKEINTRESOURCEW(IDI_BSOD_VIEWER));
    windowClass.hIconSm = LoadIconW(instance, MAKEINTRESOURCEW(IDI_BSOD_VIEWER));
    windowClass.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_BTNFACE + 1);
    windowClass.lpszClassName = kClassName;
    windowClass.style = CS_HREDRAW | CS_VREDRAW;
    if (!RegisterClassExW(&windowClass)) return 1;
    HWND window = CreateWindowExW(0, kClassName, L"Blue Screen Dump Viewer", WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 1060, 760, nullptr, nullptr, instance, nullptr);
    if (!window) return 1;
    ShowWindow(window, showCommand);
    UpdateWindow(window);
    MSG message{};
    while (GetMessageW(&message, nullptr, 0, 0) > 0) { TranslateMessage(&message); DispatchMessageW(&message); }
    if (g_everythingReplyEvent) CloseHandle(g_everythingReplyEvent);
    CoUninitialize();
    return static_cast<int>(message.wParam);
}