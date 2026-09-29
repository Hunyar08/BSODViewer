# Blue Screen Dump Viewer

A native Windows desktop utility built with C++, Win32, and Windows Common Controls.

## Features

- Reads recent Event Viewer System log bugcheck reports (event 1001).
- Queries the running Everything index for `.dmp`, `.mdmp`, and `.hdmp` files across indexed volumes using Everything's local IPC interface.
- Falls back to `%WINDIR%\Minidump`, `%WINDIR%\MEMORY.DMP`, `%WINDIR%\LiveKernelReports`, and `%LOCALAPPDATA%\CrashDumps` when Everything is unavailable or a location is not indexed.
- Scans an additional user-selected folder, including its subfolders.
- Inspects minidump headers and process exception records with `DbgHelp`; links a dump to a bugcheck event only when its path or timestamp supports the match.
- Explains common stop codes and offers practical troubleshooting steps.

Guidance is heuristic, not a guaranteed root-cause finding. Full kernel dumps are detected but not decoded. The app does not upload dumps or change system settings. Reading protected files may require running it as administrator.

## Looks
<img width="1145" height="790" alt="image" src="https://github.com/user-attachments/assets/36295810-4252-4324-80c5-0790df717130" />

## Build

Install Visual Studio with the **Desktop development with C++** workload and CMake, then run in this folder:

```powershell
cmake -S . -B build
cmake --build build --config Release
```

Run `build\Release\BSODViewer.exe` (or `build\BSODViewer.exe` for a single-configuration generator).
