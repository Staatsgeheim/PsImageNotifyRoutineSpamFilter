# PsImageNotifyRoutine Spam Filter v1.0
PsImageNotifyRoutine Spam Filter is a small project that will enable you to filter out garbage or otherwise not interesting events that are send to the PLOAD_IMAGE_NOTIFY_ROUTINE handler.

If you ever used this kernel callback I'm pretty sure you noticed that it generates a lot of useless events caused mainly by the fact that Shell32.dll has the annoying habit to load executable images in memory using the SEC_IMAGE and PAGE_EXECUTE flags even for trivial tasks like extracting icon's or other file information causing a flood of pretty much useless events being send to the LoadImageNotifyRoutine.

By using RtlWalkFrameChain to trace the call stack back into usermode my spam filter will verify if the event was actually triggerd by the Windows PE loader instead of Shell32 or some random other software component effectively leaving you with only the real DLL, Driver or EXE image load events.

The current Visual Studio project only supports 64 bits Windows versions but it's fully compatible with 32 bits applications running on the WoW64 emulation layer.

*Tested only on Windows 7 x64*

*Screenshot showing the nice and clean output after filtering*
![alt tag](https://raw.githubusercontent.com/Staatsgeheim/PsImageNotifyRoutineSpamFilter/master/SampleOutput.png)
