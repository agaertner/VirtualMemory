# VirtualMemory.AddressSpace

To use create an ``AddressSpace`` object and set its name to the process name you want to access.

```csharp
using VirtualMemory;

var myProcessMemory = new AddressSpace("processName")

```  

If you are confronted with multi-level pointers you need to resolve the actual address by doing
```csharp
long address = myProcessMemory.ResolveInt64FromString($"{BaseAddress} + 0x01639068 + 0x508 + 0x38 + 0x30 + 0x338 + 0xDC");
```  
for a 64bit address space; or
  
```csharp
int address = myProcessMemory.ResolveInt32FromString($"{BaseAddress} + 0x01639068 + 0x508 + 0x38 + 0x30 + 0x338 + 0xDC");
```
for a 32bit address space.

You may or may not need to cast an address to ``IntPtr`` prior to using it in read or write operations.  
```csharp
var someValue = myProcessMemory.ReadByte((IntPtr)address)
```