using System;
using System.Reflection;
using System.Diagnostics;

namespace SharpSploit.Execution.Injection
{
    /// <summary>
    /// Base class for allocation techniques.
    /// </summary>
    public abstract class AllocationTechnique
    {
        // An array containing a set of PayloadType objects that are supported.
        protected Type[] supportedPayloads;

        /// <summary>
        /// Informs objects using this technique whether or not it supports the type of a particular payload.
        /// </summary>
        /// <author>The Wover (@TheRealWover)</author>
        /// <param name="Payload">A payload.</param>
        /// <returns>Whether or not the payload is of a supported type for this strategy.</returns>
        public abstract bool IsSupportedPayloadType(PayloadType Payload);

        /// <summary>
        /// Internal method for setting the supported payload types. Used in constructors.
        /// </summary>
        /// <author>The Wover (@TheRealWover)</author>
        internal abstract void DefineSupportedPayloadTypes();

        /// <summary>
        /// Allocate the payload to the target process at a specified address.
        /// </summary>
        /// <author>The Wover (@TheRealWover)</author>
        /// <param name="Payload">The payload to allocate to the target process.</param>
        /// <param name="Process">The target process.</param>
        /// <param name="Address">The address at which to allocate the payload in the target process.</param>
        /// <returns>True when allocation was successful. Otherwise, throws relevant exceptions.</returns>
        public virtual IntPtr Allocate(PayloadType Payload, Process Process, IntPtr Address)
        {
            Type[] funcPrototype = new Type[] { Payload.GetType(), typeof(Process), Address.GetType() };

            try
            {
                // Get delegate to the overload of Allocate that supports the type of payload passed in
                MethodInfo allocate = this.GetType().GetMethod("Allocate", funcPrototype);

                // Dynamically invoke the appropriate Allocate overload
                return (IntPtr)allocate.Invoke(this, new object[] { Payload, Process, Address });
            }
            // If there is no such method
            catch (ArgumentNullException)
            {
                throw new PayloadTypeNotSupported(Payload.GetType());
            }
        }

        /// <summary>
        /// Allocate the payload to the target process.
        /// </summary>
        /// <author>The Wover (@TheRealWover)</author>
        /// <param name="Payload">The payload to allocate to the target process.</param>
        /// <param name="Process">The target process.</param>
        /// <returns>Base address of allocated memory within the target process's virtual memory space.</returns>
        public virtual IntPtr Allocate(PayloadType Payload, Process Process)
        {

            Type[] funcPrototype = new Type[] { Payload.GetType(), typeof(Process) };

            try
            {
                // Get delegate to the overload of Allocate that supports the type of payload passed in
                MethodInfo allocate = this.GetType().GetMethod("Allocate", funcPrototype);

                // Dynamically invoke the appropriate Allocate overload
                return (IntPtr)allocate.Invoke(this, new object[] { Payload, Process });
            }
            // If there is no such method
            catch (ArgumentNullException)
            {
                throw new PayloadTypeNotSupported(Payload.GetType());
            }
        }
    }


    /// <summary>
    /// Exception thrown when the payload memory fails to allocate
    /// </summary>
    public class AllocationFailed : Exception
    {
        public AllocationFailed() { }

        public AllocationFailed(int error) : base(string.Format("Memory failed to allocate with system error code: {0}", error)) { }
    }

    /// <summary>
    /// Exception thrown when the memory fails to write
    /// </summary>
    public class MemoryWriteFailed : Exception
    {
        public MemoryWriteFailed() { }

        public MemoryWriteFailed(int error) : base(string.Format("Memory failed to write with system error code: {0}", error)) { }
    }
}