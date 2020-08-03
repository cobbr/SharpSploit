using System;

namespace SharpSploit.Execution.Injection
{
    /// <summary>
    /// Base class for all types of payloads.
    /// Variants are responsible for specifying what types of payloads they support.
    /// </summary>
    /// <author>The Wover (@TheRealWover)</author>
    public abstract class PayloadType
    {
        public byte[] Payload { get; private set; }

        // Constructor that requires the user to pass in the payload as a byte array.
        protected PayloadType(byte[] data)
        {
            Payload = data;
        }
    }

    /// <summary>
    /// Represents payloads that are position-independent-code.
    /// </summary>
    /// <author>The Wover (@TheRealWover)</author>
    public class PICPayload : PayloadType
    {
        // Declares the constructor as equivalent to that of the base class.
        public PICPayload(byte[] data) : base(data) { }
    }

    /// <summary>
    /// Exception thrown when the type of a payload is not supported by a injection variant.
    /// </summary>
    /// <author>The Wover (@TheRealWover)</author>
    public class PayloadTypeNotSupported : Exception
    {
        public PayloadTypeNotSupported() { }

        public PayloadTypeNotSupported(Type payloadType) : base(string.Format("Unsupported Payload type: {0}", payloadType.Name)) { }
    }
}
