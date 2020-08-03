using System.Diagnostics;

namespace SharpSploit.Execution.Injection
{
    /// <summary>
    /// Provides static functions for performing injection using a combination of Allocation and Execution components.
    /// </summary>
    /// <author>The Wover (@TheRealWover)</author>
    public static class Injector
    {
        /// <summary>
        /// Inject a payload into a target process using a specified allocation and execution technique.
        /// </summary>
        /// <author>The Wover (@TheRealWover)</author>
        /// <param name="Payload"></param>
        /// <param name="AllocationTechnique"></param>
        /// <param name="ExecutionTechnique"></param>
        /// <param name="Process"></param>
        /// <returns></returns>
        public static bool Inject(PayloadType Payload, AllocationTechnique AllocationTechnique, ExecutionTechnique ExecutionTechnique, Process Process)
        {
            return ExecutionTechnique.Inject(Payload, AllocationTechnique, Process);
        }

        /// <summary>
        /// Inject a payload into the current process using a specified allocation and execution technique.
        /// </summary>
        /// <param name="Payload"></param>
        /// <param name="AllocationTechnique"></param>
        /// <param name="ExecutionTechnique"></param>
        /// <returns></returns>
        public static bool Inject(PayloadType Payload, AllocationTechnique AllocationTechnique, ExecutionTechnique ExecutionTechnique)
        {
            return ExecutionTechnique.Inject(Payload, AllocationTechnique);
        }
    }
}
