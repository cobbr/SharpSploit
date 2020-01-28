using System.Diagnostics;

namespace SharpSploit.Execution.Injection
{
    /// <summary>
    /// Baase class for injectors.
    /// </summary>
    /// <author>The Wover (@TheRealWover)</author>
    public static class Injector
    {
        /// <summary>
        ///  Inject a payload into a target process using a specified allocation and execution technique.
        /// </summary>
        /// <author>The Wover (@TheRealWover)</author>
        /// <param name="payload"></param>
        /// <param name="allocation"></param>
        /// <param name="execution"></param>
        /// <param name="process"></param>
        /// <returns></returns>
        public static bool Inject (PayloadType payload, AllocationTechnique allocation, ExecutionTechnique execution, Process process)
        {
            return execution.Inject(payload, allocation, process);
        }

        /// <summary>
        /// Inject a payload into the current process using a specified allocation and execution technique.
        /// </summary>
        /// <param name="payload"></param>
        /// <param name="allocation"></param>
        /// <param name="execution"></param>
        /// <returns></returns>
        public static bool Inject(PayloadType payload, AllocationTechnique allocation, ExecutionTechnique execution)
        {
            return execution.Inject(payload, allocation);
        }
    }
}
