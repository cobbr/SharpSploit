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
        /// 
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

        //Used for Execution techniques that do not take a Process as a parameter.
        //Can be used for local injection, or for Execution primitives that rely on process creation.
        /// <summary>
        /// I
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
