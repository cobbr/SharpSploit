// Author: Ryan Cobb (@cobbr_io)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using System.Threading;
using Microsoft.VisualStudio.TestTools.UnitTesting;

using SharpSploit.Execution;
using SharpSploit.Execution.ManualMap;

namespace SharpSploit.Tests.Execution
{
    [TestClass]
    public class MapTests
    {
        [TestMethod]
        public void TestMapAndFree()
        {
            PE.PE_MANUAL_MAP mappedPE = Map.MapModuleToMemory("C:\\example.exe");
            SharpSploit.Execution.DynamicInvoke.Generic.CallMappedPEModule(mappedPE.PEINFO, mappedPE.ModuleBase);
            Thread.Sleep(5000);
            Map.FreeModule(mappedPE);
        }
    }
}
