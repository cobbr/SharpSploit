// Author: Ryan Cobb (@cobbr_io)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using Microsoft.VisualStudio.TestTools.UnitTesting;

using SharpSploit.Evasion;

namespace SharpSploit.Tests.Evasion
{
    [TestClass]
    public class ETWTests
    {
        [TestMethod]
        public void TestPatchETWEventWrite()
        {
            Assert.IsTrue(ETW.PatchETWEventWrite());
        }
    }
}
