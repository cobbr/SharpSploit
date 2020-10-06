// Author: Ryan Cobb (@cobbr_io)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using Threads = System.Threading;
using Forms = System.Windows.Forms;
using Microsoft.VisualStudio.TestTools.UnitTesting;

using SharpSploit.Enumeration;

namespace SharpSploit.Tests.Enumeration
{
    [TestClass]
    public class ClipboardTests
    {
        [TestMethod]
        public void TestClipboard()
        {
            string results = "";
            Threads.Thread t = new Threads.Thread(() =>
            {
                results = Clipboard.StartClipboardMonitor(8);
            });
            Threads.Thread c = new Threads.Thread(() =>
            {
                Forms.Clipboard.SetText("test123");
            });
            c.SetApartmentState(Threads.ApartmentState.STA);

            t.Start();
            Threads.Thread.Sleep(2000);
            c.Start();
            c.Join();
            t.Join(6000);
            Assert.IsTrue(results.Length > 0);
            Assert.IsTrue(results.Contains("test123"));
        }
    }
}