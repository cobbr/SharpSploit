// Author: Ryan Cobb (@cobbr_io)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using System.Net;
using Microsoft.VisualStudio.TestTools.UnitTesting;

using SharpSploit.Pivoting;

namespace SharpSploit.Tests.Pivoting
{
    [TestClass]
    public class RPortFwdTest
    {
        [TestMethod]
        public void TestAddReversePortForward()
        {
            ReversePortForwarding.AddReversePortForward("8080", "downloads.nickelviper.co.uk", "80");

            string result = string.Empty;

            using (var client = new WebClient())
            {
                try { result = client.DownloadString("http://localhost:8080/test.txt"); }
                catch (WebException) { }
            }

            Assert.IsTrue(result.Equals("this is a test\n"));
        }

        [TestMethod]
        public void TestDeleteReversePortForward()
        {
            ReversePortForwarding.AddReversePortForward("8080", "downloads.nickelviper.co.uk", "80");

            string result = string.Empty;

            using (var client = new WebClient())
            {
                try { result = client.DownloadString("http://localhost:8080/test.txt"); }
                catch (WebException) { }

                Assert.IsTrue(result.Equals("this is a test\n"));
                result = string.Empty;

                ReversePortForwarding.DeleteReversePortForward("8080");

                try { result = client.DownloadString("http://localhost:8080/test.txt"); }
                catch (WebException) { }

                Assert.IsFalse(result.Equals("this is a test\n"));
            }
        }

        [TestMethod]
        public void TestFlushReversePortForward()
        {
            ReversePortForwarding.AddReversePortForward("8080", "downloads.nickelviper.co.uk", "80");
            ReversePortForwarding.AddReversePortForward("8081", "downloads.nickelviper.co.uk", "80");

            string result = string.Empty;

            using (var client = new WebClient())
            {
                try { result = client.DownloadString("http://localhost:8080/test.txt"); }
                catch (WebException) { }
                Assert.IsTrue(result.Equals("this is a test\n"));
                result = string.Empty;

                try { result = client.DownloadString("http://localhost:8081/test.txt"); }
                catch (WebException) { }
                Assert.IsTrue(result.Equals("this is a test\n"));
                result = string.Empty;

                ReversePortForwarding.FlushReversePortFowards();

                try { result = client.DownloadString("http://localhost:8080/test.txt"); }
                catch (WebException) { }
                Assert.IsFalse(result.Equals("this is a test\n"));
                result = string.Empty;
                try { result = client.DownloadString("http://localhost:8080/test.txt"); }
                catch (WebException) { }
                Assert.IsFalse(result.Equals("this is a test\n"));
            };
        }

        [TestMethod]
        public void TestListReversePortForwards()
        {
            var list = ReversePortForwarding.ListReversePortForwards();
            Assert.IsTrue(list.Count == 0);

            ReversePortForwarding.AddReversePortForward("8080", "downloads.nickelviper.co.uk", "80");
            list = ReversePortForwarding.ListReversePortForwards();
            Assert.IsTrue(list.Count == 1);

            ReversePortForwarding.DeleteReversePortForward("8080");
            list = ReversePortForwarding.ListReversePortForwards();
            Assert.IsTrue(list.Count == 0);
        }
    }
}