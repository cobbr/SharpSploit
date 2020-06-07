// Author: Ryan Cobb (@cobbr_io)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using System.Net;
using System.Text;
using System.Threading;
using Microsoft.VisualStudio.TestTools.UnitTesting;

using SharpSploit.Pivoting;

namespace SharpSploit.Tests.Pivoting
{
    [TestClass]
    public class RPortFwdTest
    {
        public const string testWebResponse = "this is a test";

        [TestMethod]
        public void TestAddReversePortForward()
        {
            var httpListener = new Thread(() => CreateHttpListener());
            httpListener.Start();

            ReversePortForwarding.AddReversePortForward("4444", "127.0.0.1", "8080");

            string result = string.Empty;

            using (var client = new WebClient())
            {
                try { result = client.DownloadString("http://localhost:4444"); }
                catch (WebException) { }
            }

            Assert.IsTrue(result.Equals(testWebResponse));
        }

        [TestMethod]
        public void TestDeleteReversePortForward()
        {
            var httpListener = new Thread(() => CreateHttpListener());
            httpListener.Start();

            ReversePortForwarding.AddReversePortForward("4444", "127.0.0.1", "8080");

            string result = string.Empty;

            using (var client = new WebClient())
            {
                try { result = client.DownloadString("http://localhost:4444"); }
                catch (WebException) { }

                Assert.IsTrue(result.Equals(testWebResponse));
                result = string.Empty;

                ReversePortForwarding.DeleteReversePortForward("4444");

                try { result = client.DownloadString("http://localhost:4444"); }
                catch (WebException) { }

                Assert.IsFalse(result.Equals(testWebResponse));
            }
        }

        [TestMethod]
        public void TestFlushReversePortForward()
        {
            var list = ReversePortForwarding.ListReversePortForwards();
            Assert.IsTrue(list.Count == 0);

            ReversePortForwarding.AddReversePortForward("4444", "127.0.0.1", "8080");
            ReversePortForwarding.AddReversePortForward("4445", "127.0.0.1", "8080");
            list = ReversePortForwarding.ListReversePortForwards();
            Assert.IsTrue(list.Count == 2);

            ReversePortForwarding.FlushReversePortFowards();
            list = ReversePortForwarding.ListReversePortForwards();
            Assert.IsTrue(list.Count == 0);
        }

        [TestMethod]
        public void TestListReversePortForwards()
        {
            var list = ReversePortForwarding.ListReversePortForwards();
            Assert.IsTrue(list.Count == 0);

            ReversePortForwarding.AddReversePortForward("4444", "127.0.0.1", "8080");
            list = ReversePortForwarding.ListReversePortForwards();
            Assert.IsTrue(list.Count == 1);

            ReversePortForwarding.DeleteReversePortForward("4444");
            list = ReversePortForwarding.ListReversePortForwards();
            Assert.IsTrue(list.Count == 0);
        }

        private static void CreateHttpListener()
        {
            using (var listener = new HttpListener())
            {
                listener.Prefixes.Add($"http://127.0.0.1:8080/");

                listener.Start();

                while (true)
                {
                    var context = listener.GetContext();
                    var response = context.Response;
                    var responseString = testWebResponse;
                    var buffer = Encoding.UTF8.GetBytes(responseString);
                    response.ContentLength64 = buffer.Length;

                    var output = response.OutputStream;
                    output.Write(buffer, 0, buffer.Length);
                }
            }
        }
    }
}