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
    public class ReversePortForwardingTests
    {
        public const string testWebResponse = "this is a test";

        [TestMethod]
        public void TestCreateReversePortForward()
        {
            Thread httpListener = new Thread(() => CreateHttpListener());
            httpListener.Start();

            ReversePortForwarding.CreateReversePortForward(4444, "127.0.0.1", 8080);

            string result = string.Empty;

            using (WebClient client = new WebClient())
            {
                try { result = client.DownloadString("http://localhost:4444"); }
                catch (WebException) { }
            }

            Assert.IsTrue(result.Equals(testWebResponse));
            httpListener.Abort();
        }

        [TestMethod]
        public void TestDeleteReversePortForward()
        {
            Thread httpListener = new Thread(() => CreateHttpListener());
            httpListener.Start();

            ReversePortForwarding.CreateReversePortForward(4444, "127.0.0.1", 8080);

            string result = string.Empty;

            using (WebClient client = new WebClient())
            {
                try { result = client.DownloadString("http://localhost:4444"); }
                catch (WebException) { }

                Assert.IsTrue(result.Equals(testWebResponse));
                result = string.Empty;

                ReversePortForwarding.DeleteReversePortForward(4444);

                try { result = client.DownloadString("http://localhost:4444"); }
                catch (WebException) { }

                Assert.IsFalse(result.Equals(testWebResponse));
            }
            httpListener.Abort();
        }

        [TestMethod]
        public void TestFlushReversePortForward()
        {
            var list = ReversePortForwarding.GetReversePortForwards();
            Assert.IsTrue(list.Count == 0);

            ReversePortForwarding.CreateReversePortForward(4444, "127.0.0.1", 8080);
            ReversePortForwarding.CreateReversePortForward(4445, "127.0.0.1", 8080);
            list = ReversePortForwarding.GetReversePortForwards();
            Assert.IsTrue(list.Count == 2);

            ReversePortForwarding.FlushReversePortFowards();
            list = ReversePortForwarding.GetReversePortForwards();
            Assert.IsTrue(list.Count == 0);
        }

        [TestMethod]
        public void TestListReversePortForwards()
        {
            var list = ReversePortForwarding.GetReversePortForwards();
            Assert.IsTrue(list.Count == 0);

            ReversePortForwarding.CreateReversePortForward(4444, "127.0.0.1", 8080);
            list = ReversePortForwarding.GetReversePortForwards();
            Assert.IsTrue(list.Count == 1);

            ReversePortForwarding.DeleteReversePortForward(4444);
            list = ReversePortForwarding.GetReversePortForwards();
            Assert.IsTrue(list.Count == 0);
        }

        private static void CreateHttpListener()
        {
            using (HttpListener listener = new HttpListener())
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