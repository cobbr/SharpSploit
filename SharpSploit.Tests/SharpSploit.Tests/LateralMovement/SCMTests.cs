// Author: Ryan Cobb (@cobbr_io)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using System.IO;
using System.Linq;
using System.ServiceProcess;
using Microsoft.VisualStudio.TestTools.UnitTesting;

using SharpSploit.LateralMovement;

namespace SharpSploit.Tests.LateralMovement
{
    [TestClass]
    public class SCMTests
    {
        [TestMethod]
        public void TestGetServices()
        {
            var services = SCM.GetServices("localhost");
            Assert.IsTrue(services.Count > 5);
            Assert.IsNotNull(services.FirstOrDefault(S => S.DisplayName == "Netlogon"));
        }

        [TestMethod]
        public void TestGetService()
        {
            var service = SCM.GetService("localhost", "Netlogon");
            Assert.IsNotNull(service);
            Assert.AreEqual("Netlogon", service.DisplayName);
        }

        [TestMethod]
        public void TestGetServiceBadServiceName()
        {
            var service = SCM.GetService("localhost", "blah");
            Assert.IsNull(service);
        }

        [TestMethod]
        public void TestGetServicesBadComputerName()
        {
            var results = SCM.GetServices("blah");
            Assert.IsNull(results);
        }

        [TestMethod]
        public void TestCreateGetStartStopDeleteService()
        {
            bool result = SCM.CreateService("localhost", "SharpSploit Service", "SharpSploitSvc", @"C:\Temp\SharpSploitService.exe");
            Assert.IsTrue(result);

            var service = SCM.GetService("localhost", "SharpSploitSvc");
            Assert.AreEqual("SharpSploitSvc", service.DisplayName);
            Assert.AreEqual("SharpSploit Service", service.ServiceName);
            Assert.AreEqual(ServiceControllerStatus.Stopped, service.Status);
            Assert.AreEqual(false, service.CanStop);

            result = SCM.StartService("localhost", "SharpSploitSvc");
            Assert.IsTrue(result);

            service = SCM.GetService("localhost", "SharpSploitSvc");
            Assert.AreEqual("SharpSploitSvc", service.DisplayName);
            Assert.AreEqual("SharpSploit Service", service.ServiceName);
            Assert.AreEqual(ServiceControllerStatus.Running, service.Status);
            Assert.AreEqual(true, service.CanStop);

            result = SCM.StopService("localhost", "SharpSploitSvc");
            Assert.IsTrue(result);

            service = SCM.GetService("localhost", "SharpSploitSvc");
            Assert.AreEqual("SharpSploitSvc", service.DisplayName);
            Assert.AreEqual("SharpSploit Service", service.ServiceName);
            Assert.AreEqual(ServiceControllerStatus.Stopped, service.Status);
            Assert.AreEqual(false, service.CanStop);

            result = SCM.DeleteService("localhost", "SharpSploit Service");
            Assert.IsTrue(result);

            service = SCM.GetService("localhost", "SharpSploitSvc");
            Assert.IsNull(service);
        }
    }
}
