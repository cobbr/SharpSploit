// Author: Ryan Cobb (@cobbr_io)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using System;
using System.Linq;
using System.Collections.Generic;
using Microsoft.VisualStudio.TestTools.UnitTesting;

using SharpSploit.Enumeration;
using System.DirectoryServices.ActiveDirectory;
using SharpSploit.Generic;

namespace SharpSploit.Tests.Enumeration
{
    [TestClass]
    public class DnsTests
    {
        [TestMethod]
        public void TestDumpDns()
        {
            SharpSploitResultList<Dns.DnsResult> hosts = Dns.DumpDns(System.DirectoryServices.ActiveDirectory.Domain.GetCurrentDomain().FindDomainController().Name, true);
            Assert.IsTrue(hosts.Count > 0);
            foreach (Dns.DnsResult host in hosts)
            {
                Assert.IsTrue(!string.IsNullOrEmpty(host.IP) || host.Tombstoned == true);
            }
        }
    }
}
