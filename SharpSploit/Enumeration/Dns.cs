// Author: Ryan Cobb (@cobbr_io)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using System;
using System.Net;
using System.DirectoryServices;
using SharpSploit.Generic;
using System.Collections.Generic;

namespace SharpSploit.Enumeration
{
    /// <summary>
    /// Dns is a library for dumping entry from Active Directory-integrated DNS.
    /// </summary>
    public class Dns
    {
        /// <summary>
        /// DnsResult represent the result entry of an host.
        /// </summary>
        public sealed class DnsResult : SharpSploitResult
        {
            public string DomainName { get; } = string.Empty;
            public string ComputerName { get; } = string.Empty;
            public string IP { get; set; } = string.Empty;
            public bool Tombstoned { get; set; } = false;

            protected internal override IList<SharpSploitResultProperty> ResultProperties
            {
                get
                {
                    return new List<SharpSploitResultProperty>
                    {
                        new SharpSploitResultProperty
                        {
                            Name = "DomainName",
                            Value = this.DomainName
                        },
                        new SharpSploitResultProperty
                        {
                            Name = "ComputerName",
                            Value = this.ComputerName
                        },
                        new SharpSploitResultProperty
                        {
                            Name = "IP",
                            Value = this.IP
                        },
                        new SharpSploitResultProperty
                        {
                            Name = "Tombstoned",
                            Value = this.Tombstoned
                        }
                    };
                }
            }

            public DnsResult(string DomainName = "", string ComputerName = "", string IP = "", bool Tombstoned = false)
            {
                this.DomainName = DomainName;
                this.ComputerName = ComputerName;
                this.IP = IP;
                this.Tombstoned = Tombstoned;
            }
        }

        /// <summary>
        /// Query specified domain controller via ldap and extrat hosts name list from Active Directory-integrated DNS, than perform a dns lookup to resolve ips. .
        /// </summary>
        /// <author>@b4rtik</author>
        /// <param name="DomainController">DomainController to query.</param>
        /// <returns>List of PortScanResults</returns>
        /// <remarks>
        /// based on 
        /// Getting in the zone dumping active directory dns with adidnsdump
        /// https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/
        /// by @_dirkjan
        /// </remarks>
        public static SharpSploitResultList<DnsResult> DumpDns(string DomainController)
        {
            SharpSploitResultList<DnsResult> results = new SharpSploitResultList<DnsResult>();

            try
            {
                
                string rootDn = "DC=DomainDnsZones";

                string domain_local = System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().DomainName;

                string domain_path = "";

                foreach (string domain_path_r in domain_local.Split('.'))
                {
                    domain_path += ",DC=" + domain_path_r;
                }

                rootDn += domain_path;
                DirectoryEntry rootEntry = new DirectoryEntry("LDAP://" + DomainController + "/" + rootDn);
                rootEntry.AuthenticationType = AuthenticationTypes.Delegation;
                DirectorySearcher searcher = new DirectorySearcher(rootEntry);

                //find domains
                var queryFormat = "(&(objectClass=DnsZone)(!(DC=*arpa))(!(DC=RootDNSServers)))";
                searcher.Filter = queryFormat;
                searcher.SearchScope = SearchScope.Subtree;

                foreach (SearchResult result in searcher.FindAll())
                {
                    String domain = (result.Properties["DC"].Count > 0 ? result.Properties["DC"][0].ToString() : string.Empty);
                    Console.WriteLine();
                    Console.WriteLine("Domain: {0}", domain);
                    Console.WriteLine();

                    DirectoryEntry rootEntry_d = new DirectoryEntry("LDAP://" + DomainController + "/DC=" + result.Properties["DC"][0].ToString() + ",CN=microsoftdns," + rootDn);
                    rootEntry_d.AuthenticationType = AuthenticationTypes.Delegation;
                    DirectorySearcher searcher_h = new DirectorySearcher(rootEntry_d);

                    //find hosts
                    queryFormat = "(&(!(objectClass=DnsZone))(!(DC=@))(!(DC=*arpa))(!(DC=*DNSZones)))";
                    searcher_h.Filter = queryFormat;
                    searcher_h.SearchScope = SearchScope.Subtree;

                    foreach (SearchResult result_h in searcher_h.FindAll())
                    {
                        String target = "";

                        if (result_h.Properties["DC"].Count > 0)
                        {
                            target = result_h.Properties["DC"][0].ToString();
                        }
                        else
                        {
                            //Hidden entry
                            String path = result_h.Path;
                            target = (path.Substring(path.IndexOf("LDAP://" + DomainController + "/"), path.IndexOf(","))).Split('=')[1];
                        }

                        DnsResult dnsentry = new DnsResult(DomainName: domain, ComputerName: target);

                        if (!target.EndsWith("."))
                            target += "." + domain;

                        bool tombstoned = result_h.Properties["dNSTombstoned"].Count > 0 ? (bool)result_h.Properties["dNSTombstoned"][0] : false;

                        dnsentry.Tombstoned = tombstoned;

                        if(!tombstoned)
                        {
                            try
                            {
                                IPHostEntry hostInfo = System.Net.Dns.GetHostEntry(target);
                                foreach (IPAddress result_ip in hostInfo.AddressList)
                                {
                                    dnsentry.IP = result_ip.ToString();
                                    results.Add(dnsentry);
                                }
                            }
                            catch (Exception)
                            {
                                
                            }
                        }
                        else
                        {
                            results.Add(dnsentry);
                        }
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("Error retriving data : {0}", e.Message);
            }

            return results;
        }
    }
}

