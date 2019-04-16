// Author: Ryan Cobb (@cobbr_io)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.DirectoryServices.ActiveDirectory;
using System.DirectoryServices;
using System.DirectoryServices.Protocols;
using System.IO;

namespace SharpSploit.Enumeration
{
    /// <summary>
    /// GPORemoteAccessPolicies is a class which Checks GPO for settings which deal with remote access policies relevant to lateral movement
    /// (e.g., "EnableLUA" and "LocalAccountTokenFilterPolicy").
    /// </summary>
    public class GPORemoteAccessPolicies
    {
        /// <summary>
        /// Check if EnableLUA is disabled
        /// </summary>
        /// <param name="GptTmplPath">The path of the GptTmpl.inf file</param>
        /// <returns></returns>
        public static bool CheckEnableLUA(string GptTmplPath)
        {
            bool enableLUA = false;

            if (File.Exists(GptTmplPath))
            {
                foreach (string line in File.ReadAllLines(GptTmplPath, Encoding.UTF8))
                {
                    string EnableLUAConfiguration = @"MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA=4,0";
                    if (line.Equals(EnableLUAConfiguration))
                    {
                        enableLUA = true;
                    }
                }
            }
            return enableLUA;
        }

        /// <summary>
        /// Check if FilterAdministratorToken is disabled
        /// </summary>
        /// <param name="GptTmplPath">The path of the GptTmpl.inf file</param>
        /// <returns></returns>
        public static bool CheckFilterAdministratorToken(string GptTmplPath)
        {
            bool FilterAdministratorToken = false;

            if (File.Exists(GptTmplPath))
            {
                foreach (string line in File.ReadAllLines(GptTmplPath, Encoding.UTF8))
                {
                    string FilterAdministratorTokenConfiguration = @"MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken=4,0";
                    if (line.Equals(FilterAdministratorTokenConfiguration))
                    {
                        FilterAdministratorToken = true;
                    }
                }
            }
            return FilterAdministratorToken;
        }

        /// <summary>
        /// Check the value of the LocalAccountTokenFilterPolicy 
        /// </summary>
        /// <param name="RegistryXMLpath">The path of the Registry.xml file</param>
        /// <returns></returns>
        public static bool CheckLocalAccountTokenFilterPolicy(string RegistryXMLpath)
        {
            bool LocalAccountTokenFilterPolicy = false;

            if (File.Exists(RegistryXMLpath))
            {
                foreach (string line in File.ReadAllLines(RegistryXMLpath, Encoding.UTF8))
                {
                    string LocalAccountTokenFilterPolicyConfiguration = "name=\"LocalAccountTokenFilterPolicy\" type=\"REG_DWORD\" value=\"00000001\"";
                    if (line.Contains(LocalAccountTokenFilterPolicyConfiguration))
                    {
                        LocalAccountTokenFilterPolicy = true;
                    }
                }
            }
            return LocalAccountTokenFilterPolicy;
        }

        /// <summary>
        /// Check if Administrators are not allowed to perform network authentication
        /// </summary>
        /// <param name="GptTmplPath">The path of the GptTmpl.inf file</param>
        /// <returns></returns>
        public static bool CheckSeDenyNetworkLogonRight(string GptTmplPath)
        {
            bool SeDenyNetworkLogonRight = false;

            if (File.Exists(GptTmplPath))
            {
                foreach (string line in File.ReadAllLines(GptTmplPath, Encoding.UTF8))
                {
                    string SeDenyNetworkLogonRightConfiguration = @"SeDenyNetworkLogonRight = *S-1-5-32-544";
                    if (line.Contains(SeDenyNetworkLogonRightConfiguration))
                    {
                        SeDenyNetworkLogonRight = true;
                    }
                }
            }

            return SeDenyNetworkLogonRight;
        }

        /// <summary>
        /// Check if Administrators are not allowed to perform remote interactive authentication
        /// </summary>
        /// <param name="GptTmplPath">The path of the GptTmpl.inf file</param>
        /// <returns></returns>
        public static bool CheckSeDenyRemoteInteractiveLogonRight(string GptTmplPath)
        {
            bool SeDenyRemoteInteractiveLogonRight = false;

            if (File.Exists(GptTmplPath))
            {
                foreach (string line in File.ReadAllLines(GptTmplPath, Encoding.UTF8))
                {
                    string SeDenyRemoteInteractiveLogonRightConfiguration = @"SeDenyRemoteInteractiveLogonRight = *S-1-5-32-544";
                    if (line.Contains(SeDenyRemoteInteractiveLogonRightConfiguration))
                    {
                        SeDenyRemoteInteractiveLogonRight = true;
                    }
                }
            }
            return SeDenyRemoteInteractiveLogonRight;
        }

        /// <summary>
        /// Checks GPO for settings which deal with remote access policies relevant to lateral movement (e.g., "EnableLUA" and "LocalAccountTokenFilterPolicy").
        /// The OUs to which these GPOs are applied are then identified, and then the computer objects from each are retrieved.Note that this only retrieves computer
        /// objects who have had the relevent registry keys set through group policy.
        /// </summary>
        /// <author>Dennis Panagiotopoulos (@den_n1s)</author>
        /// <param name="domain">pecifies the domain to use for the query, defaults to the current domain.</param>
        /// <param name="domainController">Specifies an Active Directory server (domain controller) to bind to.</param>
        /// <param name="searchScope">Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).</param>
        /// <param name="searchBase">The LDAP source to search through, e.g. /OU=Workstations,DC=domain,DC=local. Useful for OU queries.</param>
        /// <returns>Bool. True if execution succeeds, false otherwise.</returns>
        /// <remarks>
        /// Credits to Jon Cave (@joncave) and William Knowles (@william_knows)for their PowerShell implementation.
        /// https://labs.mwrinfosecurity.com/blog/enumerating-remote-access-policies-through-gpo/
        /// </remarks>
        public static bool EnumerateRemoteAccessPolicies(string domain, string domainController, string searchScope, string searchBase)
        {

            if(string.IsNullOrEmpty(searchScope))
            {
                searchScope = "SubTree";
            }

            if(string.IsNullOrEmpty(searchBase))
            {
                searchBase = "";
            }

            var listEnableLUA = new List<string>();
            var listFilterAdministratorToken = new List<string>();
            var listLocalAccountTokenFilterPolicy = new List<string>();
            var listSeDenyNetworkLogonRight = new List<string>();
            var listSeDenyRemoteInteractiveLogonRight = new List<string>();
            var computerPolicyEnableLUA = new List<string>();
            var computerPolicyFilterAdministratorToken = new List<string>();
            var computerPolicyLocalAccountTokenFilterPolicy = new List<string>();
            var computerPolicySeDenyNetworkLogonRight = new List<string>();
            var computerPolicySeDenyRemoteInteractiveLogonRight = new List<string>();
 
            //discover current domain            
            System.DirectoryServices.ActiveDirectory.Domain current_domain = null;
            if (string.IsNullOrEmpty(domain))
            {
                try
                {
                    current_domain = System.DirectoryServices.ActiveDirectory.Domain.GetCurrentDomain();
                    domain = current_domain.Name;
                }
                catch
                {
                    Console.WriteLine("[!] Cannot enumerate domain.\n");
                    return false;
                }
            }
            else
            {
                DirectoryContext domainContext = new DirectoryContext(DirectoryContextType.Domain, domain);
                try
                {
                    current_domain = System.DirectoryServices.ActiveDirectory.Domain.GetDomain(domainContext);
                }
                catch
                {
                    Console.WriteLine("[!] The specified domain does not exist or cannot be contacted.\n");
                    return false;
                }

            }

            //retrieve domain controller
            if (string.IsNullOrEmpty(domainController))
            {
                domainController = current_domain.FindDomainController().Name;
            }
            else
            {
                var ldapId = new LdapDirectoryIdentifier(domainController);
                using (var testConnection = new LdapConnection(ldapId))
                {
                    try
                    {
                        testConnection.Bind();
                    }
                    catch
                    {
                        Console.WriteLine("[!] The specified domain controller cannot be contacted.\n");
                        return false;
                    }
                }
            }

            domain = domain.ToLower();

            String[] DC_array = null;
            String distinguished_name = null;
            distinguished_name = "CN=Policies,CN=System";
            DC_array = domain.Split('.');

            foreach (String DC in DC_array)
            {
                distinguished_name += ",DC=" + DC;
            }

            System.DirectoryServices.Protocols.LdapDirectoryIdentifier identifier = new System.DirectoryServices.Protocols.LdapDirectoryIdentifier(domainController, 389);
            System.DirectoryServices.Protocols.LdapConnection connection = null;

            //make the connection to the domain controller
            connection = new System.DirectoryServices.Protocols.LdapConnection(identifier);
            connection.SessionOptions.Sealing = true;
            connection.SessionOptions.Signing = true;
            try
            {
                connection.Bind();
            }
            catch
            {
                Console.WriteLine("Domain controller cannot be contacted.\n");
                return false;
            }

            SearchRequest requestGUID = null;
            if (string.Equals(searchScope, "SubTree"))
            {
                requestGUID = new System.DirectoryServices.Protocols.SearchRequest(distinguished_name, "cn=*", System.DirectoryServices.Protocols.SearchScope.Subtree, null);
            }
            else if (string.Equals(searchScope, "OneLevel"))
            {
                requestGUID = new System.DirectoryServices.Protocols.SearchRequest(distinguished_name, "cn=*", System.DirectoryServices.Protocols.SearchScope.OneLevel, null);
            }
            else if (string.Equals(searchScope, "Base"))
            {
                requestGUID = new System.DirectoryServices.Protocols.SearchRequest(distinguished_name, "cn=*", System.DirectoryServices.Protocols.SearchScope.Base, null);
            }

            SearchResponse responseGUID = null;
            try
            {
                responseGUID = (System.DirectoryServices.Protocols.SearchResponse)connection.SendRequest(requestGUID);
            }
            catch
            {
                Console.WriteLine("Search scope is not valid.\n");
                return false;
            }

            if (!string.IsNullOrEmpty(searchBase))
            {
                string adPath = "LDAP://" + domain + searchBase;
                if (!DirectoryEntry.Exists(adPath))
                {
                    Console.WriteLine("[!] Search base is not valid.\n");
                    return false;
                }
            }

            foreach (System.DirectoryServices.Protocols.SearchResultEntry entry in responseGUID.Entries)
            {
                try
                {
                    var requestAttributes = new System.DirectoryServices.Protocols.SearchRequest(distinguished_name, "cn=" + entry.Attributes["cn"][0].ToString(), System.DirectoryServices.Protocols.SearchScope.OneLevel, null);
                    var responseAttributes = (System.DirectoryServices.Protocols.SearchResponse)connection.SendRequest(requestAttributes);
                    foreach (System.DirectoryServices.Protocols.SearchResultEntry attribute in responseAttributes.Entries)
                    {
                        try
                        {
                            string displayName = entry.Attributes["displayName"][0].ToString();
                            string name = entry.Attributes["name"][0].ToString();
                            string gpcfilesyspath = entry.Attributes["gpcfilesyspath"][0].ToString();

                            string uncPathGptTmpl = gpcfilesyspath + @"\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf";

                            bool enableLUA = CheckEnableLUA(uncPathGptTmpl);

                            if (enableLUA)
                            {
                                listEnableLUA.Add(name);
                            }

                            bool FilterAdministratorToken = CheckFilterAdministratorToken(uncPathGptTmpl);

                            if (FilterAdministratorToken)
                            {
                                listFilterAdministratorToken.Add(name);
                            }

                            string uncPathRegistryXML = gpcfilesyspath + @"\MACHINE\Preferences\Registry\Registry.xml";

                            bool LocalAccountTokenFilterPolicy = CheckLocalAccountTokenFilterPolicy(uncPathRegistryXML);

                            if (LocalAccountTokenFilterPolicy)
                            {
                                listLocalAccountTokenFilterPolicy.Add(name);
                            }

                            bool SeDenyNetworkLogonRight = CheckSeDenyNetworkLogonRight(uncPathGptTmpl);

                            if (SeDenyNetworkLogonRight)
                            {
                                listSeDenyNetworkLogonRight.Add(name);
                            }

                            bool SeDenyRemoteInteractiveLogonRight = CheckSeDenyRemoteInteractiveLogonRight(uncPathGptTmpl);

                            if (SeDenyRemoteInteractiveLogonRight)
                            {
                                listSeDenyRemoteInteractiveLogonRight.Add(name);
                            }

                        }
                        catch
                        {
                            Console.WriteLine("[!] It was not possible to retrieve the displayname, name and gpcfilesypath\n");
                            return false;
                        }
                    }
                }
                catch
                {
                    Console.WriteLine("[!] It was not possible to retrieve GPO Policies\n");
                    return false;
                }
            }

            Console.Write("\n[+] EnableLUA: \t\t\t\t");
            foreach (var guid in listEnableLUA)
            {
                DirectoryEntry startingPoint = null;
                string filterGPLink = "(&(objectCategory=organizationalUnit)(gplink=*" + guid + "*))";

                if (string.IsNullOrEmpty(searchBase))
                {
                    startingPoint = new DirectoryEntry("LDAP://" + domain);
                }
                else
                {
                    startingPoint = new DirectoryEntry("LDAP://" + domain + searchBase);
                }

                DirectorySearcher searcher = new DirectorySearcher(startingPoint);
                searcher.Filter = filterGPLink;

                foreach (SearchResult OU in searcher.FindAll())
                {
                    DirectoryEntry startingPoint1 = new DirectoryEntry(OU.Path);
                    DirectorySearcher searcherOU = new DirectorySearcher(startingPoint1);
                    searcherOU.Filter = "(&(samAccountType=805306369))";
                    foreach (SearchResult computerObject in searcherOU.FindAll())
                    {
                        DirectoryEntry computer = computerObject.GetDirectoryEntry();
                        if (!(computerPolicyEnableLUA.Contains(computer.Properties["dNSHostName"].Value.ToString())))
                        {
                            Console.Write("{0} ", computer.Properties["dNSHostName"].Value.ToString());
                        }
                        computerPolicyEnableLUA.Add(computer.Properties["dNSHostName"].Value.ToString());
                    }
                }
            }

            Console.Write("\n[+] FilterAdministratorToken: \t\t");
            foreach (var guid in listFilterAdministratorToken)
            {
                DirectoryEntry startingPoint = null;
                string filterGPLink = "(&(objectCategory=organizationalUnit)(gplink=*" + guid + "*))";

                if (string.IsNullOrEmpty(searchBase))
                {
                    startingPoint = new DirectoryEntry("LDAP://" + domain);
                }
                else
                {
                    startingPoint = new DirectoryEntry("LDAP://" + domain + searchBase);
                }

                DirectorySearcher searcher = new DirectorySearcher(startingPoint);
                searcher.Filter = filterGPLink;

                foreach (SearchResult OU in searcher.FindAll())
                {
                    DirectoryEntry startingPoint1 = new DirectoryEntry(OU.Path);
                    DirectorySearcher searcherOU = new DirectorySearcher(startingPoint1);
                    searcherOU.Filter = "(&(samAccountType=805306369))";
                    foreach (SearchResult computerObject in searcherOU.FindAll())
                    {
                        DirectoryEntry computer = computerObject.GetDirectoryEntry();
                        if (!(computerPolicyFilterAdministratorToken.Contains(computer.Properties["dNSHostName"].Value.ToString())))
                        {
                            Console.Write("{0} ", computer.Properties["dNSHostName"].Value.ToString());
                        }
                        computerPolicyFilterAdministratorToken.Add(computer.Properties["dNSHostName"].Value.ToString());
                    }

                }
            }
            Console.Write("\n");

            Console.Write("[+] LocalAccountTokenFilterPolicy: \t");
            foreach (var guid in listLocalAccountTokenFilterPolicy)
            {
                DirectoryEntry startingPoint = null;
                string filterGPLink = "(&(objectCategory=organizationalUnit)(gplink=*" + guid + "*))";

                if (string.IsNullOrEmpty(searchBase))
                {
                    startingPoint = new DirectoryEntry("LDAP://" + domain);
                }
                else
                {
                    startingPoint = new DirectoryEntry("LDAP://" + domain + searchBase);
                }

                DirectorySearcher searcher = new DirectorySearcher(startingPoint);
                searcher.Filter = filterGPLink;

                foreach (SearchResult OU in searcher.FindAll())
                {
                    DirectoryEntry startingPoint1 = new DirectoryEntry(OU.Path);
                    DirectorySearcher searcherOU = new DirectorySearcher(startingPoint1);
                    searcherOU.Filter = "(&(samAccountType=805306369))";
                    foreach (SearchResult computerObject in searcherOU.FindAll())
                    {
                        DirectoryEntry computer = computerObject.GetDirectoryEntry();
                        if (!(computerPolicyLocalAccountTokenFilterPolicy.Contains(computer.Properties["dNSHostName"].Value.ToString())))
                        {
                            Console.Write("{0} ", computer.Properties["dNSHostName"].Value.ToString());
                        }
                        computerPolicyLocalAccountTokenFilterPolicy.Add(computer.Properties["dNSHostName"].Value.ToString());
                    }

                }
            }
            Console.Write("\n");

            Console.Write("[+] SeDenyNetworkLogonRight: \t\t");
            foreach (var guid in listSeDenyNetworkLogonRight)
            {
                DirectoryEntry startingPoint = null;
                string filterGPLink = "(&(objectCategory=organizationalUnit)(gplink=*" + guid + "*))";

                if (string.IsNullOrEmpty(searchBase))
                {
                    startingPoint = new DirectoryEntry("LDAP://" + domain);
                }
                else
                {
                    startingPoint = new DirectoryEntry("LDAP://" + domain + searchBase);
                }

                DirectorySearcher searcher = new DirectorySearcher(startingPoint);
                searcher.Filter = filterGPLink;

                foreach (SearchResult OU in searcher.FindAll())
                {
                    DirectoryEntry startingPoint1 = new DirectoryEntry(OU.Path);
                    DirectorySearcher searcherOU = new DirectorySearcher(startingPoint1);
                    searcherOU.Filter = "(&(samAccountType=805306369))";
                    foreach (SearchResult computerObject in searcherOU.FindAll())
                    {
                        DirectoryEntry computer = computerObject.GetDirectoryEntry();
                        if (!(computerPolicySeDenyNetworkLogonRight.Contains(computer.Properties["dNSHostName"].Value.ToString())))
                        {
                            Console.Write("{0} ", computer.Properties["dNSHostName"].Value.ToString());
                        }
                        computerPolicySeDenyNetworkLogonRight.Add(computer.Properties["dNSHostName"].Value.ToString());
                    }

                }
            }
            Console.Write("\n");

            Console.Write("[+] SeDenyRemoteInteractiveLogonRight: \t");
            foreach (var guid in listSeDenyRemoteInteractiveLogonRight)
            {
                DirectoryEntry startingPoint = null;
                string filterGPLink = "(&(objectCategory=organizationalUnit)(gplink=*" + guid + "*))";

                if (string.IsNullOrEmpty(searchBase))
                {
                    startingPoint = new DirectoryEntry("LDAP://" + domain);
                }
                else
                {
                    startingPoint = new DirectoryEntry("LDAP://" + domain + searchBase);
                }

                DirectorySearcher searcher = new DirectorySearcher(startingPoint);
                searcher.Filter = filterGPLink;

                foreach (SearchResult OU in searcher.FindAll())
                {
                    DirectoryEntry startingPoint1 = new DirectoryEntry(OU.Path);
                    DirectorySearcher searcherOU = new DirectorySearcher(startingPoint1);
                    searcherOU.Filter = "(&(samAccountType=805306369))";
                    foreach (SearchResult computerObject in searcherOU.FindAll())
                    {
                        DirectoryEntry computer = computerObject.GetDirectoryEntry();
                        if (!(computerPolicySeDenyRemoteInteractiveLogonRight.Contains(computer.Properties["dNSHostName"].Value.ToString())))
                        {
                            Console.Write("{0} ", computer.Properties["dNSHostName"].Value.ToString());
                        }
                        computerPolicySeDenyRemoteInteractiveLogonRight.Add(computer.Properties["dNSHostName"].Value.ToString());
                    }
                }
            }
            Console.Write("\n");
            Console.WriteLine("[-] Enumeration finished\n");
            return true;
        }
    }
}