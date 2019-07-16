// Author: Ryan Cobb (@cobbr_io)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using System;
using System.IO;
using System.Text;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.Protocols;
using System.DirectoryServices.ActiveDirectory;

namespace SharpSploit.Enumeration
{
    /// <summary>
    /// GPO is a library for GPO enumeration.
    /// </summary>
    public class GPO
    {
        /// <summary>
        /// Gets the value of EnableLUA from a GptTmpl.inf file.
        /// </summary>
        /// <author>Dennis Panagiotopoulos (@den_n1s)</author>
        /// <param name="GptTmplPath">Path to the GptTmpl.inf file.</param>
        /// <returns>True if EnableLUA is enabled, false otherwise.</returns>
        public static bool GetEnableLua(string GptTmplPath)
        {
            if (File.Exists(GptTmplPath))
            {
                foreach (string line in File.ReadAllLines(GptTmplPath, Encoding.UTF8))
                {
                    if (line.Equals(@"MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA=4,0", StringComparison.CurrentCulture))
                    {
                        return true;
                    }
                }
            }
            return false;
        }

        /// <summary>
        /// Gets the value of FilterAdministratorToken from a GptTmpl.inf file.
        /// </summary>
        /// <author>Dennis Panagiotopoulos (@den_n1s)</author>
        /// <param name="GptTmplPath">Path to the GptTmpl.inf file.</param>
        /// <returns>True if FilterAdministratorToken is enabled, false otherwise.</returns>
        public static bool GetFilterAdministratorToken(string GptTmplPath)
        {
            if (File.Exists(GptTmplPath))
            {
                foreach (string line in File.ReadAllLines(GptTmplPath, Encoding.UTF8))
                {
                    if (line.Equals(@"MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken=4,0", StringComparison.CurrentCulture))
                    {
                        return true;
                    }
                }
            }
            return false;
        }

        /// <summary>
        /// Gets the value of LocalAccountTokenFilterPolicy from a Registry.xml file.
        /// </summary>
        /// <author>Dennis Panagiotopoulos (@den_n1s)</author>
        /// <param name="RegistryXMLPath">Path to the Registry.xml file.</param>
        /// <returns>True if LocalAccountTokenFilterPolicy is enabled, false otherwise.</returns>
        public static bool GetLocalAccountTokenFilterPolicy(string RegistryXMLPath)
        {
            if (File.Exists(RegistryXMLPath))
            {
                foreach (string line in File.ReadAllLines(RegistryXMLPath, Encoding.UTF8))
                {
                    if (line.Contains("name=\"LocalAccountTokenFilterPolicy\" type=\"REG_DWORD\" value=\"00000001\""))
                    {
                        return true;
                    }
                }
            }
            return false;
        }

        /// <summary>
        /// Gets the value of SeDenyNetworkLogonRight from a GptTmpl.inf file,
        /// which determines if Administrators are allowed to perform network authentication.
        /// </summary>
        /// <author>Dennis Panagiotopoulos (@den_n1s)</author>
        /// <param name="GptTmplPath">Path to the GptTmpl.inf file.</param>
        /// <returns>True if SeDenyNetworkLogonRight is enabled, false otherwise.</returns>
        public static bool GetSeDenyNetworkLogonRight(string GptTmplPath)
        {
            if (File.Exists(GptTmplPath))
            {
                foreach (string line in File.ReadAllLines(GptTmplPath, Encoding.UTF8))
                {
                    if (line.Contains(@"SeDenyNetworkLogonRight = *S-1-5-32-544"))
                    {
                        return true;
                    }
                }
            }
            return false;
        }

        /// <summary>
        /// Gets the value of SeDenyRemoteInteractiveLogonRight from a GptTmpl.inf file,
        /// which determines if Administrators are allowed to perform remote interactive authentication.
        /// </summary>
        /// <author>Dennis Panagiotopoulos (@den_n1s)</author>
        /// <param name="GptTmplPath">Path to the GptTmpl.inf file.</param>
        /// <returns>True if SeDenyRemoteInteractiveLogonRight is enabled, false otherwise.</returns>
        public static bool GetSeDenyRemoteInteractiveLogonRight(string GptTmplPath)
        {
            if (File.Exists(GptTmplPath))
            {
                foreach (string line in File.ReadAllLines(GptTmplPath, Encoding.UTF8))
                {
                    if (line.Contains(@"SeDenyRemoteInteractiveLogonRight = *S-1-5-32-544"))
                    {
                        return true;
                    }
                }
            }
            return false;
        }

        /// <summary>
        /// Gets domain computer objects for which remote access policies are applied via GPO.
        /// </summary>
        /// <author>Dennis Panagiotopoulos (@den_n1s)</author>
        /// <param name="Domain">pecifies the domain to use for the query, defaults to the current domain.</param>
        /// <param name="DomainController">Specifies an Active Directory server (domain controller) to bind to.</param>
        /// <param name="SearchScope">Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).</param>
        /// <param name="SearchBase">The LDAP source to search through, e.g. /OU=Workstations,DC=domain,DC=local. Useful for OU queries.</param>
        /// <returns>True if execution succeeds, false otherwise.</returns>
        /// <remarks>
        /// Credits to Jon Cave (@joncave) and William Knowles (@william_knows) for their PowerShell implementation.
        /// https://labs.mwrinfosecurity.com/blog/enumerating-remote-access-policies-through-gpo/
        /// </remarks>
        public static bool GetRemoteAccessPolicies(string Domain, string DomainController, string SearchScope, string SearchBase)
        {

            if(string.IsNullOrEmpty(SearchScope))
            {
                SearchScope = "SubTree";
            }

            if(string.IsNullOrEmpty(SearchBase))
            {
                SearchBase = "";
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
            if (string.IsNullOrEmpty(Domain))
            {
                try
                {
                    current_domain = System.DirectoryServices.ActiveDirectory.Domain.GetCurrentDomain();
                    Domain = current_domain.Name;
                }
                catch
                {
                    Console.Error.WriteLine("[!] Cannot enumerate domain.\n");
                    return false;
                }
            }
            else
            {
                DirectoryContext domainContext = new DirectoryContext(DirectoryContextType.Domain, Domain);
                try
                {
                    current_domain = System.DirectoryServices.ActiveDirectory.Domain.GetDomain(domainContext);
                }
                catch
                {
                    Console.Error.WriteLine("[!] The specified domain does not exist or cannot be contacted.\n");
                    return false;
                }

            }

            //retrieve domain controller
            if (string.IsNullOrEmpty(DomainController))
            {
                DomainController = current_domain.FindDomainController().Name;
            }
            else
            {
                var ldapId = new LdapDirectoryIdentifier(DomainController);
                using (var testConnection = new LdapConnection(ldapId))
                {
                    try
                    {
                        testConnection.Bind();
                    }
                    catch
                    {
                        Console.Error.WriteLine("[!] The specified domain controller cannot be contacted.\n");
                        return false;
                    }
                }
            }

            Domain = Domain.ToLower();

            String[] DC_array = null;
            String distinguished_name = null;
            distinguished_name = "CN=Policies,CN=System";
            DC_array = Domain.Split('.');

            foreach (String DC in DC_array)
            {
                distinguished_name += ",DC=" + DC;
            }

            LdapDirectoryIdentifier identifier = new LdapDirectoryIdentifier(DomainController, 389);
            LdapConnection connection = null;

            //make the connection to the domain controller
            connection = new LdapConnection(identifier);
            connection.SessionOptions.Sealing = true;
            connection.SessionOptions.Signing = true;
            try
            {
                connection.Bind();
            }
            catch
            {
                Console.Error.WriteLine("Domain controller cannot be contacted.\n");
                return false;
            }

            SearchRequest requestGUID = null;
            if (string.Equals(SearchScope, "SubTree"))
            {
                requestGUID = new SearchRequest(distinguished_name, "cn=*", System.DirectoryServices.Protocols.SearchScope.Subtree, null);
            }
            else if (string.Equals(SearchScope, "OneLevel"))
            {
                requestGUID = new SearchRequest(distinguished_name, "cn=*", System.DirectoryServices.Protocols.SearchScope.OneLevel, null);
            }
            else if (string.Equals(SearchScope, "Base"))
            {
                requestGUID = new SearchRequest(distinguished_name, "cn=*", System.DirectoryServices.Protocols.SearchScope.Base, null);
            }

            SearchResponse responseGUID = null;
            try
            {
                responseGUID = (SearchResponse)connection.SendRequest(requestGUID);
            }
            catch
            {
                Console.Error.WriteLine("Search scope is not valid.\n");
                return false;
            }

            if (!string.IsNullOrEmpty(SearchBase))
            {
                string adPath = "LDAP://" + Domain + SearchBase;
                if (!DirectoryEntry.Exists(adPath))
                {
                    Console.Error.WriteLine("[!] Search base is not valid.\n");
                    return false;
                }
            }

            foreach (SearchResultEntry entry in responseGUID.Entries)
            {
                try
                {
                    var requestAttributes = new SearchRequest(distinguished_name, "cn=" + entry.Attributes["cn"][0].ToString(), System.DirectoryServices.Protocols.SearchScope.OneLevel, null);
                    var responseAttributes = (SearchResponse)connection.SendRequest(requestAttributes);
                    foreach (SearchResultEntry attribute in responseAttributes.Entries)
                    {
                        try
                        {
                            string displayName = entry.Attributes["displayName"][0].ToString();
                            string name = entry.Attributes["name"][0].ToString();
                            string gpcfilesyspath = entry.Attributes["gpcfilesyspath"][0].ToString();

                            string uncPathGptTmpl = gpcfilesyspath + @"\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf";

                            bool enableLUA = GetEnableLua(uncPathGptTmpl);

                            if (enableLUA)
                            {
                                listEnableLUA.Add(name);
                            }

                            bool FilterAdministratorToken = GetFilterAdministratorToken(uncPathGptTmpl);

                            if (FilterAdministratorToken)
                            {
                                listFilterAdministratorToken.Add(name);
                            }

                            string uncPathRegistryXML = gpcfilesyspath + @"\MACHINE\Preferences\Registry\Registry.xml";

                            bool LocalAccountTokenFilterPolicy = GetLocalAccountTokenFilterPolicy(uncPathRegistryXML);

                            if (LocalAccountTokenFilterPolicy)
                            {
                                listLocalAccountTokenFilterPolicy.Add(name);
                            }

                            bool SeDenyNetworkLogonRight = GetSeDenyNetworkLogonRight(uncPathGptTmpl);

                            if (SeDenyNetworkLogonRight)
                            {
                                listSeDenyNetworkLogonRight.Add(name);
                            }

                            bool SeDenyRemoteInteractiveLogonRight = GetSeDenyRemoteInteractiveLogonRight(uncPathGptTmpl);

                            if (SeDenyRemoteInteractiveLogonRight)
                            {
                                listSeDenyRemoteInteractiveLogonRight.Add(name);
                            }

                        }
                        catch
                        {
                            Console.Error.WriteLine("[!] It was not possible to retrieve the displayname, name and gpcfilesypath\n");
                            return false;
                        }
                    }
                }
                catch
                {
                    Console.Error.WriteLine("[!] It was not possible to retrieve GPO Policies\n");
                    return false;
                }
            }

            Console.Write("[+] EnableLUA: \t\t\t\t");
            foreach (var guid in listEnableLUA)
            {
                DirectoryEntry startingPoint = null;
                string filterGPLink = "(&(objectCategory=organizationalUnit)(gplink=*" + guid + "*))";
                if (string.IsNullOrEmpty(SearchBase))
                {
                    startingPoint = new DirectoryEntry("LDAP://" + Domain);
                }
                else
                {
                    startingPoint = new DirectoryEntry("LDAP://" + Domain + SearchBase);
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
            Console.WriteLine();
            Console.Write("[+] FilterAdministratorToken: \t\t");
            foreach (var guid in listFilterAdministratorToken)
            {
                DirectoryEntry startingPoint = null;
                string filterGPLink = "(&(objectCategory=organizationalUnit)(gplink=*" + guid + "*))";
                if (string.IsNullOrEmpty(SearchBase))
                {
                    startingPoint = new DirectoryEntry("LDAP://" + Domain);
                }
                else
                {
                    startingPoint = new DirectoryEntry("LDAP://" + Domain + SearchBase);
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
            Console.WriteLine();
            Console.Write("[+] LocalAccountTokenFilterPolicy: \t");
            foreach (var guid in listLocalAccountTokenFilterPolicy)
            {
                DirectoryEntry startingPoint = null;
                string filterGPLink = "(&(objectCategory=organizationalUnit)(gplink=*" + guid + "*))";
                if (string.IsNullOrEmpty(SearchBase))
                {
                    startingPoint = new DirectoryEntry("LDAP://" + Domain);
                }
                else
                {
                    startingPoint = new DirectoryEntry("LDAP://" + Domain + SearchBase);
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
            Console.WriteLine();
            Console.Write("[+] SeDenyNetworkLogonRight: \t\t");
            foreach (var guid in listSeDenyNetworkLogonRight)
            {
                DirectoryEntry startingPoint = null;
                string filterGPLink = "(&(objectCategory=organizationalUnit)(gplink=*" + guid + "*))";
                if (string.IsNullOrEmpty(SearchBase))
                {
                    startingPoint = new DirectoryEntry("LDAP://" + Domain);
                }
                else
                {
                    startingPoint = new DirectoryEntry("LDAP://" + Domain + SearchBase);
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
            Console.WriteLine();
            Console.Write("[+] SeDenyRemoteInteractiveLogonRight: \t");
            foreach (var guid in listSeDenyRemoteInteractiveLogonRight)
            {
                DirectoryEntry startingPoint = null;
                string filterGPLink = "(&(objectCategory=organizationalUnit)(gplink=*" + guid + "*))";
                if (string.IsNullOrEmpty(SearchBase))
                {
                    startingPoint = new DirectoryEntry("LDAP://" + Domain);
                }
                else
                {
                    startingPoint = new DirectoryEntry("LDAP://" + Domain + SearchBase);
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
            Console.WriteLine();
            Console.WriteLine("[-] Enumeration finished");
            return true;
        }
    }
}