// Author: Ryan Cobb (@cobbr_io)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using System.Net;
using System.Linq;
using System.Threading;
using System.Net.Sockets;
using System.Collections.Generic;

using SharpSploit.Generic;

namespace SharpSploit.Pivoting
{
    public class ReversePortForwarding
    {
        public class ReversePortForward
        {
            public IPAddress[] BindAddresses { get; set; }
            public int BindPort { get; set; }
            public IPAddress ForwardAddress { get; set; }
            public int ForwardPort { get; set; }
        }

        static List<ReversePortForward> _reversePortForwards = new List<ReversePortForward>();
        static List<Dictionary<int, List<Socket>>> _boundSockets = new List<Dictionary<int, List<Socket>>>();

        /// <summary>
        /// Creates a new Reverse Port Forward.
        /// </summary>
        /// <param name="BindPort">The port to bind on the local system.</param>
        /// <param name="ForwardAddress">The IP Address or DNS name to forward traffic to.</param>
        /// <param name="ForwardPort">The port to forward traffic to.</param>
        /// <returns>Bool.</returns>
        /// <author>Daniel Duggan (@_RastaMouse)</author>
        public static bool AddReversePortForward(string BindPort, string ForwardAddress, string ForwardPort)
        {
            // Sort inputs out
            if (!int.TryParse(BindPort, out int bindPort) || !int.TryParse(ForwardPort, out int forwardPort))
                return false;

            var bindAddresses = new IPAddress[] { IPAddress.Any };

            // If ForwardHost is not a valid IP, try to resolve it as DNS.
            if (!IPAddress.TryParse(ForwardAddress, out IPAddress forwardAddress))
            {
                try
                {
                    var ipHostInfo = Dns.GetHostEntry(ForwardAddress);
                    forwardAddress = ipHostInfo.AddressList[0];
                }
                catch { return false; }
            }

            // Check if bindPort is not already bound.
            foreach (var boundSocket in _boundSockets)
                if (boundSocket.ContainsKey(bindPort))
                    return false;

            // Bind the sockets
            var newBoundSockets = BindSocket(bindAddresses, bindPort);
            if (newBoundSockets != null && newBoundSockets.Count > 0)
            {
                var newReversePortForward = new ReversePortForward
                {
                    BindAddresses = bindAddresses,
                    BindPort = bindPort,
                    ForwardAddress = forwardAddress,
                    ForwardPort = forwardPort
                };

                // Add to Lists
                _reversePortForwards.Add(newReversePortForward);
                _boundSockets.Add(new Dictionary<int, List<Socket>> { { bindPort, newBoundSockets } });

                // Kick off client sockets in new thread.
                var clientThread = new Thread(() => CreateClientSocketThread(newBoundSockets, forwardAddress, forwardPort));
                clientThread.Start();

                return true;
            }
            else
            {
                return false;
            }
        }

        /// <summary>
        /// Deletes an active Reverse Port Forward.
        /// </summary>
        /// <param name="BindPort">The bind port of the Reverse Port Forward.</param>
        /// <returns>Bool.</returns>
        /// <author>Daniel Duggan (@_RastaMouse)</author>
        public static bool DeleteReversePortForward(string BindPort)
        {
            var success = false;

            if (!int.TryParse(BindPort, out int bindPort))
                return false;

            if (_boundSockets.Count == 0)
                return false;

            try
            {
                foreach (var boundSocket in _boundSockets)
                {
                    if (boundSocket.TryGetValue(bindPort, out List<Socket> sockets))
                    {
                        foreach (var socket in sockets)
                        {
                            try { socket.Shutdown(SocketShutdown.Both); }
                            catch (SocketException) { }
                            socket.Close();
                        }

                        _boundSockets.Remove(boundSocket);

                        var reversePortForward = _reversePortForwards.Where(r => r.BindPort.Equals(bindPort)).FirstOrDefault();
                        _reversePortForwards.Remove(reversePortForward);

                        success = true;
                    }
                }
            }
            catch { }

            return success;
        }

        public static SharpSploitResultList<ReversePortFwdResult> ListReversePortForwards()
        {
            var reversePortForwards = new SharpSploitResultList<ReversePortFwdResult>();

            foreach (var rportwd in _reversePortForwards)
            {
                var bindAddresses = string.Join(",", rportwd.BindAddresses.Select(a => a.ToString()).ToArray());
                reversePortForwards.Add(new ReversePortFwdResult
                {
                    BindAddresses = bindAddresses,
                    BindPort = rportwd.BindPort,
                    ForwardAddress = rportwd.ForwardAddress.ToString(),
                    ForwardPort = rportwd.ForwardPort
                });
            }
            return reversePortForwards;
        }

        /// <summary>
        /// Delete all active Reverse Port Forwards.
        /// </summary>
        /// <author>Daniel Duggan (@_RastaMouse)</author>
        public static void FlushReversePortFowards()
        {
            if (_boundSockets.Count == 0)
                return;

            try
            {
                foreach (var dict in _boundSockets)
                {
                    foreach (var list in dict.Values)
                    {
                        foreach (var socket in list)
                        {
                            try { socket.Shutdown(SocketShutdown.Both); }
                            catch (SocketException) { }
                            socket.Close();
                        }

                    }
                }

                _boundSockets.Clear();
                _reversePortForwards.Clear();
            }
            catch { }
        }

        private static List<Socket> BindSocket(IPAddress[] BindAddreses, int BindPort)
        {
            var socketList = new List<Socket>();

            foreach (var bindAddress in BindAddreses)
            {
                var localEP = new IPEndPoint(bindAddress, BindPort);
                var socket = new Socket(bindAddress.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                try
                {
                    socket.Bind(localEP);
                    socket.Listen(10);
                    socketList.Add(socket);
                }
                catch (SocketException) { }
            }
            return socketList;
        }

        private static void CreateClientSocketThread(List<Socket> BoundSockets, IPAddress ForwardAddress, int ForwardPort)
        {
            var remoteEP = new IPEndPoint(ForwardAddress, ForwardPort);

            while (true)
            {
                var boundBuffer = new byte[1024];
                var clientBuffer = new byte[1048576];

                foreach (var boundSocket in BoundSockets)
                {
                    try
                    {
                        // Receive data on bound socket
                        var handler = boundSocket.Accept();
                        handler.Receive(boundBuffer);

                        // Create new client socket
                        using (var clientSocket = new Socket(ForwardAddress.AddressFamily, SocketType.Stream, ProtocolType.Tcp))
                        {
                            try
                            {
                                clientSocket.Connect(remoteEP);
                                clientSocket.Send(boundBuffer);
                                clientSocket.Receive(clientBuffer);
                            }
                            catch (SocketException) { }
                        }
                        handler.Send(clientBuffer);
                    }
                    catch { }
                }
            }
        }

        public sealed class ReversePortFwdResult : SharpSploitResult
        {
            public string BindAddresses { get; set; }
            public int BindPort { get; set; }
            public string ForwardAddress { get; set; }
            public int ForwardPort { get; set; }
            protected internal override IList<SharpSploitResultProperty> ResultProperties
            {
                get
                {
                    return new List<SharpSploitResultProperty> {
                        new SharpSploitResultProperty { Name = "BindAddresses", Value = this.BindAddresses },
                        new SharpSploitResultProperty { Name = "BindPort", Value = this.BindPort },
                        new SharpSploitResultProperty { Name = "ForwardAddress", Value = this.ForwardAddress },
                        new SharpSploitResultProperty { Name = "ForwardPort", Value = this.ForwardPort }
                    };
                }
            }
        }
    }
}