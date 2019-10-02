// Author: Ryan Cobb (@cobbr_io)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using System;
using System.Linq;
using System.Threading;
using System.ServiceProcess;
using System.Collections.Generic;

using SharpSploit.Generic;
using SharpSploit.Execution;

namespace SharpSploit.LateralMovement
{
    /// <summary>
    /// Service is a class for interacting with the Service Control Manager on a target computer.
    /// </summary>
    public class Service
    {
        /// <summary>
        /// Query Services on a remote target.
        /// </summary>
        /// <param name="ComputerName">The target computer.</param>
        /// <param name="ServiceName">Optional. The short service name.</param>
        /// <returns>A SharpSploitResultList of services.</returns>
        /// <author>Daniel Duggan (@_RastaMouse)</author>
        public static SharpSploitResultList<ServiceResult> QueryServices(string ComputerName, string ServiceName = "")
        {
            SharpSploitResultList<ServiceResult> results = new SharpSploitResultList<ServiceResult>();
            try
            {
                var services = ServiceController.GetServices(ComputerName).OrderBy(S => S.ServiceName);
                if (ServiceName != "")
                {
                    var service = services.Where(s => s.ServiceName == ServiceName).FirstOrDefault();
                    results.Add(new ServiceResult(service.ServiceName, service.DisplayName, service.Status, service.CanStop));
                }
                else
                {
                    foreach (var service in services)
                    {
                        results.Add(new ServiceResult(service.ServiceName, service.DisplayName, service.Status, service.CanStop));
                    }
                }
                return results;
            }
            catch (Exception e)
            {
                Console.Error.WriteLine(e.Message);
            }
            return results;
        }

        /// <summary>
        /// Creates a new service on the target computer.
        /// </summary>
        /// <param name="ComputerName">The target computer.</param>
        /// <param name="ServiceName">The short service name.</param>
        /// <param name="ServiceDisplayName">The friendly display name.</param>
        /// <param name="BinaryPath">The path to the Service Executable.</param>
        /// <returns>Bool. True if execution succeeds, false otherwise.</returns>
        /// <author>Daniel Duggan (@_RastaMouse)</author>
        public static bool CreateService(string ComputerName, string ServiceName, string ServiceDisplayName, string BinaryPath)
        {
            var success = false;
            try
            {
                var hManager = OpenServiceManager(ComputerName);
                var hService = Win32.Advapi32.CreateService(hManager, ServiceName, ServiceDisplayName,
                    Win32.Advapi32.SERVICE_ACCESS.SERVICE_ALL_ACCESS,
                    Win32.Advapi32.SERVICE_TYPE.SERVICE_WIN32_OWN_PROCESS,
                    Win32.Advapi32.SERVICE_START.SERVICE_DEMAND_START,
                    Win32.Advapi32.SERVICE_ERROR.SERVICE_ERROR_NORMAL,
                    BinaryPath, null, null, null, null, null);
                if (hService != IntPtr.Zero)
                    success = true;

                CloseHandle(hService);
                CloseHandle(hManager);
            }
            catch (Exception e)
            {
                Console.Error.WriteLine(e.Message);
            }
            return success;
        }

        /// <summary>
        /// Starts a service.
        /// </summary>
        /// <param name="ComputerName">The target computer.</param>
        /// <param name="ServiceName">The (short) service name to start.</param>
        /// <returns>Bool. True if execution succeeds, false otherwise.</returns>
        /// <author>Daniel Duggan (@_RastaMouse)</author>
        public static bool StartService(string ComputerName, string ServiceName)
        {
            var success = false;
            try
            {
                using (var service = new ServiceController(ServiceName, ComputerName))
                {
                    if (service.Status == ServiceControllerStatus.Running || service.Status == ServiceControllerStatus.StartPending)
                        success = true;

                    service.Start();
                    service.WaitForStatus(ServiceControllerStatus.Running);
                    success = true;
                }
            }
            catch (Exception e)
            {
                Console.Error.WriteLine(e.Message);
            }
            return success;
        }

        /// <summary>
        /// Stops a service.
        /// </summary>
        /// <param name="ComputerName">The target computer.</param>
        /// <param name="ServiceName">The (short) service name to stop.</param>
        /// <returns>Bool. True if execution succeeds, false otherwise.</returns>
        /// <author>Daniel Duggan (@_RastaMouse)</author>
        public static bool StopService(string ComputerName, string ServiceName)
        {
            var success = false;
            try
            {
                using (var service = new ServiceController(ServiceName, ComputerName))
                {
                    if (service.Status == ServiceControllerStatus.Stopped || service.Status == ServiceControllerStatus.StopPending)
                        success = true;

                    service.Stop();
                    service.WaitForStatus(ServiceControllerStatus.Stopped);
                    success = true;
                }
            }
            catch (Exception e)
            {
                Console.Error.WriteLine(e.Message);
            }
            return success;
        }

        /// <summary>
        /// Deletes a service.
        /// </summary>
        /// <param name="ComputerName">The target computer.</param>
        /// <param name="ServiceName">The (short) service name to delete.</param>
        /// <returns>Bool. True if execution succeeds, false otherwise.</returns>
        /// <author>Daniel Duggan (@_RastaMouse)</author>
        public static bool DeleteService(string ComputerName, string ServiceName)
        {
            var success = false;
            try
            {
                var hManager = OpenServiceManager(ComputerName);
                var hService = Win32.Advapi32.OpenService(hManager, ServiceName, Win32.Advapi32.SERVICE_ACCESS.DELETE);
                success = Win32.Advapi32.DeleteService(hService);
                CloseHandle(hService);
                CloseHandle(hManager);
            }
            catch (Exception e)
            {
                Console.Error.WriteLine(e.Message);
            }
            return success;
        }

        /// <summary>
        /// Execute a process on a remote system using PSExec.
        /// </summary>
        /// <param name="ComputerName">The target computer.</param>
        /// <param name="ServiceName">The short service name.</param>
        /// <param name="ServiceDisplayName">The friendly display name.</param>
        /// <param name="BinaryPath">The path to the Service Executable.</param>
        /// <returns>Bool. True if execution succeeds, false otherwise.</returns>
        /// <author>Daniel Duggan (@_RastaMouse)</author>
        public static bool PSExec(string ComputerName, string BinaryPath, string ServiceName = "SharpSploit", string ServiceDisplayName = "SharpSploit Service")
        {
            // We need a little wait after each step
            const int sleepTime = 1000;
            var success = false;
            try
            {
                // Connect to the target service manager
                var hManager = OpenServiceManager(ComputerName);

                if (hManager == IntPtr.Zero)
                    return false;

                // Create the service
                Thread.Sleep(sleepTime);
                var created = CreateService(ComputerName, ServiceName, ServiceDisplayName, BinaryPath);
                if (!created)
                    return false;

                // Start the service
                Thread.Sleep(sleepTime);
                var started = StartService(ComputerName, ServiceName);

                // If the service started successfully...
                if (started)
                {
                    // Stop the service
                    Thread.Sleep(sleepTime);
                    var stopped = StopService(ComputerName, ServiceName);

                    if (!stopped)
                        Console.Error.WriteLine("Could not stop service {0}", ServiceName);
                }
                else
                    Console.Error.WriteLine("Could not start service {0}", ServiceName);
                // don't return, so we can still delete the service


                // Now delete the service
                Thread.Sleep(sleepTime);
                var deleted = DeleteService(ComputerName, ServiceName);

                if (!deleted)
                {
                    Console.Error.WriteLine("Could not delete Service {0}", ServiceName);
                    return false;
                }

                Thread.Sleep(sleepTime);
                CloseHandle(hManager);

                // If we got to the end and didn't start the service, we should return false
                if (!started)
                    success = false;
                else
                    success = true;
            }
            catch (Exception e)
            {
                Console.Error.WriteLine("PSExec Failed: {0}", e.Message);
                success = false;
            }
            return success;
        }

        /// <summary>
        /// Closes Service Handles.
        /// </summary>
        /// <param name="handle">The handle to close.</param>
        /// <returns>Bool. True if execution succeeds, false otherwise.</returns>
        /// <author>
        /// Daniel Duggan (@_RastaMouse)
        /// </author>
        private static bool CloseHandle(IntPtr handle)
        {
            var success = false;
            try
            {
                success = Win32.Advapi32.CloseServiceHandle(handle);
            }
            catch (Exception e)
            {
                Console.Error.WriteLine(e.Message);
            }
            return success;
        }

        /// <summary>
        /// Opens the Service Control Manager on the target computer.
        /// </summary>
        /// <param name="ComputerName">The target computer.</param>
        /// <returns>IntPtr. Returns a handle to the SCM.</returns>
        /// <author>Daniel Duggan (@_RastaMouse)</author>
        private static IntPtr OpenServiceManager(string ComputerName)
        {
            var handle = IntPtr.Zero;
            try
            {
                handle = Win32.Advapi32.OpenSCManager(ComputerName, null, Win32.Advapi32.SCM_ACCESS.SC_MANAGER_CREATE_SERVICE);
            }
            catch (Exception e)
            {
                Console.Error.WriteLine(e.Message);
            }
            return handle;
        }

        public sealed class ServiceResult : SharpSploitResult
        {
            public string ServiceName { get; } = "";
            public string DisplayName { get; } = "";
            public ServiceControllerStatus Status { get; } = new ServiceControllerStatus();
            public bool CanStop { get; } = false;
            protected internal override IList<SharpSploitResultProperty> ResultProperties
            {
                get
                {
                    return new List<SharpSploitResultProperty> {
                        new SharpSploitResultProperty { Name = "ServiceName", Value = this.ServiceName },
                        new SharpSploitResultProperty { Name = "DisplayName", Value = this.DisplayName },
                        new SharpSploitResultProperty { Name = "Status", Value = this.Status },
                        new SharpSploitResultProperty { Name = "CanStop", Value = this.CanStop }
                    };
                }
            }

            public ServiceResult(string ServiceName = "", string DisplayName = "", ServiceControllerStatus Status = new ServiceControllerStatus(), bool CanStop = false)
            {
                this.ServiceName = ServiceName;
                this.DisplayName = DisplayName;
                this.Status = Status;
                this.CanStop = CanStop;
            }
        }
    }
}