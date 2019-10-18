// Author: Ryan Cobb (@cobbr_io)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using System;
using System.Linq;
using System.Threading;
using System.ServiceProcess;
using System.ComponentModel;
using System.Collections.Generic;

using SharpSploit.Generic;
using SharpSploit.Execution;
using PInvoke = SharpSploit.Execution.PlatformInvoke;

namespace SharpSploit.LateralMovement
{
    /// <summary>
    /// SCM is a class for interacting with the Service Control Manager on a target computer.
    /// </summary>
    public class SCM
    {
        /// <summary>
        /// Get a service on a remote computer.
        /// </summary>
        /// <param name="ComputerName">The ComputerName of the remote machine.</param>
        /// <param name="DisplayName">The DisplayName of the service to retrieve.</param>
        /// <returns>ServiceResult that represents the given service. NULL if not found</returns>
        /// <author>Ryan Cobb (@cobbr_io)</author>
        public static ServiceResult GetService(string ComputerName, string DisplayName)
        {
            try
            {
                using (ServiceController service = new ServiceController(DisplayName, ComputerName))
                {
                    return service == null ? null : new ServiceResult
                    {
                        ServiceName = service.ServiceName,
                        DisplayName = service.DisplayName,
                        Status = service.Status,
                        CanStop = service.CanStop
                    };
                }
            }
            catch (Win32Exception) { return null; }
            catch (InvalidOperationException) { return null; }
        }

        /// <summary>
        /// Get all services on a remote computer.
        /// </summary>
        /// <param name="ComputerName">The ComputerName of the remote machine.</param>
        /// <returns>A SharpSploitResultList of ServiceResults. NULL if none found.</returns>
        /// <author>Daniel Duggan (@_RastaMouse)</author>
        public static SharpSploitResultList<ServiceResult> GetServices(string ComputerName)
        {
            try
            {
                SharpSploitResultList<ServiceResult> results = new SharpSploitResultList<ServiceResult>();
                IEnumerable<ServiceController> services = ServiceController.GetServices(ComputerName).OrderBy(S => S.ServiceName);
                foreach (ServiceController service in services)
                {
                    results.Add(new ServiceResult
                    {
                        ServiceName = service.ServiceName,
                        DisplayName = service.DisplayName,
                        Status = service.Status,
                        CanStop = service.CanStop
                    });
                    service.Dispose();
                }
                return results;
            }
            catch (Win32Exception) { return null; }
            catch (InvalidOperationException) { return null; }
        }

        /// <summary>
        /// Creates a new service on a remote computer.
        /// </summary>
        /// <param name="ComputerName">The ComputerName of the remote machine.</param>
        /// <param name="ServiceName">The short service name.</param>
        /// <param name="ServiceDisplayName">The friendly display name.</param>
        /// <param name="BinaryPath">The path to the Service executable.</param>
        /// <returns>Bool. True if execution succeeds, false otherwise.</returns>
        /// <author>Daniel Duggan (@_RastaMouse)</author>
        public static bool CreateService(string ComputerName, string ServiceName, string ServiceDisplayName, string BinaryPath)
        {
            bool success = false;
            IntPtr hManager = OpenServiceManager(ComputerName);
            IntPtr hService = PInvoke.Win32.Advapi32.CreateService(hManager, ServiceName, ServiceDisplayName,
                Win32.Advapi32.SERVICE_ACCESS.SERVICE_ALL_ACCESS,
                Win32.Advapi32.SERVICE_TYPE.SERVICE_WIN32_OWN_PROCESS,
                Win32.Advapi32.SERVICE_START.SERVICE_DEMAND_START,
                Win32.Advapi32.SERVICE_ERROR.SERVICE_ERROR_NORMAL,
                BinaryPath, null, null, null, null, null);
            if (hService != IntPtr.Zero)
            {
                success = true;
            }

            CloseHandle(hService);
            CloseHandle(hManager);
            return success;
        }

        /// <summary>
        /// Starts a service on a remote computer.
        /// </summary>
        /// <param name="ComputerName">The ComputerName of the remote machine.</param>
        /// <param name="DisplayName">The DisplayName of the service to retrieve.</param>
        /// <returns>Bool. True if execution succeeds, false otherwise.</returns>
        /// <author>Daniel Duggan (@_RastaMouse)</author>
        public static bool StartService(string ComputerName, string DisplayName)
        {
            try
            {
                using (ServiceController service = new ServiceController(DisplayName, ComputerName))
                {
                    if (service.Status == ServiceControllerStatus.Running)
                    {
                        return true;
                    }
                    if (service.Status == ServiceControllerStatus.StartPending)
                    {
                        service.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(30));
                        return true;
                    }
                    service.Start();
                    service.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(30));
                    return true;
                }
            }
            catch (System.ComponentModel.Win32Exception e)
            {
                Console.Error.WriteLine(e.Message);
            }
            return false;
        }

        /// <summary>
        /// Stops a service on a remote computer.
        /// </summary>
        /// <param name="ComputerName">The ComputerName of the remote machine.</param>
        /// <param name="DisplayName">The DisplayName of the service to stop.</param>
        /// <returns>Bool. True if execution succeeds, false otherwise.</returns>
        /// <author>Daniel Duggan (@_RastaMouse)</author>
        public static bool StopService(string ComputerName, string DisplayName)
        {
            try
            {
                using (ServiceController service = new ServiceController(DisplayName, ComputerName))
                {
                    if (service.Status == ServiceControllerStatus.Stopped)
                    {
                        return true;
                    }
                    if (service.Status == ServiceControllerStatus.StopPending)
                    {
                        service.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(30));
                        return true;
                    }
                    service.Stop();
                    service.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(30));
                    return true;
                }
            }
            catch (System.ComponentModel.Win32Exception e)
            {
                Console.Error.WriteLine(e.Message);
            }
            return false;
        }

        /// <summary>
        /// Deletes a service on a remote computer.
        /// </summary>
        /// <param name="ComputerName">The ComputerName of the remote machine.</param>
        /// <param name="ServiceName">The short ServiceName of the service to delete.</param>
        /// <returns>Bool. True if execution succeeds, false otherwise.</returns>
        /// <author>Daniel Duggan (@_RastaMouse)</author>
        public static bool DeleteService(string ComputerName, string ServiceName)
        {
            bool success = false;
            try
            {
                IntPtr hManager = OpenServiceManager(ComputerName);
                IntPtr hService = PInvoke.Win32.Advapi32.OpenService(hManager, ServiceName, Win32.Advapi32.SERVICE_ACCESS.DELETE);
                success = PInvoke.Win32.Advapi32.DeleteService(hService);
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
        /// Execute a process on a remote computer using a PSExec-like technique.
        /// </summary>
        /// <param name="ComputerName">The ComputerName of the remote machine.</param>
        /// <param name="ServiceName">The short ServiceName of the service to create.</param>
        /// <param name="DisplayName">The DisplayName of the service to create.</param>
        /// <param name="BinaryPath">The path to the Service Executable.</param>
        /// <returns>Bool. True if execution succeeds, false otherwise.</returns>
        /// <author>Daniel Duggan (@_RastaMouse)</author>
        public static bool PSExec(string ComputerName, string BinaryPath, string ServiceName = "SharpSploit", string DisplayName = "SharpSploit Service")
        {
            // We need a little wait after each step
            const int sleepTime = 1000;
            try
            {
                // Connect to the target service manager
                IntPtr hManager = OpenServiceManager(ComputerName);
                if (hManager == IntPtr.Zero)
                {
                    return false;
                }

                // Create the service
                Thread.Sleep(sleepTime);
                if (!CreateService(ComputerName, ServiceName, DisplayName, BinaryPath))
                {
                    return false;
                }

                // Start the service
                Thread.Sleep(sleepTime);
                // If the service started successfully...
                bool started = StartService(ComputerName, ServiceName);
                if (started)
                {
                    // Stop the service
                    Thread.Sleep(sleepTime);
                    if (!StopService(ComputerName, ServiceName))
                    {
                        Console.Error.WriteLine("Could not stop service {0}", ServiceName);
                    }
                }
                else
                {
                    Console.Error.WriteLine("Could not start service {0}", ServiceName);
                    // don't return, so we can still delete the service
                }

                // Now delete the service
                Thread.Sleep(sleepTime);
                if (!DeleteService(ComputerName, ServiceName))
                {
                    Console.Error.WriteLine("Could not delete Service {0}", ServiceName);
                    return false;
                }

                Thread.Sleep(sleepTime);
                CloseHandle(hManager);

                // If we got to the end and didn't start the service, we should return false
                return started;
            }
            catch (Exception e)
            {
                Console.Error.WriteLine("PSExec Failed: {0}", e.Message);
            }
            return false;
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
                success = PInvoke.Win32.Advapi32.CloseServiceHandle(handle);
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
                handle = PInvoke.Win32.Advapi32.OpenSCManager(ComputerName, null, Win32.Advapi32.SCM_ACCESS.SC_MANAGER_CREATE_SERVICE);
            }
            catch (Exception e)
            {
                Console.Error.WriteLine(e.Message);
            }
            return handle;
        }

        public sealed class ServiceResult : SharpSploitResult
        {
            public string ServiceName { get; set;  } = "";
            public string DisplayName { get; set; } = "";
            public ServiceControllerStatus Status { get; set; } = new ServiceControllerStatus();
            public bool CanStop { get; set; } = false;
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
        }
    }
}