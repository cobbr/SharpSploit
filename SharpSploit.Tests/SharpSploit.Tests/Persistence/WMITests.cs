// Author: Ryan Cobb (@cobbr_io)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using System.IO;
using System.Threading;
using System.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;

using SharpSploit.Persistence;

namespace SharpSploit.Tests.Persistence
{
    [TestClass]
    public class WMITests
    {
        private static Process StartNotepad()
        {
            ProcessStartInfo startInfo = new ProcessStartInfo();
            startInfo.FileName = @"C:\Windows\System32\notepad.exe";
            startInfo.WindowStyle = ProcessWindowStyle.Hidden;
            return Process.Start(startInfo);
        }

        [TestMethod]
        public void TestInstallWMICommandLine()
        {
            string filePath = @"C:\CommandLineTest.txt";
            string command = $@"cmd /c ""echo ""Command Line Test"" > {filePath}""";

            WMI.InstallWMIPersistence("CommandLineTest", WMI.EventFilter.ProcessStart, WMI.EventConsumer.CommandLine, command, "notepad.exe");

            Process notepad = StartNotepad();
            Thread.Sleep(3000);

            Assert.IsTrue(File.Exists(filePath));
        }

        [TestMethod]
        public void TestInstallWMIVBScript()
        {
            string filePath = @"C:\VBScriptTest.txt";
            string vbscript = $@"
Set objFSO=CreateObject(""Scripting.FileSystemObject"")
outFile = ""{filePath}""
Set objFile = objFSO.CreateTextFile(outFile, True)
objFile.Write ""VBScript Test""
objFile.Close";

            WMI.InstallWMIPersistence("VBScriptTest", WMI.EventFilter.ProcessStart, WMI.EventConsumer.ActiveScript, vbscript, "notepad.exe", WMI.ScriptingEngine.VBScript);

            Process notepad = StartNotepad();
            Thread.Sleep(3000);

            Assert.IsTrue(File.Exists(filePath));
        }

        [TestMethod]
        public void TestInstallWMIJScript()
        {
            string filePath = @"C:\\JScriptTest.txt";
            string jscript = $@"
var myObject, newfile;
myObject = new ActiveXObject(""Scripting.FileSystemObject"");
newfile = myObject.CreateTextFile(""{filePath}"", false);
";

            WMI.InstallWMIPersistence("JScriptTest", WMI.EventFilter.ProcessStart, WMI.EventConsumer.ActiveScript, jscript, "notepad.exe", WMI.ScriptingEngine.JScript);

            Process notepad = StartNotepad();
            Thread.Sleep(3000);

            Assert.IsTrue(File.Exists(filePath));
        }
    }
}