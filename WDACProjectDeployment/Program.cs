using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;
using System.Management.Automation.Runspaces;
using System.Management;
using System.Security;
using System.Management.Automation;
using System.IO;
using System.Security.AccessControl;
using System.Diagnostics;

namespace WDACProjectDeployment
{
    class Program
    {

        


        static void Main(string[] args)
        {

            // File path of the policy XML file
            string policyXmlFile = @"C:\Windows\schemas\CodeIntegrity\ExamplePolicies\DefaultWindows_Enforced.xml";
            // File path of the binary file to be created
            string binaryFile = @"C:\users\forensics\policy.bin";

            // Create a PowerShell object
            Runspace runspace = RunspaceFactory.CreateRunspace();
            runspace.Open();
            PowerShell ps = PowerShell.Create();
            ps.Runspace = runspace;
            
            // Execute the PowerShell command to convert the policy XML file to a binary file
            ps.AddCommand("ConvertFrom-CIPolicy");
            ps.AddParameter("XmlFilePath", policyXmlFile);
            ps.AddParameter("BinaryFilePath", binaryFile);
            ps.Invoke();

            
            //string dstFile = @"%systemroot%\System32\CodeIntegrity\SiPolicy.p7b";
            string dstFilepath = "C:\\Windows\\System32\\CodeIntegrity\\SiPolicy.p7b";
            Dictionary<string, string> dic = new Dictionary<string, string>();
            dic.Add("FilePath", dstFilepath);
            //string dstFilename = @"SiPolicy.p7b";

            string namepsacestring = "root\\Microsoft\\Windows\\CI";
            string classnamestring = "PS_UpdateAndCompareCIPolicy";
            string methodname = "UpdateAndCompare";
            try
            {
                if (CopyFileFromSrcDst(binaryFile, dstFilepath))
                {
                    //ps.AddCommand("Invoke-CimMethod").AddParameter("Namespace", namepsacestring).AddParameter("ClassName", classnamestring).AddParameter("MethodName", methodname).AddParameter("Arguments", dic).Invoke();
                    
                    
                    /*var process = new Process
                    {
                        StartInfo = new ProcessStartInfo
                        {
                            FileName = @"C:\Users\forensics\Desktop\RefreshPolicyAMD64.exe",
                            UseShellExecute = false,
                            RedirectStandardOutput = true,
                            CreateNoWindow = true
                        }
                    };
                    process.Start();*/


                    ConnectionOptions options = new ConnectionOptions();
                    options.Impersonation = ImpersonationLevel.Impersonate;
                    options.Authentication = AuthenticationLevel.Default;
                    options.EnablePrivileges = true;

                    // Connect to the WMI namespace
                    ManagementScope scope = new ManagementScope(@"root\Microsoft\Windows\CI", options);
                    scope.Connect();

                    // Create the method parameters
                    ManagementBaseObject inParams = null;
                    inParams = new ManagementClass(scope, new ManagementPath("PS_UpdateAndCompareCIPolicy"), null).GetMethodParameters("Update");
                    inParams["FilePath"] = dstFilepath;

                    // Invoke the method
                    ManagementBaseObject outParams = null;
                    using (ManagementClass cimClass = new ManagementClass(scope, new ManagementPath("PS_UpdateAndCompareCIPolicy"), null))
                    {
                        outParams = cimClass.InvokeMethod("Update", inParams, null);
                    }
                    if (outParams != null)
                    {
                        uint retVal = (uint)outParams["ReturnValue"];
                    }
                }
            }
            catch(Exception ex) { }
            


            // Check for errors
            if (ps.HadErrors)
            {
                foreach (ErrorRecord error in ps.Streams.Error)
                {
                    Console.WriteLine("Error: {0}", error.ToString());
                }
                Console.WriteLine("Failed to convert policy XML file to binary file");
            }
            else
            {
                Console.WriteLine("Policy XML file converted to binary file successfully");
            }


        }



        /// <summary>
        /// 
        /// </summary>
        /// <param name="src">file source path</param>
        /// <param name="dst"></param>
        /// <returns></returns>
        public static bool CopyFileFromSrcDst(string src, string dst)
        {
            try
            {
                if (!string.IsNullOrEmpty(src) && !string.IsNullOrEmpty(dst))
                {
                    
                    if (File.Exists(src) && Directory.Exists(Directory.GetParent(dst).FullName))
                    {
                        File.Copy(src, dst, true);
                        if (File.Exists(dst))
                        {
                            return true;
                        }
                    }
                }
            }
            catch(Exception ex) { }
            return false;
        }

        public static bool SetReadAccessFolder(string dst)
        {
            FileSystemRights Rights = (FileSystemRights)0;
            Rights = FileSystemRights.Read;

            try
            {            
                // *** Add Access Rule to the actual directory itself
                FileSystemAccessRule AccessRule = new FileSystemAccessRule("Administrators", Rights,
                                            InheritanceFlags.None,
                                            PropagationFlags.NoPropagateInherit,
                                            AccessControlType.Allow);

                DirectoryInfo Info = new DirectoryInfo(dst);
                DirectorySecurity Security = Info.GetAccessControl(AccessControlSections.Access);

                bool Result = false;
                Security.ModifyAccessRule(AccessControlModification.Set, AccessRule, out Result);

                if (!Result)
                    return false;

                // *** Always allow objects to inherit on a directory
                InheritanceFlags iFlags = InheritanceFlags.ObjectInherit;
                iFlags = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;

                // *** Add Access rule for the inheritance
                AccessRule = new FileSystemAccessRule("Administrators", Rights,
                                            iFlags,
                                            PropagationFlags.InheritOnly,
                                            AccessControlType.Allow);
                Result = false;
                Security.ModifyAccessRule(AccessControlModification.Add, AccessRule, out Result);

                if (!Result)
                    return false;

                Info.SetAccessControl(Security);
            }
            catch(Exception ex) { }
            return true;
        }
    }
}
