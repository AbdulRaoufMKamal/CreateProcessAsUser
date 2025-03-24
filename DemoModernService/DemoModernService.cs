
using Microsoft.Extensions.Hosting;
using murrayju.ProcessExtensions;
using System.Diagnostics;

namespace DemoModernService;

internal class DemoModernService : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        string appPath = "AppWithPrivileges.exe";
        
        string solutionDirectory = Directory.GetParent(AppDomain.CurrentDomain.BaseDirectory).Parent.Parent.Parent.Parent.FullName;
        string targetProjectName = Path.GetFileNameWithoutExtension(appPath);
        string workDir = Path.Combine(solutionDirectory, targetProjectName, "bin", "Debug", "net6.0-windows");

        /* NOTE YOU MUST COMMENT ONE OF THE BELOW LINES BASED ON YOUR CHOICE OF RUNNING THE SERVICE */

        // DEBUG MODE
        ProcessExtensions.LaunchProcess(appPath: appPath, workDir: workDir, asAdmin: false);

        // SERVICE MODE
        ProcessExtensions.LaunchProcess(appPath: appPath, workDir: workDir, asAdmin: true);
    }
}