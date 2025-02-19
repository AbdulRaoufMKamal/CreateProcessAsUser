
using Microsoft.Extensions.Hosting;
using murrayju.ProcessExtensions;
using System.Diagnostics;

namespace DemoModernService;

internal class DemoModernService : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        string path = AppDomain.CurrentDomain.BaseDirectory;
        int levelsUp = 5;
        for (int i = 0; i < levelsUp; i++)
        {
            path = Directory.GetParent(path)?.FullName ?? path;
        }
        Debug.WriteLine("OUTPUT PATH: " + path);
        string appPath = "AppWithPrivileges.exe";
        string? workDir = Path.Combine(path, "AppWithPrivileges", "bin", "Debug", "net6.0-windows");
        ProcessExtensions.StartProcessAsCurrentUser(appPath: appPath, workDir: workDir);
        //ProcessExtensions.StartProcessAsCurrentUser("calc.exe");
    }
}