using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.ServiceProcess;

internal static class Constants
{
    public const string ServiceName = "AppElevator";
    public const string EventSource = "AppElevator";
    public const string EventLogName = "Application";
    public const int ServiceLogEventId = 1000;
    public const int TriggerEventId = 1001;
}

internal sealed class AppElevatorService : ServiceBase
{
    private EventLogWatcher? _watcher;
    private readonly object _sync = new();
    private long? _lastRecordId;

    public AppElevatorService()
    {
        ServiceName = Constants.ServiceName;
        CanStop = true;
        CanPauseAndContinue = false;
        AutoLog = false;
    }

    protected override void OnStart(string[] args)
    {
        try
        {
            EnsureEventSource();
            StartWatcher();
            WriteServiceLog("Service started and watching for trigger events.");
        }
        catch (Exception ex)
        {
            WriteServiceLog($"Failed to start service: {ex}", EventLogEntryType.Error);
            throw;
        }
    }

    protected override void OnStop()
    {
        try
        {
            _watcher?.Dispose();
            _watcher = null;
            WriteServiceLog("Service stopped.");
        }
        catch (Exception ex)
        {
            WriteServiceLog($"Failed to stop service cleanly: {ex}", EventLogEntryType.Warning);
        }
    }

    private void StartWatcher()
    {
        var query = new EventLogQuery(Constants.EventLogName, PathType.LogName,
            $"*[System[(EventID={Constants.TriggerEventId}) and Provider[@Name='{Constants.EventSource}']]]");

        var bookmark = GetLatestBookmark();

        _watcher = new EventLogWatcher(query, bookmark, true)
        {
            Enabled = true
        };

        _watcher.EventRecordWritten += (_, e) =>
        {
            if (e.EventException != null)
            {
                WriteServiceLog($"Event subscription error: {e.EventException}", EventLogEntryType.Error);
                return;
            }

            try
            {
                var recordId = e.EventRecord?.RecordId;
                if (recordId == null)
                {
                    WriteServiceLog("Trigger event received without RecordId; ignoring.", EventLogEntryType.Warning);
                    return;
                }

                lock (_sync)
                {
                    if (_lastRecordId == recordId)
                    {
                        return;
                    }

                    _lastRecordId = recordId;
                }

                if (InteractiveLaunch.IsProcessRunningInActiveSession("cmd"))
                {
                    WriteServiceLog("cmd.exe is already running in the active session. Skipping launch.");
                    return;
                }

                WriteServiceLog("Trigger event received. Launching cmd.exe in active session.");
                InteractiveLaunch.LaunchInActiveSession("cmd.exe");
            }
            catch (Exception ex)
            {
                WriteServiceLog($"Failed to launch cmd.exe: {ex}", EventLogEntryType.Error);
            }
        };
    }

    private static EventBookmark? GetLatestBookmark()
    {
        var query = new EventLogQuery(Constants.EventLogName, PathType.LogName, "*")
        {
            ReverseDirection = true
        };

        using var reader = new EventLogReader(query);
        using var record = reader.ReadEvent();
        return record?.Bookmark;
    }

    private static void EnsureEventSource()
    {
        if (!EventLog.SourceExists(Constants.EventSource))
        {
            EventLog.CreateEventSource(Constants.EventSource, Constants.EventLogName);
        }
    }

    private static void WriteServiceLog(string message, EventLogEntryType type = EventLogEntryType.Information)
    {
        EventLog.WriteEntry(Constants.EventSource, message, type, Constants.ServiceLogEventId);
    }
}

internal static class Program
{
    public static void Main(string[] args)
    {
        if (args.Length > 0 && args[0].Equals("--console", StringComparison.OrdinalIgnoreCase))
        {
            RunConsole();
            return;
        }

        ServiceBase.Run(new AppElevatorService());
    }

    private static void RunConsole()
    {
        Console.WriteLine("Running AppElevator in console mode. Press Ctrl+C to exit.");

        using var service = new AppElevatorService();
        service.StartServiceForConsole();

        using var exitEvent = new ManualResetEvent(false);
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            exitEvent.Set();
        };

        exitEvent.WaitOne();
        service.Stop();
    }

    private static void StartServiceForConsole(this ServiceBase service)
    {
        typeof(ServiceBase).GetMethod("OnStart", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!
            .Invoke(service, new object[] { Array.Empty<string>() });
    }
}
