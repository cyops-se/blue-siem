using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Threading.Channels;
using BlueFwd.Service.Configuration;
using BlueFwd.Service.Monitoring;

namespace BlueFwd.Service.Pipeline;

/// <summary>
/// Single consumer of the event queue. Keeps a TCP (optionally TLS) connection to the syslog server,
/// writes events in batches and only advances stored positions once a batch has been flushed.
/// A failed batch is retried after reconnecting (at-least-once delivery).
/// </summary>
public sealed class SyslogSender(
    ConfigStore configStore,
    Channel<OutgoingEvent> queue,
    PositionStore positions,
    StatsRegistry stats,
    ILogger<SyslogSender> logger) : BackgroundService
{
    private const int MaxBatch = 500;
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(10);

    private TcpClient? _client;
    private Stream? _stream;
    private int _reconnectRequested;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        configStore.Changed += OnConfigChanged;
        var reader = queue.Reader;
        var batch = new List<OutgoingEvent>(MaxBatch);

        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    if (batch.Count == 0)
                    {
                        if (!await reader.WaitToReadAsync(stoppingToken))
                            break;
                        while (batch.Count < MaxBatch && reader.TryRead(out var ev))
                            batch.Add(ev);
                    }

                    var target = configStore.Current.Syslog;
                    await EnsureConnectedAsync(target, stoppingToken);

                    long bytes = 0;
                    foreach (var ev in batch)
                    {
                        var data = SyslogEncoder.Encode(ev, target);
                        await _stream!.WriteAsync(data, stoppingToken);
                        bytes += data.Length;
                    }
                    await _stream!.FlushAsync(stoppingToken);

                    Complete(batch, bytes);
                    batch.Clear();
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                {
                    break;
                }
                catch (Exception ex)
                {
                    var target = configStore.Current.Syslog;
                    stats.Sender.OnError(ex.Message);
                    logger.LogWarning("Syslog send to {Host}:{Port} failed: {Error}. Retrying in {Delay}s ({Count} events pending)",
                        target.Host, target.Port, ex.Message, target.ReconnectDelaySeconds, batch.Count + reader.Count);
                    Disconnect();
                    await Task.Delay(TimeSpan.FromSeconds(target.ReconnectDelaySeconds), stoppingToken)
                        .ContinueWith(_ => { }, TaskScheduler.Default);
                }
            }
        }
        finally
        {
            configStore.Changed -= OnConfigChanged;
            Disconnect();
            positions.Flush();
        }
    }

    private void Complete(List<OutgoingEvent> batch, long bytes)
    {
        stats.Sender.OnSent(batch.Count, bytes);

        // Events from one subscription arrive in order, so the last one per subscription is the new position.
        foreach (var group in batch.Where(e => e.SubscriptionId is not null).GroupBy(e => e.SubscriptionId!))
        {
            var subStats = stats.Find(group.Key);
            foreach (var _ in group)
                subStats?.OnForwarded();

            if (group.Last().RecordId is long recordId)
                positions.Set(group.Key, recordId);
        }
    }

    private async Task EnsureConnectedAsync(SyslogTargetConfig target, CancellationToken ct)
    {
        if (Interlocked.Exchange(ref _reconnectRequested, 0) == 1)
            Disconnect();

        if (_client is not null && IsAlive(_client))
            return;

        Disconnect();

        var client = new TcpClient { NoDelay = false, SendTimeout = 30000 };
        try
        {
            client.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);

            using (var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct))
            {
                timeout.CancelAfter(ConnectTimeout);
                try
                {
                    await client.ConnectAsync(target.Host, target.Port, timeout.Token);
                }
                catch (OperationCanceledException) when (!ct.IsCancellationRequested)
                {
                    throw new TimeoutException($"Connect timed out after {ConnectTimeout.TotalSeconds:0}s");
                }
            }

            Stream stream = client.GetStream();
            if (target.UseTls)
            {
                var ssl = new SslStream(stream, leaveInnerStreamOpen: false);
                await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
                {
                    TargetHost = target.Host,
                    EnabledSslProtocols = SslProtocols.None, // let the OS pick (TLS 1.2/1.3)
                    RemoteCertificateValidationCallback = (_, _, _, errors) =>
                        errors == SslPolicyErrors.None || target.AllowUntrustedCertificate,
                }, ct);
                stream = ssl;
            }

            _client = client;
            _stream = new BufferedStream(stream, 64 * 1024);

            var endpoint = $"{target.Host}:{target.Port}{(target.UseTls ? " (TLS)" : "")}";
            stats.Sender.OnConnected(endpoint);
            logger.LogInformation("Connected to syslog server {Endpoint}", endpoint);
        }
        catch
        {
            client.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Detects a connection the server has closed while we were idle. Without this the first write after
    /// a server-side close appears to succeed and that batch would be lost.
    /// </summary>
    private static bool IsAlive(TcpClient client)
    {
        try
        {
            var socket = client.Client;
            if (!socket.Connected) return false;
            return !(socket.Poll(0, SelectMode.SelectRead) && socket.Available == 0);
        }
        catch (Exception ex) when (ex is SocketException or ObjectDisposedException)
        {
            return false;
        }
    }

    private void Disconnect()
    {
        try { _stream?.Dispose(); } catch { /* connection already broken */ }
        _client?.Dispose();
        _stream = null;
        _client = null;
        stats.Sender.Connected = false;
    }

    private void OnConfigChanged(ForwarderConfig _) => Interlocked.Exchange(ref _reconnectRequested, 1);
}
