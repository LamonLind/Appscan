package com.lamonlind.appscan;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.Uri;
import android.os.Binder;
import android.os.Build;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.PowerManager;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public class ScanService extends Service {
    public static final String ACTION_START = "com.lamonlind.appscan.action.START";
    public static final String ACTION_STOP = "com.lamonlind.appscan.action.STOP";
    public static final String PREFS_NAME = "appscan_progress";

    public static final String PREF_ACTIVE = "active";
    public static final String PREF_DONE = "done";
    public static final String PREF_HOST_INDEX = "hostIndex";
    public static final String PREF_CIDR = "cidr";
    public static final String PREF_INPUT_URI = "inputUri";
    public static final String PREF_OUTPUT_URI = "outputUri";
    public static final String PREF_PORTS = "ports";
    public static final String PREF_THREADS = "threads";
    public static final String PREF_HOSTS_ONLY = "hostsOnly";
    public static final String PREF_SERVER = "server";
    public static final String PREF_TOTAL = "total";

    private static final String CHANNEL_ID = "appscan_scanning";
    private static final int NOTIFICATION_ID = 1;
    private static final long WAKE_LOCK_TIMEOUT_MS = 12L * 60L * 60L * 1000L;

    private final IBinder binder = new LocalBinder();
    private final Handler handler = new Handler(Looper.getMainLooper());
    private ScanController controller;
    private PowerManager.WakeLock wakeLock;

    private volatile long done;
    private volatile long total;
    private volatile double requestsPerSecond;
    private volatile String serverSummary = "no servers";
    private volatile String statusSummary = "no status codes";
    private volatile boolean finished;

    private volatile Ipv4Cidr cidr;
    private volatile List<String> hosts = new ArrayList<String>();
    private volatile List<Integer> ports = new ArrayList<Integer>();
    private volatile int threads;
    private volatile boolean hostsOnly;
    private volatile String serverFilter;
    private volatile Uri outputUri;
    private volatile Uri inputUri;
    private volatile long hostStartIndex;

    public class LocalBinder extends Binder {
        public ScanService getService() {
            return ScanService.this;
        }
    }

    @Override
    public IBinder onBind(Intent intent) {
        return binder;
    }

    @Override
    public void onCreate() {
        super.onCreate();
        createNotificationChannel();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && ACTION_STOP.equals(intent.getAction())) {
            stopScanning();
            return START_NOT_STICKY;
        }

        if (intent != null && ACTION_START.equals(intent.getAction())) {
            startFromIntent(intent);
        }
        return START_NOT_STICKY;
    }

    private void startFromIntent(Intent intent) {
        if (controller != null) controller.stop();

        String cidrText = intent.getStringExtra(PREF_CIDR);
        String inputUriText = intent.getStringExtra(PREF_INPUT_URI);
        String outputUriText = intent.getStringExtra(PREF_OUTPUT_URI);
        String portsText = intent.getStringExtra(PREF_PORTS);
        threads = intent.getIntExtra(PREF_THREADS, 40);
        hostsOnly = intent.getBooleanExtra(PREF_HOSTS_ONLY, false);
        serverFilter = intent.getStringExtra(PREF_SERVER);
        if (serverFilter == null) serverFilter = "all";
        hostStartIndex = intent.getLongExtra(PREF_HOST_INDEX, 0);

        inputUri = inputUriText == null || inputUriText.isEmpty()
                ? null : Uri.parse(inputUriText);
        outputUri = outputUriText == null || outputUriText.isEmpty()
                ? null : Uri.parse(outputUriText);
        ports = parsePorts(portsText);

        cidr = null;
        hosts = new ArrayList<String>();
        long hostCount = 0;
        if (inputUri != null) {
            hosts = readHosts(inputUri);
            hostCount = hosts.size();
        } else if (cidrText != null) {
            try {
                cidr = Ipv4Cidr.parse(cidrText);
                hostCount = cidr.count;
            } catch (IllegalArgumentException e) {
                stopSelf();
                return;
            }
        }
        if (hostCount == 0 || ports.isEmpty() || outputUri == null) {
            stopSelf();
            return;
        }

        total = hostCount * ports.size();
        done = hostStartIndex * ports.size();
        if (done > total) done = total;
        finished = false;
        requestsPerSecond = 0;

        BufferedWriter writer = openWriter(hostStartIndex == 0 ? "wt" : "wa");
        if (writer == null) {
            stopSelf();
            return;
        }

        startForeground(NOTIFICATION_ID, buildNotification());
        acquireWakeLock();

        final SharedPreferences prefs = getSharedPreferences(PREFS_NAME, MODE_PRIVATE);
        prefs.edit().putBoolean(PREF_ACTIVE, true)
                .putLong(PREF_DONE, done)
                .putLong(PREF_HOST_INDEX, hostStartIndex)
                .putLong(PREF_TOTAL, total)
                .putString(PREF_CIDR, cidrText == null ? "" : cidrText)
                .putString(PREF_INPUT_URI, inputUriText == null ? "" : inputUriText)
                .putString(PREF_OUTPUT_URI, outputUriText)
                .putString(PREF_PORTS, portsText)
                .putInt(PREF_THREADS, threads)
                .putBoolean(PREF_HOSTS_ONLY, hostsOnly)
                .putString(PREF_SERVER, serverFilter)
                .apply();

        controller = new ScanController(new ScanController.Callback() {
            @Override
            public void onProgress(long newDone, long newTotal, long sent,
                                   long responded, long failed, long skipped,
                                   double rps, String servers, String statuses) {
                done = newDone;
                total = newTotal;
                requestsPerSecond = rps;
                serverSummary = servers;
                statusSummary = statuses;
                saveProgress(false);
            }

            @Override
            public void onFinished() {
                finished = true;
                saveProgress(false);
                releaseWakeLock();
                stopForeground(STOP_FOREGROUND_REMOVE);
                stopSelf();
            }

            @Override
            public void onError(String message) {
                // Counters and file handling remain owned by ScanController.
            }
        });
        controller.start(hosts, ports, threads, cidr, hostCount, writer,
                hostsOnly, serverFilter, hostStartIndex);

        handler.removeCallbacks(notificationAndSaveTicker);
        handler.post(notificationAndSaveTicker);
    }

    private void stopScanning() {
        handler.removeCallbacks(notificationAndSaveTicker);
        if (controller != null) controller.stop();
        saveProgress(true);
        releaseWakeLock();
        stopForeground(STOP_FOREGROUND_REMOVE);
        stopSelf();
    }

    private final Runnable notificationAndSaveTicker = new Runnable() {
        @Override
        public void run() {
            if (finished) return;
            saveProgress(false);
            NotificationManager manager =
                    (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
            if (manager != null) manager.notify(NOTIFICATION_ID, buildNotification());
            handler.postDelayed(this, 2000);
        }
    };

    private void saveProgress(boolean stopped) {
        if (controller == null) return;
        SharedPreferences prefs = getSharedPreferences(PREFS_NAME, MODE_PRIVATE);
        done = controller.getDone();
        hostStartIndex = controller.getCurrentHostIndex();
        SharedPreferences.Editor editor = prefs.edit()
                .putBoolean(PREF_ACTIVE, stopped ? false : !finished)
                .putLong(PREF_DONE, done)
                .putLong(PREF_HOST_INDEX, hostStartIndex)
                .putLong(PREF_TOTAL, total);
        if (stopped) editor.putBoolean(PREF_ACTIVE, false);
        editor.apply();
    }

    private BufferedWriter openWriter(String mode) {
        if (outputUri == null) return null;
        try {
            OutputStream stream = getContentResolver().openOutputStream(outputUri, mode);
            if (stream == null) return null;
            return new BufferedWriter(new OutputStreamWriter(stream, StandardCharsets.UTF_8), 8192);
        } catch (IOException e) {
            return null;
        }
    }

    private ArrayList<String> readHosts(Uri uri) {
        ArrayList<String> result = new ArrayList<String>();
        try {
            InputStream stream = getContentResolver().openInputStream(uri);
            if (stream == null) return result;
            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(stream, StandardCharsets.UTF_8));
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (!line.isEmpty()) result.add(line);
            }
            reader.close();
        } catch (IOException ignored) {
        }
        return result;
    }

    private ArrayList<Integer> parsePorts(String text) {
        ArrayList<Integer> result = new ArrayList<Integer>();
        if (text == null || text.trim().isEmpty()) text = "80";
        try {
            for (String item : text.split(",")) {
                int port = Integer.parseInt(item.trim());
                if (port < 1 || port > 65535) throw new NumberFormatException();
                if (!result.contains(port)) result.add(port);
            }
        } catch (NumberFormatException e) {
            return result;
        }
        return result;
    }

    private void createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= 26) {
            NotificationChannel channel = new NotificationChannel(
                    CHANNEL_ID, "Appscan scanning", NotificationManager.IMPORTANCE_LOW);
            channel.setDescription("Appscan foreground scan progress");
            NotificationManager manager =
                    (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
            if (manager != null) manager.createNotificationChannel(channel);
        }
    }

    private Notification buildNotification() {
        Intent stopIntent = new Intent(this, ScanService.class);
        stopIntent.setAction(ACTION_STOP);
        PendingIntent stopPending = PendingIntent.getService(
                this, 2, stopIntent,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);

        Intent openIntent = new Intent(this, MainActivity.class);
        openIntent.setFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_SINGLE_TOP);
        PendingIntent openPending = PendingIntent.getActivity(
                this, 1, openIntent,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);

        String text = "Done " + done + " / " + total + " | "
                + String.format(Locale.US, "%.1f", requestsPerSecond) + " req/s";
        Notification.Builder builder;
        if (Build.VERSION.SDK_INT >= 26) {
            builder = new Notification.Builder(this, CHANNEL_ID);
        } else {
            builder = new Notification.Builder(this);
        }
        return builder.setSmallIcon(android.R.drawable.ic_menu_search)
                .setContentTitle("Appscan")
                .setContentText(text)
                .setContentIntent(openPending)
                .setOngoing(true)
                .setOnlyAlertOnce(true)
                .addAction(android.R.drawable.ic_media_pause, "Stop", stopPending)
                .build();
    }

    private void acquireWakeLock() {
        if (wakeLock != null && wakeLock.isHeld()) return;
        PowerManager power =
                (PowerManager) getSystemService(Context.POWER_SERVICE);
        if (power == null) return;
        wakeLock = power.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "Appscan::Scanning");
        wakeLock.acquire(WAKE_LOCK_TIMEOUT_MS);
    }

    private void releaseWakeLock() {
        if (wakeLock != null && wakeLock.isHeld()) wakeLock.release();
        wakeLock = null;
    }

    public long getDone() {
        if (controller != null) return controller.getDone();
        return done;
    }

    public long getTotal() {
        return total;
    }

    public double getRequestsPerSecond() {
        return requestsPerSecond;
    }

    public boolean isFinished() {
        return finished;
    }

    public boolean isScanning() {
        return controller != null && !finished;
    }

    public String getServerSummary() {
        return serverSummary;
    }

    public String getStatusSummary() {
        return statusSummary;
    }

    @Override
    public void onDestroy() {
        handler.removeCallbacks(notificationAndSaveTicker);
        releaseWakeLock();
        super.onDestroy();
    }
}
