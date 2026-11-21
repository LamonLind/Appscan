package com.lamonlind.appscan;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.PowerManager;
import android.provider.Settings;
import android.view.View;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public class MainActivity extends Activity {
    private static final int REQUEST_INPUT = 1001;
    private static final int REQUEST_OUTPUT = 1002;
    private static final int REQUEST_NOTIFICATIONS = 1003;

    private EditText inputText;
    private EditText portsText;
    private EditText threadsText;
    private EditText outputName;
    private EditText saveServer;
    private CheckBox saveHostsOnly;
    private TextView progress;
    private TextView serverSummary;
    private TextView statusSummary;
    private Button start;
    private Button stop;
    private Button test;
    private Button resume;

    private Uri inputUri;
    private Uri outputUri;
    private boolean pendingStart;

    private boolean bound;
    private ScanService scanService;
    private final Handler handler = new Handler();

    private final ServiceConnection connection = new ServiceConnection() {
        @Override
        public void onServiceConnected(ComponentName name, IBinder binder) {
            scanService = ((ScanService.LocalBinder) binder).getService();
            bound = true;
            updateUiFromService();
        }

        @Override
        public void onServiceDisconnected(ComponentName name) {
            bound = false;
            scanService = null;
        }
    };

    private final Runnable uiTicker = new Runnable() {
        @Override
        public void run() {
            updateUiFromService();
            handler.postDelayed(this, 500);
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        inputText = findViewById(R.id.inputText);
        portsText = findViewById(R.id.ports);
        threadsText = findViewById(R.id.threads);
        outputName = findViewById(R.id.outputName);
        saveServer = findViewById(R.id.saveServer);
        saveHostsOnly = findViewById(R.id.saveHostsOnly);
        progress = findViewById(R.id.progress);
        serverSummary = findViewById(R.id.serverSummary);
        statusSummary = findViewById(R.id.statusSummary);
        start = findViewById(R.id.start);
        stop = findViewById(R.id.stop);
        test = findViewById(R.id.test);
        resume = findViewById(R.id.resume);

        findViewById(R.id.chooseFile).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
                intent.addCategory(Intent.CATEGORY_OPENABLE);
                intent.setType("text/plain");
                startActivityForResult(intent, REQUEST_INPUT);
            }
        });

        start.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                beginScan();
            }
        });
        stop.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                startService(newIntent(ScanService.ACTION_STOP));
            }
        });
        test.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                runSelfTest();
            }
        });
        resume.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                resumeSavedScan();
            }
        });
        findViewById(R.id.battery).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                openBatteryOptimizationSettings();
            }
        });

        requestNotificationPermission();
        updateResumeAvailability();
    }

    @Override
    protected void onStart() {
        super.onStart();
        Intent intent = new Intent(this, ScanService.class);
        bindService(intent, connection, BIND_AUTO_CREATE);
        handler.removeCallbacks(uiTicker);
        handler.post(uiTicker);
    }

    @Override
    protected void onStop() {
        handler.removeCallbacks(uiTicker);
        if (bound) {
            unbindService(connection);
            bound = false;
            scanService = null;
        }
        super.onStop();
    }

    private void requestNotificationPermission() {
        if (Build.VERSION.SDK_INT >= 33
                && checkSelfPermission("android.permission.POST_NOTIFICATIONS")
                != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[]{"android.permission.POST_NOTIFICATIONS"},
                    REQUEST_NOTIFICATIONS);
        }
    }

    private void beginScan() {
        List<Integer> ports;
        int threads;
        try {
            ports = parsePorts(portsText.getText().toString());
            threads = Integer.parseInt(threadsText.getText().toString().trim());
            if (threads < 1) throw new NumberFormatException();
        } catch (Exception e) {
            Toast.makeText(this, "Invalid ports or thread count", Toast.LENGTH_SHORT).show();
            return;
        }

        String cidrText = "";
        if (inputUri == null) {
            cidrText = inputText.getText().toString().trim();
            if (cidrText.isEmpty()) {
                Toast.makeText(this, "Choose a host file or enter an IPv4 CIDR",
                        Toast.LENGTH_SHORT).show();
                return;
            }
            try {
                Ipv4Cidr.parse(cidrText);
            } catch (IllegalArgumentException e) {
                Toast.makeText(this, "Invalid CIDR (or choose a host file)",
                        Toast.LENGTH_SHORT).show();
                return;
            }
        }

        if (outputUri == null) {
            pendingStart = true;
            requestOutputDocument();
        } else {
            startServiceScan(cidrText, joinPorts(ports), threads, 0);
        }
    }

    private void startServiceScan(String cidrText, String portsTextValue,
                                  int threadsValue, long hostIndex) {
        pendingStart = false;
        Intent intent = newIntent(ScanService.ACTION_START);
        intent.putExtra(ScanService.PREF_CIDR, cidrText);
        intent.putExtra(ScanService.PREF_INPUT_URI,
                inputUri == null ? "" : inputUri.toString());
        intent.putExtra(ScanService.PREF_OUTPUT_URI,
                outputUri == null ? "" : outputUri.toString());
        intent.putExtra(ScanService.PREF_PORTS, portsTextValue);
        intent.putExtra(ScanService.PREF_THREADS, threadsValue);
        intent.putExtra(ScanService.PREF_HOSTS_ONLY, saveHostsOnly.isChecked());
        intent.putExtra(ScanService.PREF_SERVER,
                saveServer.getText().toString().trim());
        intent.putExtra(ScanService.PREF_HOST_INDEX, hostIndex);

        if (Build.VERSION.SDK_INT >= 26) {
            startForegroundService(intent);
        } else {
            startService(intent);
        }
        start.setEnabled(false);
        stop.setEnabled(true);
        resume.setEnabled(false);
    }

    private Intent newIntent(String action) {
        Intent intent = new Intent(this, ScanService.class);
        intent.setAction(action);
        return intent;
    }

    private void requestOutputDocument() {
        String name = outputName.getText().toString().trim();
        name = name.replace('/', '_').replace('\n', '_');
        if (name.isEmpty()) name = "Output.txt";
        if (!name.contains(".")) name += ".txt";

        Intent intent = new Intent(Intent.ACTION_CREATE_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("text/plain");
        intent.putExtra(Intent.EXTRA_TITLE, name);
        startActivityForResult(intent, REQUEST_OUTPUT);
    }

    private ArrayList<Integer> parsePorts(String text) {
        ArrayList<Integer> result = new ArrayList<Integer>();
        if (text == null || text.trim().isEmpty()) text = "80";
        for (String item : text.split(",")) {
            int port = Integer.parseInt(item.trim());
            if (port < 1 || port > 65535) throw new NumberFormatException();
            if (!result.contains(port)) result.add(port);
        }
        if (result.isEmpty()) throw new NumberFormatException();
        return result;
    }

    private String joinPorts(List<Integer> ports) {
        StringBuilder result = new StringBuilder();
        for (Integer port : ports) {
            if (result.length() > 0) result.append(',');
            result.append(port);
        }
        return result.toString();
    }

    private void updateResumeAvailability() {
        SharedPreferences prefs =
                getSharedPreferences(ScanService.PREFS_NAME, MODE_PRIVATE);
        long done = prefs.getLong(ScanService.PREF_DONE, 0);
        long total = prefs.getLong(ScanService.PREF_TOTAL, 0);
        String output = prefs.getString(ScanService.PREF_OUTPUT_URI, "");
        resume.setEnabled(output.length() > 0 && done < total);
    }

    private void resumeSavedScan() {
        SharedPreferences prefs =
                getSharedPreferences(ScanService.PREFS_NAME, MODE_PRIVATE);
        String cidrText = prefs.getString(ScanService.PREF_CIDR, "");
        String inputUriText = prefs.getString(ScanService.PREF_INPUT_URI, "");
        String outputUriText = prefs.getString(ScanService.PREF_OUTPUT_URI, "");
        String portsTextValue = prefs.getString(ScanService.PREF_PORTS, "80");
        int threadsValue = prefs.getInt(ScanService.PREF_THREADS, 40);
        long hostIndex = prefs.getLong(ScanService.PREF_HOST_INDEX, 0);

        inputUri = inputUriText.isEmpty() ? null : Uri.parse(inputUriText);
        outputUri = outputUriText.isEmpty() ? null : Uri.parse(outputUriText);
        portsText.setText(portsTextValue);
        threadsText.setText(Integer.toString(threadsValue));
        saveHostsOnly.setChecked(prefs.getBoolean(
                ScanService.PREF_HOSTS_ONLY, false));
        saveServer.setText(prefs.getString(ScanService.PREF_SERVER, "all"));
        if (inputUri == null) inputText.setText(cidrText);
        else inputText.setText(inputUri.getLastPathSegment());

        startServiceScan(cidrText, portsTextValue, threadsValue, hostIndex);
    }

    private void openBatteryOptimizationSettings() {
        Intent intent = new Intent(
                Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS,
                Uri.parse("package:" + getPackageName()));
        if (intent.resolveActivity(getPackageManager()) != null) {
            startActivity(intent);
        } else {
            Intent fallback = new Intent(
                    Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS);
            startActivity(fallback);
        }
    }

    private void updateUiFromService() {
        if (scanService == null) {
            updateResumeAvailability();
            return;
        }
        long done = scanService.getDone();
        long total = scanService.getTotal();
        double rps = scanService.getRequestsPerSecond();
        progress.setText("Done " + done + " / " + total
                + " | " + String.format(Locale.US, "%.1f", rps) + " req/s");
        serverSummary.setText(scanService.getServerSummary());
        statusSummary.setText(scanService.getStatusSummary());

        boolean scanning = scanService.isScanning();
        start.setEnabled(!scanning);
        stop.setEnabled(scanning);
        updateResumeAvailability();
    }

    private void runSelfTest() {
        test.setEnabled(false);
        progress.setText("Testing http://1.1.1.1 ...");
        new Thread(new Runnable() {
            @Override
            public void run() {
                HttpURLConnection connection = null;
                String result;
                try {
                    URL url = new URL("http://1.1.1.1");
                    connection = (HttpURLConnection) url.openConnection();
                    connection.setInstanceFollowRedirects(false);
                    connection.setRequestMethod("HEAD");
                    connection.setConnectTimeout(1000);
                    connection.setReadTimeout(1000);
                    connection.setUseCaches(false);
                    int code = connection.getResponseCode();
                    String server = connection.getHeaderField("Server");
                    result = "Status: " + code + " | Server: "
                            + (server == null || server.trim().isEmpty()
                            ? "unknown" : server.trim());
                } catch (Exception e) {
                    String message = e.getMessage();
                    result = "Exception: " + e.getClass().getName()
                            + (message == null || message.isEmpty() ? "" : ": " + message);
                } finally {
                    if (connection != null) connection.disconnect();
                }
                final String displayResult = result;
                runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        progress.setText(displayResult);
                        test.setEnabled(true);
                    }
                });
            }
        }, "appscan-self-test").start();
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (resultCode != Activity.RESULT_OK || data == null) return;
        Uri uri = data.getData();
        if (uri == null) return;

        if (requestCode == REQUEST_INPUT) {
            inputUri = uri;
            inputText.setText(uri.getLastPathSegment());
            try {
                getContentResolver().takePersistableUriPermission(
                        uri, Intent.FLAG_GRANT_READ_URI_PERMISSION);
            } catch (SecurityException ignored) {
            }
        } else if (requestCode == REQUEST_OUTPUT) {
            outputUri = uri;
            try {
                getContentResolver().takePersistableUriPermission(
                        uri, Intent.FLAG_GRANT_WRITE_URI_PERMISSION);
            } catch (SecurityException ignored) {
            }
            if (pendingStart) {
                beginScan();
            }
        }
    }
}
