package com.lamonlind.appscan;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public class MainActivity extends Activity {
    private static final int REQUEST_INPUT = 1001;
    private static final int REQUEST_OUTPUT = 1002;

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

    private Uri inputUri;
    private Uri outputUri;
    private ScanController controller;
    private boolean pendingStart;
    private List<String> pendingHosts;
    private List<Integer> pendingPorts;
    private int pendingThreads;
    private Ipv4Cidr pendingCidr;
    private long pendingHostCount;

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
                if (controller != null) controller.stop();
                stop.setEnabled(false);
            }
        });
        test.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                runSelfTest();
            }
        });
    }

    private void beginScan() {
        if (controller != null) controller.stop();

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

        ArrayList<String> hosts = new ArrayList<String>();
        Ipv4Cidr cidr = null;
        long hostCount = 0;

        if (inputUri != null) {
            hosts = readHostFile(inputUri);
            if (hosts.isEmpty()) {
                Toast.makeText(this, "Host file is empty", Toast.LENGTH_SHORT).show();
                return;
            }
        } else {
            String input = inputText.getText().toString().trim();
            if (input.isEmpty()) {
                Toast.makeText(this, "Choose a host file or enter an IPv4 CIDR", Toast.LENGTH_SHORT).show();
                return;
            }
            try {
                cidr = Ipv4Cidr.parse(input);
                hostCount = cidr.count;
            } catch (IllegalArgumentException e) {
                Toast.makeText(this, "Invalid CIDR (or choose a host file)", Toast.LENGTH_SHORT).show();
                return;
            }
        }

        pendingHosts = hosts;
        pendingPorts = ports;
        pendingThreads = threads;
        pendingCidr = cidr;
        pendingHostCount = hostCount;
        pendingStart = true;

        if (outputUri == null) {
            requestOutputDocument();
        } else {
            startController();
        }
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

    private ArrayList<String> readHostFile(Uri uri) {
        ArrayList<String> result = new ArrayList<String>();
        try {
            InputStream stream = getContentResolver().openInputStream(uri);
            if (stream == null) return result;
            BufferedReader reader = new BufferedReader(new InputStreamReader(stream, StandardCharsets.UTF_8));
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (!line.isEmpty()) result.add(line);
            }
            reader.close();
        } catch (IOException e) {
            Toast.makeText(this, "Could not read host file", Toast.LENGTH_SHORT).show();
        }
        return result;
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

    private void startController() {
        if (!pendingStart) return;
        BufferedWriter writer = openOutputWriter();
        if (writer == null) {
            pendingStart = false;
            Toast.makeText(this, "Could not open output file", Toast.LENGTH_SHORT).show();
            return;
        }

        pendingStart = false;
        progress.setText("Done 0 / " + (pendingCidr != null
                ? pendingHostCount * pendingPorts.size()
                : (long) pendingHosts.size() * pendingPorts.size()));
        serverSummary.setText("no servers");
        statusSummary.setText("no status codes");
        start.setEnabled(false);
        stop.setEnabled(true);

        controller = new ScanController(new ScanController.Callback() {
            @Override
            public void onProgress(long done, long total, long sent, long responded,
                                   long failed, long skipped, double requestsPerSecond,
                                   String servers, String statuses) {
                progress.setText("Done " + done + " / " + total
                        + " | sent " + sent
                        + " | responded " + responded
                        + " | failed " + failed
                        + " | skipped " + skipped
                        + " | " + String.format(Locale.US, "%.1f", requestsPerSecond) + " req/s");
                serverSummary.setText(servers);
                statusSummary.setText(statuses);
            }

            @Override
            public void onFinished() {
                start.setEnabled(true);
                stop.setEnabled(false);
                progress.append(" - finished");
                Toast.makeText(MainActivity.this, "Scan finished", Toast.LENGTH_SHORT).show();
            }

            @Override
            public void onError(String message) {
                Toast.makeText(MainActivity.this, message, Toast.LENGTH_SHORT).show();
            }
        });

        String server = saveServer.getText().toString().trim();
        controller.start(pendingHosts, pendingPorts, pendingThreads, pendingCidr,
                pendingHostCount, writer, saveHostsOnly.isChecked(), server);
    }

    private BufferedWriter openOutputWriter() {
        if (outputUri == null) return null;
        try {
            OutputStream stream = getContentResolver().openOutputStream(outputUri, "wt");
            if (stream == null) return null;
            return new BufferedWriter(new OutputStreamWriter(stream, StandardCharsets.UTF_8), 8192);
        } catch (IOException e) {
            return null;
        }
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
                            + (server == null || server.trim().isEmpty() ? "unknown" : server.trim());
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
            if (pendingStart) startController();
        }
    }

    @Override
    protected void onDestroy() {
        if (!isChangingConfigurations() && controller != null) controller.stop();
        super.onDestroy();
    }
}
