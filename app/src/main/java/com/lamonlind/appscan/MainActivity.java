package com.lamonlind.appscan;

import android.app.Activity;
import android.content.Intent;
import android.graphics.Color;
import android.net.Uri;
import android.os.Bundle;
import android.text.Spannable;
import android.text.SpannableString;
import android.text.Spanned;
import android.text.style.ForegroundColorSpan;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class MainActivity extends Activity {
    private static final int REQUEST_INPUT = 1001;
    private static final int REQUEST_OUTPUT = 1002;
    private static final int MAX_LINES = 500;

    private EditText inputText;
    private EditText portsText;
    private EditText threadsText;
    private EditText outputName;
    private TextView progress;
    private TextView results;
    private Button start;
    private Button stop;

    private Uri inputUri;
    private Uri outputUri;
    private ScanController controller;
    private final ArrayList<String> passedHosts = new ArrayList<String>();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        inputText = findViewById(R.id.inputText);
        portsText = findViewById(R.id.ports);
        threadsText = findViewById(R.id.threads);
        outputName = findViewById(R.id.outputName);
        progress = findViewById(R.id.progress);
        results = findViewById(R.id.results);
        start = findViewById(R.id.start);
        stop = findViewById(R.id.stop);

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
    }

    private void beginScan() {
        if (controller != null) {
            controller.stop();
        }

        List<Integer> ports;
        int threads;
        try {
            ports = parsePorts(portsText.getText().toString());
            threads = Integer.parseInt(threadsText.getText().toString().trim());
            if (threads < 1) throw new NumberFormatException();
            if (threads > 500) threads = 500;
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

        passedHosts.clear();
        results.setText("  Method  Code  Server  Port  Host");
        progress.setText("Done 0 / 0");
        start.setEnabled(false);
        stop.setEnabled(true);

        controller = new ScanController(new ScanController.Callback() {
            @Override
            public void onProgress(long done, long total) {
                progress.setText("Done " + done + " / " + total);
            }

            @Override
            public void onHit(String method, int code, String server, int port,
                              String host, String location) {
                appendHit(method, code, server, port, host, location);
            }

            @Override
            public void onFinished(List<String> passed) {
                passedHosts.clear();
                passedHosts.addAll(passed);
                start.setEnabled(true);
                stop.setEnabled(false);
                progress.append(" - finished");
                requestOutputDocument();
            }

            @Override
            public void onError(String message) {
                Toast.makeText(MainActivity.this, message, Toast.LENGTH_SHORT).show();
            }
        });

        controller.start(hosts, ports, threads, cidr, hostCount);
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

    private void appendHit(String method, int code, String server, int port,
                           String host, String location) {
        String line = "  " + method + "  " + code + "  " + server + "  " + port + "  " + host;
        if (location != null && !location.isEmpty()) line += " -> " + location;
        line += "\n";

        String text = results.getText().toString();
        String[] lines = text.split("\n", -1);
        if (lines.length >= MAX_LINES) {
            StringBuilder sb = new StringBuilder();
            sb.append(lines[0]).append('\n');
            int start = lines.length - MAX_LINES + 2;
            for (int i = start; i < lines.length; i++) {
                if (!lines[i].isEmpty()) sb.append(lines[i]).append('\n');
            }
            results.setText(sb.toString());
        }

        SpannableString span = new SpannableString(line);
        if ("Varnish".equals(server) && code == 500) {
            span.setSpan(new ForegroundColorSpan(Color.rgb(0, 160, 0)), 0, line.length(),
                    Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
        }
        results.append(span);
        final ScrollView scroll = (ScrollView) results.getParent();
        scroll.post(new Runnable() {
            @Override
            public void run() {
                scroll.fullScroll(View.FOCUS_DOWN);
            }
        });
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
            writeOutput(uri);
        }
    }

    private void writeOutput(Uri uri) {
        try {
            OutputStream stream = getContentResolver().openOutputStream(uri, "wt");
            if (stream == null) return;
            OutputStreamWriter writer = new OutputStreamWriter(stream, StandardCharsets.UTF_8);
            for (String host : passedHosts) {
                writer.write(host);
                writer.write('\n');
            }
            writer.flush();
            writer.close();
            Toast.makeText(this, "Output saved", Toast.LENGTH_SHORT).show();
        } catch (IOException e) {
            Toast.makeText(this, "Could not save output", Toast.LENGTH_SHORT).show();
        }
    }

    @Override
    protected void onDestroy() {
        if (!isChangingConfigurations() && controller != null) controller.stop();
        super.onDestroy();
    }
}
