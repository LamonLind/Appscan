package com.lamonlind.appscan;

import android.os.Handler;
import android.os.Looper;

import java.io.BufferedWriter;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

final class ScanController {
    interface Callback {
        void onProgress(long done, long total, long sent, long responded,
                        long failed, long skipped, double requestsPerSecond,
                        String serverSummary, String statusSummary);
        void onFinished();
        void onError(String message);
    }

    private static final int CONNECT_TIMEOUT_MS = 1000;
    private static final int READ_TIMEOUT_MS = 1000;
    private static final long FLUSH_INTERVAL_NANOS = 3000L * 1000000L;

    private final Callback callback;
    private final Handler mainHandler = new Handler(Looper.getMainLooper());
    private volatile ExecutorService executor;
    private final AtomicBoolean stopping = new AtomicBoolean(false);
    private final AtomicBoolean finished = new AtomicBoolean(false);
    private final AtomicLong done = new AtomicLong();
    private final AtomicLong sent = new AtomicLong();
    private final AtomicLong responded = new AtomicLong();
    private final AtomicLong failed = new AtomicLong();
    private final AtomicLong skipped = new AtomicLong();
    private final ConcurrentHashMap<String, AtomicInteger> serverCounts =
            new ConcurrentHashMap<String, AtomicInteger>();
    private final ConcurrentHashMap<String, AtomicInteger> statusCounts =
            new ConcurrentHashMap<String, AtomicInteger>();
    private volatile BufferedWriter outputWriter;
    private volatile boolean hostsOnly;
    private volatile String serverFilter = "";
    private volatile long lastFlushNanos;
    private volatile long total;
    private volatile long startedAtNanos;
    private volatile Thread producerThread;

    private final Runnable progressTicker = new Runnable() {
        @Override
        public void run() {
            postProgress();
            flushIfNeeded();
            if (!finished.get()) mainHandler.postDelayed(this, 500);
        }
    };

    ScanController(Callback callback) {
        this.callback = callback;
    }

    void start(List<String> hosts, List<Integer> ports, int threads,
               Ipv4Cidr cidr, long hostCount, BufferedWriter writer,
               boolean saveHostsOnly, String saveServer) {
        stopping.set(false);
        finished.set(false);
        done.set(0);
        sent.set(0);
        responded.set(0);
        failed.set(0);
        skipped.set(0);
        serverCounts.clear();
        statusCounts.clear();
        outputWriter = writer;
        hostsOnly = saveHostsOnly;
        serverFilter = normalizeServer(saveServer);
        if ("all".equals(serverFilter)) serverFilter = "";
        lastFlushNanos = System.nanoTime();
        total = cidr != null ? hostCount * ports.size() : (long) hosts.size() * ports.size();
        startedAtNanos = System.nanoTime();

        executor = Executors.newFixedThreadPool(threads);
        mainHandler.post(progressTicker);
        producerThread = new Thread(new Runnable() {
            @Override
            public void run() {
                if (cidr != null) {
                    submitCidr(cidr, ports);
                } else {
                    submitHosts(hosts, ports);
                }
                ExecutorService current = executor;
                if (current != null) current.shutdown();
                try {
                    if (current != null) current.awaitTermination(Long.MAX_VALUE, TimeUnit.NANOSECONDS);
                } catch (InterruptedException ignored) {
                    if (current != null) current.shutdownNow();
                }
                finish();
            }
        }, "appscan-producer");
        producerThread.start();
    }

    private void submitHosts(List<String> hosts, List<Integer> ports) {
        for (String host : hosts) {
            if (stopping.get()) break;
            host = host.trim();
            if (host.isEmpty()) continue;
            for (Integer port : ports) {
                if (stopping.get()) break;
                submitTask(host, port);
            }
        }
    }

    private void submitCidr(Ipv4Cidr cidr, List<Integer> ports) {
        for (long i = 0; i < cidr.count && !stopping.get(); i++) {
            String host = Ipv4Cidr.format(cidr.first + i);
            for (Integer port : ports) {
                if (stopping.get()) break;
                submitTask(host, port);
            }
        }
    }

    private void submitTask(final String host, final int port) {
        try {
            executor.execute(new Runnable() {
                @Override
                public void run() {
                    check(host, port);
                }
            });
        } catch (RejectedExecutionException e) {
            skipped.incrementAndGet();
            incrementDone();
        }
    }

    private void check(String host, int port) {
        if (stopping.get()) {
            skipped.incrementAndGet();
            incrementDone();
            return;
        }

        HttpURLConnection connection = null;
        int code = 0;
        String server = "";
        String location = "";
        boolean gotResponse = false;

        for (int attempt = 0; attempt < 2; attempt++) {
            if (stopping.get()) {
                skipped.incrementAndGet();
                incrementDone();
                return;
            }
            sent.incrementAndGet();
            try {
                String urlText = "http://" + (port == 80 ? host : host + ":" + port);
                URL url = new URL(urlText);
                connection = (HttpURLConnection) url.openConnection();
                connection.setInstanceFollowRedirects(false);
                connection.setRequestMethod("HEAD");
                connection.setConnectTimeout(CONNECT_TIMEOUT_MS);
                connection.setReadTimeout(READ_TIMEOUT_MS);
                connection.setUseCaches(false);
                code = connection.getResponseCode();
                server = header(connection, "Server");
                location = header(connection, "Location");
                responded.incrementAndGet();
                gotResponse = true;
                break;
            } catch (Exception ignored) {
                code = 0;
            } finally {
                if (connection != null) connection.disconnect();
            }
        }

        if (!gotResponse) {
            if (stopping.get()) {
                skipped.incrementAndGet();
            } else {
                failed.incrementAndGet();
            }
        } else if (!stopping.get()) {
            String normalizedServer = normalizeServer(server);
            if (code >= 100 &&
                    !"https://jio.com/BalanceExhaust".equals(location) &&
                    !"akamaighost".equals(normalizedServer) &&
                    !"akamainetstorage".equals(normalizedServer)) {
                incrementMap(serverCounts, normalizedServer);
                incrementMap(statusCounts, Integer.toString(code));
                writePass(host, port, code, normalizedServer);
            }
        }
        incrementDone();
    }

    private String normalizeServer(String server) {
        if (server == null) return "unknown";
        String result = server.trim().toLowerCase(Locale.US);
        return result.isEmpty() ? "unknown" : result;
    }

    private void incrementMap(ConcurrentHashMap<String, AtomicInteger> map, String key) {
        AtomicInteger count = map.get(key);
        if (count == null) {
            AtomicInteger created = new AtomicInteger();
            AtomicInteger existing = map.putIfAbsent(key, created);
            count = existing != null ? existing : created;
        }
        count.incrementAndGet();
    }

    private void writePass(String host, int port, int code, String server) {
        if (serverFilter.length() > 0 && !serverFilter.equals(server)) return;
        BufferedWriter writer = outputWriter;
        if (writer == null) return;
        synchronized (writer) {
            try {
                if (hostsOnly) {
                    writer.write(host);
                } else {
                    writer.write(host);
                    writer.write(":");
                    writer.write(Integer.toString(port));
                    writer.write(" | ");
                    writer.write(Integer.toString(code));
                    writer.write(" | ");
                    writer.write(server);
                }
                writer.newLine();
            } catch (IOException e) {
                callbackError("Could not write output");
            }
        }
    }

    private void callbackError(final String message) {
        mainHandler.post(new Runnable() {
            @Override
            public void run() {
                callback.onError(message);
            }
        });
    }

    private String header(HttpURLConnection connection, String name) {
        String value = connection.getHeaderField(name);
        return value == null ? "" : value;
    }

    private void incrementDone() {
        done.incrementAndGet();
    }

    private void postProgress() {
        final long value = done.get();
        final long sentValue = sent.get();
        final long respondedValue = responded.get();
        final long failedValue = failed.get();
        final long skippedValue = skipped.get();
        final long elapsedMillis = Math.max(1L, (System.nanoTime() - startedAtNanos) / 1000000L);
        final double rps = sentValue * 1000.0 / elapsedMillis;
        final String serverSummary = buildServerSummary();
        final String statusSummary = buildStatusSummary();
        mainHandler.post(new Runnable() {
            @Override
            public void run() {
                callback.onProgress(value, total, sentValue, respondedValue,
                        failedValue, skippedValue, rps, serverSummary, statusSummary);
            }
        });
    }

    private String buildServerSummary() {
        ArrayList<Map.Entry<String, AtomicInteger>> entries =
                new ArrayList<Map.Entry<String, AtomicInteger>>(serverCounts.entrySet());
        Collections.sort(entries, new Comparator<Map.Entry<String, AtomicInteger>>() {
            @Override
            public int compare(Map.Entry<String, AtomicInteger> left,
                               Map.Entry<String, AtomicInteger> right) {
                int result = Integer.compare(right.getValue().get(), left.getValue().get());
                return result != 0 ? result : left.getKey().compareTo(right.getKey());
            }
        });

        StringBuilder result = new StringBuilder();
        long others = 0;
        for (int i = 0; i < entries.size(); i++) {
            int count = entries.get(i).getValue().get();
            if (i < 10) {
                if (result.length() > 0) result.append(" | ");
                result.append(entries.get(i).getKey()).append(" : ").append(count);
            } else {
                others += count;
            }
        }
        if (others > 0) {
            if (result.length() > 0) result.append(" | ");
            result.append("others : ").append(others);
        }
        return result.length() == 0 ? "no servers" : result.toString();
    }

    private String buildStatusSummary() {
        ArrayList<Map.Entry<String, AtomicInteger>> entries =
                new ArrayList<Map.Entry<String, AtomicInteger>>(statusCounts.entrySet());
        Collections.sort(entries, new Comparator<Map.Entry<String, AtomicInteger>>() {
            @Override
            public int compare(Map.Entry<String, AtomicInteger> left,
                               Map.Entry<String, AtomicInteger> right) {
                return Integer.compare(Integer.parseInt(left.getKey()), Integer.parseInt(right.getKey()));
            }
        });
        StringBuilder result = new StringBuilder();
        for (Map.Entry<String, AtomicInteger> entry : entries) {
            if (result.length() > 0) result.append(" | ");
            result.append(entry.getKey()).append(" : ").append(entry.getValue().get());
        }
        return result.length() == 0 ? "no status codes" : result.toString();
    }

    private void flushIfNeeded() {
        BufferedWriter writer = outputWriter;
        if (writer == null) return;
        long now = System.nanoTime();
        if (now - lastFlushNanos < FLUSH_INTERVAL_NANOS) return;
        lastFlushNanos = now;
        synchronized (writer) {
            try {
                writer.flush();
            } catch (IOException e) {
                callbackError("Could not flush output");
            }
        }
    }

    private void flushAndClose() {
        BufferedWriter writer = outputWriter;
        outputWriter = null;
        if (writer == null) return;
        synchronized (writer) {
            try {
                writer.flush();
                writer.close();
            } catch (IOException e) {
                callbackError("Could not finish output");
            }
        }
    }

    private void finish() {
        if (!finished.compareAndSet(false, true)) return;
        long remaining = total - done.get();
        if (remaining > 0) {
            skipped.addAndGet(remaining);
            done.addAndGet(remaining);
        }
        if (done.get() > total) done.set(total);
        mainHandler.removeCallbacks(progressTicker);
        flushAndClose();
        mainHandler.post(new Runnable() {
            @Override
            public void run() {
                callback.onFinished();
            }
        });
    }

    void stop() {
        if (!stopping.compareAndSet(false, true)) return;
        ExecutorService current = executor;
        if (current != null) {
            List<Runnable> canceled = current.shutdownNow();
            for (Runnable ignored : canceled) {
                skipped.incrementAndGet();
                incrementDone();
            }
        }
        Thread producer = producerThread;
        if (producer != null) producer.interrupt();
        flushAndClose();
    }
}
